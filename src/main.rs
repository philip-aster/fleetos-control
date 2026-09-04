//! `fleetos-control` entrypoint.
//!
//! Full integration: Raft cluster, dual CAs, gRPC servers, leader-gated controllers.
use clap::Parser;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use fleetos_control::attestation::join_token::JoinTokenStore;
use fleetos_control::ca::CaService;
use fleetos_control::config::{ClusterMode, ControlConfig};
use fleetos_control::controllers::leader::{ControllerFactory, LeaderGate};
use fleetos_control::controllers::{
    CronController, WorkloadController, node_controller::NodeController,
    pod_controller::PodController,
};
use fleetos_control::dummy_ip::allocator::DummyIpAllocator;
use fleetos_control::provisioning::control_pool::ControlPoolManager;
use fleetos_control::raft::raft_proto::raft_transport_server::RaftTransportServer;
use fleetos_control::raft::records::ControlNodeAddressRecord;
use fleetos_control::raft::state_machine::FjallStateMachine;
use fleetos_control::raft::store::FjallLogStorage;
use fleetos_control::raft::{AuditedCommand, FleetosCommand};
use fleetos_control::raft::{RaftHandle, network::TonicRaftNetworkFactory};
use fleetos_control::scheduler::OrdinalTracker;
use fleetos_control::secrets::SecretStore;
use fleetos_control::secrets::crypto::FileMasterKey;
use fleetos_control::storage::version::VersionedState;
use fleetos_control::storage::{init_keyspaces, open_database};
use fleetos_control::tls::PeerConnectInfo;
use fleetos_control::watch::broadcast::BroadcastHub;
use fleetos_core::spiffe::SpiffeId;
use openraft::{Config, Raft};

#[derive(Parser)]
#[command(name = "fleetos-control", about = "FleetOS Control Plane Brain")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, default_value = "control.example.toml")]
    config: PathBuf,
}

/// Everything main() needs from a first-boot join flow.
struct JoinInfo {
    node_id: u64,
    svid_cert_der: Vec<u8>,
    svid_key_der: Vec<u8>,
    trust_bundle_pem: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install the ring crypto provider as the process default.
    // REQUIRED by rustls 0.23 — without this, ServerConfig::builder() panics.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls ring crypto provider");

    // Parse CLI and load config BEFORE initializing the tracing subscriber,
    // because the subscriber now carries OTel layers that need config.
    let cli = Cli::parse();
    let config = match ControlConfig::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config {}: {}", cli.config.display(), e);
            return Err(e.into());
        }
    };

    // OpenTelemetry providers (metrics + traces + logs), if enabled.
    let telemetry = fleetos_control::telemetry::init_providers(&config)?;

    // Tracing subscriber: console output always; OTel trace + log bridges when
    // telemetry is enabled.
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let mut layers: Vec<
        Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync>,
    > = Vec::new();
    layers.push(Box::new(tracing_subscriber::fmt::layer()));
    if let Some(ref t) = telemetry {
        layers.push(Box::new(
            tracing_opentelemetry::layer().with_tracer(fleetos_control::telemetry::tracer(t)),
        ));
        layers.push(Box::new(
            opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(
                &t.logger_provider,
            ),
        ));
    }
    tracing_subscriber::registry()
        .with(layers)
        .with(env_filter)
        .init();

    tracing::info!(config = %cli.config.display(), "configuration loaded");
    tracing::info!(
        node_name = %config.node.name,
        cluster_mode = ?config.cluster.mode,
        fjall_path = %config.storage.fjall_path.display(),
        "configuration loaded"
    );

    // --- Phase 1: Storage initialization ---
    let db = open_database(&config.storage.fjall_path)?;
    let keyspaces = init_keyspaces(&db)?;
    let versioned_state = VersionedState::new(keyspaces.version.clone());
    tracing::info!(
        version = ?versioned_state.current_version(),
        "storage initialized"
    );

    // --- Phase 2: Broadcast hub ---
    let broadcast_hub = BroadcastHub::new();
    tracing::info!("broadcast hub initialized");

    // --- Phase 3: Load master key (secrets + CA encryption at rest) ---
    let master_key = if config.secrets.master_key_path.exists() {
        FileMasterKey::load(&config.secrets.master_key_path)?
    } else {
        FileMasterKey::generate(&config.secrets.master_key_path)?
    };
    tracing::info!("master key loaded");

    // --- Phase 4: Trust bundles (dual CAs) ---
    // Bootstrap: generate + persist roots.
    // Join: load persisted roots (present after the first successful catch-up
    //       and restart). On the very first join boot nothing is persisted yet —
    //       the CA arrives via Raft snapshot, and this node's identity comes
    //       from the join flow instead.
    let ca_bundle_exists = keyspaces
        .trust_bundles
        .get(format!("bundle:{}", config.trust_domains.data_control).as_bytes())?
        .is_some();

    let ca_service: Option<CaService> = match config.cluster.mode {
        ClusterMode::Bootstrap => Some(CaService::bootstrap(
            &config,
            keyspaces.trust_bundles.clone(),
            &master_key,
        )?),
        ClusterMode::Join if ca_bundle_exists => Some(CaService::load(
            &config,
            keyspaces.trust_bundles.clone(),
            &master_key,
        )?),
        ClusterMode::Join => None,
    };
    tracing::info!(
        data_control_td = %config.trust_domains.data_control,
        admin_td = %config.trust_domains.admin,
        ca_available = ca_service.is_some(),
        "dual-root CA phase complete"
    );

    // --- Phase 5: Core services initialization ---
    let join_token_store = Arc::new(JoinTokenStore::with_ttl(
        keyspaces.join_tokens.clone(),
        config.attestation.join_token_ttl_secs,
    ));

    let dummy_ip_allocator = Arc::new(DummyIpAllocator::new(
        keyspaces.dummy_ips.clone(),
        config.dummy_ip.tenant_block_prefix,
    )?);

    let ordinal_tracker = Arc::new(OrdinalTracker::new(keyspaces.ordinals.clone()));

    // The CA borrow of master_key ended in Phase 4, so ownership transfers
    // cleanly into the SecretStore here.
    let secret_store = Arc::new(SecretStore::new(
        keyspaces.secrets.clone(),
        Box::new(master_key),
    ));

    // --- Phase 6: Controllers ---
    let storage_engine = Arc::new(fleetos_control::storage::StorageEngine::new(
        keyspaces.version.clone(),
        keyspaces.raft_log.clone(),
        keyspaces.raft_log_meta.clone(),
        keyspaces.raft_state.clone(),
        keyspaces.raft_snapshot.clone(),
        keyspaces.nodes.clone(),
        keyspaces.svids.clone(),
        keyspaces.placements.clone(),
        keyspaces.tenants.clone(),
        keyspaces.ordinals.clone(),
        keyspaces.workloads.clone(),
        keyspaces.router_assignments.clone(),
        keyspaces.active_delegations.clone(),
        keyspaces.revoked_delegations.clone(),
        keyspaces.join_tokens.clone(),
        keyspaces.pcr_policies.clone(),
        keyspaces.dummy_ips.clone(),
        keyspaces.secrets.clone(),
        keyspaces.sag_rules.clone(),
        keyspaces.node_pools.clone(),
        keyspaces.audit_log.clone(),
        keyspaces.operator_grants.clone(),
        keyspaces.workload_status.clone(),
        keyspaces.tenant_quotas.clone(),
    ));

    // JoinHandles for the gRPC listeners, awaited during graceful shutdown.
    let mut server_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // --- Phase 7: Raft cluster initialization ---
    let (raft_handle, shutdown_tx, join_info, dc_mtls, dc_resolver, raft_resolver) =
        init_raft_cluster(
            &config,
            db.clone(),
            keyspaces.clone(),
            versioned_state.clone(),
            broadcast_hub.clone(),
            ca_service.as_ref(),
        )
        .await?;

    // --- OTel metrics registration (G-1) ---
    // Register observable gauges now that the Raft handle exists.
    if let Some(ref t) = telemetry {
        fleetos_control::telemetry::register_metrics(
            &t.meter_provider,
            versioned_state.clone(),
            broadcast_hub.clone(),
            raft_handle.raft.clone(),
        );
    }

    // --- Controllers (need the Raft handle; created after Raft init) ---
    let workload_controller = Arc::new(WorkloadController::new(
        storage_engine.clone(),
        ordinal_tracker.clone(),
        raft_handle.raft.clone(),
        dummy_ip_allocator.clone(),
    ));
    let pod_controller = Arc::new(PodController::new(
        ordinal_tracker.clone(),
        raft_handle.raft.clone(),
    ));
    let node_controller = Arc::new(NodeController::new(
        raft_handle.raft.clone(),
        config.svid.node_ttl_secs,
    ));
    let cron_controller = Arc::new(CronController::new(
        workload_controller.clone(),
        raft_handle.raft.clone(),
        keyspaces.cron_checkpoints.clone(),
    ));

    // --- Phase 7b: Raft transport listener (inbound consensus RPCs) ---
    // Required for ANY multi-node operation: replication, votes, snapshots,
    // and RequestJoin from joining nodes.
    // --- Phase 7b: Raft transport listener (inbound consensus RPCs) ---
    let raft_addr: std::net::SocketAddr = config.listeners.raft.parse()?;
    let raft_transport_impl =
        fleetos_control::raft::server::RaftTransportServerImpl::new(raft_handle.raft.clone());
    let raft_server_config =
        std::sync::Arc::new(fleetos_control::tls::mtls::build_server_config_dynamic(
            &dc_mtls.trust_bundle_pem,
            raft_resolver.clone(),
        )?);
    let raft_tls_acceptor = tokio_rustls::TlsAcceptor::from(raft_server_config);
    let raft_td_config =
        fleetos_control::tls::trust_domains::TrustDomainConfig::from_config(&config);
    let raft_revoked_svids = keyspaces.revoked_svids.clone();

    // 1. Subscribe BEFORE the spawn (in main)
    let raft_shutdown_rx = shutdown_tx.subscribe();

    // 2. Spawn the task (ONLY ONE SPAWN)
    let raft_server_handle = tokio::spawn(async move {
        tracing::info!(addr = %raft_addr, "starting Raft transport listener (mTLS)");
        let listener = match tokio::net::TcpListener::bind(raft_addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, "failed to bind Raft transport listener");
                return;
            }
        };
        let incoming = async_stream::stream! {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let acceptor = raft_tls_acceptor.clone();
                        let td_config = raft_td_config.clone();
                        let revoked_ks = raft_revoked_svids.clone();
                        yield async move {
                            let tls_stream = acceptor.accept(stream).await.map_err(|e| {
                                tracing::warn!(error = %e, addr = %addr, "raft TLS handshake failed");
                                std::io::Error::new(std::io::ErrorKind::ConnectionAborted, e)
                            })?;
                            let (_, server_conn) = tls_stream.get_ref();
                            let peer_certs = server_conn.peer_certificates().ok_or_else(|| {
                                std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no peer certificate")
                            })?;
                            let peer_cert_der = peer_certs.first().ok_or_else(|| {
                                std::io::Error::new(std::io::ErrorKind::PermissionDenied, "empty cert chain")
                            })?;
                            let spiffe_uri = fleetos_control::tls::mtls::extract_spiffe_uri_san(peer_cert_der)
                                .map_err(|e| {
                                    tracing::warn!(addr = %addr, error = %e, "raft SPIFFE extraction failed");
                                    std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)
                                })?;
                            fleetos_control::tls::trust_domains::validate_peer_identity(
                                &spiffe_uri,
                                fleetos_control::tls::trust_domains::TrustDomainRole::DataControl,
                                &td_config,
                            ).map_err(|e| {
                                tracing::warn!(addr = %addr, spiffe = %spiffe_uri, error = %e, "raft peer identity rejected");
                                std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)
                            })?;
                            let spiffe_id: SpiffeId = spiffe_uri.parse().map_err(|e| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                            })?;
                            if spiffe_id.kind != fleetos_core::spiffe::IdKind::Control {
                                tracing::warn!(addr = %addr, spiffe = %spiffe_id, "raft peer is not control-kind");
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    "raft peers must be control-kind",
                                ));
                            }
                            if fleetos_control::revocation::is_svid_revoked(&revoked_ks, &spiffe_id.to_string()) {
                                tracing::warn!(addr = %addr, spiffe = %spiffe_id, "raft peer SVID is revoked");
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    "raft peer SVID has been revoked",
                                ));
                            }
                            tracing::debug!(addr = %addr, spiffe = %spiffe_id, "raft peer authenticated");
                            Ok::<_, std::io::Error>(PeerAuthenticatedStream {
                                inner: tls_stream,
                                spiffe_id: Some(spiffe_id),
                            })
                        }.await;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to accept raft connection");
                    }
                }
            }
        };

        if let Err(e) = tonic::transport::Server::builder()
            .add_service(RaftTransportServer::new(raft_transport_impl))
            .serve_with_incoming_shutdown(incoming, wait_for_shutdown_flag(raft_shutdown_rx))
            .await
        {
            tracing::error!(error = %e, "Raft transport server failed");
        }
    }); // <-- End of the single spawn

    // 3. Push the handle AFTER the spawn (in main)
    server_handles.push(raft_server_handle);

    // --- Phase 7c: First-boot join — request cluster membership ---
    // Sent AFTER the raft listener is spawned so the leader's blocking
    // add_learner can reach us as soon as it starts replicating.
    if let Some(ref info) = join_info {
        let join_raft_target = config
            .cluster
            .join_raft_target
            .clone()
            .expect("join_raft_target validated in init_raft_cluster");
        let our_raft_addr = config.listeners.raft.clone();
        let our_dc_addr = config.listeners.data_control.clone();
        let trust_domain = config.trust_domains.data_control.clone();
        let node_id = info.node_id;
        let svid_cert_der = info.svid_cert_der.clone();
        let svid_key_der = info.svid_key_der.clone();
        let trust_bundle_pem = info.trust_bundle_pem.clone();
        tokio::spawn(async move {
            match fleetos_control::join::request_membership(
                &join_raft_target,
                node_id,
                &our_raft_addr,
                &our_dc_addr,
                &svid_cert_der,
                &svid_key_der,
                &trust_bundle_pem,
                &trust_domain,
            )
            .await
            {
                Ok(()) => tracing::info!(node_id, "cluster membership established"),
                Err(e) => tracing::error!(error = %e, "membership request loop failed"),
            }
        });
    }

    // --- Phase 8: Controller factory and leader gate ---
    let controller_factory = Arc::new(FleetosControllerFactory {
        workload_controller: workload_controller.clone(),
        pod_controller: pod_controller.clone(),
        node_controller: node_controller.clone(),
        cron_controller: cron_controller.clone(),
        storage_engine: storage_engine.clone(),
        node_lease_timeout_secs: config.health.node_lease_timeout_secs,
        node_check_interval_secs: config.health.node_check_interval_secs,
        pod_check_interval_secs: config.health.pod_check_interval_secs,
        workload_status_staleness_secs: config.health.workload_status_staleness_secs,
    });

    let leader_gate = LeaderGate::new(raft_handle.raft.as_ref().clone());
    let shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        leader_gate.run(controller_factory, shutdown_rx).await;
    });

    // --- Phase 9: Control Pool Manager (needs raft_handle from Phase 7) ---
    let control_pool_manager = Arc::new(ControlPoolManager::new(
        raft_handle.raft.clone(),
        storage_engine.clone(),
    ));

    // --- Phase 10 (optional): Provisioning ---
    // Only start provisioning if a provider endpoint is configured.
    // This is leader-gated, so it only runs on the Raft leader.
    let provisioning_config = fleetos_control::provisioning::ProvisioningConfig {
        endpoint: config.provisioning.endpoint.clone(),
        poll_interval_secs: config.provisioning.poll_interval_secs,
    };

    if provisioning_config.is_enabled() {
        match fleetos_control::provisioning::reconcile::ProvisioningReconciler::new(
            provisioning_config,
            join_token_store.clone(),
            control_pool_manager.clone(),
            storage_engine.clone(),
            raft_handle.raft.clone(),
        )
        .await
        {
            Ok(mut reconciler) => {
                let provisioning_shutdown_rx = shutdown_tx.subscribe();
                tokio::spawn(async move {
                    reconciler.run_loop(provisioning_shutdown_rx).await;
                });
                tracing::info!("provisioning reconciler started");
            }
            Err(e) => {
                tracing::warn!(error = %e, "provisioning not started (endpoint not configured or unreachable)");
            }
        }
    } else {
        tracing::info!("provisioning disabled (no endpoint configured)");
    }

    // --- Phase 11: gRPC Servers ---

    // Optional client auth on Data/Control: attestation is inherently pre-SVID.
    // Authenticated peers are still fully validated; unauthenticated peers get
    // spiffe_id = None and are rejected by every identity-gated service.
    let dc_server_config = std::sync::Arc::new(
        fleetos_control::tls::mtls::build_server_config_optional_auth_dynamic(
            &dc_mtls.trust_bundle_pem,
            dc_resolver.clone(),
        )?,
    );

    tracing::info!("setting up gRPC servers");

    // Initialize gRPC services
    let status_service = fleetos_control::watch::status_service::WorkloadStatusServiceImpl::new(
        raft_handle.raft.clone(),
    );
    let policy_service =
        fleetos_control::watch::policy_stream::PolicyServiceImpl::new(broadcast_hub.clone());
    let watch_service =
        fleetos_control::watch::watch_service::WatchServiceImpl::new(broadcast_hub.clone());
    let scheduler_service =
        fleetos_control::watch::scheduler_stream::SchedulerServiceImpl::new(broadcast_hub.clone());
    let secret_service = fleetos_control::watch::secret_service::SecretServiceImpl::new(
        secret_store.clone(),
        keyspaces.svids.clone(),
    );
    let router_service =
        fleetos_control::watch::router_assignment::RouterAssignmentServiceImpl::new(
            broadcast_hub.clone(),
        );

    // Attestation and CA services (Data/Control listener)
    let nonce_manager = Arc::new(fleetos_control::attestation::nonce::NonceManager::new(
        keyspaces.nonces.clone(),
    ));
    let pcr_store = Arc::new(
        fleetos_control::attestation::pcr_policy::PcrPolicyStore::new(
            keyspaces.pcr_policies.clone(),
        ),
    );
    let attestation_service =
        fleetos_control::attestation::grpc_service::AttestationServiceImpl::new(
            nonce_manager,
            join_token_store.clone(),
            pcr_store,
            keyspaces.nonce_claims.clone(),
            keyspaces.svid_grants.clone(),
            raft_handle.raft.clone(),
            keyspaces.control_addresses.clone(),
            keyspaces.node_eks.clone(),
            keyspaces.pending_activations.clone(),
            ca_service.as_ref().map(|ca| ca.data_control.clone()),
            config.svid.node_ttl_secs,
            config.attestation.mode,
            config.tpm.clone(),
        );

    // CaService is only available when the local CA is loaded.
    let ca_grpc_service = ca_service.as_ref().map(|ca| {
        fleetos_control::ca::grpc_service::CaServiceImpl::new(
            ca.data_control.clone(),
            config.svid.node_ttl_secs,
            keyspaces.svids.clone(),
            keyspaces.svid_grants.clone(),
            keyspaces.placements.clone(),
            keyspaces.control_addresses.clone(),
            raft_handle.raft.clone(),
        )
    });

    let ca_data_control = ca_service.as_ref().map(|ca| ca.data_control.clone());
    let admin_service = fleetos_control::admin::service::AdminServiceImpl::new(
        storage_engine.clone(),
        join_token_store.clone(),
        dummy_ip_allocator.clone(),
        raft_handle.raft.clone(),
        config.operators.clone(),
        config.svid.node_ttl_secs,
        secret_store.clone(),
        ca_data_control,
        config.svid.delegated_key_ttl_secs,
        keyspaces.node_eks.clone(),
    );

    let dc_addr: std::net::SocketAddr = config.listeners.data_control.parse()?;
    let admin_addr: std::net::SocketAddr = config.listeners.admin.parse()?;

    // Spawn Data/Control listener with custom TLS (optional client auth)
    let dc_tls_acceptor = tokio_rustls::TlsAcceptor::from(dc_server_config);
    let dc_td_config = fleetos_control::tls::trust_domains::TrustDomainConfig::from_config(&config);
    let dc_revoked_svids = keyspaces.revoked_svids.clone();

    // 1. Subscribe BEFORE the spawn (in main)
    let dc_shutdown_rx = shutdown_tx.subscribe();

    // 2. Spawn the task (ONLY ONE SPAWN)
    let dc_server_handle = tokio::spawn(async move {
        tracing::info!(addr = %dc_addr, "starting Data/Control gRPC listener");
        let listener = match tokio::net::TcpListener::bind(dc_addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, "failed to bind Data/Control listener");
                return;
            }
        };

        let incoming = async_stream::stream! {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let acceptor = dc_tls_acceptor.clone();
                        let td_config = dc_td_config.clone();
                        let revoked_ks = dc_revoked_svids.clone();
                        yield async move {
                            let tls_stream = acceptor.accept(stream).await
                                .map_err(|e| {
                                    tracing::warn!(error = %e, addr = %addr, "TLS handshake failed");
                                    std::io::Error::new(std::io::ErrorKind::ConnectionAborted, e)
                                })?;
                            let (_, server_conn) = tls_stream.get_ref();
                            let spiffe_id = match server_conn.peer_certificates().and_then(|c| c.first()) {
                                Some(peer_cert_der) => {
                                    let spiffe_uri = fleetos_control::tls::mtls::extract_spiffe_uri_san(peer_cert_der)
                                        .map_err(|e| {
                                            tracing::warn!(addr = %addr, error = %e, "SPIFFE extraction failed");
                                            std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)
                                        })?;
                                    fleetos_control::tls::trust_domains::validate_peer_identity(
                                        &spiffe_uri,
                                        fleetos_control::tls::trust_domains::TrustDomainRole::DataControl,
                                        &td_config,
                                    ).map_err(|e| {
                                        tracing::warn!(addr = %addr, spiffe = %spiffe_uri, error = %e, "peer identity rejected");
                                        std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)
                                    })?;
                                    let id: SpiffeId = spiffe_uri.parse()
                                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                                    tracing::debug!(addr = %addr, spiffe = %id, "peer authenticated");
                                    if fleetos_control::revocation::is_svid_revoked(&revoked_ks, &id.to_string()) {
                                        tracing::warn!(addr = %addr, spiffe = %id, "peer SVID is revoked");
                                        return Err(std::io::Error::new(
                                            std::io::ErrorKind::PermissionDenied,
                                            "peer SVID has been revoked",
                                        ));
                                    }
                                    Some(id)
                                }
                                None => {
                                    tracing::debug!(addr = %addr, "unauthenticated connection (pre-attestation)");
                                    None
                                }
                            };
                            Ok::<_, std::io::Error>(PeerAuthenticatedStream {
                                inner: tls_stream,
                                spiffe_id,
                            })
                        }.await;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to accept connection");
                    }
                }
            }
        };

        let mut server = tonic::transport::Server::builder()
            .add_service(fleetos_core::proto::fleetos::workload_status_service_server::WorkloadStatusServiceServer::new(status_service))
            .add_service(fleetos_core::proto::fleetos::policy_service_server::PolicyServiceServer::new(policy_service))
            .add_service(fleetos_core::proto::fleetos::watch_service_server::WatchServiceServer::new(watch_service))
            .add_service(fleetos_core::proto::fleetos::scheduler_service_server::SchedulerServiceServer::new(scheduler_service))
            .add_service(fleetos_core::proto::fleetos::router_assignment_service_server::RouterAssignmentServiceServer::new(router_service))
            .add_service(fleetos_core::proto::fleetos::secret_service_server::SecretServiceServer::new(secret_service))
            .add_service(fleetos_core::proto::fleetos::attestation_service_server::AttestationServiceServer::new(attestation_service));

        if let Some(ca_svc) = ca_grpc_service {
            server = server.add_service(
                fleetos_core::proto::fleetos::ca_service_server::CaServiceServer::new(ca_svc),
            );
        }

        if let Err(e) = server
            .serve_with_incoming_shutdown(incoming, wait_for_shutdown_flag(dc_shutdown_rx))
            .await
        {
            tracing::error!(error = %e, "Data/Control gRPC server failed");
        }
    }); // <-- End of the single spawn

    // 3. Push the handle AFTER the spawn (in main)
    server_handles.push(dc_server_handle);

    // Spawn Admin listener with custom TLS (strict mTLS, Admin domain).
    // Disabled on a first join boot — the Admin CA isn't available until the
    // cluster state (including CAs) has been replicated to this node.
    // Spawn Admin listener with custom TLS (strict mTLS, Admin domain).
    if let Some(ref ca) = ca_service {
        let (admin_svid, admin_root_pem) = {
            let admin_bundle = ca.admin.read();
            let admin_params = fleetos_control::ca::rcgen_impl::SvidParams {
                spiffe_id: format!(
                    "spiffe://{}/ns/system/control/{}",
                    config.trust_domains.admin, config.node.name
                ),
                kind: fleetos_control::ca::rcgen_impl::SvidKind::Control,
                role: None,
                ordinal: None,
                degraded: false,
                ttl_secs: config.svid.admin_ttl_secs,
            };
            let svid = fleetos_control::ca::rcgen_impl::sign_svid(
                &admin_params,
                &admin_bundle.current_key,
                &admin_bundle.current_cert_der,
            )?;
            (svid, admin_bundle.trust_bundle_pem())
        };
        let admin_initial_key = fleetos_control::tls::mtls::certified_key_from_der(
            &admin_svid.cert_der,
            &admin_svid.private_key_der,
        )?;
        let admin_mtls = fleetos_control::tls::mtls::MtlsConfig {
            cert_chain: vec![rustls::pki_types::CertificateDer::from(admin_svid.cert_der)],
            private_key: rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(admin_svid.private_key_der.to_vec()),
            ),
            trust_bundle_pem: admin_root_pem,
            role: fleetos_control::tls::trust_domains::TrustDomainRole::Admin,
        };

        let admin_resolver = Arc::new(fleetos_control::tls::mtls::DynamicCertResolver::new(
            admin_initial_key,
        ));
        let admin_server_config =
            std::sync::Arc::new(fleetos_control::tls::mtls::build_server_config_dynamic(
                &admin_mtls.trust_bundle_pem,
                admin_resolver.clone(),
            )?);
        let admin_tls_acceptor = tokio_rustls::TlsAcceptor::from(admin_server_config);
        let admin_td_config =
            fleetos_control::tls::trust_domains::TrustDomainConfig::from_config(&config);
        let admin_revoked_svids = keyspaces.revoked_svids.clone();

        // 1. Subscribe BEFORE the spawn (in main)
        let admin_shutdown_rx = shutdown_tx.subscribe();

        // 2. Spawn the task (ONLY ONE SPAWN)
        let admin_server_handle = tokio::spawn(async move {
            tracing::info!(addr = %admin_addr, "starting Admin gRPC listener");
            let listener = match tokio::net::TcpListener::bind(admin_addr).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(error = %e, "failed to bind Admin listener");
                    return;
                }
            };

            let incoming = async_stream::stream! {
                loop {
                    match listener.accept().await {
                        Ok((stream, addr)) => {
                            let acceptor = admin_tls_acceptor.clone();
                            let td_config = admin_td_config.clone();
                            let revoked_ks = admin_revoked_svids.clone();
                            yield async move {
                                let tls_stream = acceptor.accept(stream).await
                                    .map_err(|e| {
                                        tracing::warn!(error = %e, addr = %addr, "TLS handshake failed");
                                        std::io::Error::new(std::io::ErrorKind::ConnectionAborted, e)
                                    })?;
                                let (_, server_conn) = tls_stream.get_ref();
                                let peer_certs = server_conn.peer_certificates()
                                    .ok_or_else(|| {
                                        tracing::warn!(addr = %addr, "no peer certificates");
                                        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no peer cert")
                                    })?;
                                let peer_cert_der = peer_certs.first()
                                    .ok_or_else(|| {
                                        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "empty cert chain")
                                    })?;
                                let spiffe_uri = fleetos_control::tls::mtls::extract_spiffe_uri_san(peer_cert_der)
                                    .map_err(|e| {
                                        tracing::warn!(addr = %addr, error = %e, "SPIFFE extraction failed");
                                        std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)
                                    })?;
                                fleetos_control::tls::trust_domains::validate_peer_identity(
                                    &spiffe_uri,
                                    fleetos_control::tls::trust_domains::TrustDomainRole::Admin,
                                    &td_config,
                                ).map_err(|e| {
                                    tracing::warn!(addr = %addr, spiffe = %spiffe_uri, error = %e, "peer identity rejected");
                                    std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)
                                })?;
                                let spiffe_id: SpiffeId = spiffe_uri.parse()
                                    .map_err(|e| {
                                        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                                    })?;
                                tracing::debug!(addr = %addr, spiffe = %spiffe_id, "admin peer authenticated");
                                if fleetos_control::revocation::is_svid_revoked(&revoked_ks, &spiffe_id.to_string()) {
                                    tracing::warn!(addr = %addr, spiffe = %spiffe_id, "admin peer SVID is revoked");
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::PermissionDenied,
                                        "admin peer SVID has been revoked",
                                    ));
                                }
                                Ok::<_, std::io::Error>(PeerAuthenticatedStream {
                                    inner: tls_stream,
                                    spiffe_id: Some(spiffe_id),
                                })
                            }.await;
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "failed to accept admin connection");
                        }
                    }
                }
            };

            let server = tonic::transport::Server::builder().add_service(
                fleetos_core::proto::fleetos::admin_service_server::AdminServiceServer::new(
                    admin_service,
                ),
            );

            if let Err(e) = server
                .serve_with_incoming_shutdown(incoming, wait_for_shutdown_flag(admin_shutdown_rx))
                .await
            {
                tracing::error!(error = %e, "Admin gRPC server failed");
            }
        }); // <-- End of the single spawn

        // 3. Push the handle AFTER the spawn
        server_handles.push(admin_server_handle);

        // --- G-5: Control SVID Renewal Task ---
        let renewer = fleetos_control::ca::renewal::ControlSvidRenewer::new(
            config.node.name.clone(),
            config.trust_domains.data_control.clone(),
            config.trust_domains.admin.clone(),
            config.svid.node_ttl_secs,
            config.svid.admin_ttl_secs,
            ca.data_control.clone(),
            Some(ca.admin.clone()),
            dc_resolver.clone(),
            raft_resolver.clone(),
            Some(admin_resolver),
        );
        let renewer_shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            renewer.run_loop(renewer_shutdown_rx).await;
        });
        tracing::info!("control SVID renewal task started (G-5)");
    } else {
        tracing::warn!("admin listener disabled until the CA is replicated (join mode first boot)");
    }

    tracing::info!("fleetos-control fully initialized, awaiting shutdown");

    // Wait for SIGINT (Ctrl+C) or SIGTERM.
    // tokio::select! does not support #[cfg] attributes on its branches, so
    // we split the signal-wait block by target OS.
    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received SIGINT");
            }
            _ = sigterm.recv() => {
                tracing::info!("received SIGTERM");
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        tracing::info!("received SIGINT");
    }

    tracing::info!("beginning graceful shutdown");

    // 1. Signal leader-gated controllers and the provisioning reconciler to
    //    stop proposing new work.
    let _ = shutdown_tx.send(true);

    // 2. Grace period for controllers and in-flight requests to finish.
    let grace = std::time::Duration::from_secs(config.graceful_shutdown.grace_period_secs);
    tracing::info!(grace_secs = grace.as_secs(), "draining in-flight work");

    // 3. Wait for the gRPC listeners to drain. They stop accepting new
    //    connections when the shutdown flag fires and let in-flight requests
    //    (including pending Raft proposals) complete.
    let drain = async {
        for handle in server_handles {
            let _ = handle.await;
        }
    };
    if tokio::time::timeout(grace, drain).await.is_err() {
        tracing::warn!("grace period expired before all listeners drained");
    }

    // 4. Shut down the Raft node. If this node is the leader it steps down,
    //    letting the remaining voters elect a new leader.
    if let Err(e) = raft_handle.raft.shutdown().await {
        tracing::warn!(error = ?e, "raft shutdown returned error");
    }
    tracing::info!("raft node shut down");

    // 5. Flush all OTel providers before exit.
    if let Some(ref t) = telemetry {
        fleetos_control::telemetry::shutdown(t);
    }

    tracing::info!("fleetos-control shutdown complete");
    Ok(())
}

/// A TLS stream that carries an authenticated peer identity.
///
/// `spiffe_id` is `None` for unauthenticated connections, which are only
/// possible on listeners configured with optional client auth (the
/// Data/Control listener, for the pre-SVID attestation flow).
struct PeerAuthenticatedStream<S> {
    inner: S,
    spiffe_id: Option<SpiffeId>,
}

impl<S> tokio::io::AsyncRead for PeerAuthenticatedStream<S>
where
    S: tokio::io::AsyncRead + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S> tokio::io::AsyncWrite for PeerAuthenticatedStream<S>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S> tonic::transport::server::Connected for PeerAuthenticatedStream<S>
where
    S: Send + 'static,
{
    type ConnectInfo = PeerConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        PeerConnectInfo {
            spiffe_id: self.spiffe_id.clone(),
        }
    }
}

/// Resolves once the shutdown watch flag becomes true (or the sender drops).
/// Used as the shutdown signal for `serve_with_incoming_shutdown`.
async fn wait_for_shutdown_flag(mut rx: watch::Receiver<bool>) {
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Initialize the Raft cluster based on configuration (bootstrap or join).
async fn init_raft_cluster(
    config: &ControlConfig,
    db: Arc<fjall::Database>,
    keyspaces: fleetos_control::storage::Keyspaces,
    versioned_state: VersionedState,
    broadcast_hub: Arc<BroadcastHub>,
    ca_service: Option<&CaService>,
) -> Result<
    (
        RaftHandle,
        watch::Sender<bool>,
        Option<JoinInfo>,
        fleetos_control::tls::mtls::MtlsConfig,
        Arc<fleetos_control::tls::mtls::DynamicCertResolver>,
        Arc<fleetos_control::tls::mtls::DynamicCertResolver>,
    ),
    Box<dyn std::error::Error>,
> {
    let raft_config = Config {
        heartbeat_interval: 500,
        election_timeout_min: 1500,
        election_timeout_max: 3000,
        // Bound raft log growth and give lagging followers a snapshot
        // catch-up path.
        snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(
            config.raft.snapshot_logs_since_last,
        ),
        purge_batch_size: config.raft.purge_batch_size,
        ..Default::default()
    };
    let raft_config =
        Arc::new(raft_config.validate().map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("invalid raft config: {}", e))
        })?);

    let log_storage = FjallLogStorage::new(
        db.clone(),
        keyspaces.raft_log.clone(),
        keyspaces.raft_log_meta.clone(),
    );
    let state_machine = FjallStateMachine::new(
        db.clone(),
        keyspaces.clone(),
        versioned_state,
        broadcast_hub,
        config.trust_domains.data_control.clone(),
    );

    let peer_addresses = match config.cluster.mode {
        ClusterMode::Bootstrap => config
            .cluster
            .initial_members
            .iter()
            .map(|m| (m.id, m.address.clone()))
            .collect(),
        ClusterMode::Join => std::collections::HashMap::new(),
    };

    let node_id = match config.cluster.mode {
        ClusterMode::Bootstrap => config
            .cluster
            .initial_members
            .first()
            .map(|m| m.id)
            .unwrap_or(1),
        ClusterMode::Join => fleetos_control::raft::derive_raft_node_id(&config.node.name),
    };

    // Build the Data/Control mTLS material (control SVID + trust bundle) once.
    let mut join_info: Option<JoinInfo> = None;
    let dc_mtls: fleetos_control::tls::mtls::MtlsConfig = match config.cluster.mode {
        ClusterMode::Bootstrap => {
            let ca = ca_service.expect("CA service required for bootstrap");
            let (cert_der, key_der, trust_pem) = {
                let dc_bundle = ca.data_control.read();
                let params = fleetos_control::ca::rcgen_impl::SvidParams {
                    spiffe_id: format!(
                        "spiffe://{}/ns/system/control/{}",
                        config.trust_domains.data_control, config.node.name
                    ),
                    kind: fleetos_control::ca::rcgen_impl::SvidKind::Control,
                    role: None,
                    ordinal: None,
                    degraded: false,
                    ttl_secs: config.svid.node_ttl_secs,
                };
                let svid = fleetos_control::ca::rcgen_impl::sign_svid(
                    &params,
                    &dc_bundle.current_key,
                    &dc_bundle.current_cert_der,
                )
                .map_err(|e| Box::<dyn std::error::Error>::from(e.to_string()))?;
                (
                    svid.cert_der,
                    svid.private_key_der.to_vec(),
                    dc_bundle.trust_bundle_pem(),
                )
            };
            fleetos_control::tls::mtls::MtlsConfig {
                cert_chain: vec![rustls::pki_types::CertificateDer::from(cert_der)],
                private_key: rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
                ),
                trust_bundle_pem: trust_pem,
                role: fleetos_control::tls::trust_domains::TrustDomainRole::DataControl,
            }
        }
        ClusterMode::Join => {
            let join_target = config.cluster.join_target.as_deref().ok_or_else(|| {
                Box::<dyn std::error::Error>::from(
                    "cluster.join_target is required when mode = \"join\"",
                )
            })?;
            config.cluster.join_raft_target.as_deref().ok_or_else(|| {
                Box::<dyn std::error::Error>::from(
                    "cluster.join_raft_target is required when mode = \"join\"",
                )
            })?;
            if config.cluster.join_token.is_empty() {
                return Err(Box::<dyn std::error::Error>::from(
                    "cluster.join_token is required when mode = \"join\"",
                ));
            }

            let is_restart = keyspaces.raft_log.first_key_value().is_some();
            if is_restart {
                tracing::info!("join mode: persisted raft state found, resuming membership");
                let ca = ca_service.expect("CA service required for join restart");
                let (cert_der, key_der, trust_pem) = {
                    let dc_bundle = ca.data_control.read();
                    let params = fleetos_control::ca::rcgen_impl::SvidParams {
                        spiffe_id: format!(
                            "spiffe://{}/ns/system/control/{}",
                            config.trust_domains.data_control, config.node.name
                        ),
                        kind: fleetos_control::ca::rcgen_impl::SvidKind::Control,
                        role: None,
                        ordinal: None,
                        degraded: false,
                        ttl_secs: config.svid.node_ttl_secs,
                    };
                    let svid = fleetos_control::ca::rcgen_impl::sign_svid(
                        &params,
                        &dc_bundle.current_key,
                        &dc_bundle.current_cert_der,
                    )
                    .map_err(|e| Box::<dyn std::error::Error>::from(e.to_string()))?;
                    (
                        svid.cert_der,
                        svid.private_key_der.to_vec(),
                        dc_bundle.trust_bundle_pem(),
                    )
                };
                fleetos_control::tls::mtls::MtlsConfig {
                    cert_chain: vec![rustls::pki_types::CertificateDer::from(cert_der)],
                    private_key: rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
                    ),
                    trust_bundle_pem: trust_pem,
                    role: fleetos_control::tls::trust_domains::TrustDomainRole::DataControl,
                }
            } else {
                tracing::info!(join_target = %join_target, "join mode: attesting to existing cluster");
                let join_trust_bundle_pem = config
                    .cluster
                    .join_trust_bundle_path
                    .as_deref()
                    .map(std::fs::read_to_string)
                    .transpose()
                    .map_err(|e| {
                        Box::<dyn std::error::Error>::from(format!(
                            "failed to read join_trust_bundle_path: {}",
                            e
                        ))
                    })?
                    .ok_or_else(|| {
                        Box::<dyn std::error::Error>::from(
                            "cluster.join_trust_bundle_path is required when mode = \"join\"",
                        )
                    })?;
                let join_result = fleetos_control::join::join_cluster(
                    join_target,
                    &config.cluster.join_token,
                    &config.node.name,
                    &config.trust_domains.data_control,
                    &join_trust_bundle_pem,
                )
                .await
                .map_err(|e| {
                    Box::<dyn std::error::Error>::from(format!("join flow failed: {}", e))
                })?;

                tracing::info!(
                    spiffe_id = %join_result.claimed_spiffe_id,
                    "join attestation complete, SVID acquired"
                );

                let mtls = fleetos_control::tls::mtls::MtlsConfig {
                    cert_chain: vec![rustls::pki_types::CertificateDer::from(
                        join_result.svid_cert_der.clone(),
                    )],
                    private_key: rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(
                            join_result.svid_key_der.clone(),
                        ),
                    ),
                    trust_bundle_pem: join_result.trust_bundle_pem.clone(),
                    role: fleetos_control::tls::trust_domains::TrustDomainRole::DataControl,
                };

                join_info = Some(JoinInfo {
                    node_id,
                    svid_cert_der: join_result.svid_cert_der.clone(),
                    svid_key_der: join_result.svid_key_der.clone(),
                    trust_bundle_pem: join_result.trust_bundle_pem.clone(),
                });
                mtls
            }
        }
    };

    let raft_client_tls = fleetos_control::raft::network::RaftClientTls {
        cert_der: dc_mtls
            .cert_chain
            .first()
            .map(|c| c.to_vec())
            .unwrap_or_default(),
        key_der: match &dc_mtls.private_key {
            rustls::pki_types::PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
            rustls::pki_types::PrivateKeyDer::Pkcs1(k) => k.secret_pkcs1_der().to_vec(),
            rustls::pki_types::PrivateKeyDer::Sec1(k) => k.secret_sec1_der().to_vec(),
            _ => Vec::new(),
        },
        trust_bundle_pem: dc_mtls.trust_bundle_pem.clone(),
        domain: config.trust_domains.data_control.clone(),
    };
    let network_factory = TonicRaftNetworkFactory::new(peer_addresses, raft_client_tls);

    let raft = Raft::new(
        node_id,
        raft_config,
        network_factory,
        log_storage,
        state_machine,
    )
    .await
    .map_err(|e| Box::<dyn std::error::Error>::from(format!("raft init failed: {}", e)))?;

    match config.cluster.mode {
        ClusterMode::Bootstrap => {
            let members: BTreeMap<u64, openraft::BasicNode> = config
                .cluster
                .initial_members
                .iter()
                .map(|m| {
                    (
                        m.id,
                        openraft::BasicNode {
                            addr: m.address.clone(),
                        },
                    )
                })
                .collect();
            raft.initialize(members).await.map_err(|e| {
                Box::<dyn std::error::Error>::from(format!("raft bootstrap failed: {}", e))
            })?;
            tracing::info!("raft cluster bootstrapped");
            // V-2: register each initial member's DC address so followers
            // can redirect joiners to the leader's Data/Control listener.
            for m in &config.cluster.initial_members {
                let _ = raft
                    .client_write(AuditedCommand::system(
                        FleetosCommand::RegisterControlAddress {
                            record: ControlNodeAddressRecord {
                                node_id: m.id,
                                dc_addr: m.dc_address.clone(),
                                raft_addr: m.address.clone(),
                            },
                        },
                    ))
                    .await;
            }
        }
        ClusterMode::Join => {
            // NOTE: we do NOT call raft.initialize() here for first-boot joins.
        }
    }

    let raft_handle = RaftHandle {
        raft: Arc::new(raft),
    };
    let (shutdown_tx, _) = watch::channel(false);

    // G-5: Build dynamic cert resolvers for hot-swap renewal.
    // Both the Raft and DC listeners get their own resolver so they can be
    // independently addressed, but they start with the same CertifiedKey.
    let initial_key = fleetos_control::tls::mtls::certified_key_from_der(
        &dc_mtls
            .cert_chain
            .first()
            .map(|c| c.to_vec())
            .unwrap_or_default(),
        match &dc_mtls.private_key {
            rustls::pki_types::PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
            rustls::pki_types::PrivateKeyDer::Pkcs1(k) => k.secret_pkcs1_der().to_vec(),
            rustls::pki_types::PrivateKeyDer::Sec1(k) => k.secret_sec1_der().to_vec(),
            _ => Vec::new(),
        }
        .as_slice(),
    )
    .map_err(|e| Box::<dyn std::error::Error>::from(e.to_string()))?;

    let dc_resolver = Arc::new(fleetos_control::tls::mtls::DynamicCertResolver::new(
        initial_key.clone(),
    ));
    let raft_resolver = Arc::new(fleetos_control::tls::mtls::DynamicCertResolver::new(
        initial_key,
    ));

    Ok((
        raft_handle,
        shutdown_tx,
        join_info,
        dc_mtls,
        dc_resolver,
        raft_resolver,
    ))
}

/// Factory for creating controller tasks when this node becomes leader.
struct FleetosControllerFactory {
    workload_controller: Arc<WorkloadController>,
    pod_controller: Arc<PodController>,
    node_controller: Arc<NodeController>,
    cron_controller: Arc<CronController>,
    storage_engine: Arc<fleetos_control::storage::StorageEngine>,
    node_lease_timeout_secs: i64,
    node_check_interval_secs: u64,
    pod_check_interval_secs: u64,
    workload_status_staleness_secs: i64,
}

impl ControllerFactory for FleetosControllerFactory {
    fn start_controllers(&self, join_set: &mut tokio::task::JoinSet<()>) {
        tracing::info!("starting controllers (this node is leader)");

        // Workload controller: periodically re-reconcile all stored workloads.
        let wc = self.workload_controller.clone();
        let se = self.storage_engine.clone();
        join_set.spawn(async move {
            tracing::info!("workload controller started");
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                match se.list_workloads() {
                    Ok(workloads) => {
                        for record in workloads {
                            match prost::Message::decode(record.spec_bytes.as_slice()) {
                                Ok(spec) => {
                                    if let Err(e) = wc.reconcile(&spec).await {
                                        tracing::warn!(
                                            workload_id = %record.workload_id,
                                            error = %e,
                                            "workload re-reconciliation failed"
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        workload_id = %record.workload_id,
                                        error = %e,
                                        "failed to decode workload spec"
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to list workloads");
                    }
                }
            }
        });

        // Pod controller: detect dead pods and reconcile.
        // Scans workload specs, checks each expected ordinal for a live placement,
        // and calls reconcile_dead_pod for any ordinal whose placement is missing.
        let pc = self.pod_controller.clone();
        let se_pod = self.storage_engine.clone();
        let pod_interval_secs = self.pod_check_interval_secs;
        let staleness_secs = self.workload_status_staleness_secs;
        join_set.spawn(async move {
            tracing::info!("pod controller started");
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(pod_interval_secs));
            loop {
                interval.tick().await;
                match se_pod.list_workloads() {
                    Ok(workloads) => {
                        for record in workloads {
                            let spec: fleetos_core::proto::workload::WorkloadSpec =
                                match prost::Message::decode(record.spec_bytes.as_slice()) {
                                    Ok(s) => s,
                                    Err(_) => continue,
                                };
                            for (role, count) in &spec.replicas {
                                for ordinal in 0..*count {
                                    let placement =
                                        se_pod.list_placements().ok().and_then(|placements| {
                                            placements.into_iter().find(|p| {
                                                p.tenant_id == spec.tenant_id
                                                    && p.service == spec.workload_id
                                                    && p.role == *role
                                                    && p.ordinal == ordinal
                                            })
                                        });

                                    // G-10: a pod is dead if its placement is missing,
                                    // its latest status reports live=false, or its
                                    // status report is stale (agent stopped reporting).
                                    let is_dead = match &placement {
                                        None => true,
                                        Some(p) => match se_pod.get_workload_status(&p.pod_id) {
                                            Ok(Some(status)) => {
                                                let now = time::OffsetDateTime::now_utc()
                                                    .unix_timestamp();
                                                let stale = (now - status.observed_at_unix)
                                                    > staleness_secs;
                                                !status.live || stale
                                            }
                                            // No status reported yet — assume alive.
                                            _ => false,
                                        },
                                    };

                                    if is_dead {
                                        tracing::info!(
                                            tenant = %spec.tenant_id,
                                            workload = %spec.workload_id,
                                            role = %role,
                                            ordinal = ordinal,
                                            "missing placement detected, reconciling dead pod"
                                        );
                                        if let Err(e) = pc
                                            .reconcile_dead_pod(
                                                &spec.tenant_id,
                                                &spec.workload_id,
                                                role,
                                                ordinal,
                                            )
                                            .await
                                        {
                                            tracing::warn!(
                                                tenant = %spec.tenant_id,
                                                workload = %spec.workload_id,
                                                role = %role,
                                                ordinal = ordinal,
                                                error = %e,
                                                "pod reconciliation failed"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to list workloads for pod check");
                    }
                }
            }
        });

        // Node controller: detect dead nodes via heartbeat lease and evict.
        // Scans all registered nodes; any node whose last_heartbeat is older
        // than the lease timeout is evicted (delegations revoked, placements removed).
        let nc = self.node_controller.clone();
        let se_node = self.storage_engine.clone();
        let lease_timeout = self.node_lease_timeout_secs;
        let node_interval_secs = self.node_check_interval_secs;
        join_set.spawn(async move {
            tracing::info!("node controller started");
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(node_interval_secs));
            loop {
                interval.tick().await;
                let now = time::OffsetDateTime::now_utc().unix_timestamp();
                match se_node.list_node_records() {
                    Ok(records) => {
                        for record in records {
                            // Skip already-evicted nodes.
                            if record.status == fleetos_control::raft::records::NodeStatus::Evicted
                            {
                                continue;
                            }
                            let age = now - record.last_heartbeat;
                            if age > lease_timeout {
                                tracing::warn!(
                                    node_id = %record.node_id,
                                    age_secs = age,
                                    lease_timeout_secs = lease_timeout,
                                    "node heartbeat expired, evicting"
                                );
                                match record.node_id.parse::<fleetos_core::spiffe::SpiffeId>() {
                                    Ok(spiffe_id) => {
                                        if let Err(e) = nc.evict_node(&spiffe_id).await {
                                            tracing::warn!(
                                                node_id = %record.node_id,
                                                error = %e,
                                                "node eviction failed"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            node_id = %record.node_id,
                                            error = %e,
                                            "cannot parse node_id as SpiffeId, skipping eviction"
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to list node records");
                    }
                }
            }
        });

        // Cron controller: evaluate cron schedules and trigger when due.
        let cc = self.cron_controller.clone();
        let se_cron = self.storage_engine.clone();
        join_set.spawn(async move {
            tracing::info!("cron controller started");
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                match se_cron.list_cron_workloads() {
                    Ok(cron_workloads) => {
                        for record in cron_workloads {
                            match prost::Message::decode(record.spec_bytes.as_slice()) {
                                Ok(cron) => {
                                    if let Err(e) = cc.evaluate_and_trigger(&cron).await {
                                        tracing::warn!(
                                            cron_id = %record.cron_workload_id,
                                            error = %e,
                                            "cron evaluation failed"
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        cron_id = %record.cron_workload_id,
                                        error = %e,
                                        "failed to decode cron workload spec"
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to list cron workloads");
                    }
                }
            }
        });
    }
}
