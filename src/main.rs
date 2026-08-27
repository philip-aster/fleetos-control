//! `fleetos-control` entrypoint.
//!
//! Full integration: Raft cluster, dual CAs, gRPC servers, leader-gated controllers.
use clap::Parser;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

use fleetos_control::attestation::join_token::JoinTokenStore;
use fleetos_control::ca::CaService;
use fleetos_control::config::{ClusterMode, ControlConfig};
use fleetos_control::controllers::leader::{ControllerFactory, LeaderGate};
use fleetos_control::controllers::{
    CronController, WorkloadController, node_controller::NodeController,
    pod_controller::PodController,
};
use fleetos_control::delegation::revocation::DelegationRevocationStore;
use fleetos_control::dummy_ip::allocator::DummyIpAllocator;
use fleetos_control::provisioning::control_pool::ControlPoolManager;
use fleetos_control::raft::raft_proto::raft_transport_server::RaftTransportServer;
use fleetos_control::raft::state_machine::FjallStateMachine;
use fleetos_control::raft::store::FjallLogStorage;
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
    join_result: fleetos_control::join::JoinResult,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install the ring crypto provider as the process default.
    // REQUIRED by rustls 0.23 — without this, ServerConfig::builder() panics.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls ring crypto provider");

    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    tracing::info!(config = %cli.config.display(), "loading configuration");

    let config = ControlConfig::load(&cli.config)?;
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
    let delegation_revocation = Arc::new(DelegationRevocationStore::new(
        keyspaces.active_delegations.clone(),
        keyspaces.revoked_delegations.clone(),
    ));
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
    ));

    let workload_controller = Arc::new(WorkloadController::new(
        storage_engine.clone(),
        ordinal_tracker.clone(),
        broadcast_hub.clone(),
    ));
    let pod_controller = Arc::new(PodController::new(
        storage_engine.clone(),
        ordinal_tracker.clone(),
    ));
    let node_controller = Arc::new(NodeController::new(
        storage_engine.clone(),
        delegation_revocation.clone(),
        broadcast_hub.clone(),
    ));
    let cron_controller = Arc::new(CronController::new(
        storage_engine.clone(),
        workload_controller.clone(),
    ));

    // --- Phase 7: Raft cluster initialization ---
    let (raft_handle, shutdown_tx, join_info) = init_raft_cluster(
        &config,
        db.clone(),
        keyspaces.clone(),
        versioned_state.clone(),
        broadcast_hub.clone(),
    )
    .await?;

    // --- Phase 7b: Raft transport listener (inbound consensus RPCs) ---
    // Required for ANY multi-node operation: replication, votes, snapshots,
    // and RequestJoin from joining nodes.
    let raft_addr: std::net::SocketAddr = config.listeners.raft.parse()?;
    let raft_transport_impl =
        fleetos_control::raft::server::RaftTransportServerImpl::new(raft_handle.raft.clone());
    tokio::spawn(async move {
        tracing::info!(addr = %raft_addr, "starting Raft transport listener");
        if let Err(e) = tonic::transport::Server::builder()
            .add_service(RaftTransportServer::new(raft_transport_impl))
            .serve(raft_addr)
            .await
        {
            tracing::error!(error = %e, "Raft transport listener failed");
        }
    });

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
        let node_id = info.node_id;
        tokio::spawn(async move {
            match fleetos_control::join::request_membership(
                &join_raft_target,
                node_id,
                &our_raft_addr,
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
        )
        .await
        {
            Ok(mut reconciler) => {
                tokio::spawn(async move {
                    reconciler.run_loop().await;
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

    // Data/Control SVID: the join-flow SVID on a first join boot, otherwise
    // freshly minted from the local CA (bootstrap, or join-restart after the
    // CA has been replicated to us).
    let dc_mtls = if let Some(ref info) = join_info {
        fleetos_control::tls::mtls::MtlsConfig {
            cert_chain: vec![rustls::pki_types::CertificateDer::from(
                info.join_result.svid_cert_der.clone(),
            )],
            private_key: rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(info.join_result.svid_key_der.clone()),
            ),
            trust_bundle_pem: info.join_result.trust_bundle_pem.clone(),
            role: fleetos_control::tls::trust_domains::TrustDomainRole::DataControl,
        }
    } else {
        let ca = ca_service
            .as_ref()
            .expect("CA must be available when no join flow ran");
        let (dc_svid, dc_root_pem) = {
            let dc_bundle = ca.data_control.read();
            let dc_params = fleetos_control::ca::rcgen_impl::SvidParams {
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
                &dc_params,
                &dc_bundle.current_key,
                &dc_bundle.current_cert_der,
            )?;
            (svid, dc_bundle.trust_bundle_pem())
        };
        fleetos_control::tls::mtls::MtlsConfig {
            cert_chain: vec![rustls::pki_types::CertificateDer::from(dc_svid.cert_der)],
            private_key: rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(dc_svid.private_key_der.to_vec()),
            ),
            // Root CA PEM — NOT the leaf cert. The root store must contain the
            // CA that signed peer certs.
            trust_bundle_pem: dc_root_pem,
            role: fleetos_control::tls::trust_domains::TrustDomainRole::DataControl,
        }
    };

    // Optional client auth on Data/Control: attestation is inherently pre-SVID.
    // Authenticated peers are still fully validated; unauthenticated peers get
    // spiffe_id = None and are rejected by every identity-gated service.
    let dc_server_config = std::sync::Arc::new(
        fleetos_control::tls::mtls::build_server_config_optional_auth(&dc_mtls)?,
    );

    tracing::info!("setting up gRPC servers");

    // Initialize gRPC services
    let status_service = fleetos_control::watch::status_service::WorkloadStatusServiceImpl::new();
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
        );

    // CaService is only available when the local CA is loaded.
    let ca_grpc_service = ca_service.as_ref().map(|ca| {
        fleetos_control::ca::grpc_service::CaServiceImpl::new(
            ca.data_control.clone(),
            config.svid.node_ttl_secs,
            keyspaces.svids.clone(),
            keyspaces.svid_grants.clone(),
            keyspaces.placements.clone(),
        )
    });

    let admin_service = fleetos_control::admin::service::AdminServiceImpl::new(
        storage_engine.clone(),
        join_token_store.clone(),
        dummy_ip_allocator.clone(),
        workload_controller.clone(),
        cron_controller.clone(),
        raft_handle.raft.clone(),
    );

    let dc_addr: std::net::SocketAddr = config.listeners.data_control.parse()?;
    let admin_addr: std::net::SocketAddr = config.listeners.admin.parse()?;

    // Spawn Data/Control listener with custom TLS (optional client auth)
    let dc_tls_acceptor = tokio_rustls::TlsAcceptor::from(dc_server_config);
    let dc_td_config = fleetos_control::tls::trust_domains::TrustDomainConfig::from_config(&config);

    tokio::spawn(async move {
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

                        yield async move {
                            let tls_stream = acceptor.accept(stream).await
                                .map_err(|e| {
                                    tracing::warn!(error = %e, addr = %addr, "TLS handshake failed");
                                    std::io::Error::new(std::io::ErrorKind::ConnectionAborted, e)
                                })?;

                            let (_, server_conn) = tls_stream.get_ref();

                            // Optional client auth: peer cert may be absent (pre-SVID attestation).
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

        if let Err(e) = server.serve_with_incoming(incoming).await {
            tracing::error!(error = %e, "Data/Control gRPC server failed");
        }
    });

    // Spawn Admin listener with custom TLS (strict mTLS, Admin domain).
    // Disabled on a first join boot — the Admin CA isn't available until the
    // cluster state (including CAs) has been replicated to this node.
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

        let admin_mtls = fleetos_control::tls::mtls::MtlsConfig {
            cert_chain: vec![rustls::pki_types::CertificateDer::from(admin_svid.cert_der)],
            private_key: rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(admin_svid.private_key_der.to_vec()),
            ),
            trust_bundle_pem: admin_root_pem,
            role: fleetos_control::tls::trust_domains::TrustDomainRole::Admin,
        };
        let admin_server_config = std::sync::Arc::new(
            fleetos_control::tls::mtls::build_server_config(&admin_mtls)?,
        );
        let admin_tls_acceptor = tokio_rustls::TlsAcceptor::from(admin_server_config);
        let admin_td_config =
            fleetos_control::tls::trust_domains::TrustDomainConfig::from_config(&config);

        tokio::spawn(async move {
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

            // Admin listener ONLY registers the AdminService
            let server = tonic::transport::Server::builder().add_service(
                fleetos_core::proto::fleetos::admin_service_server::AdminServiceServer::new(
                    admin_service,
                ),
            );

            if let Err(e) = server.serve_with_incoming(incoming).await {
                tracing::error!(error = %e, "Admin gRPC server failed");
            }
        });
    } else {
        tracing::warn!("admin listener disabled until the CA is replicated (join mode first boot)");
    }

    tracing::info!("fleetos-control fully initialized, awaiting shutdown");

    // Wait for shutdown signal.
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown signal received");

    // Signal all components to shut down
    let _ = shutdown_tx.send(true);

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

/// Initialize the Raft cluster based on configuration (bootstrap or join).
async fn init_raft_cluster(
    config: &ControlConfig,
    db: Arc<fjall::Database>,
    keyspaces: fleetos_control::storage::Keyspaces,
    versioned_state: VersionedState,
    broadcast_hub: Arc<BroadcastHub>,
) -> Result<(RaftHandle, watch::Sender<bool>, Option<JoinInfo>), Box<dyn std::error::Error>> {
    let raft_config = Config {
        heartbeat_interval: 500,
        election_timeout_min: 1500,
        election_timeout_max: 3000,
        ..Default::default()
    };

    let raft_config =
        Arc::new(raft_config.validate().map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("invalid raft config: {}", e))
        })?);

    // Create log storage and state machine
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
    );

    // Create network factory.
    // Bootstrap: static map from config. Join: empty — peers are discovered
    // via replicated membership (the network factory falls back to the address
    // openraft passes to new_client).
    let peer_addresses = match config.cluster.mode {
        ClusterMode::Bootstrap => config
            .cluster
            .initial_members
            .iter()
            .map(|m| (m.id, m.address.clone()))
            .collect(),
        ClusterMode::Join => std::collections::HashMap::new(),
    };
    let network_factory = TonicRaftNetworkFactory::new(peer_addresses);

    // Node ID: bootstrap uses the configured member id; join derives a
    // deterministic id from the node name so the joiner and the leader agree
    // on it (same derivation the CONTROL-pool provisioner uses).
    let node_id = match config.cluster.mode {
        ClusterMode::Bootstrap => config
            .cluster
            .initial_members
            .first()
            .map(|m| m.id)
            .unwrap_or(1),
        ClusterMode::Join => fleetos_control::raft::derive_raft_node_id(&config.node.name),
    };

    let raft = Raft::new(
        node_id,
        raft_config,
        network_factory,
        log_storage,
        state_machine,
    )
    .await
    .map_err(|e| Box::<dyn std::error::Error>::from(format!("raft init failed: {}", e)))?;

    let mut join_info: Option<JoinInfo> = None;

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
        }
        ClusterMode::Join => {
            // Restart detection: a persisted raft log means we already joined
            // once — openraft resumes from persisted vote/log/membership.
            let is_restart = keyspaces.raft_log.first_key_value().is_some();

            if is_restart {
                tracing::info!("join mode: persisted raft state found, resuming membership");
            } else {
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

                tracing::info!(join_target = %join_target, "join mode: attesting to existing cluster");

                let join_result = fleetos_control::join::join_cluster(
                    join_target,
                    &config.cluster.join_token,
                    &config.node.name,
                    &config.trust_domains.data_control,
                )
                .await
                .map_err(|e| {
                    Box::<dyn std::error::Error>::from(format!("join flow failed: {}", e))
                })?;

                tracing::info!(
                    spiffe_id = %join_result.claimed_spiffe_id,
                    "join attestation complete, SVID acquired"
                );

                join_info = Some(JoinInfo {
                    node_id,
                    join_result,
                });

                // NOTE: we do NOT call raft.initialize() here. The node starts
                // with no membership and waits to be added as a learner. The
                // membership request is sent from main() once the raft
                // transport listener is up.
            }
        }
    }

    let raft_handle = RaftHandle {
        raft: Arc::new(raft),
    };

    let (shutdown_tx, _) = watch::channel(false);
    Ok((raft_handle, shutdown_tx, join_info))
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
                                    // Check if a placement exists for this ordinal.
                                    let has_placement = se_pod
                                        .list_placements()
                                        .map(|placements| {
                                            placements.iter().any(|p| {
                                                p.tenant_id == spec.tenant_id
                                                    && p.service == spec.workload_id
                                                    && p.role == *role
                                                    && p.ordinal == ordinal
                                            })
                                        })
                                        .unwrap_or(false);

                                    if !has_placement {
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
                                    if let Err(e) = cc.trigger(&cron).await {
                                        tracing::warn!(
                                            cron_id = %record.cron_workload_id,
                                            error = %e,
                                            "cron trigger failed"
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
