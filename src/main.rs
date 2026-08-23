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

    // --- Phase 3: Trust bundles (dual CAs) ---
    let ca_service = CaService::bootstrap(&config)?;
    tracing::info!(
        data_control_td = %config.trust_domains.data_control,
        admin_td = %config.trust_domains.admin,
        "dual-root CA bootstrapped"
    );

    // --- Phase 4: Core services initialization ---
    let join_token_store = Arc::new(JoinTokenStore::new(keyspaces.join_tokens.clone()));
    let dummy_ip_allocator = Arc::new(DummyIpAllocator::new(
        keyspaces.dummy_ips.clone(),
        config.dummy_ip.tenant_block_prefix,
    )?);
    let ordinal_tracker = Arc::new(OrdinalTracker::new(keyspaces.ordinals.clone()));
    let delegation_revocation = Arc::new(DelegationRevocationStore::new(
        keyspaces.active_delegations.clone(),
        keyspaces.revoked_delegations.clone(),
    ));

    // Load master key for secrets
    let master_key = if config.secrets.master_key_path.exists() {
        FileMasterKey::load(&config.secrets.master_key_path)?
    } else {
        FileMasterKey::generate(&config.secrets.master_key_path)?
    };
    let secret_store = Arc::new(SecretStore::new(
        keyspaces.secrets.clone(),
        Box::new(master_key),
    ));

    // --- Phase 5: Controllers ---
    let storage_engine = Arc::new(fleetos_control::storage::StorageEngine::new(
        keyspaces.raft_log.clone(),
        keyspaces.raft_log_meta.clone(),
        keyspaces.nodes.clone(),
        keyspaces.placements.clone(),
        keyspaces.workloads.clone(),
        keyspaces.active_delegations.clone(),
        keyspaces.revoked_delegations.clone(),
        keyspaces.join_tokens.clone(),
        keyspaces.pcr_policies.clone(),
        keyspaces.dummy_ips.clone(),
        keyspaces.secrets.clone(),
        keyspaces.sag_rules.clone(),
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

    // --- Phase 6: Raft cluster initialization ---
    let (raft_handle, shutdown_tx) = init_raft_cluster(
        &config,
        db.clone(),
        keyspaces.clone(),
        versioned_state.clone(),
    )
    .await?;

    // --- Phase 7: Controller factory and leader gate ---
    let controller_factory = Arc::new(FleetosControllerFactory {
        workload_controller: workload_controller.clone(),
        pod_controller: pod_controller.clone(),
        node_controller: node_controller.clone(),
        cron_controller: cron_controller.clone(),
    });

    let leader_gate = LeaderGate::new(raft_handle.raft.as_ref().clone());
    let shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        leader_gate.run(controller_factory, shutdown_rx).await;
    });

    // --- Phase 8: gRPC Servers ---
    tracing::info!("setting up gRPC servers");

    // Mint control plane SVIDs for both trust domains
    let dc_bundle = ca_service.data_control.read();
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
    let dc_svid = fleetos_control::ca::rcgen_impl::sign_svid(
        &dc_params,
        &dc_bundle.current_key,
        &dc_bundle.current_params,
    )?;
    drop(dc_bundle);

    let admin_bundle = ca_service.admin.read();
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
    let admin_svid = fleetos_control::ca::rcgen_impl::sign_svid(
        &admin_params,
        &admin_bundle.current_key,
        &admin_bundle.current_params,
    )?;
    drop(admin_bundle);

    // Build mTLS configs using our tls/mtls.rs module
    let dc_mtls = fleetos_control::tls::mtls::MtlsConfig {
        cert_chain: vec![rustls::pki_types::CertificateDer::from(
            dc_svid.cert_der.clone(),
        )],
        private_key: rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(dc_svid.private_key_der.to_vec()),
        ),
        trust_bundle_pem: dc_svid.cert_pem.clone(),
        role: fleetos_control::tls::trust_domains::TrustDomainRole::DataControl,
    };
    let dc_server_config =
        std::sync::Arc::new(fleetos_control::tls::mtls::build_server_config(&dc_mtls)?);

    let admin_mtls = fleetos_control::tls::mtls::MtlsConfig {
        cert_chain: vec![rustls::pki_types::CertificateDer::from(
            admin_svid.cert_der.clone(),
        )],
        private_key: rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(admin_svid.private_key_der.to_vec()),
        ),
        trust_bundle_pem: admin_svid.cert_pem.clone(),
        role: fleetos_control::tls::trust_domains::TrustDomainRole::Admin,
    };
    let admin_server_config = std::sync::Arc::new(fleetos_control::tls::mtls::build_server_config(
        &admin_mtls,
    )?);

    // Initialize gRPC services
    let policy_service =
        fleetos_control::watch::policy_stream::PolicyServiceImpl::new(broadcast_hub.clone());
    let watch_service =
        fleetos_control::watch::watch_service::WatchServiceImpl::new(broadcast_hub.clone());
    let scheduler_service =
        fleetos_control::watch::scheduler_stream::SchedulerServiceImpl::new(broadcast_hub.clone());
    let router_service =
        fleetos_control::watch::router_assignment::RouterAssignmentServiceImpl::new(
            broadcast_hub.clone(),
        );
    let secret_service =
        fleetos_control::watch::secret_service::SecretServiceImpl::new(secret_store.clone());

    let admin_service = fleetos_control::admin::service::AdminServiceImpl::new(
        storage_engine.clone(),
        join_token_store.clone(),
        dummy_ip_allocator.clone(),
        workload_controller.clone(),
        cron_controller.clone(),
    );

    let dc_addr: std::net::SocketAddr = config.listeners.data_control.parse()?;
    let admin_addr: std::net::SocketAddr = config.listeners.admin.parse()?;

    // Spawn Data/Control listener with custom TLS
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

                            // Extract peer certificate and validate SPIFFE identity
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

                            // Extract SPIFFE URI SAN
                            let spiffe_uri = fleetos_control::tls::mtls::extract_spiffe_uri_san(peer_cert_der)
                                .map_err(|e| {
                                    tracing::warn!(addr = %addr, error = %e, "SPIFFE extraction failed");
                                    std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)
                                })?;

                            // Validate trust domain and identity kind
                            fleetos_control::tls::trust_domains::validate_peer_identity(
                                &spiffe_uri,
                                fleetos_control::tls::trust_domains::TrustDomainRole::DataControl,
                                &td_config,
                            ).map_err(|e| {
                                tracing::warn!(addr = %addr, spiffe = %spiffe_uri, error = %e, "peer identity rejected");
                                std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)
                            })?;

                            // Parse into SpiffeId
                            let spiffe_id: SpiffeId = spiffe_uri.parse()
                                .map_err(|e| {
                                    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                                })?;

                            tracing::debug!(addr = %addr, spiffe = %spiffe_id, "peer authenticated");

                            // Wrap the stream to carry the SpiffeId
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

        let server = tonic::transport::Server::builder()
            .add_service(fleetos_core::proto::fleetos::policy_service_server::PolicyServiceServer::new(policy_service))
            .add_service(fleetos_core::proto::fleetos::watch_service_server::WatchServiceServer::new(watch_service))
            .add_service(fleetos_core::proto::fleetos::scheduler_service_server::SchedulerServiceServer::new(scheduler_service))
            .add_service(fleetos_core::proto::fleetos::router_assignment_service_server::RouterAssignmentServiceServer::new(router_service))
            .add_service(fleetos_core::proto::fleetos::secret_service_server::SecretServiceServer::new(secret_service));

        if let Err(e) = server.serve_with_incoming(incoming).await {
            tracing::error!(error = %e, "Data/Control gRPC server failed");
        }
    });

    // Spawn Admin listener with custom TLS
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

                            // Extract peer certificate and validate SPIFFE identity
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

                            // Extract SPIFFE URI SAN
                            let spiffe_uri = fleetos_control::tls::mtls::extract_spiffe_uri_san(peer_cert_der)
                                .map_err(|e| {
                                    tracing::warn!(addr = %addr, error = %e, "SPIFFE extraction failed");
                                    std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)
                                })?;

                            // Validate trust domain and identity kind (Admin domain)
                            fleetos_control::tls::trust_domains::validate_peer_identity(
                                &spiffe_uri,
                                fleetos_control::tls::trust_domains::TrustDomainRole::Admin,
                                &td_config,
                            ).map_err(|e| {
                                tracing::warn!(addr = %addr, spiffe = %spiffe_uri, error = %e, "peer identity rejected");
                                std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)
                            })?;

                            // Parse into SpiffeId
                            let spiffe_id: SpiffeId = spiffe_uri.parse()
                                .map_err(|e| {
                                    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                                })?;

                            tracing::debug!(addr = %addr, spiffe = %spiffe_id, "admin peer authenticated");

                            Ok::<_, std::io::Error>(PeerAuthenticatedStream {
                                inner: tls_stream,
                                spiffe_id,
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
struct PeerAuthenticatedStream<S> {
    inner: S,
    spiffe_id: SpiffeId,
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
) -> Result<(RaftHandle, watch::Sender<bool>), Box<dyn std::error::Error>> {
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
    let state_machine = FjallStateMachine::new(db.clone(), keyspaces.clone(), versioned_state);

    // Create network factory
    let peer_addresses = match config.cluster.mode {
        ClusterMode::Bootstrap => config
            .cluster
            .initial_members
            .iter()
            .map(|m| (m.id, m.address.clone()))
            .collect(),
        ClusterMode::Join => {
            // For join mode, we'd discover peers after attestation
            // For now, use an empty map (will be populated after join)
            std::collections::HashMap::new()
        }
    };
    let network_factory = TonicRaftNetworkFactory::new(peer_addresses);

    // Create the Raft node
    let node_id = match config.cluster.mode {
        ClusterMode::Bootstrap => config
            .cluster
            .initial_members
            .first()
            .map(|m| m.id)
            .unwrap_or(1),
        ClusterMode::Join => {
            // For join mode, we'd get our node_id after attestation
            // For now, use a placeholder
            0
        }
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

    // Bootstrap or join
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
            // TODO: Implement join flow
            // 1. Attest with join_target
            // 2. Get Join Token
            // 3. Get SVID
            // 4. Call add_learner on the cluster
            // 5. Wait for promotion to voter
            tracing::warn!("join mode not yet implemented, running as standalone node");
        }
    }

    let raft_handle = RaftHandle {
        raft: Arc::new(raft),
    };

    let (shutdown_tx, _) = watch::channel(false);

    Ok((raft_handle, shutdown_tx))
}

/// Factory for creating controller tasks when this node becomes leader.
struct FleetosControllerFactory {
    workload_controller: Arc<WorkloadController>,
    pod_controller: Arc<PodController>,
    node_controller: Arc<NodeController>,
    cron_controller: Arc<CronController>,
}

impl ControllerFactory for FleetosControllerFactory {
    fn start_controllers(&self, join_set: &mut tokio::task::JoinSet<()>) {
        tracing::info!("starting controllers (this node is leader)");

        // Start workload controller reconciliation loop
        let wc = self.workload_controller.clone();
        join_set.spawn(async move {
            tracing::info!("workload controller started");
            // TODO: Implement actual reconciliation loop
            // For now, just keep the task alive
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                let _ = &wc; // Use wc to suppress warning
            }
        });

        // Start pod controller
        let pc = self.pod_controller.clone();
        join_set.spawn(async move {
            tracing::info!("pod controller started");
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                let _ = &pc;
            }
        });

        // Start node controller
        let nc = self.node_controller.clone();
        join_set.spawn(async move {
            tracing::info!("node controller started");
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                let _ = &nc;
            }
        });

        // Start cron controller
        let cc = self.cron_controller.clone();
        join_set.spawn(async move {
            tracing::info!("cron controller started");
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                let _ = &cc;
            }
        });
    }
}
