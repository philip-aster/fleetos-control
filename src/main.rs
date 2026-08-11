pub mod api;
pub mod cloud;
pub mod config;
pub mod controllers;
pub mod grpc;
pub mod raft;
pub mod scheduler;
pub mod secrets;
pub mod storage;

use std::collections::BTreeMap;
use std::sync::Arc;

use fleetos_core::proto::identity::identity_service_server::IdentityServiceServer;
use fleetos_core::proto::secret::secret_service_server::SecretServiceServer;
use fleetos_core::proto::state::state_service_server::StateServiceServer;

use config::Config;
use controllers::{NodeController, PodController, SecretController};
use grpc::{FleetIdentityService, FleetSecretService, FleetStateService};
use openraft::Config as RaftConfig;
use redb::Database;
use tonic::transport::Server;
use tracing::{Level, info, warn};
use tracing_subscriber::FmtSubscriber;

use crate::raft::{FleetRaft, Network, RedbStore};
use crate::scheduler::FleetScheduler;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Initialize tracing subscriber
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set global tracing subscriber");

    info!("Initializing FleetOS Control Plane...");

    // 2. Load unified environment/file configuration
    let cfg = Config::load_from_env();
    info!(
        "Configuration loaded | Node ID: {}, gRPC: {}, DB: {}",
        cfg.node_id,
        cfg.grpc_bind_addr,
        cfg.db_path.display()
    );

    // 3. Initialize Redb persistent storage
    let db = Arc::new(Database::create(&cfg.db_path)?);

    // 4. Initialize Redb Raft storage adapter (returns log_store & state_machine)
    let (log_store, state_machine) = RedbStore::new(db.clone())?;

    // 5. Configure and spin up OpenRaft node
    let openraft_cfg = RaftConfig {
        cluster_name: "fleetos-cluster".to_string(),
        ..Default::default()
    };

    let openraft_cfg = Arc::new(openraft_cfg.validate()?);
    let network = Network::new();

    let raft: FleetRaft =
        openraft::Raft::new(cfg.node_id, openraft_cfg, network, log_store, state_machine).await?;

    info!(
        "FleetRaft consensus node {} initialized successfully",
        cfg.node_id
    );

    // Initialize single-node cluster if node_id == 1 and not yet initialized
    let mut nodes = BTreeMap::new();
    nodes.insert(
        cfg.node_id,
        openraft::BasicNode::new(cfg.raft_bind_addr.to_string()),
    );
    if let Err(e) = raft.initialize(nodes).await {
        warn!(
            "Raft cluster initialization skipped/already initialized: {:?}",
            e
        );
    }

    // 6. Instantiate gRPC services
    let identity_service = FleetIdentityService::new();
    let state_service = Arc::new(FleetStateService::new(raft.clone(), db.clone()));
    let secret_service = FleetSecretService::new(db.clone(), cfg.master_key);

    // 7. Initialize Scheduler and Background Controllers
    let scheduler = Arc::new(FleetScheduler::new(state_service.clone()));
    let pod_controller = PodController::new(state_service.clone(), scheduler.clone());
    let node_controller = NodeController::new(state_service.clone());
    let secret_controller = SecretController::new(state_service.clone());

    // Spawn PodController background task
    tokio::spawn(async move {
        info!("Starting PodController reconciliation loop...");
        if let Err(e) = pod_controller.run_reconciliation_loop().await {
            tracing::error!("PodController worker loop failed: {:?}", e);
        }
    });

    // Spawn NodeController background task
    tokio::spawn(async move {
        info!("Starting NodeController monitoring loop...");
        if let Err(e) = node_controller.run_monitoring_loop().await {
            tracing::error!("NodeController worker loop failed: {:?}", e);
        }
    });

    // Spawn SecretController background task
    tokio::spawn(async move {
        info!("Starting SecretController rotation loop...");
        if let Err(e) = secret_controller.run_rotation_loop().await {
            tracing::error!("SecretController worker loop failed: {:?}", e);
        }
    });

    // 8. Start Tonic gRPC server with graceful shutdown handling
    Server::builder()
        .add_service(IdentityServiceServer::new(identity_service))
        .add_service(StateServiceServer::from_arc(state_service))
        .add_service(SecretServiceServer::new(secret_service))
        .serve_with_shutdown(cfg.grpc_bind_addr, async {
            let _ = tokio::signal::ctrl_c().await;
            info!("Received shutdown signal, stopping FleetOS Control Plane...");
        })
        .await?;

    Ok(())
}
