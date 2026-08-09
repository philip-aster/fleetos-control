mod api;
mod cloud;
mod config;
mod controllers;
mod grpc;
mod raft;
mod scheduler;
mod secrets;
mod storage;

use std::net::SocketAddr;
use std::sync::Arc;

use fleetos_core::proto::identity::identity_service_server::IdentityServiceServer;
use fleetos_core::proto::secret::secret_service_server::SecretServiceServer;
use fleetos_core::proto::state::state_service_server::StateServiceServer;

use grpc::{FleetIdentityService, FleetSecretService, FleetStateService};
use openraft::Config;
use redb::Database;
use tonic::transport::Server;
use tracing::info;

use crate::raft::{FleetRaft, Network, RedbStore};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let addr: SocketAddr = "127.0.0.1:50051".parse()?;
    info!("Starting FleetOS Control Plane gRPC server on {}...", addr);

    // 1. Initialize Redb persistent storage
    let db_path = std::env::var("FLEETOS_DB_PATH").unwrap_or_else(|_| "fleetos.redb".to_string());
    let db = Arc::new(Database::create(&db_path)?);

    // 2. Initialize Redb Raft storage adapter (returns log_store & state_machine)
    let (log_store, state_machine) = RedbStore::new(db.clone())?;

    // 3. Configure and spin up OpenRaft node
    let node_id = std::env::var("NODE_ID")
        .unwrap_or_else(|_| "1".to_string())
        .parse::<u64>()?;

    let raft_config = Config {
        cluster_name: "fleetos-cluster".to_string(),
        ..Default::default()
    };

    let raft_config = Arc::new(raft_config.validate()?);
    let network = Network::new();

    let raft: FleetRaft =
        openraft::Raft::new(node_id, raft_config, network, log_store, state_machine).await?;

    info!(
        "FleetRaft consensus node {} initialized successfully",
        node_id
    );

    // 4. Instantiate gRPC services
    let identity_service = FleetIdentityService::new();
    // Pass raft directly into FleetStateService
    let state_service = FleetStateService::new(raft.clone());
    let secret_service = FleetSecretService::new();

    // 5. Start gRPC server
    Server::builder()
        .add_service(IdentityServiceServer::new(identity_service))
        .add_service(StateServiceServer::new(state_service))
        .add_service(SecretServiceServer::new(secret_service))
        .serve(addr)
        .await?;

    Ok(())
}
