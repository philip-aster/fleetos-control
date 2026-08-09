mod api;
mod cloud;
mod config;
mod controllers;
mod grpc;
mod raft;
mod scheduler;
mod secrets;
mod storage;

use fleetos_core::proto::identity::identity_service_server::IdentityServiceServer;
use fleetos_core::proto::secret::secret_service_server::SecretServiceServer;
use fleetos_core::proto::state::state_service_server::StateServiceServer;

use grpc::{FleetIdentityService, FleetSecretService, FleetStateService};
use std::net::SocketAddr;
use tonic::transport::Server;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let addr: SocketAddr = "127.0.0.1:50051".parse()?;
    info!("Starting FleetOS Control Plane gRPC server on {}...", addr);

    let identity_service = FleetIdentityService::new();
    let state_service = FleetStateService::new();
    let secret_service = FleetSecretService::new();

    Server::builder()
        .add_service(IdentityServiceServer::new(identity_service))
        .add_service(StateServiceServer::new(state_service))
        .add_service(SecretServiceServer::new(secret_service))
        .serve(addr)
        .await?;

    Ok(())
}
