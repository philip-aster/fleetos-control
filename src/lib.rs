// fleetos-control/src/lib.rs
pub mod api;
pub mod cloud;
pub mod controllers;
pub mod grpc;
pub mod raft;
pub mod scheduler;
pub mod secrets;
pub mod storage;

#[cfg(feature = "test-helpers")]
pub mod test_helpers {
    use crate::grpc::{FleetIdentityService, FleetSecretService, FleetStateService};
    use crate::raft::{FleetRaft, Network, RedbStore};
    use anyhow::Result;
    use fleetos_core::proto::identity::identity_service_server::IdentityServiceServer;
    use fleetos_core::proto::secret::secret_service_server::SecretServiceServer;
    use fleetos_core::proto::state::state_service_server::StateServiceServer;
    use openraft::Config as RaftConfig;
    use redb::Database;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::time::sleep;
    use tonic::transport::Server;

    /// Spawns a fully functional in-process control plane server for integration testing
    pub async fn spawn_test_control_plane(addr: SocketAddr) -> Result<()> {
        let dir = tempdir()?;
        let db_path = dir.path().join("test_fleetos.redb");
        let db = Arc::new(Database::create(&db_path)?);

        let (log_store, state_machine) = RedbStore::new(db.clone())?;

        let raft_config = Arc::new(
            RaftConfig {
                cluster_name: "test-cluster".to_string(),
                ..Default::default()
            }
            .validate()?,
        );

        let network = Network::new();
        let raft: FleetRaft =
            openraft::Raft::new(1, raft_config, network, log_store, state_machine).await?;

        // ------------------------------------------------------------------
        // Promote Node 1 to Leader in single-node test cluster
        // ------------------------------------------------------------------
        let mut nodes = BTreeMap::new();
        nodes.insert(
            1,
            Node {
                rpc_addr: addr.to_string(),
                node_id: 1,
            },
        );

        // Initialize single-node membership
        if let Err(e) = raft.initialize(nodes).await {
            tracing::warn!("Raft initialize notice: {:?}", e);
        }

        // Wait briefly for Raft state machine to complete leader election
        sleep(Duration::from_millis(150)).await;

        let identity_service = FleetIdentityService::new();
        let state_service = FleetStateService::new(raft.clone(), db.clone());
        let master_key = [0x42; 32];
        let secret_service = FleetSecretService::new(db.clone(), master_key);

        tokio::spawn(async move {
            Server::builder()
                .add_service(IdentityServiceServer::new(identity_service))
                .add_service(StateServiceServer::new(state_service))
                .add_service(SecretServiceServer::new(secret_service))
                .serve(addr)
                .await
                .unwrap();
        });

        sleep(Duration::from_millis(200)).await;
        Ok(())
    }
}
