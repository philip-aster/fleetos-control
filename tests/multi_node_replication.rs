//! Multi-node Raft replication integration test (M-4).
//!
//! Spins up a 3-node Raft cluster over an in-memory network, bootstraps
//! node 1, adds nodes 2 and 3 as voters, proposes a command on the leader,
//! and verifies it replicates to all followers' state machines.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::sync::Arc;

use fleetos_control::raft::records::TenantRecord;
use fleetos_control::raft::state_machine::FjallStateMachine;
use fleetos_control::raft::store::FjallLogStorage;
use fleetos_control::raft::{AuditedCommand, FleetosCommand, FleetosRaftConfig};
use fleetos_control::storage::version::VersionedState;
use fleetos_control::watch::broadcast::BroadcastHub;
use openraft::error::{
    Fatal, InstallSnapshotError, NetworkError, RPCError, RaftError, ReplicationClosed,
    StreamingError,
};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    SnapshotResponse, VoteRequest, VoteResponse,
};
use openraft::{Config, Raft, Snapshot, Vote};
use parking_lot::Mutex;
use tempfile::tempdir;

type NodeRegistry = Arc<Mutex<HashMap<u64, Arc<Raft<FleetosRaftConfig>>>>>;

// ---------------------------------------------------------------------------
// In-memory network: routes openraft RPCs directly between Raft instances.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MemoryNetworkFactory {
    registry: NodeRegistry,
}

impl RaftNetworkFactory<FleetosRaftConfig> for MemoryNetworkFactory {
    type Network = MemoryNetwork;

    async fn new_client(&mut self, target: u64, _node: &openraft::BasicNode) -> Self::Network {
        MemoryNetwork {
            registry: self.registry.clone(),
            target,
        }
    }
}

struct MemoryNetwork {
    registry: NodeRegistry,
    target: u64,
}

impl MemoryNetwork {
    fn lookup(
        &self,
    ) -> Result<Arc<Raft<FleetosRaftConfig>>, RPCError<u64, openraft::BasicNode, RaftError<u64>>>
    {
        let reg = self.registry.lock();
        reg.get(&self.target).cloned().ok_or_else(|| {
            RPCError::Network(NetworkError::new(&std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("target node {} not found", self.target),
            )))
        })
    }

    fn map_err(e: RaftError<u64>) -> RPCError<u64, openraft::BasicNode, RaftError<u64>> {
        RPCError::Network(NetworkError::new(&std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        )))
    }
}

impl RaftNetwork<FleetosRaftConfig> for MemoryNetwork {
    async fn append_entries(
        &mut self,
        req: AppendEntriesRequest<FleetosRaftConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, openraft::BasicNode, RaftError<u64>>>
    {
        let target = self.lookup()?;
        target.append_entries(req).await.map_err(Self::map_err)
    }

    async fn vote(
        &mut self,
        req: VoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, openraft::BasicNode, RaftError<u64>>> {
        let target = self.lookup()?;
        target.vote(req).await.map_err(Self::map_err)
    }

    async fn install_snapshot(
        &mut self,
        req: InstallSnapshotRequest<FleetosRaftConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, openraft::BasicNode, RaftError<u64, InstallSnapshotError>>,
    > {
        let target = self.lookup().map_err(|e| {
            RPCError::Network(NetworkError::new(&std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            )))
        })?;
        target.install_snapshot(req).await.map_err(|e| {
            RPCError::Network(NetworkError::new(&std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            )))
        })
    }

    async fn full_snapshot(
        &mut self,
        vote: Vote<u64>,
        snapshot: Snapshot<FleetosRaftConfig>,
        _cancel: impl std::future::Future<Output = ReplicationClosed> + openraft::OptionalSend + 'static,
        _option: RPCOption,
    ) -> Result<SnapshotResponse<u64>, StreamingError<FleetosRaftConfig, Fatal<u64>>> {
        let target = {
            let reg = self.registry.lock();
            reg.get(&self.target).cloned()
        };
        let target = target.ok_or_else(|| {
            StreamingError::Network(NetworkError::new(&std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "target not found",
            )))
        })?;
        let mut cursor = snapshot.snapshot;
        cursor.set_position(0);
        let mut data = Vec::new();
        cursor
            .read_to_end(&mut data)
            .map_err(|e| StreamingError::Network(NetworkError::new(&e)))?;
        let req = InstallSnapshotRequest {
            vote,
            meta: snapshot.meta,
            offset: 0,
            data,
            done: true,
        };
        let resp = target.install_snapshot(req).await.map_err(|e| {
            StreamingError::Network(NetworkError::new(&std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            )))
        })?;
        Ok(SnapshotResponse { vote: resp.vote })
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

struct TestNode {
    raft: Arc<Raft<FleetosRaftConfig>>,
    keyspaces: fleetos_control::storage::Keyspaces,
    _dir: tempfile::TempDir,
}

async fn create_node(node_id: u64, registry: NodeRegistry) -> TestNode {
    let dir = tempdir().unwrap();
    let db = fleetos_control::storage::open_database(dir.path()).unwrap();
    let keyspaces = fleetos_control::storage::init_keyspaces(&db).unwrap();
    let versioned_state = VersionedState::new(keyspaces.version.clone());
    let broadcast_hub = BroadcastHub::new();

    let raft_config = Config {
        heartbeat_interval: 50,
        election_timeout_min: 150,
        election_timeout_max: 300,
        ..Default::default()
    };
    let raft_config = Arc::new(raft_config.validate().unwrap());

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
        "test.example.internal".to_owned(),
    );

    let factory = MemoryNetworkFactory {
        registry: registry.clone(),
    };

    let raft = Raft::new(node_id, raft_config, factory, log_storage, state_machine)
        .await
        .unwrap();
    let raft = Arc::new(raft);
    registry.lock().insert(node_id, raft.clone());

    TestNode {
        raft,
        keyspaces,
        _dir: dir,
    }
}

fn tenant_record(id: &str) -> TenantRecord {
    TenantRecord {
        tenant_id: id.to_owned(),
        created_at: 1000,
    }
}

fn read_tenant(
    keyspaces: &fleetos_control::storage::Keyspaces,
    tenant_id: &str,
) -> Option<TenantRecord> {
    let bytes = keyspaces.tenants.get(tenant_id.as_bytes()).unwrap()?;
    postcard::from_bytes(&bytes).ok()
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn three_node_cluster_replicates_commands() {
    let registry: NodeRegistry = Arc::new(Mutex::new(HashMap::new()));

    // Create three nodes.
    let node1 = create_node(1, registry.clone()).await;
    let node2 = create_node(2, registry.clone()).await;
    let node3 = create_node(3, registry.clone()).await;

    // Bootstrap node 1 as a single-node cluster.
    let mut members: BTreeMap<u64, openraft::BasicNode> = BTreeMap::new();
    members.insert(
        1,
        openraft::BasicNode {
            addr: String::new(),
        },
    );
    node1.raft.initialize(members).await.unwrap();

    // Add nodes 2 and 3 as learners (blocking until caught up), then promote
    // both to voters in a single membership change.
    node1
        .raft
        .add_learner(
            2,
            openraft::BasicNode {
                addr: String::new(),
            },
            true,
        )
        .await
        .unwrap();
    node1
        .raft
        .add_learner(
            3,
            openraft::BasicNode {
                addr: String::new(),
            },
            true,
        )
        .await
        .unwrap();

    let mut voters: BTreeMap<u64, openraft::BasicNode> = BTreeMap::new();
    voters.insert(
        1,
        openraft::BasicNode {
            addr: String::new(),
        },
    );
    voters.insert(
        2,
        openraft::BasicNode {
            addr: String::new(),
        },
    );
    voters.insert(
        3,
        openraft::BasicNode {
            addr: String::new(),
        },
    );
    node1
        .raft
        .change_membership(openraft::ChangeMembers::AddVoters(voters), false)
        .await
        .unwrap();

    // Wait until node 1 observes a 3-voter membership.
    for _ in 0..100 {
        let metrics_rx = node1.raft.metrics();
        let m = metrics_rx.borrow();
        let voter_count = m.membership_config.membership().voter_ids().count();
        if voter_count == 3 {
            break;
        }
        drop(m);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Propose a command on the leader (node 1).
    node1
        .raft
        .client_write(AuditedCommand::system(FleetosCommand::CreateTenant {
            record: tenant_record("tenant-replicated"),
        }))
        .await
        .unwrap();

    // Wait for the command to be applied on all three nodes.
    for node in [&node1, &node2, &node3] {
        let mut applied = false;
        for _ in 0..100 {
            if read_tenant(&node.keyspaces, "tenant-replicated").is_some() {
                applied = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(applied, "tenant did not replicate to node");
    }

    // All three nodes must agree on the replicated tenant.
    for node in [&node1, &node2, &node3] {
        let record = read_tenant(&node.keyspaces, "tenant-replicated").unwrap();
        assert_eq!(record.tenant_id, "tenant-replicated");
    }
}
