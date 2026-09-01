//! V-2: Join-token consumption must replicate cluster-wide.
//!
//! Mints a token via Raft, consumes it via Raft on the leader, then asserts
//! the token is gone from ALL followers — not just the leader. This catches
//! the node-local consumption bug the Senior/Master audit flagged.
use fleetos_control::attestation::join_token::{JoinTokenRecord, NodeKind};
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
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::sync::Arc;
use tempfile::tempdir;

type NodeRegistry = Arc<Mutex<HashMap<u64, Arc<Raft<FleetosRaftConfig>>>>>;

// ---------------------------------------------------------------------------
// In-memory network (same as multi_node_replication.rs)
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

fn token_record(token: Vec<u8>) -> JoinTokenRecord {
    let now = 1_700_000_000i64;
    JoinTokenRecord {
        token,
        node_kind: NodeKind::Agent,
        created_at: now,
        expires_at: Some(now + 3600),
        consumed: false,
    }
}

fn read_token(
    keyspaces: &fleetos_control::storage::Keyspaces,
    token: &[u8],
) -> Option<JoinTokenRecord> {
    let bytes = keyspaces.join_tokens.get(token).unwrap()?;
    postcard::from_bytes(&bytes).ok()
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------
#[tokio::test]
async fn join_token_consumption_replicates_cluster_wide() {
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

    // Add nodes 2 and 3 as learners then promote to voters.
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
    for id in [1u64, 2, 3] {
        voters.insert(
            id,
            openraft::BasicNode {
                addr: String::new(),
            },
        );
    }
    node1
        .raft
        .change_membership(openraft::ChangeMembers::AddVoters(voters), false)
        .await
        .unwrap();

    // Wait until node 1 observes a 3-voter membership.
    for _ in 0..100 {
        let voter_count = {
            let metrics_rx = node1.raft.metrics();
            let m = metrics_rx.borrow();
            m.membership_config.membership().voter_ids().count()
        };
        if voter_count == 3 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Mint a join token via Raft on the leader.
    let token_bytes: Vec<u8> = vec![0xAB; 32];
    node1
        .raft
        .client_write(AuditedCommand::system(FleetosCommand::MintJoinToken {
            record: token_record(token_bytes.clone()),
        }))
        .await
        .unwrap();

    // Wait for the token to replicate to all three nodes.
    for node in [&node1, &node2, &node3] {
        let mut found = false;
        for _ in 0..100 {
            if read_token(&node.keyspaces, &token_bytes).is_some() {
                found = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(found, "join token did not replicate to node");
    }

    // Consume the token via Raft on the leader (the V-2 fix path).
    node1
        .raft
        .client_write(AuditedCommand::system(FleetosCommand::ConsumeJoinToken {
            token: token_bytes.clone(),
        }))
        .await
        .unwrap();

    // CRITICAL ASSERTION: the token must be gone from ALL nodes, not just the leader.
    for node in [&node1, &node2, &node3] {
        let mut gone = false;
        for _ in 0..100 {
            if read_token(&node.keyspaces, &token_bytes).is_none() {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            gone,
            "join token still present on a follower after ConsumeJoinToken — \
             consumption is node-local, not cluster-wide (V-2 regression)"
        );
    }
}
