//! Hard invariant: a snapshot built from one state machine, when installed
//! into a fresh state machine, reproduces all application state exactly.
use fleetos_control::raft::records::{NodeRecord, NodeStatus, TenantRecord};
use fleetos_control::raft::{AuditedCommand, FleetosCommand, FleetosRaftConfig};
use fleetos_control::scheduler::{Placement, ResourceSpec};
use fleetos_core::spiffe::SpiffeId;
use openraft::storage::RaftStateMachine;
use openraft::{Entry, EntryPayload, LeaderId, LogId};
use std::io::Cursor;
use tempfile::tempdir;

fn make_entry(index: u64, cmd: AuditedCommand) -> Entry<FleetosRaftConfig> {
    Entry {
        log_id: LogId::new(LeaderId::new(1, 1), index),
        payload: EntryPayload::Normal(cmd),
    }
}

fn setup(
    dir: &std::path::Path,
) -> (
    std::sync::Arc<fjall::Database>,
    fleetos_control::storage::Keyspaces,
    fleetos_control::raft::state_machine::FjallStateMachine,
) {
    let db = fleetos_control::storage::open_database(dir).unwrap();
    let keyspaces = fleetos_control::storage::init_keyspaces(&db).unwrap();
    let versioned_state =
        fleetos_control::storage::version::VersionedState::new(keyspaces.version.clone());
    let broadcast_hub = fleetos_control::watch::broadcast::BroadcastHub::new();
    let sm = fleetos_control::raft::state_machine::FjallStateMachine::new(
        db.clone(),
        keyspaces.clone(),
        versioned_state,
        broadcast_hub,
    );
    (db, keyspaces, sm)
}

#[tokio::test]
async fn snapshot_round_trip_preserves_state() {
    // --- Source: populate state ---
    let src_dir = tempdir().unwrap();
    let (src_db, src_ks, mut src_sm) = setup(src_dir.path());

    let tenant = TenantRecord {
        tenant_id: "tenant-1".to_owned(),
        created_at: 1000,
    };
    src_sm
        .apply(vec![make_entry(
            1,
            AuditedCommand::system(FleetosCommand::CreateTenant { record: tenant }),
        )])
        .await
        .unwrap();

    let node_spiffe: SpiffeId = "spiffe://fleet.example.internal/ns/system/node/agent-1"
        .parse()
        .unwrap();
    let node_record = NodeRecord {
        node_id: node_spiffe.to_string(),
        node_kind: 1,
        status: NodeStatus::Active,
        schedulable: true,
        last_heartbeat: 1000,
        registered_at: 1000,
        capacity_cpu_millicores: 4000,
        capacity_memory_bytes: 8 * 1024 * 1024 * 1024,
        failure_domain: "zone-a".to_owned(),
    };
    src_sm
        .apply(vec![make_entry(
            2,
            AuditedCommand::system(FleetosCommand::RegisterNode {
                record: node_record,
            }),
        )])
        .await
        .unwrap();

    let placement = Placement {
        pod_id: "db-replica-0".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        service: "db".to_owned(),
        role: "replica".to_owned(),
        ordinal: 0,
        node_id: node_spiffe.clone(),
        resources: ResourceSpec {
            cpu_millicores: 500,
            memory_bytes: 512 * 1024 * 1024,
        },
    };
    src_sm
        .apply(vec![make_entry(
            3,
            AuditedCommand::system(FleetosCommand::CommitPlacement { record: placement }),
        )])
        .await
        .unwrap();

    // --- Build snapshot from source ---
    let mut builder =
        fleetos_control::raft::snapshot::FjallSnapshotBuilder::new(src_db.clone(), src_ks.clone());
    let snapshot = openraft::RaftSnapshotBuilder::build_snapshot(&mut builder)
        .await
        .unwrap();

    // --- Target: install snapshot into fresh state machine ---
    let dst_dir = tempdir().unwrap();
    let (_dst_db, dst_ks, mut dst_sm) = setup(dst_dir.path());

    let meta = snapshot.meta.clone();
    let data = snapshot.snapshot.into_inner(); // Cursor<Vec<u8>> -> Vec<u8>
    dst_sm
        .install_snapshot(&meta, Box::new(Cursor::new(data)))
        .await
        .unwrap();

    // --- Verify: tenant exists in target ---
    let tenant_bytes = dst_ks
        .tenants
        .get(b"tenant-1")
        .unwrap()
        .expect("tenant should exist after snapshot install");
    let restored_tenant: TenantRecord = postcard::from_bytes(&tenant_bytes).unwrap();
    assert_eq!(restored_tenant.tenant_id, "tenant-1");

    // --- Verify: node exists in target ---
    let node_bytes = dst_ks
        .nodes
        .get(node_spiffe.to_string().as_bytes())
        .unwrap()
        .expect("node should exist after snapshot install");
    let restored_node: NodeRecord = postcard::from_bytes(&node_bytes).unwrap();
    assert_eq!(restored_node.status, NodeStatus::Active);

    // --- Verify: placement exists in target ---
    let placement_bytes = dst_ks
        .placements
        .get(b"db-replica-0")
        .unwrap()
        .expect("placement should exist after snapshot install");
    let restored_placement: Placement = postcard::from_bytes(&placement_bytes).unwrap();
    assert_eq!(restored_placement.tenant_id, "tenant-1");
    assert_eq!(restored_placement.ordinal, 0);
}
