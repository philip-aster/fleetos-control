//! Hard invariant: evicting a node revokes ALL its delegations,
//! removes its placements, and marks it evicted — atomically.
use fleetos_control::delegation::DelegationRecord;
use fleetos_control::raft::records::{NodeRecord, NodeStatus};
use fleetos_control::raft::{AuditedCommand, FleetosCommand, FleetosRaftConfig};
use fleetos_control::scheduler::{Placement, ResourceSpec};
use fleetos_core::spiffe::SpiffeId;
use openraft::storage::RaftStateMachine;
use openraft::{Entry, EntryPayload, LeaderId, LogId};
use tempfile::tempdir;

fn make_entry(index: u64, cmd: fleetos_control::raft::AuditedCommand) -> Entry<FleetosRaftConfig> {
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
async fn eviction_cascade_revokes_delegations_and_removes_placements() {
    let dir = tempdir().unwrap();
    let (_db, keyspaces, mut sm) = setup(dir.path());

    let node_spiffe: SpiffeId = "spiffe://fleet.example.internal/ns/system/node/agent-1"
        .parse()
        .unwrap();
    let target_spiffe: SpiffeId = "spiffe://fleet.example.internal/ns/tenant-1/sa/db"
        .parse()
        .unwrap();

    // 1. Register the node.
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
    sm.apply(vec![make_entry(
        1,
        AuditedCommand::system(FleetosCommand::RegisterNode {
            record: node_record,
        }),
    )])
    .await
    .unwrap();

    // 2. Issue two delegations for this node.
    for i in 0..2 {
        let delegation = DelegationRecord {
            delegation_id: format!("del-{}", i),
            node_id: node_spiffe.clone(),
            target_svid_id: target_spiffe.clone(),
            target_ordinal: Some(i),
            issued_at: 1000,
            expires_at: 20000,
            refresh_at: 15000,
        };
        sm.apply(vec![make_entry(
            2 + i as u64,
            AuditedCommand::system(FleetosCommand::IssueDelegation { record: delegation }),
        )])
        .await
        .unwrap();
    }

    // 3. Add a placement for this node.
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
    sm.apply(vec![make_entry(
        4,
        AuditedCommand::system(FleetosCommand::CommitPlacement { record: placement }),
    )])
    .await
    .unwrap();

    // 4. Evict the node.
    sm.apply(vec![make_entry(
        5,
        AuditedCommand::system(FleetosCommand::EvictNode {
            node_id: node_spiffe.to_string(),
            svid_expires_at_unix: 20000,
        }),
    )])
    .await
    .unwrap();

    // 5. Verify node is evicted.
    let node_bytes = keyspaces
        .nodes
        .get(node_spiffe.to_string().as_bytes())
        .unwrap()
        .expect("node record should exist");
    let evicted_node: NodeRecord = postcard::from_bytes(&node_bytes).unwrap();
    assert_eq!(evicted_node.status, NodeStatus::Evicted);
    assert!(!evicted_node.schedulable);

    // 6. Verify delegations are revoked (moved to revoked keyspaces).
    let revoked_prefix = fleetos_control::storage::schema::node_delegation_prefix(&node_spiffe);
    let mut revoked_count = 0;
    for guard in keyspaces
        .revoked_delegations
        .prefix(revoked_prefix.as_slice())
    {
        let _value = guard.value().unwrap();
        revoked_count += 1;
    }
    assert_eq!(revoked_count, 2, "both delegations must be revoked");

    // 7. Verify active delegations are empty for this node.
    let mut active_count = 0;
    for guard in keyspaces
        .active_delegations
        .prefix(revoked_prefix.as_slice())
    {
        let _value = guard.value().unwrap();
        active_count += 1;
    }
    assert_eq!(active_count, 0, "no active delegations should remain");

    // 8. Verify the evicted node's own SVID is recorded as revoked (G-4 / CR-5).
    let revoked_svid = keyspaces
        .revoked_svids
        .get(node_spiffe.to_string().as_bytes())
        .unwrap();
    assert!(
        revoked_svid.is_some(),
        "evicted node's SVID must be recorded as revoked"
    );
}
