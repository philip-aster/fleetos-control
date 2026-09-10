//! Hard invariant: kill pod at ordinal N → replacement is N, not N+1.
//!
//! Ordinal mutations go through Raft (V-5 / S-1), so this test drives the
//! state machine with the same commands the controllers propose:
//! `CommitPlacement` + `RecordOrdinalAssignment` for the initial schedule,
//! `ReassignPodId` for the in-place replacement — then reads back through
//! the read-only `OrdinalTracker` and the placements keyspace.
use fleetos_control::raft::{AuditedCommand, FleetosCommand, FleetosRaftConfig};
use fleetos_control::scheduler::ordinal::OrdinalAssignment;
use fleetos_control::scheduler::{OrdinalTracker, Placement, ResourceSpec};
use fleetos_core::spiffe::SpiffeId;
use openraft::storage::RaftStateMachine;
use openraft::{Entry, EntryPayload, LeaderId, LogId};
use tempfile::tempdir;

fn make_entry(index: u64, cmd: AuditedCommand) -> Entry<FleetosRaftConfig> {
    Entry {
        log_id: LogId::new(LeaderId::new(1, 1), index),
        payload: EntryPayload::Normal(cmd),
    }
}

#[tokio::test]
async fn kill_and_reconcile_preserves_ordinal() {
    let dir = tempdir().unwrap();
    let db = fleetos_control::storage::open_database(dir.path()).unwrap();
    let keyspaces = fleetos_control::storage::init_keyspaces(&db).unwrap();
    let versioned_state =
        fleetos_control::storage::version::VersionedState::new(keyspaces.version.clone());
    let broadcast_hub = fleetos_control::watch::broadcast::BroadcastHub::new();
    let mut sm = fleetos_control::raft::state_machine::FjallStateMachine::new(
        db.clone(),
        keyspaces.clone(),
        versioned_state,
        broadcast_hub,
        "test.example.internal".to_owned(),
    );

    let node_spiffe: SpiffeId = "spiffe://fleet.example.internal/ns/system/node/node-1"
        .parse()
        .unwrap();
    let node_str = node_spiffe.to_string();

    // 1. Initial schedule: tenant-A/db replica at ordinal 1.
    let placement = Placement {
        pod_id: "db-replica-1-old".to_owned(),
        tenant_id: "tenant-A".to_owned(),
        service: "db".to_owned(),
        role: "replica".to_owned(),
        ordinal: 1,
        node_id: node_spiffe.clone(),
        resources: ResourceSpec {
            cpu_millicores: 500,
            memory_bytes: 512 * 1024 * 1024,
        },
    };
    let assignment = OrdinalAssignment {
        tenant_id: "tenant-A".to_owned(),
        service: "db".to_owned(),
        role: "replica".to_owned(),
        ordinal: 1,
        current_pod_id: Some("db-replica-1-old".to_owned()),
        current_node_id: Some(node_str.clone()),
    };
    sm.apply(vec![make_entry(
        1,
        AuditedCommand::system(FleetosCommand::CommitPlacement { record: placement }),
    )])
    .await
    .unwrap();
    sm.apply(vec![make_entry(
        2,
        AuditedCommand::system(FleetosCommand::RecordOrdinalAssignment { record: assignment }),
    )])
    .await
    .unwrap();

    // 2. Simulate death and in-place replacement via Raft
    //    (pod_controller::reconcile_dead_pod path).
    sm.apply(vec![make_entry(
        3,
        AuditedCommand::system(FleetosCommand::ReassignPodId {
            tenant_id: "tenant-A".to_owned(),
            service: "db".to_owned(),
            role: "replica".to_owned(),
            ordinal: 1,
            new_pod_id: "db-replica-1-new".to_owned(),
        }),
    )])
    .await
    .unwrap();

    // 3. The ordinal is still 1 — the slot was replaced, never extended.
    let tracker = OrdinalTracker::new(keyspaces.ordinals.clone());
    let updated = tracker
        .get_assignment("tenant-A", "db", "replica", 1)
        .unwrap()
        .unwrap();
    assert_eq!(updated.current_pod_id.as_deref(), Some("db-replica-1-new"));
    assert_eq!(updated.current_node_id.as_deref(), Some(node_str.as_str()));

    let ordinal_2 = tracker
        .get_assignment("tenant-A", "db", "replica", 2)
        .unwrap();
    assert!(
        ordinal_2.is_none(),
        "Ordinal 2 should not exist; identity must be stable"
    );

    // 4. The placements keyspace reflects the swap exactly once.
    let new_bytes = keyspaces
        .placements
        .get("db-replica-1-new".as_bytes())
        .unwrap()
        .expect("replacement placement must exist");
    let new_placement: Placement = postcard::from_bytes(&new_bytes).unwrap();
    assert_eq!(new_placement.ordinal, 1);
    assert_eq!(new_placement.node_id, node_spiffe);
    assert!(
        keyspaces
            .placements
            .get("db-replica-1-old".as_bytes())
            .unwrap()
            .is_none(),
        "old pod placement must be removed by the in-place swap"
    );
}
