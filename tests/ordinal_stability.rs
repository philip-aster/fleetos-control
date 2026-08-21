//! Hard invariant: kill pod at ordinal N → replacement is N, not N+1.

use fleetos_control::scheduler::OrdinalTracker;
use fleetos_control::scheduler::ordinal::OrdinalAssignment;
use tempfile::tempdir;

#[test]
fn kill_and_reconcile_preserves_ordinal() {
    let dir = tempdir().unwrap();

    // Create the database and keyspace using the project's exact pattern
    let db = fjall::Database::builder(dir.path())
        .open()
        .expect("failed to open database");
    let keyspace = db
        .keyspace("ordinals", fjall::KeyspaceCreateOptions::default)
        .expect("failed to open keyspace");

    let tracker = OrdinalTracker::new(keyspace);

    // 1. Record an initial assignment at ordinal 1
    let initial_assignment = OrdinalAssignment {
        tenant_id: "tenant-A".to_owned(),
        service: "db".to_owned(),
        role: "replica".to_owned(),
        ordinal: 1,
        current_pod_id: Some("db-replica-1-old".to_owned()),
        current_node_id: Some("node-1".to_owned()),
    };
    tracker.record_assignment(&initial_assignment).unwrap();

    // 2. Simulate death and replacement: update the placement
    tracker
        .update_placement("tenant-A", "db", "replica", 1, "db-replica-1-new", "node-2")
        .unwrap();

    // 3. Assert the ordinal is still 1, and no ordinal 2 was created
    let updated = tracker
        .get_assignment("tenant-A", "db", "replica", 1)
        .unwrap()
        .unwrap();
    assert_eq!(updated.current_pod_id.as_deref(), Some("db-replica-1-new"));
    assert_eq!(updated.current_node_id.as_deref(), Some("node-2"));

    let ordinal_2 = tracker
        .get_assignment("tenant-A", "db", "replica", 2)
        .unwrap();
    assert!(
        ordinal_2.is_none(),
        "Ordinal 2 should not exist; identity must be stable"
    );
}
