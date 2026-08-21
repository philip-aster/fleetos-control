//! Hard invariant: eviction revokes ALL delegations for a node (one-to-many).

use fleetos_control::delegation::DelegationRecord;
use fleetos_control::delegation::revocation::DelegationRevocationStore;
use fleetos_core::spiffe::SpiffeId;
use tempfile::tempdir;

#[test]
fn eviction_revokes_all_node_delegations() {
    let dir = tempdir().unwrap();

    // Create the database with both keyspaces using the project's exact pattern
    let db = fjall::Database::builder(dir.path())
        .open()
        .expect("failed to open database");

    let active_ks = db
        .keyspace("active_delegations", fjall::KeyspaceCreateOptions::default)
        .expect("failed to open active keyspace");

    let revoked_ks = db
        .keyspace("revoked_delegations", fjall::KeyspaceCreateOptions::default)
        .expect("failed to open revoked keyspace");

    let store = DelegationRevocationStore::new(active_ks, revoked_ks);

    let node_a: SpiffeId = "spiffe://test.internal/ns/system/node/node-A"
        .parse()
        .unwrap();
    let node_b: SpiffeId = "spiffe://test.internal/ns/system/node/node-B"
        .parse()
        .unwrap();
    let target: SpiffeId = "spiffe://test.internal/ns/tenant/sa/db".parse().unwrap();

    // 1. Create 3 active delegations for node-A
    for i in 0..3 {
        let record = DelegationRecord {
            delegation_id: format!("del-A-{}", i),
            node_id: node_a.clone(),
            target_svid_id: target.clone(),
            target_ordinal: Some(i),
            issued_at: 1000,
            expires_at: 20000,
            refresh_at: 15000,
        };
        store.record_active(&record).unwrap();
    }

    // 2. Create 1 active delegation for node-B
    let record_b = DelegationRecord {
        delegation_id: "del-B-0".to_owned(),
        node_id: node_b.clone(),
        target_svid_id: target.clone(),
        target_ordinal: Some(0),
        issued_at: 1000,
        expires_at: 20000,
        refresh_at: 15000,
    };
    store.record_active(&record_b).unwrap();

    // 3. Revoke all for node-A
    let revoked = store.revoke_all_for_node(&node_a).unwrap();
    assert_eq!(
        revoked.len(),
        3,
        "All 3 delegations for node-A must be revoked"
    );

    // 4. Assert node-B's delegation is untouched
    let revoked_set = store.get_revoked_set().unwrap();
    assert!(
        !revoked_set.contains(&"del-B-0".to_owned()),
        "node-B's delegation should not be revoked"
    );
}
