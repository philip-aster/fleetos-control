//! Hard invariant: a DelegatedSigningKey is only issued if the requesting node
//! actually hosts the target workload (placement verification).
use fleetos_control::ca::key_issuance::{PlacementVerifier, StoragePlacementVerifier};
use fleetos_control::scheduler::{Placement, ResourceSpec};
use fleetos_core::spiffe::SpiffeId;
use tempfile::tempdir;

#[test]
fn placement_verification_enforces_node_hosting() {
    let dir = tempdir().unwrap();
    let db = fjall::Database::builder(dir.path())
        .open()
        .expect("open db");
    let placements_ks = db
        .keyspace("placements", fjall::KeyspaceCreateOptions::default)
        .expect("open placements keyspace");
    let verifier = StoragePlacementVerifier::new(placements_ks.clone());

    let node_a: SpiffeId = "spiffe://fleet.example.internal/ns/system/node/node-A"
        .parse()
        .unwrap();
    let node_b: SpiffeId = "spiffe://fleet.example.internal/ns/system/node/node-B"
        .parse()
        .unwrap();
    let db_svid: SpiffeId = "spiffe://fleet.example.internal/ns/tenant-1/sa/db"
        .parse()
        .unwrap();

    // node-A hosts tenant-1/db ordinal 0.
    let placement = Placement {
        pod_id: "db-replica-0".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        service: "db".to_owned(),
        role: "replica".to_owned(),
        ordinal: 0,
        node_id: node_a.clone(),
        resources: ResourceSpec {
            cpu_millicores: 500,
            memory_bytes: 512 * 1024 * 1024,
        },
    };
    let serialized = postcard::to_allocvec(&placement).unwrap();
    placements_ks
        .insert(placement.pod_id.as_bytes(), serialized.as_slice())
        .unwrap();

    // Hosting node + matching workload + matching ordinal → pass.
    assert!(
        verifier
            .verify_placement(&node_a, &db_svid, Some(0))
            .is_ok()
    );
    // Different node → reject.
    assert!(
        verifier
            .verify_placement(&node_b, &db_svid, Some(0))
            .is_err()
    );
    // Wrong ordinal → reject.
    assert!(
        verifier
            .verify_placement(&node_a, &db_svid, Some(5))
            .is_err()
    );
    // Different workload → reject.
    let web_svid: SpiffeId = "spiffe://fleet.example.internal/ns/tenant-1/sa/web"
        .parse()
        .unwrap();
    assert!(
        verifier
            .verify_placement(&node_a, &web_svid, Some(0))
            .is_err()
    );
}
