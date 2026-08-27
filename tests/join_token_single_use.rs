//! Hard invariant: join tokens are strictly single-use.
//!
//! Minting is Raft-replicated (FleetosCommand::MintJoinToken), so this test
//! persists the computed record exactly the way the state machine's apply
//! does, then exercises the consume path.
use fleetos_control::attestation::AttestationError;
use fleetos_control::attestation::join_token::{JoinTokenStore, NodeKind};
use tempfile::tempdir;

#[test]
fn join_token_cannot_be_reused() {
    let dir = tempdir().unwrap();
    let db = fjall::Database::builder(dir.path())
        .open()
        .expect("failed to open database");
    let keyspace = db
        .keyspace("join_tokens", fjall::KeyspaceCreateOptions::default)
        .expect("failed to open keyspace");
    let store = JoinTokenStore::new(keyspace.clone());

    // 1. Compute a token record and persist it the way the Raft state
    //    machine's MintJoinToken apply does.
    let record = store.compute_token_record(NodeKind::Agent).unwrap();
    let token = record.token.clone();
    let serialized = postcard::to_allocvec(&record).unwrap();
    keyspace
        .insert(token.as_slice(), serialized.as_slice())
        .unwrap();

    // 2. First use succeeds.
    let consumed = store.validate_and_consume(&token).unwrap();
    assert_eq!(consumed.node_kind, NodeKind::Agent);

    // 3. Second use MUST fail.
    let result = store.validate_and_consume(&token);
    assert!(
        matches!(result, Err(AttestationError::JoinTokenNotFound)),
        "Second use of join token must be rejected"
    );
}
