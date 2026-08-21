//! Hard invariant: join tokens are strictly single-use.

use fleetos_control::attestation::AttestationError;
use fleetos_control::attestation::join_token::{JoinTokenStore, NodeKind};
use tempfile::tempdir;

#[test]
fn join_token_cannot_be_reused() {
    let dir = tempdir().unwrap();

    // Create the database and keyspace using the project's exact pattern
    let db = fjall::Database::builder(dir.path())
        .open()
        .expect("failed to open database");
    let keyspace = db
        .keyspace("join_tokens", fjall::KeyspaceCreateOptions::default)
        .expect("failed to open keyspace");

    let store = JoinTokenStore::new(keyspace);

    // 1. Generate a token
    let token = store.generate(NodeKind::Agent).unwrap();

    // 2. First use succeeds
    let record = store.validate_and_consume(&token).unwrap();
    assert_eq!(record.node_kind, NodeKind::Agent);

    // 3. Second use MUST fail
    let result = store.validate_and_consume(&token);
    assert!(
        matches!(result, Err(AttestationError::JoinTokenNotFound)),
        "Second use of join token must be rejected"
    );
}
