//! Hard invariant: join tokens are strictly single-use.
//!
//! Exercises the Raft consumption path: MintJoinToken persists the token,
//! ConsumeJoinToken deletes it cluster-wide, and validate_only rejects
//! any subsequent attempt.

use fleetos_control::attestation::AttestationError;
use fleetos_control::attestation::join_token::{JoinTokenStore, NodeKind};
use fleetos_control::raft::state_machine::FjallStateMachine;
use fleetos_control::raft::{AuditedCommand, FleetosCommand, FleetosRaftConfig};
use fleetos_control::storage::version::VersionedState;
use fleetos_control::watch::broadcast::BroadcastHub;
use openraft::LogId;
use openraft::storage::RaftStateMachine;

fn make_entry(index: u64, cmd: AuditedCommand) -> openraft::Entry<FleetosRaftConfig> {
    openraft::Entry {
        log_id: LogId {
            leader_id: openraft::LeaderId {
                term: 1,
                node_id: 1,
            },
            index,
        },
        payload: openraft::EntryPayload::Normal(cmd),
    }
}

#[tokio::test]
async fn join_token_cannot_be_reused() {
    let dir = std::env::temp_dir().join(format!(
        "fleetos-join-token-single-use-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let db = fleetos_control::storage::open_database(&dir).unwrap();
    let keyspaces = fleetos_control::storage::init_keyspaces(&db).unwrap();
    let versioned_state = VersionedState::new(keyspaces.version.clone());
    let broadcast_hub = BroadcastHub::new();

    let mut sm = FjallStateMachine::new(
        db.clone(),
        keyspaces.clone(),
        versioned_state,
        broadcast_hub,
        "test.example.internal".to_owned(),
    );

    // 1. Compute a token record (random, not yet persisted).
    let store = JoinTokenStore::new(keyspaces.join_tokens.clone());
    let record = store.compute_token_record(NodeKind::Agent).unwrap();
    let token = record.token.clone();

    // 2. Mint via Raft (persists the token).
    sm.apply(vec![make_entry(
        1,
        AuditedCommand::system(FleetosCommand::MintJoinToken { record }),
    )])
    .await
    .unwrap();

    // 3. Token is valid after minting.
    assert!(store.validate_only(&token).is_ok());

    // 4. Consume via Raft (deletes the token cluster-wide).
    sm.apply(vec![make_entry(
        2,
        AuditedCommand::system(FleetosCommand::ConsumeJoinToken {
            token: token.clone(),
        }),
    )])
    .await
    .unwrap();

    // 5. Second use MUST fail — token is gone.
    let result = store.validate_only(&token);
    assert!(
        matches!(result, Err(AttestationError::JoinTokenNotFound)),
        "second use of join token must be rejected, got {:?}",
        result
    );
}
