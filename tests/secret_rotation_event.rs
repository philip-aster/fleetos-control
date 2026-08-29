//! Hard invariant: StoreSecret broadcasts a SecretRotationNotification
//! carrying the target_spiffe_id, so agents know which identity's secret rotated.
use fleetos_control::raft::records::SecretRecord;
use fleetos_control::raft::{AuditedCommand, FleetosCommand, FleetosRaftConfig};
use fleetos_control::watch::broadcast::WatchEvent;
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
async fn store_secret_broadcasts_rotation_with_target_spiffe_id() {
    let dir = tempdir().unwrap();
    let db = fleetos_control::storage::open_database(dir.path()).unwrap();
    let keyspaces = fleetos_control::storage::init_keyspaces(&db).unwrap();
    let versioned_state =
        fleetos_control::storage::version::VersionedState::new(keyspaces.version.clone());
    let broadcast_hub = fleetos_control::watch::broadcast::BroadcastHub::new();

    // Subscribe BEFORE creating the state machine so we don't miss the event.
    let mut watch_rx = broadcast_hub.subscribe_watch();

    let mut sm = fleetos_control::raft::state_machine::FjallStateMachine::new(
        db.clone(),
        keyspaces.clone(),
        versioned_state,
        broadcast_hub.clone(),
    );

    let target_spiffe_id = "spiffe://fleet.example.internal/ns/tenant-1/sa/db".to_owned();
    let record = SecretRecord {
        key: "db-password".to_owned(),
        envelope_bytes: vec![1, 2, 3],
        acl_bytes: vec![4, 5, 6],
    };

    sm.apply(vec![make_entry(
        1,
        AuditedCommand::system(FleetosCommand::StoreSecret {
            record,
            target_spiffe_id: target_spiffe_id.clone(),
        }),
    )])
    .await
    .unwrap();

    // Receive the broadcast event.
    let event = watch_rx.recv().await.unwrap();
    match event {
        WatchEvent::SecretRotationNotification { spiffe_id, .. } => {
            assert_eq!(
                spiffe_id, target_spiffe_id,
                "rotation event must carry the target SpiffeId"
            );
        }
    }
}
