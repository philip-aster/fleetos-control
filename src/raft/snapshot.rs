//! Snapshot builder for fjall.

use std::io::Cursor;

use fjall::Keyspace;
use openraft::{RaftSnapshotBuilder, Snapshot, SnapshotMeta, StorageError, StoredMembership};

use super::FleetosRaftConfig;

pub struct FjallSnapshotBuilder {
    /// Will be used when implementing actual snapshot building
    /// (serializing full application state from the keyspace).
    #[allow(dead_code)]
    raft_snapshot: Keyspace,
}

impl FjallSnapshotBuilder {
    pub fn new(raft_snapshot: Keyspace) -> Self {
        Self { raft_snapshot }
    }
}

impl RaftSnapshotBuilder<FleetosRaftConfig> for FjallSnapshotBuilder {
    async fn build_snapshot(&mut self) -> Result<Snapshot<FleetosRaftConfig>, StorageError<u64>> {
        let data: Vec<u8> = Vec::new();
        let cursor = Cursor::new(data);

        let meta = SnapshotMeta {
            last_log_id: None,
            last_membership: StoredMembership::default(),
            snapshot_id: "initial".to_string(),
        };

        Ok(Snapshot {
            meta,
            snapshot: Box::new(cursor),
        })
    }
}
