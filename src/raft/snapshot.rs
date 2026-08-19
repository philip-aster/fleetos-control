use std::io::Cursor;
use std::sync::Arc;

use openraft::{RaftSnapshotBuilder, Snapshot, SnapshotMeta, StorageError, StoredMembership};

use super::FleetosRaftConfig;

pub struct RedbSnapshotBuilder {
    #[allow(dead_code)]
    db: Arc<redb::Database>,
}

impl RedbSnapshotBuilder {
    pub fn new(db: Arc<redb::Database>) -> Self {
        Self { db }
    }
}

impl RaftSnapshotBuilder<FleetosRaftConfig> for RedbSnapshotBuilder {
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
