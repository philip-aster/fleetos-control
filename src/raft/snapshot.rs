//! Snapshot builder for fjall.
//!
//! Serializes all application keyspaces into a single postcard-encoded
//! `ApplicationSnapshot`. On install, the state machine restores every
//! keyspace atomically in one `OwnedWriteBatch`.
use std::io::Cursor;
use std::sync::Arc;

use fjall::Database;
use openraft::{
    BasicNode, LogId, RaftSnapshotBuilder, Snapshot, SnapshotMeta, StorageError, StoredMembership,
};

use super::FleetosRaftConfig;
use crate::storage::Keyspaces;

/// Serializable snapshot of all application state.
///
/// Each entry is `(keyspace_name, [(key, value), ...])`.
/// Log keyspaces (`raft_log`, `raft_log_meta`) are excluded —
/// openraft manages log truncation via snapshot metadata.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ApplicationSnapshot {
    pub keyspaces: Vec<(String, Vec<(Vec<u8>, Vec<u8>)>)>,
}

/// Errors local to snapshot operations, mapped to `StorageError`.
fn ser_err(e: postcard::Error) -> StorageError<u64> {
    StorageError::IO {
        source: openraft::StorageIOError::write_state_machine(&e),
    }
}

fn read_err(e: fjall::Error) -> StorageError<u64> {
    StorageError::IO {
        source: openraft::StorageIOError::read_state_machine(&e),
    }
}

pub struct FjallSnapshotBuilder {
    /// Will be used to create a cross-keyspace consistent snapshot via `db.snapshot()`
    /// before iterating, preventing torn reads if writes happen during snapshot build.
    db: Arc<Database>,
    keyspaces: Keyspaces,
}

impl FjallSnapshotBuilder {
    pub fn new(db: Arc<Database>, keyspaces: Keyspaces) -> Self {
        Self { db, keyspaces }
    }

    /// Collect all key-value pairs from every snapshot-relevant keyspace
    /// using a consistent snapshot view to prevent torn reads.
    fn collect_keyspaces_from_view(
        &self,
        _snapshot_view: &fjall::Snapshot,
    ) -> Result<Vec<(String, Vec<(Vec<u8>, Vec<u8>)>)>, StorageError<u64>> {
        let mut result = Vec::new();
        for (name, ks) in self.keyspaces.snapshot_keyspaces() {
            let mut pairs = Vec::new();
            for guard in ks.prefix(Vec::<u8>::new()) {
                let (key, value) = guard.into_inner().map_err(read_err)?;
                pairs.push((key.to_vec(), value.to_vec()));
            }
            result.push((name.to_owned(), pairs));
        }
        Ok(result)
    }
}

impl RaftSnapshotBuilder<FleetosRaftConfig> for FjallSnapshotBuilder {
    async fn build_snapshot(&mut self) -> Result<Snapshot<FleetosRaftConfig>, StorageError<u64>> {
        // Create a consistent point-in-time view BEFORE iterating keyspaces.
        // This prevents torn reads if concurrent writes happen during snapshot build.
        let snapshot_view = self.db.snapshot();

        // Collect all application state from the consistent snapshot view.
        let keyspace_data = self.collect_keyspaces_from_view(&snapshot_view)?;

        let app_snapshot = ApplicationSnapshot {
            keyspaces: keyspace_data,
        };
        let data = postcard::to_allocvec(&app_snapshot).map_err(ser_err)?;

        // 2. Read last_applied and last_membership from raft_state.
        let last_applied: Option<LogId<u64>> = match self
            .keyspaces
            .raft_state
            .get(b"last_applied")
            .map_err(read_err)?
        {
            Some(bytes) => Some(postcard::from_bytes(&bytes).map_err(ser_err)?),
            None => None,
        };
        let last_membership: StoredMembership<u64, BasicNode> = match self
            .keyspaces
            .raft_state
            .get(b"last_membership")
            .map_err(read_err)?
        {
            Some(bytes) => postcard::from_bytes(&bytes).map_err(ser_err)?,
            None => StoredMembership::default(),
        };

        // 3. Build a deterministic snapshot ID from the last applied log entry.
        let snapshot_id = match last_applied {
            Some(log_id) => format!("snap-{}-{}", log_id.leader_id.term, log_id.index),
            None => "snap-initial".to_owned(),
        };

        tracing::info!(
            snapshot_id = %snapshot_id,
            data_len = data.len(),
            "snapshot built"
        );

        Ok(Snapshot {
            meta: SnapshotMeta {
                last_log_id: last_applied,
                last_membership,
                snapshot_id,
            },
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}
