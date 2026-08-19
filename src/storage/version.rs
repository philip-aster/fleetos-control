//! `MonotonicVersion` management.
//!
//! Every mutation applied to the state machine increments a `MonotonicVersion`
//! (from `fleetos-core`). This version is attached to SAG updates so
//! downstream components can detect stale local caches.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fleetos_core::MonotonicVersion;
use redb::ReadableDatabase;

use super::StorageError;

/// Shared, version-tracked application state.
#[derive(Clone)]
pub struct VersionedState {
    #[allow(dead_code)]
    db: Arc<redb::Database>,
    version: Arc<AtomicU64>,
    broadcast: Arc<tokio::sync::broadcast::Sender<VersionUpdate>>,
}

/// Notification sent to watchers when a new version is committed.
#[derive(Debug, Clone)]
pub struct VersionUpdate {
    pub version: MonotonicVersion,
    pub change_kind: ChangeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeKind {
    SagUpdate,
    TrustBundleRotation,
    ClusterMembership,
    SecretRotation,
    RevokedDelegations,
    SchedulingUpdate,
    DummyIpUpdate,
}

impl VersionedState {
    pub fn new(db: Arc<redb::Database>) -> Self {
        let initial = Self::load_persisted_version(&db).unwrap_or(0);
        let (tx, _) = tokio::sync::broadcast::channel(1024);

        Self {
            db,
            version: Arc::new(AtomicU64::new(initial)),
            broadcast: Arc::new(tx),
        }
    }

    /// Current version (read-only, for attaching to outgoing messages).
    pub fn current_version(&self) -> MonotonicVersion {
        MonotonicVersion::new(self.version.load(Ordering::Acquire))
    }

    /// Increment the version. Called ONLY from the Raft state machine apply path.
    pub fn increment(&self, change_kind: ChangeKind) -> MonotonicVersion {
        let new_val = self.version.fetch_add(1, Ordering::AcqRel) + 1;
        let new_version = MonotonicVersion::new(new_val);

        let _ = self.broadcast.send(VersionUpdate {
            version: new_version,
            change_kind,
        });

        new_version
    }

    /// Subscribe to version updates (for watch streams).
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<VersionUpdate> {
        self.broadcast.subscribe()
    }

    /// Persist the current version to redb (called within the Raft apply transaction).
    pub fn persist_version(
        &self,
        version: u64,
        txn: &redb::WriteTransaction,
    ) -> Result<(), StorageError> {
        // open_table returns Result<_, TableError>
        let mut table = txn
            .open_table(crate::storage::tables::VERSION_TABLE)
            .map_err(StorageError::Table)?;
        // insert returns Result<_, StorageError> (NOT TableError)
        table
            .insert("current", version.to_le_bytes().as_slice())
            .map_err(StorageError::Storage)?;
        Ok(())
    }

    fn load_persisted_version(db: &redb::Database) -> Result<u64, StorageError> {
        let txn = db.begin_read().map_err(StorageError::Transaction)?;
        // open_table returns Result<_, TableError>
        let table = txn
            .open_table(crate::storage::tables::VERSION_TABLE)
            .map_err(StorageError::Table)?;

        // get returns Result<_, StorageError> (NOT TableError)
        match table.get("current").map_err(StorageError::Storage)? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes
                    .value()
                    .try_into()
                    .map_err(|_| StorageError::NotFound("corrupted version field".to_owned()))?;
                Ok(u64::from_le_bytes(arr))
            }
            None => Ok(0),
        }
    }
}
