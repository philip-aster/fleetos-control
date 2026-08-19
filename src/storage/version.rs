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

    pub fn current_version(&self) -> MonotonicVersion {
        MonotonicVersion::new(self.version.load(Ordering::Acquire))
    }

    /// Allocate a new version number. Call this BEFORE the transaction commits.
    /// Returns the new version. Does NOT broadcast yet.
    pub fn allocate_version(&self) -> MonotonicVersion {
        let new_val = self.version.fetch_add(1, Ordering::AcqRel) + 1;
        MonotonicVersion::new(new_val)
    }

    /// Broadcast a version update. Call this ONLY AFTER the transaction has committed.
    pub fn notify_version(&self, version: MonotonicVersion, change_kind: ChangeKind) {
        let _ = self.broadcast.send(VersionUpdate {
            version,
            change_kind,
        });
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<VersionUpdate> {
        self.broadcast.subscribe()
    }

    pub fn persist_version(
        &self,
        version: u64,
        txn: &redb::WriteTransaction,
    ) -> Result<(), StorageError> {
        let mut table = txn
            .open_table(crate::storage::tables::VERSION_TABLE)
            .map_err(StorageError::Table)?;
        table
            .insert("current", version.to_le_bytes().as_slice())
            .map_err(StorageError::Storage)?;
        Ok(())
    }

    fn load_persisted_version(db: &redb::Database) -> Result<u64, StorageError> {
        let txn = db.begin_read().map_err(StorageError::Transaction)?;
        let table = txn
            .open_table(crate::storage::tables::VERSION_TABLE)
            .map_err(StorageError::Table)?;

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
