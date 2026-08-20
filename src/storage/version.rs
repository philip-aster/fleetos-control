//! `MonotonicVersion` management.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fjall::Keyspace;
use fleetos_core::MonotonicVersion;

use super::StorageError;

/// Shared, version-tracked application state.
#[derive(Clone)]
pub struct VersionedState {
    version_keyspace: Keyspace,
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
    pub fn new(version_keyspace: Keyspace) -> Self {
        let initial = Self::load_persisted_version(&version_keyspace).unwrap_or(0);
        let (tx, _) = tokio::sync::broadcast::channel(1024);

        Self {
            version_keyspace,
            version: Arc::new(AtomicU64::new(initial)),
            broadcast: Arc::new(tx),
        }
    }

    pub fn current_version(&self) -> MonotonicVersion {
        MonotonicVersion::new(self.version.load(Ordering::Acquire))
    }

    pub fn allocate_version(&self) -> MonotonicVersion {
        let new_val = self.version.fetch_add(1, Ordering::AcqRel) + 1;
        MonotonicVersion::new(new_val)
    }

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
        batch: &mut fjall::OwnedWriteBatch,
    ) -> Result<(), StorageError> {
        batch.insert(
            &self.version_keyspace,
            "current",
            version.to_le_bytes().as_slice(),
        );
        Ok(())
    }

    fn load_persisted_version(keyspace: &Keyspace) -> Result<u64, StorageError> {
        match keyspace.get("current").map_err(StorageError::Storage)? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| StorageError::NotFound("corrupted version field".to_owned()))?;
                Ok(u64::from_le_bytes(arr))
            }
            None => Ok(0),
        }
    }
}
