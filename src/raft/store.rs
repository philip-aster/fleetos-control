use std::ops::RangeBounds;
use std::sync::Arc;

use fjall::{Database, Keyspace};
use openraft::storage::{LogFlushed, RaftLogStorage};
use openraft::{
    Entry, LogId, LogState, RaftLogId, RaftLogReader, StorageError, StorageIOError, Vote,
};

use super::FleetosRaftConfig;
use super::entry::{deserialize_entry, serialize_entry};

pub struct FjallLogStorage {
    db: Arc<Database>,
    raft_log: Keyspace,
    raft_log_meta: Keyspace,
}

impl FjallLogStorage {
    pub fn new(db: Arc<Database>, raft_log: Keyspace, raft_log_meta: Keyspace) -> Self {
        Self {
            db,
            raft_log,
            raft_log_meta,
        }
    }
}

#[derive(Clone)]
pub struct FjallLogReader {
    raft_log: Keyspace,
}

impl RaftLogReader<FleetosRaftConfig> for FjallLogReader {
    async fn try_get_log_entries<R: RangeBounds<u64> + Send + std::fmt::Debug + Clone>(
        &mut self,
        range: R,
    ) -> Result<Vec<Entry<FleetosRaftConfig>>, StorageError<u64>> {
        // Convert the u64 index range to a big-endian byte range.
        // BE encoding preserves lexicographic order, so this byte range is
        // exactly the requested index range.
        let start = match range.start_bound() {
            std::ops::Bound::Included(n) => std::ops::Bound::Included(n.to_be_bytes().to_vec()),
            std::ops::Bound::Excluded(n) => std::ops::Bound::Excluded(n.to_be_bytes().to_vec()),
            std::ops::Bound::Unbounded => std::ops::Bound::Unbounded,
        };
        let end = match range.end_bound() {
            std::ops::Bound::Included(n) => std::ops::Bound::Included(n.to_be_bytes().to_vec()),
            std::ops::Bound::Excluded(n) => std::ops::Bound::Excluded(n.to_be_bytes().to_vec()),
            std::ops::Bound::Unbounded => std::ops::Bound::Unbounded,
        };

        let mut entries = Vec::new();
        for guard in self.raft_log.range((start, end)) {
            let value = guard.value().map_err(|e| StorageError::IO {
                source: StorageIOError::read_logs(&e),
            })?;
            if let Ok(entry) = deserialize_entry(value.as_ref()) {
                entries.push(entry);
            }
        }
        Ok(entries)
    }
}

impl RaftLogReader<FleetosRaftConfig> for FjallLogStorage {
    async fn try_get_log_entries<R: RangeBounds<u64> + Send + std::fmt::Debug + Clone>(
        &mut self,
        range: R,
    ) -> Result<Vec<Entry<FleetosRaftConfig>>, StorageError<u64>> {
        let mut reader = FjallLogReader {
            raft_log: self.raft_log.clone(),
        };
        reader.try_get_log_entries(range).await
    }
}

impl RaftLogStorage<FleetosRaftConfig> for FjallLogStorage {
    type LogReader = FjallLogReader;

    async fn get_log_state(&mut self) -> Result<LogState<FleetosRaftConfig>, StorageError<u64>> {
        // last_key_value() returns Option<Guard>
        let last_log_id = self.raft_log.last_key_value().and_then(|guard| {
            guard.value().ok().and_then(|slice| {
                deserialize_entry(slice.as_ref())
                    .ok()
                    .map(|e| *e.get_log_id())
            })
        });

        let last_purged =
            match self
                .raft_log_meta
                .get("last_purged")
                .map_err(|e| StorageError::IO {
                    source: StorageIOError::read_logs(&e),
                })? {
                Some(bytes) => {
                    let lid: LogId<u64> =
                        postcard::from_bytes(&bytes).map_err(|e| StorageError::IO {
                            source: StorageIOError::read_logs(&e),
                        })?;
                    Some(lid)
                }
                None => None,
            };

        Ok(LogState {
            last_purged_log_id: last_purged,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        FjallLogReader {
            raft_log: self.raft_log.clone(),
        }
    }

    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), StorageError<u64>> {
        let serialized = postcard::to_allocvec(vote).map_err(|e| StorageError::IO {
            source: StorageIOError::write_vote(&e),
        })?;
        let mut batch = self.db.batch();
        batch.insert(&self.raft_log_meta, "vote", serialized.as_slice());
        batch.commit().map_err(|e| StorageError::IO {
            source: StorageIOError::write_vote(&e),
        })?;
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, StorageError<u64>> {
        match self
            .raft_log_meta
            .get("vote")
            .map_err(|e| StorageError::IO {
                source: StorageIOError::read_vote(&e),
            })? {
            Some(bytes) => {
                let vote: Vote<u64> =
                    postcard::from_bytes(&bytes).map_err(|e| StorageError::IO {
                        source: StorageIOError::read_vote(&e),
                    })?;
                Ok(Some(vote))
            }
            None => Ok(None),
        }
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<FleetosRaftConfig>,
    ) -> Result<(), StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<FleetosRaftConfig>> + Send,
        I::IntoIter: Send,
    {
        let mut batch = self.db.batch();

        for entry in entries {
            let index = entry.get_log_id().index;
            let serialized = serialize_entry(&entry).map_err(|e| StorageError::IO {
                source: StorageIOError::write_log_entry(*entry.get_log_id(), &e),
            })?;
            batch.insert(&self.raft_log, index.to_be_bytes(), serialized.as_slice());
        }

        batch.commit().map_err(|e| StorageError::IO {
            source: StorageIOError::write_logs(&e),
        })?;
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        let mut batch = self.db.batch();
        let mut keys_to_remove: Vec<Vec<u8>> = Vec::new();

        // Remove the entire suffix: every entry with index >= log_id.index.
        for guard in self.raft_log.range(log_id.index.to_be_bytes()..) {
            let key_slice = guard.key().map_err(|e| StorageError::IO {
                source: StorageIOError::write_logs(&e),
            })?;
            keys_to_remove.push(key_slice.as_ref().to_vec());
        }
        for key in keys_to_remove {
            batch.remove(&self.raft_log, key.as_slice());
        }

        batch.commit().map_err(|e| StorageError::IO {
            source: StorageIOError::write_logs(&e),
        })?;
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        let mut batch = self.db.batch();
        let mut keys_to_remove: Vec<Vec<u8>> = Vec::new();

        // Remove the prefix covered by the snapshot: every entry with index <= log_id.index.
        for guard in self.raft_log.range(..=log_id.index.to_be_bytes()) {
            let key_slice = guard.key().map_err(|e| StorageError::IO {
                source: StorageIOError::write_logs(&e),
            })?;
            keys_to_remove.push(key_slice.as_ref().to_vec());
        }
        for key in keys_to_remove {
            batch.remove(&self.raft_log, key.as_slice());
        }

        // Record the purge watermark in the same atomic batch.
        let serialized = postcard::to_allocvec(&log_id).map_err(|e| StorageError::IO {
            source: StorageIOError::write_logs(&e),
        })?;
        batch.insert(&self.raft_log_meta, "last_purged", serialized.as_slice());

        batch.commit().map_err(|e| StorageError::IO {
            source: StorageIOError::write_logs(&e),
        })?;
        Ok(())
    }
}
