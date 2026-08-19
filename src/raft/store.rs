use std::ops::RangeBounds;
use std::sync::Arc;

use openraft::storage::{LogFlushed, RaftLogStorage};
use openraft::{
    Entry, LogId, LogState, RaftLogId, RaftLogReader, StorageError, StorageIOError, Vote,
};
use redb::{ReadableDatabase, ReadableTable};

use super::FleetosRaftConfig;
use super::entry::{deserialize_entry, serialize_entry};
use crate::storage::tables;

pub struct RedbLogStorage {
    db: Arc<redb::Database>,
}

impl RedbLogStorage {
    pub fn new(db: Arc<redb::Database>) -> Self {
        Self { db }
    }
}

#[derive(Clone)]
pub struct RedbLogReader {
    db: Arc<redb::Database>,
}

// --- RaftLogReader impl for RedbLogReader (used by replication tasks) ---
impl RaftLogReader<FleetosRaftConfig> for RedbLogReader {
    async fn try_get_log_entries<R: RangeBounds<u64> + Send>(
        &mut self,
        range: R,
    ) -> Result<Vec<Entry<FleetosRaftConfig>>, StorageError<u64>> {
        let txn = self.db.begin_read().map_err(|e| StorageError::IO {
            source: StorageIOError::read_logs(&e),
        })?;
        let table = txn
            .open_table(tables::RAFT_LOG_TABLE)
            .map_err(|e| StorageError::IO {
                source: StorageIOError::read_logs(&e),
            })?;

        let mut entries = Vec::new();
        let iter = table.range(range).map_err(|e| StorageError::IO {
            source: StorageIOError::read_logs(&e),
        })?;
        for item in iter {
            let (_key, value) = item.map_err(|e| StorageError::IO {
                source: StorageIOError::read_logs(&e),
            })?;
            let entry = deserialize_entry(value.value()).map_err(|e| StorageError::IO {
                source: StorageIOError::read_logs(&e),
            })?;
            entries.push(entry);
        }
        Ok(entries)
    }
}

// --- RaftLogReader impl for RedbLogStorage (required as supertrait of RaftLogStorage) ---
impl RaftLogReader<FleetosRaftConfig> for RedbLogStorage {
    async fn try_get_log_entries<R: RangeBounds<u64> + Send>(
        &mut self,
        range: R,
    ) -> Result<Vec<Entry<FleetosRaftConfig>>, StorageError<u64>> {
        let txn = self.db.begin_read().map_err(|e| StorageError::IO {
            source: StorageIOError::read_logs(&e),
        })?;
        let table = txn
            .open_table(tables::RAFT_LOG_TABLE)
            .map_err(|e| StorageError::IO {
                source: StorageIOError::read_logs(&e),
            })?;

        let mut entries = Vec::new();
        let iter = table.range(range).map_err(|e| StorageError::IO {
            source: StorageIOError::read_logs(&e),
        })?;
        for item in iter {
            let (_key, value) = item.map_err(|e| StorageError::IO {
                source: StorageIOError::read_logs(&e),
            })?;
            let entry = deserialize_entry(value.value()).map_err(|e| StorageError::IO {
                source: StorageIOError::read_logs(&e),
            })?;
            entries.push(entry);
        }
        Ok(entries)
    }
}

impl RaftLogStorage<FleetosRaftConfig> for RedbLogStorage {
    type LogReader = RedbLogReader;

    async fn get_log_state(&mut self) -> Result<LogState<FleetosRaftConfig>, StorageError<u64>> {
        let txn = self.db.begin_read().map_err(|e| StorageError::IO {
            source: StorageIOError::read_logs(&e),
        })?;
        let table = txn
            .open_table(tables::RAFT_LOG_TABLE)
            .map_err(|e| StorageError::IO {
                source: StorageIOError::read_logs(&e),
            })?;

        let last = table.last().map_err(|e| StorageError::IO {
            source: StorageIOError::read_logs(&e),
        })?;
        let last_log_id = match last {
            Some((_key, value)) => {
                let entry = deserialize_entry(value.value()).map_err(|e| StorageError::IO {
                    source: StorageIOError::read_logs(&e),
                })?;
                Some(*entry.get_log_id())
            }
            None => None,
        };

        // RAFT_LOG_META_TABLE key type is &str — pass string literals directly
        let meta_table =
            txn.open_table(tables::RAFT_LOG_META_TABLE)
                .map_err(|e| StorageError::IO {
                    source: StorageIOError::read_logs(&e),
                })?;
        let last_purged = match meta_table
            .get("last_purged")
            .map_err(|e| StorageError::IO {
                source: StorageIOError::read_logs(&e),
            })? {
            Some(bytes) => {
                let lid: LogId<u64> =
                    postcard::from_bytes(bytes.value()).map_err(|e| StorageError::IO {
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
        RedbLogReader {
            db: self.db.clone(),
        }
    }

    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), StorageError<u64>> {
        let serialized = postcard::to_allocvec(vote).map_err(|e| StorageError::IO {
            source: StorageIOError::write_vote(&e),
        })?;
        let txn = self.db.begin_write().map_err(|e| StorageError::IO {
            source: StorageIOError::write_vote(&e),
        })?;
        {
            let mut table =
                txn.open_table(tables::RAFT_LOG_META_TABLE)
                    .map_err(|e| StorageError::IO {
                        source: StorageIOError::write_vote(&e),
                    })?;
            // Key type is &str — pass directly
            table
                .insert("vote", serialized.as_slice())
                .map_err(|e| StorageError::IO {
                    source: StorageIOError::write_vote(&e),
                })?;
        }
        txn.commit().map_err(|e| StorageError::IO {
            source: StorageIOError::write_vote(&e),
        })?;
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, StorageError<u64>> {
        let txn = self.db.begin_read().map_err(|e| StorageError::IO {
            source: StorageIOError::read_vote(&e),
        })?;
        let table = txn
            .open_table(tables::RAFT_LOG_META_TABLE)
            .map_err(|e| StorageError::IO {
                source: StorageIOError::read_vote(&e),
            })?;

        match table.get("vote").map_err(|e| StorageError::IO {
            source: StorageIOError::read_vote(&e),
        })? {
            Some(bytes) => {
                let vote: Vote<u64> =
                    postcard::from_bytes(bytes.value()).map_err(|e| StorageError::IO {
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
        let txn = self.db.begin_write().map_err(|e| StorageError::IO {
            source: StorageIOError::write_logs(&e),
        })?;
        {
            let mut table =
                txn.open_table(tables::RAFT_LOG_TABLE)
                    .map_err(|e| StorageError::IO {
                        source: StorageIOError::write_logs(&e),
                    })?;
            for entry in entries {
                let index = entry.get_log_id().index;
                let serialized = serialize_entry(&entry).map_err(|e| StorageError::IO {
                    source: StorageIOError::write_log_entry(*entry.get_log_id(), &e),
                })?;
                table
                    .insert(index, serialized.as_slice())
                    .map_err(|e| StorageError::IO {
                        source: StorageIOError::write_log_entry(*entry.get_log_id(), &e),
                    })?;
            }
        }
        txn.commit().map_err(|e| StorageError::IO {
            source: StorageIOError::write_logs(&e),
        })?;

        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        let txn = self.db.begin_write().map_err(|e| StorageError::IO {
            source: StorageIOError::write_logs(&e),
        })?;
        {
            let mut table =
                txn.open_table(tables::RAFT_LOG_TABLE)
                    .map_err(|e| StorageError::IO {
                        source: StorageIOError::write_logs(&e),
                    })?;
            let range = table.range(log_id.index..).map_err(|e| StorageError::IO {
                source: StorageIOError::write_logs(&e),
            })?;
            let keys_to_remove: Vec<u64> = range
                .filter_map(|r| r.ok().map(|(k, _)| k.value()))
                .collect();
            for key in keys_to_remove {
                table.remove(key).map_err(|e| StorageError::IO {
                    source: StorageIOError::write_logs(&e),
                })?;
            }
        }
        txn.commit().map_err(|e| StorageError::IO {
            source: StorageIOError::write_logs(&e),
        })?;
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        let txn = self.db.begin_write().map_err(|e| StorageError::IO {
            source: StorageIOError::write_logs(&e),
        })?;
        {
            let mut table =
                txn.open_table(tables::RAFT_LOG_TABLE)
                    .map_err(|e| StorageError::IO {
                        source: StorageIOError::write_logs(&e),
                    })?;
            let range = table.range(..=log_id.index).map_err(|e| StorageError::IO {
                source: StorageIOError::write_logs(&e),
            })?;
            let keys_to_remove: Vec<u64> = range
                .filter_map(|r| r.ok().map(|(k, _)| k.value()))
                .collect();
            for key in keys_to_remove {
                table.remove(key).map_err(|e| StorageError::IO {
                    source: StorageIOError::write_logs(&e),
                })?;
            }

            // Store the entire LogId as postcard-serialized bytes
            let mut meta =
                txn.open_table(tables::RAFT_LOG_META_TABLE)
                    .map_err(|e| StorageError::IO {
                        source: StorageIOError::write_logs(&e),
                    })?;
            let serialized = postcard::to_allocvec(&log_id).map_err(|e| StorageError::IO {
                source: StorageIOError::write_logs(&e),
            })?;
            // Key type is &str — pass directly
            meta.insert("last_purged", serialized.as_slice())
                .map_err(|e| StorageError::IO {
                    source: StorageIOError::write_logs(&e),
                })?;
        }
        txn.commit().map_err(|e| StorageError::IO {
            source: StorageIOError::write_logs(&e),
        })?;
        Ok(())
    }
}
