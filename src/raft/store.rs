use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::Arc;

use openraft::storage::{Adaptor, RaftStorage};
use openraft::{
    AnyError, Entry, EntryPayload, LogId, LogState, OptionalSend, RaftLogReader, Snapshot,
    SnapshotMeta, StorageError, StorageIOError, StoredMembership, Vote,
};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use tokio::sync::RwLock;

use crate::raft::types::{ClientRequest, ClientResponse, NodeId, TypeConfig};

// Shared Redb Table Definitions
const RAFT_LOG_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("raft_log");
const STATE_MACHINE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("state_machine");
const HARD_STATE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("hard_state");

pub type LogStore = Adaptor<TypeConfig, RedbStore>;
pub type StateMachineStore = Adaptor<TypeConfig, RedbStore>;

#[derive(Clone)]
pub struct RedbStore {
    db: Arc<Database>,
    snapshot_idx: Arc<RwLock<u64>>,
}

impl RedbStore {
    pub fn new(db: Arc<Database>) -> Result<(LogStore, StateMachineStore), AnyError> {
        let write_tx = db.begin_write().map_err(|e| openraft::AnyError::new(&e))?;
        {
            let _ = write_tx
                .open_table(RAFT_LOG_TABLE)
                .map_err(|e| openraft::AnyError::new(&e))?;
            let _ = write_tx
                .open_table(STATE_MACHINE_TABLE)
                .map_err(|e| openraft::AnyError::new(&e))?;
            let _ = write_tx
                .open_table(HARD_STATE_TABLE)
                .map_err(|e| openraft::AnyError::new(&e))?;
        }
        write_tx.commit().map_err(|e| openraft::AnyError::new(&e))?;

        let store = Self {
            db,
            snapshot_idx: Arc::new(RwLock::new(0)),
        };

        let (log_store, state_machine) = Adaptor::new(store);
        Ok((log_store, state_machine))
    }
}

impl RaftLogReader<TypeConfig> for RedbStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>> {
        let read_tx = self
            .db
            .begin_read()
            .map_err(|e| StorageIOError::read_logs(&e))?;
        let table = read_tx
            .open_table(RAFT_LOG_TABLE)
            .map_err(|e| StorageIOError::read_logs(&e))?;

        let mut entries = Vec::new();
        for res in table
            .range(range)
            .map_err(|e| StorageIOError::read_logs(&e))?
        {
            let (_, val) = res.map_err(|e| StorageIOError::read_logs(&e))?;
            let entry: Entry<TypeConfig> =
                postcard::from_bytes(val.value()).map_err(|e| StorageIOError::read_logs(&e))?;
            entries.push(entry);
        }

        Ok(entries)
    }
}

impl RaftStorage<TypeConfig> for RedbStore {
    type LogReader = Self;
    type SnapshotBuilder = Self;

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        let bytes = postcard::to_allocvec(vote).map_err(|e| StorageIOError::write_vote(&e))?;
        let write_tx = self
            .db
            .begin_write()
            .map_err(|e| StorageIOError::write_vote(&e))?;
        {
            let mut table = write_tx
                .open_table(HARD_STATE_TABLE)
                .map_err(|e| StorageIOError::write_vote(&e))?;
            table
                .insert("vote", bytes.as_slice())
                .map_err(|e| StorageIOError::write_vote(&e))?;
        }
        write_tx
            .commit()
            .map_err(|e| StorageIOError::write_vote(&e))?;
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        let read_tx = self
            .db
            .begin_read()
            .map_err(|e| StorageIOError::read_vote(&e))?;
        let table = read_tx
            .open_table(HARD_STATE_TABLE)
            .map_err(|e| StorageIOError::read_vote(&e))?;
        if let Some(val) = table
            .get("vote")
            .map_err(|e| StorageIOError::read_vote(&e))?
        {
            let vote: Vote<NodeId> =
                postcard::from_bytes(val.value()).map_err(|e| StorageIOError::read_vote(&e))?;
            return Ok(Some(vote));
        }
        Ok(None)
    }

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<NodeId>> {
        let read_tx = self
            .db
            .begin_read()
            .map_err(|e| StorageIOError::read_logs(&e))?;
        let table = read_tx
            .open_table(RAFT_LOG_TABLE)
            .map_err(|e| StorageIOError::read_logs(&e))?;

        let last_iter = table
            .iter()
            .map_err(|e| StorageIOError::read_logs(&e))?
            .last();
        let last_log_id = match last_iter {
            Some(res) => {
                let (_, val) = res.map_err(|e| StorageIOError::read_logs(&e))?;
                let entry: Entry<TypeConfig> =
                    postcard::from_bytes(val.value()).map_err(|e| StorageIOError::read_logs(&e))?;
                Some(entry.log_id)
            }
            None => None,
        };

        let last_purged_log_id = {
            let hs_table = read_tx
                .open_table(HARD_STATE_TABLE)
                .map_err(|e| StorageIOError::read_logs(&e))?;
            if let Some(val) = hs_table
                .get("last_purged_log_id")
                .map_err(|e| StorageIOError::read_logs(&e))?
            {
                postcard::from_bytes(val.value()).map_err(|e| StorageIOError::read_logs(&e))?
            } else {
                None
            }
        };

        Ok(LogState {
            last_purged_log_id,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn append_to_log<I>(&mut self, entries: I) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
    {
        let write_tx = self
            .db
            .begin_write()
            .map_err(|e| StorageIOError::write_logs(&e))?;
        {
            let mut table = write_tx
                .open_table(RAFT_LOG_TABLE)
                .map_err(|e| StorageIOError::write_logs(&e))?;

            for entry in entries {
                let bytes =
                    postcard::to_allocvec(&entry).map_err(|e| StorageIOError::write_logs(&e))?;
                table
                    .insert(entry.log_id.index, bytes.as_slice())
                    .map_err(|e| StorageIOError::write_logs(&e))?;
            }
        }
        write_tx
            .commit()
            .map_err(|e| StorageIOError::write_logs(&e))?;
        Ok(())
    }

    async fn delete_conflict_logs_since(
        &mut self,
        log_id: LogId<NodeId>,
    ) -> Result<(), StorageError<NodeId>> {
        let write_tx = self
            .db
            .begin_write()
            .map_err(|e| StorageIOError::write_logs(&e))?;
        {
            let mut table = write_tx
                .open_table(RAFT_LOG_TABLE)
                .map_err(|e| StorageIOError::write_logs(&e))?;
            let keys_to_del: Vec<u64> = table
                .range(log_id.index..)
                .map_err(|e| StorageIOError::write_logs(&e))?
                .filter_map(|res| res.ok().map(|(k, _)| k.value()))
                .collect();

            for k in keys_to_del {
                table
                    .remove(k)
                    .map_err(|e| StorageIOError::write_logs(&e))?;
            }
        }
        write_tx
            .commit()
            .map_err(|e| StorageIOError::write_logs(&e))?;
        Ok(())
    }

    async fn purge_logs_upto(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let write_tx = self
            .db
            .begin_write()
            .map_err(|e| StorageIOError::write_logs(&e))?;
        {
            let mut table = write_tx
                .open_table(RAFT_LOG_TABLE)
                .map_err(|e| StorageIOError::write_logs(&e))?;
            let keys_to_del: Vec<u64> = table
                .range(..=log_id.index)
                .map_err(|e| StorageIOError::write_logs(&e))?
                .filter_map(|res| res.ok().map(|(k, _)| k.value()))
                .collect();

            for k in keys_to_del {
                table
                    .remove(k)
                    .map_err(|e| StorageIOError::write_logs(&e))?;
            }

            let mut hs_table = write_tx
                .open_table(HARD_STATE_TABLE)
                .map_err(|e| StorageIOError::write_logs(&e))?;
            let bytes =
                postcard::to_allocvec(&Some(log_id)).map_err(|e| StorageIOError::write_logs(&e))?;
            hs_table
                .insert("last_purged_log_id", bytes.as_slice())
                .map_err(|e| StorageIOError::write_logs(&e))?;
        }
        write_tx
            .commit()
            .map_err(|e| StorageIOError::write_logs(&e))?;
        Ok(())
    }

    async fn last_applied_state(
        &mut self,
    ) -> Result<
        (
            Option<LogId<NodeId>>,
            StoredMembership<NodeId, openraft::BasicNode>,
        ),
        StorageError<NodeId>,
    > {
        let read_tx = self
            .db
            .begin_read()
            .map_err(|e| StorageIOError::read_state_machine(&e))?;
        let table = read_tx
            .open_table(HARD_STATE_TABLE)
            .map_err(|e| StorageIOError::read_state_machine(&e))?;

        let last_applied_log = if let Some(val) = table
            .get("last_applied_log")
            .map_err(|e| StorageIOError::read_state_machine(&e))?
        {
            postcard::from_bytes(val.value()).map_err(|e| StorageIOError::read_state_machine(&e))?
        } else {
            None
        };

        let last_membership = if let Some(val) = table
            .get("last_membership")
            .map_err(|e| StorageIOError::read_state_machine(&e))?
        {
            postcard::from_bytes(val.value()).map_err(|e| StorageIOError::read_state_machine(&e))?
        } else {
            StoredMembership::default()
        };

        Ok((last_applied_log, last_membership))
    }

    async fn apply_to_state_machine(
        &mut self,
        entries: &[Entry<TypeConfig>],
    ) -> Result<Vec<ClientResponse>, StorageError<NodeId>> {
        let mut responses = Vec::new();
        let write_tx = self
            .db
            .begin_write()
            .map_err(|e| StorageIOError::write_state_machine(&e))?;

        {
            let mut sm_table = write_tx
                .open_table(STATE_MACHINE_TABLE)
                .map_err(|e| StorageIOError::write_state_machine(&e))?;
            let mut hs_table = write_tx
                .open_table(HARD_STATE_TABLE)
                .map_err(|e| StorageIOError::write_state_machine(&e))?;

            for entry in entries {
                let log_id = entry.log_id;

                match &entry.payload {
                    EntryPayload::Blank => {
                        responses.push(ClientResponse::Success {
                            message: "blank".into(),
                        });
                    }
                    EntryPayload::Normal(req) => match req {
                        ClientRequest::PutPod { id, data } => {
                            let key = format!("/pods/{}", id);
                            sm_table
                                .insert(key.as_str(), data.as_slice())
                                .map_err(|e| StorageIOError::write_state_machine(&e))?;
                            responses.push(ClientResponse::Success {
                                message: format!("pod {} written", id),
                            });
                        }
                        ClientRequest::DeletePod { id } => {
                            let key = format!("/pods/{}", id);
                            sm_table
                                .remove(key.as_str())
                                .map_err(|e| StorageIOError::write_state_machine(&e))?;
                            responses.push(ClientResponse::Success {
                                message: format!("pod {} deleted", id),
                            });
                        }
                        ClientRequest::PutPolicy { key, data } => {
                            let k = format!("/policies/{}", key);
                            sm_table
                                .insert(k.as_str(), data.as_slice())
                                .map_err(|e| StorageIOError::write_state_machine(&e))?;
                            responses.push(ClientResponse::Success {
                                message: format!("policy {} written", key),
                            });
                        }
                        ClientRequest::DeletePolicy { key } => {
                            let k = format!("/policies/{}", key);
                            sm_table
                                .remove(k.as_str())
                                .map_err(|e| StorageIOError::write_state_machine(&e))?;
                            responses.push(ClientResponse::Success {
                                message: format!("policy {} deleted", key),
                            });
                        }
                    },
                    EntryPayload::Membership(mem) => {
                        let membership = StoredMembership::new(Some(log_id), mem.clone());
                        let bytes = postcard::to_allocvec(&membership)
                            .map_err(|e| StorageIOError::write_state_machine(&e))?;
                        hs_table
                            .insert("last_membership", bytes.as_slice())
                            .map_err(|e| StorageIOError::write_state_machine(&e))?;
                        responses.push(ClientResponse::Success {
                            message: "membership updated".into(),
                        });
                    }
                }

                let last_log_bytes = postcard::to_allocvec(&Some(log_id))
                    .map_err(|e| StorageIOError::write_state_machine(&e))?;
                hs_table
                    .insert("last_applied_log", last_log_bytes.as_slice())
                    .map_err(|e| StorageIOError::write_state_machine(&e))?;
            }
        }

        write_tx
            .commit()
            .map_err(|e| StorageIOError::write_state_machine(&e))?;
        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        _meta: &SnapshotMeta<NodeId, openraft::BasicNode>,
        _snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeId>> {
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<NodeId>> {
        let idx = *self.snapshot_idx.read().await;
        if idx == 0 {
            return Ok(None);
        }

        let meta = SnapshotMeta {
            last_log_id: None,
            last_membership: StoredMembership::default(),
            snapshot_id: format!("snap-{}", idx),
        };

        Ok(Some(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(Vec::new())),
        }))
    }
}

impl openraft::storage::RaftSnapshotBuilder<TypeConfig> for RedbStore {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<NodeId>> {
        let mut idx = self.snapshot_idx.write().await;
        *idx += 1;

        let meta = SnapshotMeta {
            last_log_id: None,
            last_membership: StoredMembership::default(),
            snapshot_id: format!("snap-{}", idx),
        };

        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(Vec::new())),
        })
    }
}
