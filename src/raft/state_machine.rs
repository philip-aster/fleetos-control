use std::io::Cursor;
use std::sync::Arc;

use openraft::storage::RaftStateMachine;
use openraft::{
    BasicNode, Entry, EntryPayload, LogId, RaftLogId, Snapshot, SnapshotMeta, StorageError,
    StorageIOError, StoredMembership,
};
use redb::ReadableDatabase;

use super::snapshot::RedbSnapshotBuilder;
use super::{FleetosRaftConfig, FleetosResponse};
use crate::storage::tables;
use crate::storage::version::VersionedState;

pub struct RedbStateMachine {
    db: Arc<redb::Database>,
    versioned_state: VersionedState,
}

impl RedbStateMachine {
    pub fn new(db: Arc<redb::Database>, versioned_state: VersionedState) -> Self {
        Self {
            db,
            versioned_state,
        }
    }
}

impl RaftStateMachine<FleetosRaftConfig> for RedbStateMachine {
    type SnapshotBuilder = RedbSnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<u64>>, StoredMembership<u64, BasicNode>), StorageError<u64>> {
        let txn = self.db.begin_read().map_err(|e| StorageError::IO {
            source: StorageIOError::read_state_machine(&e),
        })?;
        let table = txn
            .open_table(tables::RAFT_STATE_TABLE)
            .map_err(|e| StorageError::IO {
                source: StorageIOError::read_state_machine(&e),
            })?;

        let last_applied =
            match table
                .get(b"last_applied".as_slice())
                .map_err(|e| StorageError::IO {
                    source: StorageIOError::read_state_machine(&e),
                })? {
                Some(bytes) => {
                    let lid: LogId<u64> =
                        postcard::from_bytes(bytes.value()).map_err(|e| StorageError::IO {
                            source: StorageIOError::read_state_machine(&e),
                        })?;
                    Some(lid)
                }
                None => None,
            };

        let last_membership =
            match table
                .get(b"last_membership".as_slice())
                .map_err(|e| StorageError::IO {
                    source: StorageIOError::read_state_machine(&e),
                })? {
                Some(bytes) => {
                    postcard::from_bytes(bytes.value()).map_err(|e| StorageError::IO {
                        source: StorageIOError::read_state_machine(&e),
                    })?
                }
                None => StoredMembership::default(),
            };

        Ok((last_applied, last_membership))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<FleetosResponse>, StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<FleetosRaftConfig>> + Send,
        I::IntoIter: Send,
    {
        let mut responses = Vec::new();
        let txn = self.db.begin_write().map_err(|e| StorageError::IO {
            source: StorageIOError::write_state_machine(&e),
        })?;

        let mut last_log_id: Option<LogId<u64>> = None;
        let mut final_version: Option<fleetos_core::MonotonicVersion> = None;

        {
            let mut state_table =
                txn.open_table(tables::RAFT_STATE_TABLE)
                    .map_err(|e| StorageError::IO {
                        source: StorageIOError::write_state_machine(&e),
                    })?;

            for entry in entries {
                let log_id = *entry.get_log_id();
                last_log_id = Some(log_id);

                match &entry.payload {
                    EntryPayload::Blank => {}
                    EntryPayload::Normal(_cmd) => { /* TODO: Dispatch FleetosCommand */ }
                    EntryPayload::Membership(membership) => {
                        let stored = StoredMembership::new(Some(log_id), membership.clone());
                        let serialized =
                            postcard::to_allocvec(&stored).map_err(|e| StorageError::IO {
                                source: StorageIOError::write_state_machine(&e),
                            })?;
                        state_table
                            .insert(b"last_membership".as_slice(), serialized.as_slice())
                            .map_err(|e| StorageError::IO {
                                source: StorageIOError::write_state_machine(&e),
                            })?;
                    }
                }

                let new_version = self.versioned_state.allocate_version();
                final_version = Some(new_version);

                responses.push(FleetosResponse {
                    version: new_version.get(),
                });
            }

            if let Some(lid) = last_log_id {
                let serialized = postcard::to_allocvec(&lid).map_err(|e| StorageError::IO {
                    source: StorageIOError::write_state_machine(&e),
                })?;
                state_table
                    .insert(b"last_applied".as_slice(), serialized.as_slice())
                    .map_err(|e| StorageError::IO {
                        source: StorageIOError::write_state_machine(&e),
                    })?;
            }
        }

        if let Some(lid) = last_log_id {
            self.versioned_state
                .persist_version(lid.index, &txn)
                .map_err(|e| StorageError::IO {
                    source: StorageIOError::write_state_machine(&e),
                })?;
        }

        txn.commit().map_err(|e| StorageError::IO {
            source: StorageIOError::write_state_machine(&e),
        })?;

        if let Some(v) = final_version {
            self.versioned_state
                .notify_version(v, crate::storage::version::ChangeKind::SagUpdate);
        }

        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        RedbSnapshotBuilder::new(self.db.clone())
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<u64>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<u64>> {
        let data = snapshot.into_inner();
        let serialized_meta = postcard::to_allocvec(meta).map_err(|e| StorageError::IO {
            source: StorageIOError::write_snapshot(None, &e),
        })?;

        let txn = self.db.begin_write().map_err(|e| StorageError::IO {
            source: StorageIOError::write_snapshot(None, &e),
        })?;
        {
            let mut snap_table =
                txn.open_table(tables::RAFT_SNAPSHOT_TABLE)
                    .map_err(|e| StorageError::IO {
                        source: StorageIOError::write_snapshot(None, &e),
                    })?;
            snap_table
                .insert(0u64, data.as_slice())
                .map_err(|e| StorageError::IO {
                    source: StorageIOError::write_snapshot(None, &e),
                })?;

            let mut state_table =
                txn.open_table(tables::RAFT_STATE_TABLE)
                    .map_err(|e| StorageError::IO {
                        source: StorageIOError::write_snapshot(None, &e),
                    })?;
            state_table
                .insert(b"snapshot_meta".as_slice(), serialized_meta.as_slice())
                .map_err(|e| StorageError::IO {
                    source: StorageIOError::write_snapshot(None, &e),
                })?;
        }
        txn.commit().map_err(|e| StorageError::IO {
            source: StorageIOError::write_snapshot(None, &e),
        })?;
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<FleetosRaftConfig>>, StorageError<u64>> {
        let txn = self.db.begin_read().map_err(|e| StorageError::IO {
            source: StorageIOError::read_snapshot(None, &e),
        })?;
        let state_table =
            txn.open_table(tables::RAFT_STATE_TABLE)
                .map_err(|e| StorageError::IO {
                    source: StorageIOError::read_snapshot(None, &e),
                })?;

        let meta: SnapshotMeta<u64, BasicNode> = match state_table
            .get(b"snapshot_meta".as_slice())
            .map_err(|e| StorageError::IO {
                source: StorageIOError::read_snapshot(None, &e),
            })? {
            Some(bytes) => postcard::from_bytes(bytes.value()).map_err(|e| StorageError::IO {
                source: StorageIOError::read_snapshot(None, &e),
            })?,
            None => return Ok(None),
        };

        let snap_table =
            txn.open_table(tables::RAFT_SNAPSHOT_TABLE)
                .map_err(|e| StorageError::IO {
                    source: StorageIOError::read_snapshot(None, &e),
                })?;
        let data = match snap_table.get(0u64).map_err(|e| StorageError::IO {
            source: StorageIOError::read_snapshot(None, &e),
        })? {
            Some(bytes) => bytes.value().to_vec(),
            None => return Ok(None),
        };

        Ok(Some(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        }))
    }
}
