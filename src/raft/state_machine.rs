//! `RaftStateMachine` implementation backed by `fjall`.

use std::io::Cursor;
use std::sync::Arc;

use fjall::{Database, Keyspace};
use openraft::storage::RaftStateMachine;
use openraft::{
    BasicNode, Entry, EntryPayload, LogId, RaftLogId, Snapshot, SnapshotMeta, StorageError,
    StorageIOError, StoredMembership,
};

use super::snapshot::FjallSnapshotBuilder;
use super::{FleetosRaftConfig, FleetosResponse};
use crate::storage::version::VersionedState;

pub struct FjallStateMachine {
    db: Arc<Database>,
    raft_state: Keyspace,
    raft_snapshot: Keyspace,
    versioned_state: VersionedState,
}

impl FjallStateMachine {
    pub fn new(
        db: Arc<Database>,
        raft_state: Keyspace,
        raft_snapshot: Keyspace,
        versioned_state: VersionedState,
    ) -> Self {
        Self {
            db,
            raft_state,
            raft_snapshot,
            versioned_state,
        }
    }
}

impl RaftStateMachine<FleetosRaftConfig> for FjallStateMachine {
    type SnapshotBuilder = FjallSnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<u64>>, StoredMembership<u64, BasicNode>), StorageError<u64>> {
        let last_applied =
            match self
                .raft_state
                .get(b"last_applied")
                .map_err(|e| StorageError::IO {
                    source: StorageIOError::read_state_machine(&e),
                })? {
                Some(bytes) => {
                    let lid: LogId<u64> =
                        postcard::from_bytes(&bytes).map_err(|e| StorageError::IO {
                            source: StorageIOError::read_state_machine(&e),
                        })?;
                    Some(lid)
                }
                None => None,
            };

        let last_membership =
            match self
                .raft_state
                .get(b"last_membership")
                .map_err(|e| StorageError::IO {
                    source: StorageIOError::read_state_machine(&e),
                })? {
                Some(bytes) => postcard::from_bytes(&bytes).map_err(|e| StorageError::IO {
                    source: StorageIOError::read_state_machine(&e),
                })?,
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
        let mut batch = self.db.batch();

        let mut last_log_id: Option<LogId<u64>> = None;
        let mut final_version: Option<fleetos_core::MonotonicVersion> = None;

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
                    batch.insert(&self.raft_state, b"last_membership", serialized.as_slice());
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
            batch.insert(&self.raft_state, b"last_applied", serialized.as_slice());

            self.versioned_state
                .persist_version(lid.index, &mut batch)
                .map_err(|e| StorageError::IO {
                    source: StorageIOError::write_state_machine(&e),
                })?;
        }

        batch.commit().map_err(|e| StorageError::IO {
            source: StorageIOError::write_state_machine(&e),
        })?;

        if let Some(v) = final_version {
            self.versioned_state
                .notify_version(v, crate::storage::version::ChangeKind::SagUpdate);
        }

        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        FjallSnapshotBuilder::new(self.raft_snapshot.clone())
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

        let mut batch = self.db.batch();
        batch.insert(&self.raft_snapshot, 0u64.to_be_bytes(), data.as_slice());
        batch.insert(
            &self.raft_state,
            b"snapshot_meta",
            serialized_meta.as_slice(),
        );

        batch.commit().map_err(|e| StorageError::IO {
            source: StorageIOError::write_snapshot(None, &e),
        })?;
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<FleetosRaftConfig>>, StorageError<u64>> {
        let meta: SnapshotMeta<u64, BasicNode> = match self
            .raft_state
            .get(b"snapshot_meta")
            .map_err(|e| StorageError::IO {
                source: StorageIOError::read_snapshot(None, &e),
            })? {
            Some(bytes) => postcard::from_bytes(&bytes).map_err(|e| StorageError::IO {
                source: StorageIOError::read_snapshot(None, &e),
            })?,
            None => return Ok(None),
        };

        let data =
            match self
                .raft_snapshot
                .get(0u64.to_be_bytes())
                .map_err(|e| StorageError::IO {
                    source: StorageIOError::read_snapshot(None, &e),
                })? {
                Some(bytes) => bytes.to_vec(),
                None => return Ok(None),
            };

        Ok(Some(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        }))
    }
}
