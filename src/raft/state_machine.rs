//! `RaftStateMachine` implementation backed by `fjall`.
//!
//! The state machine is the single place where replicated `FleetosCommand`s mutate
//! application keyspaces. Each entry is applied in its OWN `OwnedWriteBatch` and
//! committed before the next entry is processed, so a command may safely read
//! committed state written by earlier entries in the same `apply` call. The
//! `MonotonicVersion` is allocated and persisted in the SAME batch as the mutation
//! (atomic-apply invariant), and subscribers are notified only after a successful
//! commit, so they never observe state that isn't durable.

use std::io::Cursor;
use std::sync::Arc;

use super::snapshot::FjallSnapshotBuilder;
use super::{FleetosCommand, FleetosRaftConfig, FleetosResponse, records};
use crate::delegation::DelegationRecord;
use crate::storage::version::{ChangeKind, VersionedState};
use crate::storage::{Keyspaces, schema};
use crate::watch::broadcast::{BroadcastHub, SagUpdateEvent, ScheduleUpdateEvent, WatchEvent};
use fjall::Database;
use fleetos_core::spiffe::SpiffeId;
use openraft::storage::RaftStateMachine;
use openraft::{
    BasicNode, Entry, EntryPayload, LogId, RaftLogId, Snapshot, SnapshotMeta, StorageError,
    StorageIOError, StoredMembership,
};

pub struct FjallStateMachine {
    db: Arc<Database>,
    keyspaces: Keyspaces,
    versioned_state: VersionedState,
    broadcast_hub: Arc<BroadcastHub>,
}

impl FjallStateMachine {
    pub fn new(
        db: Arc<Database>,
        keyspaces: Keyspaces,
        versioned_state: VersionedState,
        broadcast_hub: Arc<BroadcastHub>,
    ) -> Self {
        Self {
            db,
            keyspaces,
            versioned_state,
            broadcast_hub,
        }
    }

    /// Apply one replicated command into `batch`. Returns the `ChangeKind` used to
    /// notify subscribers after commit.
    fn apply_command(
        &self,
        cmd: &FleetosCommand,
        batch: &mut fjall::OwnedWriteBatch,
    ) -> Result<ChangeKind, StorageError<u64>> {
        match cmd {
            // --- Tenant lifecycle ---
            FleetosCommand::CreateTenant { record } => {
                let value = postcard::to_allocvec(record).map_err(ser_err)?;
                batch.insert(
                    &self.keyspaces.tenants,
                    record.tenant_id.as_bytes(),
                    value.as_slice(),
                );
                Ok(ChangeKind::SchedulingUpdate)
            }
            FleetosCommand::DeleteTenant { tenant_id } => {
                batch.remove(&self.keyspaces.tenants, tenant_id.as_bytes());
                Ok(ChangeKind::SchedulingUpdate)
            }

            // --- Workloads ---
            FleetosCommand::SubmitWorkloadSpec { record } => {
                let key = format!("{}:{}", record.tenant_id, record.workload_id);
                let value = postcard::to_allocvec(record).map_err(ser_err)?;
                batch.insert(&self.keyspaces.workloads, key.as_bytes(), value.as_slice());
                Ok(ChangeKind::SchedulingUpdate)
            }
            FleetosCommand::SubmitCronWorkload { record } => {
                let key = format!("cron:{}:{}", record.tenant_id, record.cron_workload_id);
                let value = postcard::to_allocvec(record).map_err(ser_err)?;
                batch.insert(&self.keyspaces.workloads, key.as_bytes(), value.as_slice());
                Ok(ChangeKind::SchedulingUpdate)
            }

            // --- Attestation / join ---
            FleetosCommand::MintJoinToken { record } => {
                let value = postcard::to_allocvec(record).map_err(ser_err)?;
                batch.insert(
                    &self.keyspaces.join_tokens,
                    record.token.as_slice(),
                    value.as_slice(),
                );
                Ok(ChangeKind::SagUpdate)
            }
            FleetosCommand::ConsumeJoinToken { token } => {
                batch.remove(&self.keyspaces.join_tokens, token.as_slice());
                Ok(ChangeKind::SagUpdate)
            }
            FleetosCommand::SetPcrPolicy { record } => {
                let value = postcard::to_allocvec(record).map_err(ser_err)?;
                batch.insert(
                    &self.keyspaces.pcr_policies,
                    record.node_id.as_bytes(),
                    value.as_slice(),
                );
                Ok(ChangeKind::SagUpdate)
            }

            // --- Nodes ---
            FleetosCommand::RegisterNode { record } => {
                let value = postcard::to_allocvec(record).map_err(ser_err)?;
                batch.insert(
                    &self.keyspaces.nodes,
                    record.node_id.as_bytes(),
                    value.as_slice(),
                );
                Ok(ChangeKind::SchedulingUpdate)
            }
            FleetosCommand::SetNodeSchedulable {
                node_id,
                schedulable,
            } => {
                let record = match self
                    .keyspaces
                    .nodes
                    .get(node_id.as_bytes())
                    .map_err(read_err)?
                {
                    Some(bytes) => {
                        let mut r: records::NodeRecord =
                            postcard::from_bytes(&bytes).map_err(ser_err)?;
                        r.schedulable = *schedulable;
                        // Uncordoning re-activates a cordoned node, but never an evicted one.
                        if *schedulable && r.status == records::NodeStatus::Cordoned {
                            r.status = records::NodeStatus::Active;
                        }
                        r
                    }
                    None => records::NodeRecord {
                        node_id: node_id.clone(),
                        node_kind: 0,
                        status: if *schedulable {
                            records::NodeStatus::Active
                        } else {
                            records::NodeStatus::Cordoned
                        },
                        schedulable: *schedulable,
                        last_heartbeat: 0,
                        registered_at: 0,
                        // Zero capacity is fail-closed: a node with no reported capacity
                        // cannot be scheduled onto until it registers with real values.
                        capacity_cpu_millicores: 0,
                        capacity_memory_bytes: 0,
                        failure_domain: String::new(),
                    },
                };
                let value = postcard::to_allocvec(&record).map_err(ser_err)?;
                batch.insert(&self.keyspaces.nodes, node_id.as_bytes(), value.as_slice());
                Ok(ChangeKind::SchedulingUpdate)
            }
            FleetosCommand::EvictNode { node_id } => {
                let node_spiffe = parse_spiffe(node_id)?;

                // 1. Mark the node evicted (read-modify-write).
                let record = match self
                    .keyspaces
                    .nodes
                    .get(node_id.as_bytes())
                    .map_err(read_err)?
                {
                    Some(bytes) => {
                        let mut r: records::NodeRecord =
                            postcard::from_bytes(&bytes).map_err(ser_err)?;
                        r.status = records::NodeStatus::Evicted;
                        r.schedulable = false;
                        r
                    }
                    None => records::NodeRecord {
                        node_id: node_id.clone(),
                        node_kind: 0,
                        status: records::NodeStatus::Evicted,
                        schedulable: false,
                        last_heartbeat: 0,
                        registered_at: 0,
                        capacity_cpu_millicores: 0,
                        capacity_memory_bytes: 0,
                        failure_domain: String::new(),
                    },
                };
                let value = postcard::to_allocvec(&record).map_err(ser_err)?;
                batch.insert(&self.keyspaces.nodes, node_id.as_bytes(), value.as_slice());

                // 2. Revoke ALL active delegations for this node (one-to-many), in the
                //    SAME batch so eviction + revocation commit atomically.
                //    Guard::value() consumes the guard, so we read the record and
                //    reconstruct the composite key from its own fields.
                let prefix = schema::node_delegation_prefix(&node_spiffe);
                for guard in self.keyspaces.active_delegations.prefix(prefix.as_slice()) {
                    let del_value = guard.value().map_err(read_err)?;
                    if let Ok(del_record) =
                        postcard::from_bytes::<DelegationRecord>(del_value.as_ref())
                    {
                        let key = schema::composite_delegation_key(
                            &del_record.node_id,
                            &del_record.delegation_id,
                        );
                        batch.remove(&self.keyspaces.active_delegations, key.as_slice());
                        batch.insert(
                            &self.keyspaces.revoked_delegations,
                            key.as_slice(),
                            del_value.as_ref(),
                        );
                    }
                }
                Ok(ChangeKind::RevokedDelegations)
            }

            // --- Delegations ---
            FleetosCommand::IssueDelegation { record } => {
                let key = schema::composite_delegation_key(&record.node_id, &record.delegation_id);
                let value = postcard::to_allocvec(record).map_err(ser_err)?;
                batch.insert(
                    &self.keyspaces.active_delegations,
                    key.as_slice(),
                    value.as_slice(),
                );
                Ok(ChangeKind::SchedulingUpdate)
            }
            FleetosCommand::RevokeDelegation {
                node_id,
                delegation_id,
            } => {
                let node_spiffe = parse_spiffe(node_id)?;
                let key = schema::composite_delegation_key(&node_spiffe, delegation_id);
                if let Some(bytes) = self
                    .keyspaces
                    .active_delegations
                    .get(key.as_slice())
                    .map_err(read_err)?
                {
                    batch.remove(&self.keyspaces.active_delegations, key.as_slice());
                    batch.insert(
                        &self.keyspaces.revoked_delegations,
                        key.as_slice(),
                        bytes.as_ref(),
                    );
                }
                Ok(ChangeKind::RevokedDelegations)
            }

            // --- SAG policy ---
            FleetosCommand::UpsertSagRule { record } => {
                batch.insert(
                    &self.keyspaces.sag_rules,
                    record.rule_id.as_bytes(),
                    record.rule_bytes.as_slice(),
                );
                Ok(ChangeKind::SagUpdate)
            }
            FleetosCommand::DeleteSagRule { rule_id } => {
                batch.remove(&self.keyspaces.sag_rules, rule_id.as_bytes());
                Ok(ChangeKind::SagUpdate)
            }

            // --- Dummy IP ---
            FleetosCommand::AllocateTenantBlock { record } => {
                let key = format!("tenant:{}", record.tenant_id);
                let value = postcard::to_allocvec(record).map_err(ser_err)?;
                batch.insert(&self.keyspaces.dummy_ips, key.as_bytes(), value.as_slice());
                Ok(ChangeKind::DummyIpUpdate)
            }
            FleetosCommand::AllocateServiceAddress { block, address } => {
                // Updated tenant block (next_offset already incremented by the leader).
                let tenant_key = format!("tenant:{}", block.tenant_id);
                let block_value = postcard::to_allocvec(block).map_err(ser_err)?;
                batch.insert(
                    &self.keyspaces.dummy_ips,
                    tenant_key.as_bytes(),
                    block_value.as_slice(),
                );
                // Service address assignment.
                let service_key = format!(
                    "service:{}:{}:{}",
                    address.tenant_id, address.service, address.role
                );
                let addr_value = postcard::to_allocvec(address).map_err(ser_err)?;
                batch.insert(
                    &self.keyspaces.dummy_ips,
                    service_key.as_bytes(),
                    addr_value.as_slice(),
                );
                Ok(ChangeKind::DummyIpUpdate)
            }

            // --- Secrets ---
            FleetosCommand::StoreSecret { record } => {
                let secret_key = format!("secret:{}", record.key);
                batch.insert(
                    &self.keyspaces.secrets,
                    secret_key.as_bytes(),
                    record.envelope_bytes.as_slice(),
                );
                let acl_key = format!("acl:{}", record.key);
                batch.insert(
                    &self.keyspaces.secrets,
                    acl_key.as_bytes(),
                    record.acl_bytes.as_slice(),
                );
                Ok(ChangeKind::SecretRotation)
            }

            // --- Scheduler / placement ---
            FleetosCommand::RecordOrdinalAssignment { record } => {
                let key = format!(
                    "{}:{}:{}:{}",
                    record.tenant_id, record.service, record.role, record.ordinal
                );
                let value = postcard::to_allocvec(record).map_err(ser_err)?;
                batch.insert(&self.keyspaces.ordinals, key.as_bytes(), value.as_slice());
                Ok(ChangeKind::SchedulingUpdate)
            }
            FleetosCommand::CommitPlacement { record } => {
                let value = postcard::to_allocvec(record).map_err(ser_err)?;
                batch.insert(
                    &self.keyspaces.placements,
                    record.pod_id.as_bytes(),
                    value.as_slice(),
                );
                Ok(ChangeKind::SchedulingUpdate)
            }

            // --- Provisioning ---
            FleetosCommand::StoreNodePool { record } => {
                let value = postcard::to_allocvec(record).map_err(ser_err)?;
                batch.insert(
                    &self.keyspaces.node_pools,
                    record.pool_id.as_bytes(),
                    value.as_slice(),
                );
                Ok(ChangeKind::SchedulingUpdate)
            }
            FleetosCommand::DeleteNodePool { pool_id } => {
                batch.remove(&self.keyspaces.node_pools, pool_id.as_bytes());
                Ok(ChangeKind::SchedulingUpdate)
            }
        }
    }

    /// Publish events to the BroadcastHub based on the ChangeKind.
    /// Called after each entry is committed so watch streams receive data.
    fn publish_event(&self, version: fleetos_core::MonotonicVersion, change_kind: &ChangeKind) {
        match change_kind {
            ChangeKind::SagUpdate | ChangeKind::RevokedDelegations => {
                self.publish_sag_update(version);
            }
            ChangeKind::SecretRotation => {
                // For secret rotations, publish a generic notification.
                // The WatchService streams SecretRotationNotification events.
                // We publish with an empty spiffe_id as a signal to refetch.
                // TODO: Pass the actual spiffe_id through the command for targeted notifications.
                self.broadcast_hub
                    .publish_watch_event(WatchEvent::SecretRotationNotification {
                        spiffe_id: String::new(),
                        version,
                    });
            }
            ChangeKind::SchedulingUpdate => {
                self.publish_schedule_update(version);
            }
            // ClusterMembership, TrustBundleRotation, DummyIpUpdate don't have
            // dedicated watch streams in the current proto schema.
            _ => {}
        }
    }

    /// Read all SAG rules and revoked delegation IDs from keyspaces,
    /// then publish a SagUpdateEvent to the BroadcastHub.
    fn publish_sag_update(&self, version: fleetos_core::MonotonicVersion) {
        // Read all SAG rules from the sag_rules keyspace.
        // Each value is a stored rule_bytes from SagRuleRecord.
        // We construct the length-prefixed proto format expected by decode_rules().
        let mut rules_bytes = Vec::new();
        for guard in self.keyspaces.sag_rules.prefix(Vec::<u8>::new()) {
            let value = match guard.value() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let rule_bytes = value.as_ref();
            rules_bytes.extend_from_slice(&(rule_bytes.len() as u32).to_le_bytes());
            rules_bytes.extend_from_slice(rule_bytes);
        }

        // Read all revoked delegation IDs.
        let mut revoked_ids: Vec<Vec<u8>> = Vec::new();
        for guard in self.keyspaces.revoked_delegations.prefix(Vec::<u8>::new()) {
            let value = match guard.value() {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Ok(record) = postcard::from_bytes::<DelegationRecord>(value.as_ref()) {
                revoked_ids.push(record.delegation_id.into_bytes());
            }
        }

        self.broadcast_hub.publish_sag_update(SagUpdateEvent {
            version,
            rules_bytes,
            revoked_delegation_ids: revoked_ids,
        });
    }

    /// Read all placements from keyspaces and publish a ScheduleUpdateEvent.
    fn publish_schedule_update(&self, version: fleetos_core::MonotonicVersion) {
        // Read all placements and construct WorkloadAssignmentRecords.
        let mut assignments_bytes = Vec::new();
        let mut records: Vec<crate::watch::scheduler_stream::WorkloadAssignmentRecord> = Vec::new();

        for guard in self.keyspaces.placements.prefix(Vec::<u8>::new()) {
            let value = match guard.value() {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Ok(placement) =
                postcard::from_bytes::<crate::scheduler::Placement>(value.as_ref())
            {
                records.push(crate::watch::scheduler_stream::WorkloadAssignmentRecord {
                    workload_id: placement.pod_id,
                    runtime: String::new(), // TODO: Read from workload spec
                    image: String::new(),   // TODO: Read from workload spec
                    role: placement.role,
                });
            }
        }

        if let Ok(serialized) = postcard::to_allocvec(&records) {
            assignments_bytes = serialized;
        }

        self.broadcast_hub
            .publish_schedule_update(ScheduleUpdateEvent {
                version,
                assignments_bytes,
            });
    }
}

// --- error helpers ---

fn ser_err(e: postcard::Error) -> StorageError<u64> {
    StorageError::IO {
        source: StorageIOError::write_state_machine(&e),
    }
}

fn read_err(e: fjall::Error) -> StorageError<u64> {
    StorageError::IO {
        source: StorageIOError::read_state_machine(&e),
    }
}

fn commit_err(e: fjall::Error) -> StorageError<u64> {
    StorageError::IO {
        source: StorageIOError::write_state_machine(&e),
    }
}

fn storage_err(e: crate::storage::StorageError) -> StorageError<u64> {
    StorageError::IO {
        source: StorageIOError::write_state_machine(&e),
    }
}

fn parse_spiffe(s: &str) -> Result<SpiffeId, StorageError<u64>> {
    s.parse::<SpiffeId>().map_err(|e| {
        let io = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid SpiffeId '{}': {}", s, e),
        );
        StorageError::IO {
            source: StorageIOError::read_state_machine(&io),
        }
    })
}

impl RaftStateMachine<FleetosRaftConfig> for FjallStateMachine {
    type SnapshotBuilder = FjallSnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<u64>>, StoredMembership<u64, BasicNode>), StorageError<u64>> {
        let last_applied = match self
            .keyspaces
            .raft_state
            .get(b"last_applied")
            .map_err(read_err)?
        {
            Some(bytes) => Some(postcard::from_bytes(&bytes).map_err(ser_err)?),
            None => None,
        };

        let last_membership = match self
            .keyspaces
            .raft_state
            .get(b"last_membership")
            .map_err(read_err)?
        {
            Some(bytes) => postcard::from_bytes(&bytes).map_err(ser_err)?,
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

        for entry in entries {
            let log_id = *entry.get_log_id();

            // One batch per entry so a command's reads see everything earlier
            // entries committed, and each entry commits atomically on its own.
            let mut batch = self.db.batch();
            let mut change_kind = ChangeKind::SagUpdate;

            match &entry.payload {
                EntryPayload::Blank => {
                    // No-op entry (e.g., first entry of a new term). Still bumps the version.
                }
                EntryPayload::Normal(cmd) => {
                    change_kind = self.apply_command(cmd, &mut batch)?;
                }
                EntryPayload::Membership(membership) => {
                    let stored = StoredMembership::new(Some(log_id), membership.clone());
                    let serialized = postcard::to_allocvec(&stored).map_err(ser_err)?;
                    batch.insert(
                        &self.keyspaces.raft_state,
                        b"last_membership",
                        serialized.as_slice(),
                    );
                    change_kind = ChangeKind::ClusterMembership;
                }
            }

            // Persist last_applied for this entry.
            let lid_bytes = postcard::to_allocvec(&log_id).map_err(ser_err)?;
            batch.insert(
                &self.keyspaces.raft_state,
                b"last_applied",
                lid_bytes.as_slice(),
            );

            // Allocate the next monotonic version and persist it in the SAME batch.
            let new_version = self.versioned_state.allocate_version();
            self.versioned_state
                .persist_version(new_version.get(), &mut batch)
                .map_err(storage_err)?;

            // Commit this entry's mutations atomically.
            batch.commit().map_err(commit_err)?;

            // Publish to BroadcastHub so watch streams receive data.
            // Must happen BEFORE notify_version, which consumes change_kind.
            self.publish_event(new_version, &change_kind);

            // Notify only after a successful commit so subscribers see durable state.
            self.versioned_state
                .notify_version(new_version, change_kind);

            responses.push(FleetosResponse {
                version: new_version.get(),
            });
        }

        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        super::snapshot::FjallSnapshotBuilder::new(self.db.clone(), self.keyspaces.clone())
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

        // Deserialize the application snapshot.
        let app_snapshot: super::snapshot::ApplicationSnapshot =
            postcard::from_bytes(&data).map_err(ser_err)?;

        // Build a single atomic batch: clear all snapshotted keyspaces,
        // then write every key-value pair from the snapshot.
        let mut batch = self.db.batch();

        // Phase 1: clear existing data in all snapshot-relevant keyspaces.
        for (_name, ks) in self.keyspaces.snapshot_keyspaces() {
            for guard in ks.prefix(Vec::<u8>::new()) {
                let key = guard.key().map_err(read_err)?.to_vec();
                batch.remove(ks, key.as_slice());
            }
        }

        // Phase 2: write all snapshot data.
        for (name, pairs) in &app_snapshot.keyspaces {
            // Find the matching keyspace by name.
            let ks = self
                .keyspaces
                .snapshot_keyspaces()
                .into_iter()
                .find(|(n, _)| *n == name.as_str())
                .map(|(_, ks)| ks);
            let Some(ks) = ks else {
                tracing::warn!(keyspace = %name, "unknown keyspace in snapshot, skipping");
                continue;
            };
            for (key, value) in pairs {
                batch.insert(ks, key.as_slice(), value.as_slice());
            }
        }

        // Phase 3: persist the snapshot data and meta for get_current_snapshot().
        let serialized_meta = postcard::to_allocvec(meta).map_err(ser_err)?;
        batch.insert(
            &self.keyspaces.raft_snapshot,
            0u64.to_be_bytes(),
            data.as_slice(),
        );
        batch.insert(
            &self.keyspaces.raft_state,
            b"snapshot_meta",
            serialized_meta.as_slice(),
        );

        // Commit everything atomically.
        batch.commit().map_err(commit_err)?;

        tracing::info!(
            snapshot_id = %meta.snapshot_id,
            keyspaces_restored = app_snapshot.keyspaces.len(),
            "snapshot installed"
        );

        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<FleetosRaftConfig>>, StorageError<u64>> {
        let meta: SnapshotMeta<u64, BasicNode> = match self
            .keyspaces
            .raft_state
            .get(b"snapshot_meta")
            .map_err(read_err)?
        {
            Some(bytes) => postcard::from_bytes(&bytes).map_err(ser_err)?,
            None => return Ok(None),
        };

        let data = match self
            .keyspaces
            .raft_snapshot
            .get(0u64.to_be_bytes())
            .map_err(read_err)?
        {
            Some(bytes) => bytes.to_vec(),
            None => return Ok(None),
        };

        Ok(Some(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        }))
    }
}
