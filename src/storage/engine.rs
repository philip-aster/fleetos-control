//! Unified storage engine interface.
use crate::raft::records::{NodeRecord, TenantRecord};
use crate::scheduler::Placement;
use fjall::Keyspace;
use fleetos_core::spiffe::SpiffeId;

/// Unified storage engine providing access to all keyspaces.
///
/// Holds all 20 keyspaces created by `storage::init_keyspaces`. Read paths used
/// by services and controllers live here; replicated write paths live in the
/// Raft state machine.
pub struct StorageEngine {
    pub version: Keyspace,
    pub raft_log: Keyspace,
    pub raft_log_meta: Keyspace,
    pub raft_state: Keyspace,
    pub raft_snapshot: Keyspace,
    pub nodes: Keyspace,
    pub svids: Keyspace,
    pub placements: Keyspace,
    pub tenants: Keyspace,
    pub ordinals: Keyspace,
    pub workloads: Keyspace,
    pub router_assignments: Keyspace,
    pub delegations: Keyspace,
    pub delegations_revoked: Keyspace,
    pub join_tokens: Keyspace,
    pub pcr_policies: Keyspace,
    pub dummy_ips: Keyspace,
    pub secrets: Keyspace,
    pub sags: Keyspace,
    pub node_pools: Keyspace,
    pub audit_log: Keyspace,
    pub operator_grants: Keyspace,
    pub workload_status: Keyspace,
}

impl StorageEngine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: Keyspace,
        raft_log: Keyspace,
        raft_log_meta: Keyspace,
        raft_state: Keyspace,
        raft_snapshot: Keyspace,
        nodes: Keyspace,
        svids: Keyspace,
        placements: Keyspace,
        tenants: Keyspace,
        ordinals: Keyspace,
        workloads: Keyspace,
        router_assignments: Keyspace,
        delegations: Keyspace,
        delegations_revoked: Keyspace,
        join_tokens: Keyspace,
        pcr_policies: Keyspace,
        dummy_ips: Keyspace,
        secrets: Keyspace,
        sags: Keyspace,
        node_pools: Keyspace,
        audit_log: Keyspace,
        operator_grants: Keyspace,
        workload_status: Keyspace,
    ) -> Self {
        Self {
            version,
            raft_log,
            raft_log_meta,
            raft_state,
            raft_snapshot,
            nodes,
            svids,
            placements,
            tenants,
            ordinals,
            workloads,
            router_assignments,
            delegations,
            delegations_revoked,
            join_tokens,
            pcr_policies,
            dummy_ips,
            secrets,
            sags,
            node_pools,
            audit_log,
            operator_grants,
            workload_status,
        }
    }

    // --- Tenant persistence ---

    /// Store a tenant record.
    pub fn store_tenant(&self, record: &TenantRecord) -> Result<(), crate::storage::StorageError> {
        let serialized =
            postcard::to_allocvec(record).map_err(crate::storage::StorageError::Serialization)?;
        self.tenants
            .insert(record.tenant_id.as_bytes(), serialized.as_slice())
            .map_err(crate::storage::StorageError::Storage)
    }

    /// Get a tenant record by ID.
    pub fn get_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Option<TenantRecord>, crate::storage::StorageError> {
        match self
            .tenants
            .get(tenant_id.as_bytes())
            .map_err(crate::storage::StorageError::Storage)?
        {
            Some(bytes) => {
                let record: TenantRecord = postcard::from_bytes(&bytes)
                    .map_err(crate::storage::StorageError::Serialization)?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    /// List all tenant records.
    pub fn list_tenants(&self) -> Result<Vec<TenantRecord>, crate::storage::StorageError> {
        let mut records = Vec::new();
        for guard in self.tenants.prefix(Vec::<u8>::new()) {
            let value = guard
                .value()
                .map_err(crate::storage::StorageError::Storage)?;
            if let Ok(record) = postcard::from_bytes::<TenantRecord>(value.as_ref()) {
                records.push(record);
            }
        }
        Ok(records)
    }

    // --- Workload persistence ---

    /// Store a serialized WorkloadSpec.
    pub fn store_workload_spec(
        &self,
        tenant_id: &str,
        workload_id: &str,
        bytes: &[u8],
    ) -> Result<(), crate::storage::StorageError> {
        let key = format!("{}:{}", tenant_id, workload_id);
        self.workloads
            .insert(key.as_bytes(), bytes)
            .map_err(crate::storage::StorageError::Storage)
    }

    /// Get a stored WorkloadSpec.
    pub fn get_workload_spec(
        &self,
        tenant_id: &str,
        workload_id: &str,
    ) -> Result<Option<Vec<u8>>, crate::storage::StorageError> {
        let key = format!("{}:{}", tenant_id, workload_id);
        match self
            .workloads
            .get(key.as_bytes())
            .map_err(crate::storage::StorageError::Storage)?
        {
            Some(bytes) => Ok(Some(bytes.to_vec())),
            None => Ok(None),
        }
    }

    /// Load all stored workload spec records (excludes cron workloads).
    pub fn list_workloads(
        &self,
    ) -> Result<Vec<crate::raft::records::WorkloadSpecRecord>, crate::storage::StorageError> {
        let mut records = Vec::new();
        for guard in self.workloads.prefix(Vec::<u8>::new()) {
            let value = guard
                .value()
                .map_err(crate::storage::StorageError::Storage)?;
            if let Ok(record) =
                postcard::from_bytes::<crate::raft::records::WorkloadSpecRecord>(value.as_ref())
            {
                records.push(record);
            }
        }
        Ok(records)
    }

    /// Load all stored cron workload records.
    pub fn list_cron_workloads(
        &self,
    ) -> Result<Vec<crate::raft::records::CronWorkloadRecord>, crate::storage::StorageError> {
        let mut records = Vec::new();
        for guard in self.workloads.prefix(b"cron:".as_slice()) {
            let value = guard
                .value()
                .map_err(crate::storage::StorageError::Storage)?;
            if let Ok(record) =
                postcard::from_bytes::<crate::raft::records::CronWorkloadRecord>(value.as_ref())
            {
                records.push(record);
            }
        }
        Ok(records)
    }

    // --- Node persistence ---

    /// Store a serialized node record.
    pub fn store_node(
        &self,
        node_id: &str,
        bytes: &[u8],
    ) -> Result<(), crate::storage::StorageError> {
        self.nodes
            .insert(node_id.as_bytes(), bytes)
            .map_err(crate::storage::StorageError::Storage)
    }

    /// Mark a node as evicted (removes from schedulable set).
    pub fn mark_node_evicted(&self, node_id: &str) -> Result<(), crate::storage::StorageError> {
        self.nodes
            .remove(node_id.as_bytes())
            .map_err(crate::storage::StorageError::Storage)
    }

    /// Load all node records from storage.
    ///
    /// Returns `NodeRecord` (the replicated record type). Use
    /// `ClusterState::build()` to derive the scheduler's `NodeInfo` view.
    pub fn list_node_records(&self) -> Result<Vec<NodeRecord>, crate::storage::StorageError> {
        let mut records = Vec::new();
        for guard in self.nodes.prefix(Vec::<u8>::new()) {
            let value = guard
                .value()
                .map_err(crate::storage::StorageError::Storage)?;
            if let Ok(record) = postcard::from_bytes::<NodeRecord>(value.as_ref()) {
                records.push(record);
            }
        }
        Ok(records)
    }

    // --- Placement persistence ---

    /// Store a placement decision.
    pub fn store_placement(
        &self,
        placement: &Placement,
    ) -> Result<(), crate::storage::StorageError> {
        let serialized = postcard::to_allocvec(placement)
            .map_err(crate::storage::StorageError::Serialization)?;
        self.placements
            .insert(placement.pod_id.as_bytes(), serialized.as_slice())
            .map_err(crate::storage::StorageError::Storage)
    }

    /// Get a placement by pod_id.
    pub fn get_placement(
        &self,
        pod_id: &str,
    ) -> Result<Option<Placement>, crate::storage::StorageError> {
        match self
            .placements
            .get(pod_id.as_bytes())
            .map_err(crate::storage::StorageError::Storage)?
        {
            Some(bytes) => {
                let placement: Placement = postcard::from_bytes(&bytes)
                    .map_err(crate::storage::StorageError::Serialization)?;
                Ok(Some(placement))
            }
            None => Ok(None),
        }
    }

    /// Delete a placement.
    pub fn delete_placement(&self, pod_id: &str) -> Result<(), crate::storage::StorageError> {
        self.placements
            .remove(pod_id.as_bytes())
            .map_err(crate::storage::StorageError::Storage)
    }

    /// Load all placements from storage.
    pub fn list_placements(&self) -> Result<Vec<Placement>, crate::storage::StorageError> {
        let mut placements = Vec::new();
        for guard in self.placements.prefix(Vec::<u8>::new()) {
            let value = guard
                .value()
                .map_err(crate::storage::StorageError::Storage)?;
            if let Ok(placement) = postcard::from_bytes::<Placement>(value.as_ref()) {
                placements.push(placement);
            }
        }
        Ok(placements)
    }

    /// Get all placements on a specific node.
    pub fn get_placements_for_node(
        &self,
        node_id: &SpiffeId,
    ) -> Result<Vec<Placement>, crate::storage::StorageError> {
        let all = self.list_placements()?;
        Ok(all.into_iter().filter(|p| p.node_id == *node_id).collect())
    }

    /// Update the pod_id for an existing placement (replace-in-place).
    pub fn update_placement_pod_id(
        &self,
        tenant_id: &str,
        workload_id: &str,
        role: &str,
        ordinal: u32,
        new_pod_id: &str,
    ) -> Result<(), crate::storage::StorageError> {
        let all = self.list_placements()?;
        for placement in &all {
            if placement.tenant_id == tenant_id
                && placement.service == workload_id
                && placement.role == role
                && placement.ordinal == ordinal
            {
                self.placements
                    .remove(placement.pod_id.as_bytes())
                    .map_err(crate::storage::StorageError::Storage)?;
                let mut updated = placement.clone();
                updated.pod_id = new_pod_id.to_owned();
                return self.store_placement(&updated);
            }
        }
        Err(crate::storage::StorageError::NotFound(format!(
            "placement for {}:{}:{}:{}",
            tenant_id, workload_id, role, ordinal
        )))
    }

    // --- Node pool persistence ---

    /// Store a node pool record.
    pub fn store_node_pool(
        &self,
        record: &crate::provisioning::NodePoolRecord,
    ) -> Result<(), crate::storage::StorageError> {
        let serialized =
            postcard::to_allocvec(record).map_err(crate::storage::StorageError::Serialization)?;
        self.node_pools
            .insert(record.pool_id.as_bytes(), serialized.as_slice())
            .map_err(crate::storage::StorageError::Storage)
    }

    /// Get a node pool record by pool_id.
    pub fn get_node_pool(
        &self,
        pool_id: &str,
    ) -> Result<Option<crate::provisioning::NodePoolRecord>, crate::storage::StorageError> {
        match self
            .node_pools
            .get(pool_id.as_bytes())
            .map_err(crate::storage::StorageError::Storage)?
        {
            Some(bytes) => {
                let record: crate::provisioning::NodePoolRecord = postcard::from_bytes(&bytes)
                    .map_err(crate::storage::StorageError::Serialization)?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    /// Delete a node pool record.
    pub fn delete_node_pool(&self, pool_id: &str) -> Result<(), crate::storage::StorageError> {
        self.node_pools
            .remove(pool_id.as_bytes())
            .map_err(crate::storage::StorageError::Storage)
    }

    /// Load all node pool records.
    pub fn list_node_pools(
        &self,
    ) -> Result<Vec<crate::provisioning::NodePoolRecord>, crate::storage::StorageError> {
        let mut records = Vec::new();
        for guard in self.node_pools.prefix(Vec::<u8>::new()) {
            let value = guard
                .value()
                .map_err(crate::storage::StorageError::Storage)?;
            if let Ok(record) =
                postcard::from_bytes::<crate::provisioning::NodePoolRecord>(value.as_ref())
            {
                records.push(record);
            }
        }
        Ok(records)
    }

    /// Get the latest workload status for a pod (G-10).
    pub fn get_workload_status(
        &self,
        pod_id: &str,
    ) -> Result<Option<crate::raft::records::WorkloadStatusRecord>, crate::storage::StorageError>
    {
        match self
            .workload_status
            .get(pod_id.as_bytes())
            .map_err(crate::storage::StorageError::Storage)?
        {
            Some(bytes) => {
                let record: crate::raft::records::WorkloadStatusRecord =
                    postcard::from_bytes(&bytes)
                        .map_err(crate::storage::StorageError::Serialization)?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }
}
