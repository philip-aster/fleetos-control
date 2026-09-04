//! Unified storage engine interface.
use crate::raft::records::{NodeRecord, TenantRecord};
use crate::scheduler::Placement;
use fjall::Keyspace;
use fleetos_core::spiffe::SpiffeId;
use prost::Message;

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
    pub tenant_quotas: Keyspace,
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
        tenant_quotas: Keyspace,
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
            tenant_quotas,
        }
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

    // --- Node pool persistence ---

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

    // --- Tenant quota persistence ---

    /// Get the quota for a tenant, if one is set.
    pub fn get_tenant_quota(
        &self,
        tenant_id: &str,
    ) -> Result<Option<crate::raft::records::TenantQuotaRecord>, crate::storage::StorageError> {
        match self
            .tenant_quotas
            .get(tenant_id.as_bytes())
            .map_err(crate::storage::StorageError::Storage)?
        {
            Some(bytes) => {
                let record: crate::raft::records::TenantQuotaRecord = postcard::from_bytes(&bytes)
                    .map_err(crate::storage::StorageError::Serialization)?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    /// Compute current resource usage for a tenant.
    ///
    /// Returns `(total_cpu_millicores, total_memory_bytes, workload_count)`.
    /// Iterates all workload specs for the tenant, decoding each to extract
    /// resource requirements and replica counts.
    pub fn compute_tenant_usage(
        &self,
        tenant_id: &str,
    ) -> Result<(u64, u64, u32), crate::storage::StorageError> {
        let mut total_cpu: u64 = 0;
        let mut total_memory: u64 = 0;
        let mut workload_count: u32 = 0;

        for guard in self.workloads.prefix(Vec::<u8>::new()) {
            let value = guard
                .value()
                .map_err(crate::storage::StorageError::Storage)?;
            if let Ok(record) =
                postcard::from_bytes::<crate::raft::records::WorkloadSpecRecord>(value.as_ref())
            {
                if record.tenant_id != tenant_id {
                    continue;
                }
                workload_count += 1;
                // Decode the workload spec to extract resource requirements.
                if let Ok(spec) = fleetos_core::proto::workload::WorkloadSpec::decode(
                    record.spec_bytes.as_slice(),
                ) {
                    let cpu_per_pod = spec
                        .pod_spec
                        .as_ref()
                        .and_then(|ps| ps.resources.as_ref())
                        .map(|r| r.vcpus as u64 * 1000) // vcpus → millicores
                        .unwrap_or(0);
                    let mem_per_pod = spec
                        .pod_spec
                        .as_ref()
                        .and_then(|ps| ps.resources.as_ref())
                        .map(|r| r.memory_mb as u64 * 1024 * 1024) // MB → bytes
                        .unwrap_or(0);
                    let total_replicas: u64 = spec.replicas.values().map(|&c| c as u64).sum();
                    total_cpu += cpu_per_pod * total_replicas;
                    total_memory += mem_per_pod * total_replicas;
                }
            }
        }

        Ok((total_cpu, total_memory, workload_count))
    }
}
