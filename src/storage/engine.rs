//! Unified storage engine interface.
use crate::scheduler::{NodeInfo, Placement};
use fjall::Keyspace;
use fleetos_core::spiffe::SpiffeId;

/// Unified storage engine providing access to all keyspaces.
pub struct StorageEngine {
    pub raft_log: Keyspace,
    pub raft_log_meta: Keyspace,
    pub nodes: Keyspace,
    pub placements: Keyspace,
    pub workloads: Keyspace,
    pub delegations: Keyspace,
    pub delegations_revoked: Keyspace,
    pub join_tokens: Keyspace,
    pub pcr_policies: Keyspace,
    pub dummy_ips: Keyspace,
    pub secrets: Keyspace,
    pub sags: Keyspace,
}

impl StorageEngine {
    pub fn new(
        raft_log: Keyspace,
        raft_log_meta: Keyspace,
        nodes: Keyspace,
        placements: Keyspace,
        workloads: Keyspace,
        delegations: Keyspace,
        delegations_revoked: Keyspace,
        join_tokens: Keyspace,
        pcr_policies: Keyspace,
        dummy_ips: Keyspace,
        secrets: Keyspace,
        sags: Keyspace,
    ) -> Self {
        Self {
            raft_log,
            raft_log_meta,
            nodes,
            placements,
            workloads,
            delegations,
            delegations_revoked,
            join_tokens,
            pcr_policies,
            dummy_ips,
            secrets,
            sags,
        }
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

    // --- Node persistence ---

    /// Store a node record (serialized NodeInfo).
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

    /// Load all nodes from storage.
    pub fn list_nodes(&self) -> Result<Vec<NodeInfo>, crate::storage::StorageError> {
        let mut nodes = Vec::new();
        for guard in self.nodes.prefix(Vec::<u8>::new()) {
            let value = guard
                .value()
                .map_err(crate::storage::StorageError::Storage)?;
            if let Ok(node) = postcard::from_bytes::<NodeInfo>(value.as_ref()) {
                nodes.push(node);
            }
        }
        Ok(nodes)
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
        // Find the placement matching the ordinal slot
        let all = self.list_placements()?;
        for placement in &all {
            if placement.tenant_id == tenant_id
                && placement.service == workload_id
                && placement.role == role
                && placement.ordinal == ordinal
            {
                // Remove old entry, insert with new pod_id
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
}
