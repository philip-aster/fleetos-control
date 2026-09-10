//! Ordinal assignment tracking and stability.
//!
//! **Critical invariant:** `(service, role, ordinal)` is a stable slot that
//! gets replaced in-place on failure, never a fungible pool where a dead
//! replica is removed and a new one appended with the next available ordinal.
//!
//! The scheduler does NOT assign ordinals — `workload_controller.rs` does
//! that during WorkloadSpec → PodSpec expansion. This module provides a
//! **read-only** view of ordinal assignments so controllers can determine
//! which ordinals are assigned and which are free.
//!
//! **All writes go through Raft** (V-5 / S-1 record):
//! - `FleetosCommand::RecordOrdinalAssignment` — assign or free a slot
//! - `FleetosCommand::ReassignPodId` — in-place replacement on pod death
//!
//! Direct fjall writes were removed from this module in the S-1 hygiene
//! pass; reintroducing them would bypass replication and diverge state
//! across control nodes. When a pod at ordinal N dies, its replacement is
//! assigned ordinal N, not the next free integer.
use super::SchedulerError;
use fjall::Keyspace;

/// Read-only tracker for ordinal assignments.
///
/// Key: `(tenant_id, service, role, ordinal)` → assignment record.
/// Mutations are proposed through Raft by the controllers; this struct
/// only reads committed state.
pub struct OrdinalTracker {
    /// Storage keyspace for ordinal assignments.
    keyspace: Keyspace,
}

/// A recorded ordinal assignment.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OrdinalAssignment {
    /// The tenant.
    pub tenant_id: String,
    /// The service name.
    pub service: String,
    /// The workload role.
    pub role: String,
    /// The ordinal.
    pub ordinal: u32,
    /// The pod currently holding this ordinal (if any).
    pub current_pod_id: Option<String>,
    /// The node the pod is placed on (if any).
    pub current_node_id: Option<String>,
}

impl OrdinalTracker {
    pub fn new(keyspace: Keyspace) -> Self {
        Self { keyspace }
    }

    /// Build the storage key for an ordinal assignment.
    fn ordinal_key(tenant_id: &str, service: &str, role: &str, ordinal: u32) -> Vec<u8> {
        format!("{}:{}:{}:{}", tenant_id, service, role, ordinal).into_bytes()
    }

    /// Get the current assignment for a specific ordinal.
    pub fn get_assignment(
        &self,
        tenant_id: &str,
        service: &str,
        role: &str,
        ordinal: u32,
    ) -> Result<Option<OrdinalAssignment>, SchedulerError> {
        let key = Self::ordinal_key(tenant_id, service, role, ordinal);
        match self
            .keyspace
            .get(key.as_slice())
            .map_err(|e| SchedulerError::Storage(crate::storage::StorageError::Storage(e)))?
        {
            Some(bytes) => {
                let assignment: OrdinalAssignment =
                    postcard::from_bytes(&bytes).map_err(SchedulerError::Serialization)?;
                Ok(Some(assignment))
            }
            None => Ok(None),
        }
    }

    /// Get all ordinal assignments for a (service, role) pair.
    ///
    /// Used by `workload_controller` to determine which ordinals are
    /// currently assigned and which are free.
    pub fn get_assignments_for_service_role(
        &self,
        tenant_id: &str,
        service: &str,
        role: &str,
    ) -> Result<Vec<OrdinalAssignment>, SchedulerError> {
        let prefix = format!("{}:{}:{}:", tenant_id, service, role).into_bytes();
        let mut assignments = Vec::new();
        for guard in self.keyspace.prefix(prefix.as_slice()) {
            let value = guard
                .value()
                .map_err(|e| SchedulerError::Storage(crate::storage::StorageError::Storage(e)))?;
            if let Ok(assignment) = postcard::from_bytes::<OrdinalAssignment>(value.as_ref()) {
                assignments.push(assignment);
            }
        }
        // Sort by ordinal for deterministic ordering.
        assignments.sort_by_key(|a| a.ordinal);
        Ok(assignments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinal_key_format() {
        let key = OrdinalTracker::ordinal_key("tenant-1", "web", "replica", 2);
        assert_eq!(key, b"tenant-1:web:replica:2");
    }
}
