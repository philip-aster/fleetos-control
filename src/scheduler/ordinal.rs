//! Ordinal assignment tracking and stability.
//!
//! **Critical invariant:** `(service, role, ordinal)` is a stable slot that
//! gets replaced in-place on failure, never a fungible pool where a dead
//! replica is removed and a new one appended with the next available ordinal.
//!
//! The scheduler does NOT assign ordinals — `workload_controller.rs` does that
//! during WorkloadSpec → PodSpec expansion. This module TRACKS ordinal assignments
//! to ensure stability across restarts and reschedules.
//!
//! When a pod at ordinal N dies, its replacement is assigned ordinal N,
//! not the next free integer.

use fjall::Keyspace;

use super::SchedulerError;

/// Tracks ordinal assignments for stable identity.
///
/// Key: `(tenant_id, service, role, ordinal)` → node placement
/// This ensures that when a pod needs rescheduling, it gets the SAME ordinal.
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

    /// Record an ordinal assignment.
    ///
    /// Called by `workload_controller` when expanding a WorkloadSpec into PodSpecs.
    pub fn record_assignment(&self, assignment: &OrdinalAssignment) -> Result<(), SchedulerError> {
        let key = Self::ordinal_key(
            &assignment.tenant_id,
            &assignment.service,
            &assignment.role,
            assignment.ordinal,
        );
        let serialized =
            postcard::to_allocvec(assignment).map_err(SchedulerError::Serialization)?;

        self.keyspace
            .insert(key.as_slice(), serialized.as_slice())
            .map_err(|e| SchedulerError::Storage(crate::storage::StorageError::Storage(e)))?;

        Ok(())
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

    /// Find the next available ordinal for a (service, role) pair.
    ///
    /// This is used ONLY during initial expansion (when creating new ordinals).
    /// For rescheduling, the existing ordinal is always reused.
    pub fn next_available_ordinal(
        &self,
        tenant_id: &str,
        service: &str,
        role: &str,
    ) -> Result<u32, SchedulerError> {
        let assignments = self.get_assignments_for_service_role(tenant_id, service, role)?;

        // Find the first gap in the ordinal sequence.
        // This ensures we reuse freed ordinals (e.g., if ordinal 2 was freed,
        // the next new pod gets ordinal 2, not the max+1).
        let mut next_ordinal = 0u32;
        for assignment in &assignments {
            if assignment.ordinal != next_ordinal {
                break;
            }
            next_ordinal += 1;
        }

        Ok(next_ordinal)
    }

    /// Mark an ordinal as freed (pod deleted, not just rescheduled).
    ///
    /// This is called when a workload is scaled down or deleted entirely.
    /// It does NOT delete the ordinal assignment record — it marks it as
    /// having no current pod, so the ordinal can be reused.
    pub fn free_ordinal(
        &self,
        tenant_id: &str,
        service: &str,
        role: &str,
        ordinal: u32,
    ) -> Result<(), SchedulerError> {
        let assignment = self.get_assignment(tenant_id, service, role, ordinal)?;

        match assignment {
            Some(mut existing) => {
                existing.current_pod_id = None;
                existing.current_node_id = None;
                self.record_assignment(&existing)?;
            }
            None => {
                // Ordinal was never assigned — nothing to free.
                return Err(SchedulerError::OrdinalConflict(format!(
                    "ordinal {} was never assigned for {}:{}:{}",
                    ordinal, tenant_id, service, role
                )));
            }
        }

        Ok(())
    }

    /// Update the placement for an existing ordinal (reschedule).
    ///
    /// This preserves the ordinal while changing the node.
    /// Called when a pod dies and needs to be rescheduled to a new node.
    pub fn update_placement(
        &self,
        tenant_id: &str,
        service: &str,
        role: &str,
        ordinal: u32,
        new_pod_id: &str,
        new_node_id: &str,
    ) -> Result<(), SchedulerError> {
        let assignment = self.get_assignment(tenant_id, service, role, ordinal)?;

        match assignment {
            Some(mut existing) => {
                existing.current_pod_id = Some(new_pod_id.to_owned());
                existing.current_node_id = Some(new_node_id.to_owned());
                self.record_assignment(&existing)?;
            }
            None => {
                return Err(SchedulerError::OrdinalConflict(format!(
                    "cannot update placement: ordinal {} not assigned for {}:{}:{}",
                    ordinal, tenant_id, service, role
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Integration tests require a real fjall database.
    // Unit tests for ordinal logic would go here.

    #[test]
    fn ordinal_key_format() {
        let key = OrdinalTracker::ordinal_key("tenant-1", "web", "replica", 2);
        assert_eq!(key, b"tenant-1:web:replica:2");
    }
}
