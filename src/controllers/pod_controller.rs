//! Pod controller — per-ordinal reconciliation.

use std::sync::Arc;

use fleetos_core::spiffe::PodId;

use super::ControllerError;
use crate::scheduler::OrdinalTracker;
use crate::storage::StorageEngine;

/// The pod controller.
pub struct PodController {
    /// Storage engine for placement queries and updates.
    /// TODO: Used for querying current placements, updating node assignments after rescheduling.
    #[allow(dead_code)]
    storage: Arc<StorageEngine>,

    ordinal_tracker: Arc<OrdinalTracker>,
}

impl PodController {
    pub fn new(storage: Arc<StorageEngine>, ordinal_tracker: Arc<OrdinalTracker>) -> Self {
        Self {
            storage,
            ordinal_tracker,
        }
    }

    /// Reconcile a pod that has died or is missing.
    pub async fn reconcile_dead_pod(
        &self,
        tenant_id: &str,
        workload_id: &str,
        role: &str,
        ordinal: u32,
    ) -> Result<(), ControllerError> {
        // Look up the existing ordinal assignment.
        let assignment = self
            .ordinal_tracker
            .get_assignment(tenant_id, workload_id, role, ordinal)?
            .ok_or_else(|| {
                ControllerError::Storage(crate::storage::StorageError::NotFound(format!(
                    "ordinal assignment for {}:{}:{}:{}",
                    tenant_id, workload_id, role, ordinal
                )))
            })?;

        // Generate a new pod_id for the replacement.
        let new_pod_id = PodId::new(format!("{}-{}-{}", workload_id, role, ordinal));

        // TODO: Update the placement to point to the new pod_id.
        // The ordinal stays the same — this is replace-in-place.
        // self.storage.update_placement_pod_id(
        //     tenant_id, workload_id, role, ordinal, &new_pod_id
        // )?;

        // Extract the old pod_id from the Option<String> for logging.
        let old_pod_id_str = assignment
            .current_pod_id
            .as_deref()
            .unwrap_or("<unassigned>");

        tracing::info!(
            tenant = %tenant_id,
            workload = %workload_id,
            role = %role,
            ordinal = ordinal,
            old_pod_id = %old_pod_id_str,
            new_pod_id = %new_pod_id.as_str(),
            "pod replaced in place (ordinal preserved)"
        );

        Ok(())
    }

    /// Handle a scale-down event: free an ordinal.
    pub async fn handle_scale_down(
        &self,
        tenant_id: &str,
        workload_id: &str,
        role: &str,
        new_count: u32,
    ) -> Result<(), ControllerError> {
        let assignments =
            self.ordinal_tracker
                .get_assignments_for_service_role(tenant_id, workload_id, role)?;

        for assignment in assignments {
            if assignment.ordinal >= new_count {
                self.ordinal_tracker.free_ordinal(
                    tenant_id,
                    workload_id,
                    role,
                    assignment.ordinal,
                )?;

                // TODO: Remove the placement from storage.
                // self.storage.delete_placement(
                //     tenant_id, workload_id, role, assignment.ordinal
                // )?;

                tracing::info!(
                    tenant = %tenant_id,
                    workload = %workload_id,
                    role = %role,
                    ordinal = assignment.ordinal,
                    "ordinal freed (scale-down)"
                );
            }
        }

        Ok(())
    }
}
