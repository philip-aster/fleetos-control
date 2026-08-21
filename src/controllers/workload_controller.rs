//! Workload controller — expands WorkloadSpec into PodSpecs.

use std::collections::BTreeMap;
use std::sync::Arc;

use fleetos_core::proto::workload::{PodSpec, WorkloadSpec};
use fleetos_core::spiffe::PodId;

use super::ControllerError;
use crate::scheduler::{OrdinalTracker, ordinal::OrdinalAssignment};
use crate::storage::StorageEngine;

/// The workload controller.
pub struct WorkloadController {
    /// Storage engine for persisting workload specs and placements.
    /// TODO: Used for storing the WorkloadSpec, querying cluster state for scheduling.
    #[allow(dead_code)]
    storage: Arc<StorageEngine>,

    ordinal_tracker: Arc<OrdinalTracker>,
}

impl WorkloadController {
    pub fn new(storage: Arc<StorageEngine>, ordinal_tracker: Arc<OrdinalTracker>) -> Self {
        Self {
            storage,
            ordinal_tracker,
        }
    }

    /// Reconcile a WorkloadSpec: expand into PodSpecs and schedule.
    pub async fn reconcile(&self, spec: &WorkloadSpec) -> Result<(), ControllerError> {
        // Convert proto replicas map to BTreeMap for deterministic iteration.
        let replicas: BTreeMap<String, u32> =
            spec.replicas.iter().map(|(k, v)| (k.clone(), *v)).collect();

        let tenant_id = spec.tenant_id.clone();
        let workload_id = spec.workload_id.clone();

        // TODO: Store the WorkloadSpec in storage.
        // self.storage.store_workload_spec(spec)?;

        // Expand each (role, count) into individual PodSpecs.
        for (role_str, count) in &replicas {
            for ordinal in 0..*count {
                // Check if this ordinal already exists (preservation across restarts).
                let existing = self.ordinal_tracker.get_assignment(
                    &tenant_id,
                    &workload_id,
                    role_str,
                    ordinal,
                )?;

                if existing.is_some() {
                    // Ordinal already assigned — skip (preserve identity).
                    tracing::debug!(
                        tenant = %tenant_id,
                        workload = %workload_id,
                        role = %role_str,
                        ordinal = ordinal,
                        "ordinal already assigned, preserving"
                    );
                    continue;
                }

                // Generate a new pod_id.
                let pod_id = PodId::new(format!("{}-{}-{}", workload_id, role_str, ordinal));

                // Build the PodSpec, overwriting the six trusted fields.
                let pod_spec =
                    self.build_pod_spec(spec, &pod_id, &tenant_id, &workload_id, role_str, ordinal);

                // Construct the OrdinalAssignment struct and record it.
                let assignment = OrdinalAssignment {
                    tenant_id: tenant_id.clone(),
                    service: workload_id.clone(),
                    role: role_str.clone(),
                    ordinal,
                    current_pod_id: Some(pod_id.as_str().to_string()),
                    current_node_id: None, // Unassigned at expansion time
                };

                self.ordinal_tracker.record_assignment(&assignment)?;

                // TODO: Submit to scheduler for placement.
                // let decision = self.scheduler.schedule(&pod_spec, &cluster_state)?;
                // self.storage.store_placement(&decision)?;
                // self.broadcast_hub.publish_schedule_update(...)?;

                // Use pod_spec to suppress unused variable warning.
                // It will be submitted to the scheduler once that's wired up.
                let _ = &pod_spec;

                tracing::info!(
                    tenant = %tenant_id,
                    workload = %workload_id,
                    role = %role_str,
                    ordinal = ordinal,
                    pod_id = %pod_id.as_str(),
                    "expanded PodSpec"
                );
            }
        }

        Ok(())
    }

    /// Build a PodSpec from a WorkloadSpec template, overwriting the six trusted fields.
    fn build_pod_spec(
        &self,
        workload_spec: &WorkloadSpec,
        pod_id: &PodId,
        tenant_id: &str,
        workload_id: &str,
        role: &str,
        ordinal: u32,
    ) -> PodSpec {
        // Start with the template as a base.
        let mut pod_spec = workload_spec.pod_spec.clone().unwrap_or_default();

        // Unconditionally overwrite the six trusted fields.
        pod_spec.tenant_id = tenant_id.to_string();
        pod_spec.workload_id = workload_id.to_string();
        pod_spec.role = role.to_string();
        pod_spec.image = workload_spec.image.clone();
        pod_spec.ordinal = Some(ordinal);
        pod_spec.pod_id = Some(pod_id.as_str().to_string());

        pod_spec
    }
}
