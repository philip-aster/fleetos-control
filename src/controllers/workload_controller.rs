//! Workload controller — expands WorkloadSpec into PodSpecs and schedules them.
use super::ControllerError;
use crate::scheduler::{
    ClusterState, OrdinalTracker, PendingPod, Scheduler, engine::DefaultScheduler,
    ordinal::OrdinalAssignment,
};
use crate::storage::StorageEngine;
use crate::watch::broadcast::{BroadcastHub, ScheduleUpdateEvent};
use fleetos_core::MonotonicVersion;
use fleetos_core::proto::workload::{PodSpec, WorkloadSpec};
use fleetos_core::spiffe::PodId;
use prost::Message;
use std::collections::BTreeMap;
use std::sync::Arc;

/// The workload controller.
pub struct WorkloadController {
    storage: Arc<StorageEngine>,
    ordinal_tracker: Arc<OrdinalTracker>,
    scheduler: DefaultScheduler,
    broadcast_hub: Arc<BroadcastHub>,
}

impl WorkloadController {
    pub fn new(
        storage: Arc<StorageEngine>,
        ordinal_tracker: Arc<OrdinalTracker>,
        broadcast_hub: Arc<BroadcastHub>,
    ) -> Self {
        Self {
            storage,
            ordinal_tracker,
            scheduler: DefaultScheduler::new(),
            broadcast_hub,
        }
    }

    /// Reconcile a WorkloadSpec: expand into PodSpecs, schedule, and persist.
    pub async fn reconcile(&self, spec: &WorkloadSpec) -> Result<(), ControllerError> {
        let replicas: BTreeMap<String, u32> =
            spec.replicas.iter().map(|(k, v)| (k.clone(), *v)).collect();
        let tenant_id = spec.tenant_id.clone();
        let workload_id = spec.workload_id.clone();

        // 1. Persist the WorkloadSpec using prost (proto types don't implement serde).
        let spec_bytes = spec.encode_to_vec();
        self.storage
            .store_workload_spec(&tenant_id, &workload_id, &spec_bytes)
            .map_err(ControllerError::Storage)?;

        // 2. Build ClusterState from storage for scheduling decisions.
        let cluster_state = self.build_cluster_state()?;

        // 3. Expand each (role, count) into individual PodSpecs.
        let mut new_assignments: Vec<(String, PendingPod)> = Vec::new();

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

                // Record the ordinal assignment.
                let assignment = OrdinalAssignment {
                    tenant_id: tenant_id.clone(),
                    service: workload_id.clone(),
                    role: role_str.clone(),
                    ordinal,
                    current_pod_id: Some(pod_id.as_str().to_string()),
                    current_node_id: None,
                };
                self.ordinal_tracker.record_assignment(&assignment)?;

                // 4. Build PendingPod for scheduling (convert proto ResourceRequirements
                //    to scheduler ResourceSpec: vcpus→millicores, memory_mb→bytes).
                let resources = pod_spec.resources.as_ref().map_or(
                    crate::scheduler::ResourceSpec {
                        cpu_millicores: 500,
                        memory_bytes: 512 * 1024 * 1024,
                    },
                    |r| crate::scheduler::ResourceSpec {
                        cpu_millicores: (r.vcpus as u64) * 1000,
                        memory_bytes: (r.memory_mb as u64) * 1024 * 1024,
                    },
                );

                let pending_pod = PendingPod {
                    pod_id: pod_id.as_str().to_string(),
                    tenant_id: tenant_id.clone(),
                    service: workload_id.clone(),
                    role: role_str.clone(),
                    ordinal,
                    resources,
                    previous_node: None,
                };

                match self.scheduler.schedule(&pending_pod, &cluster_state) {
                    Ok(decision) => {
                        // 5. Persist the placement.
                        let placement = crate::scheduler::Placement {
                            pod_id: pod_id.as_str().to_string(),
                            tenant_id: tenant_id.clone(),
                            service: workload_id.clone(),
                            role: role_str.clone(),
                            ordinal,
                            node_id: decision.node_id.clone(),
                            resources: pending_pod.resources,
                        };
                        self.storage
                            .store_placement(&placement)
                            .map_err(ControllerError::Storage)?;

                        // Update the ordinal assignment with the node.
                        self.ordinal_tracker.update_placement(
                            &tenant_id,
                            &workload_id,
                            role_str,
                            ordinal,
                            pod_id.as_str(),
                            &decision.node_id.to_string(),
                        )?;

                        new_assignments.push((pod_id.as_str().to_string(), pending_pod));

                        tracing::info!(
                            tenant = %tenant_id,
                            workload = %workload_id,
                            role = %role_str,
                            ordinal = ordinal,
                            pod_id = %pod_id.as_str(),
                            node = %decision.node_id,
                            "scheduled PodSpec"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            pod_id = %pod_id.as_str(),
                            error = %e,
                            "scheduling failed, will retry on next reconcile"
                        );
                    }
                }
            }
        }

        // 6. Publish schedule update if any new assignments were made.
        if !new_assignments.is_empty() {
            let assignments_bytes =
                postcard::to_allocvec(&new_assignments).map_err(ControllerError::Serialization)?;
            self.broadcast_hub
                .publish_schedule_update(ScheduleUpdateEvent {
                    version: MonotonicVersion::new(0),
                    assignments_bytes,
                });
        }

        Ok(())
    }

    /// Build a ClusterState snapshot from storage.
    fn build_cluster_state(&self) -> Result<ClusterState, ControllerError> {
        let node_records = self
            .storage
            .list_node_records()
            .map_err(ControllerError::Storage)?;
        let placements = self
            .storage
            .list_placements()
            .map_err(ControllerError::Storage)?;
        Ok(ClusterState::build(&node_records, placements))
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
