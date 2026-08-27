//! Workload controller — expands WorkloadSpec into PodSpecs and schedules them.
use super::ControllerError;
use crate::raft::{FleetosCommand, FleetosRaftConfig};
use crate::scheduler::{
    ClusterState, OrdinalTracker, PendingPod, Scheduler, engine::DefaultScheduler,
    ordinal::OrdinalAssignment,
};
use crate::storage::StorageEngine;
use fleetos_core::proto::workload::{PodSpec, WorkloadSpec};
use fleetos_core::spiffe::PodId;
use openraft::Raft;
use std::collections::BTreeMap;
use std::sync::Arc;

pub struct WorkloadController {
    storage: Arc<StorageEngine>,
    ordinal_tracker: Arc<OrdinalTracker>,
    scheduler: DefaultScheduler,
    raft: Arc<Raft<FleetosRaftConfig>>,
}

impl WorkloadController {
    pub fn new(
        storage: Arc<StorageEngine>,
        ordinal_tracker: Arc<OrdinalTracker>,
        raft: Arc<Raft<FleetosRaftConfig>>,
    ) -> Self {
        Self {
            storage,
            ordinal_tracker,
            scheduler: DefaultScheduler::new(),
            raft,
        }
    }

    /// Reconcile a WorkloadSpec: expand into PodSpecs and schedule them.
    ///
    /// The spec itself is persisted by whoever submitted it (AdminService or the
    /// cron controller) via `FleetosCommand::SubmitWorkloadSpec`. This method only
    /// schedules: it proposes ordinal assignments and placements through Raft.
    /// Schedule broadcasts are emitted by the state machine on apply.
    pub async fn reconcile(&self, spec: &WorkloadSpec) -> Result<(), ControllerError> {
        let replicas: BTreeMap<String, u32> =
            spec.replicas.iter().map(|(k, v)| (k.clone(), *v)).collect();
        let tenant_id = spec.tenant_id.clone();
        let workload_id = spec.workload_id.clone();

        let cluster_state = self.build_cluster_state()?;

        for (role_str, count) in &replicas {
            for ordinal in 0..*count {
                let existing = self.ordinal_tracker.get_assignment(
                    &tenant_id,
                    &workload_id,
                    role_str,
                    ordinal,
                )?;
                if existing.is_some() {
                    continue;
                }

                let pod_id = PodId::new(format!("{}-{}-{}", workload_id, role_str, ordinal));
                let pod_spec =
                    self.build_pod_spec(spec, &pod_id, &tenant_id, &workload_id, role_str, ordinal);

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
                        // Record the ordinal assignment (with node) via Raft.
                        let assignment = OrdinalAssignment {
                            tenant_id: tenant_id.clone(),
                            service: workload_id.clone(),
                            role: role_str.clone(),
                            ordinal,
                            current_pod_id: Some(pod_id.as_str().to_string()),
                            current_node_id: Some(decision.node_id.to_string()),
                        };
                        self.raft
                            .client_write(FleetosCommand::RecordOrdinalAssignment {
                                record: assignment,
                            })
                            .await
                            .map_err(|e| ControllerError::Raft(e.to_string()))?;

                        // Commit the placement via Raft.
                        let placement = crate::scheduler::Placement {
                            pod_id: pod_id.as_str().to_string(),
                            tenant_id: tenant_id.clone(),
                            service: workload_id.clone(),
                            role: role_str.clone(),
                            ordinal,
                            node_id: decision.node_id.clone(),
                            resources: pending_pod.resources,
                        };
                        self.raft
                            .client_write(FleetosCommand::CommitPlacement { record: placement })
                            .await
                            .map_err(|e| ControllerError::Raft(e.to_string()))?;

                        tracing::info!(
                            tenant = %tenant_id, workload = %workload_id, role = %role_str,
                            ordinal = ordinal, pod_id = %pod_id.as_str(),
                            node = %decision.node_id, "scheduled PodSpec"
                        );
                    }
                    Err(e) => {
                        // Ordinal intentionally NOT recorded here so the next
                        // reconcile retries scheduling for this slot.
                        tracing::warn!(
                            pod_id = %pod_id.as_str(), error = %e,
                            "scheduling failed, will retry on next reconcile"
                        );
                    }
                }
            }
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
