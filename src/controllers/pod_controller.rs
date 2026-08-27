use super::ControllerError;
use crate::raft::{FleetosCommand, FleetosRaftConfig};
use crate::scheduler::OrdinalTracker;
use fleetos_core::spiffe::PodId;
use openraft::Raft;
use std::sync::Arc;

pub struct PodController {
    ordinal_tracker: Arc<OrdinalTracker>,
    raft: Arc<Raft<FleetosRaftConfig>>,
}

impl PodController {
    pub fn new(ordinal_tracker: Arc<OrdinalTracker>, raft: Arc<Raft<FleetosRaftConfig>>) -> Self {
        Self {
            ordinal_tracker,
            raft,
        }
    }

    /// Replace a dead pod in place: same ordinal slot, fresh pod_id.
    pub async fn reconcile_dead_pod(
        &self,
        tenant_id: &str,
        workload_id: &str,
        role: &str,
        ordinal: u32,
    ) -> Result<(), ControllerError> {
        let _assignment = self
            .ordinal_tracker
            .get_assignment(tenant_id, workload_id, role, ordinal)?
            .ok_or_else(|| {
                ControllerError::Storage(crate::storage::StorageError::NotFound(format!(
                    "ordinal assignment for {}:{}:{}:{}",
                    tenant_id, workload_id, role, ordinal
                )))
            })?;

        let new_pod_id = PodId::new(format!("{}-{}-{}", workload_id, role, ordinal));
        self.raft
            .client_write(FleetosCommand::ReassignPodId {
                tenant_id: tenant_id.to_owned(),
                service: workload_id.to_owned(),
                role: role.to_owned(),
                ordinal,
                new_pod_id: new_pod_id.as_str().to_string(),
            })
            .await
            .map_err(|e| ControllerError::Raft(e.to_string()))?;

        tracing::info!(
            tenant = %tenant_id, workload = %workload_id, role = %role, ordinal = ordinal,
            new_pod_id = %new_pod_id.as_str(), "pod replaced in place (ordinal preserved)"
        );
        Ok(())
    }

    /// Scale-down: free ordinal slots at/above new_count and remove placements.
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
                // Free the ordinal slot (record with no pod/node) via Raft.
                let freed = crate::scheduler::ordinal::OrdinalAssignment {
                    tenant_id: tenant_id.to_owned(),
                    service: workload_id.to_owned(),
                    role: role.to_owned(),
                    ordinal: assignment.ordinal,
                    current_pod_id: None,
                    current_node_id: None,
                };
                self.raft
                    .client_write(FleetosCommand::RecordOrdinalAssignment { record: freed })
                    .await
                    .map_err(|e| ControllerError::Raft(e.to_string()))?;

                if let Some(ref pod_id) = assignment.current_pod_id {
                    self.raft
                        .client_write(FleetosCommand::RemovePlacement {
                            pod_id: pod_id.clone(),
                        })
                        .await
                        .map_err(|e| ControllerError::Raft(e.to_string()))?;
                }
                tracing::info!(
                    tenant = %tenant_id, workload = %workload_id, role = %role,
                    ordinal = assignment.ordinal, "ordinal freed (scale-down)"
                );
            }
        }
        Ok(())
    }
}
