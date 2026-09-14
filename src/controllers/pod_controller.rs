use super::ControllerError;
use crate::raft::{FleetosCommand, FleetosRaftConfig};
use crate::scheduler::OrdinalTracker;
use fleetos_core::spiffe::PodId;
use openraft::Raft;
use std::sync::Arc;

/// CR-CTRL-3: grace window before a "started but policy not enforced" pod is
/// escalated to the death/replace path. A pod running without its eBPF policy
/// is a security invariant violation (Ruling D). Tune against observed
/// agent policy-apply latency.
pub const READINESS_GATE_GRACE_SECS: i64 = 30;

/// Returns true if the pod has sustained a readiness-gate violation
/// (started but policy not enforced) beyond the grace window. Such a pod is
/// running in a policy vacuum and must be replaced. Wall-clock reads live
/// here (leader-gated controller), never in the state machine.
pub fn readiness_gate_violation_sustained(
    record: &crate::raft::records::WorkloadStatusRecord,
    grace_secs: i64,
    now_unix: i64,
) -> bool {
    record.gate_violation_since_unix > 0
        && (now_unix - record.gate_violation_since_unix) > grace_secs
}

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
            .client_write(crate::raft::AuditedCommand::system(
                FleetosCommand::ReassignPodId {
                    tenant_id: tenant_id.to_owned(),
                    service: workload_id.to_owned(),
                    role: role.to_owned(),
                    ordinal,
                    new_pod_id: new_pod_id.as_str().to_string(),
                },
            ))
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
                    .client_write(crate::raft::AuditedCommand::system(
                        FleetosCommand::RecordOrdinalAssignment { record: freed },
                    ))
                    .await
                    .map_err(|e| ControllerError::Raft(e.to_string()))?;

                if let Some(ref pod_id) = assignment.current_pod_id {
                    self.raft
                        .client_write(crate::raft::AuditedCommand::system(
                            FleetosCommand::RemovePlacement {
                                pod_id: pod_id.clone(),
                            },
                        ))
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

#[cfg(test)]
mod readiness_gate_tests {
    use super::*;
    use crate::raft::records::WorkloadStatusRecord;

    fn make_status(
        started: bool,
        policy_enforced: bool,
        router_connected: bool,
        gate_violation_since_unix: i64,
    ) -> WorkloadStatusRecord {
        WorkloadStatusRecord {
            pod_id: "test-pod".to_owned(),
            workload_id: "test-wl".to_owned(),
            tenant_id: "test-tenant".to_owned(),
            ready: true,
            live: true,
            observed_at_unix: 1000,
            restart_count: 0,
            started,
            policy_enforced,
            router_connected,
            gate_violation_since_unix,
        }
    }

    #[test]
    fn violation_older_than_grace_is_true() {
        let record = make_status(true, false, true, 1000);
        let now = 1000 + READINESS_GATE_GRACE_SECS + 10;
        assert!(readiness_gate_violation_sustained(
            &record,
            READINESS_GATE_GRACE_SECS,
            now
        ));
    }

    #[test]
    fn violation_within_grace_is_false() {
        let record = make_status(true, false, true, 1000);
        let now = 1000 + READINESS_GATE_GRACE_SECS - 10;
        assert!(!readiness_gate_violation_sustained(
            &record,
            READINESS_GATE_GRACE_SECS,
            now
        ));
    }

    #[test]
    fn no_violation_is_false() {
        // Policy is enforced and router connected, so gate_violation_since_unix should be 0
        let record = make_status(true, true, true, 0);
        let now = 5000;
        assert!(!readiness_gate_violation_sustained(
            &record,
            READINESS_GATE_GRACE_SECS,
            now
        ));
        // Not started yet, so no violation can be sustained
        let record_not_started = make_status(false, false, true, 0);
        assert!(!readiness_gate_violation_sustained(
            &record_not_started,
            READINESS_GATE_GRACE_SECS,
            now
        ));
    }

    #[test]
    fn router_disconnected_is_violation() {
        // Started, policy enforced, but router disconnected -> violation
        let record = make_status(true, true, false, 1000);
        let now = 1000 + READINESS_GATE_GRACE_SECS + 10;
        assert!(readiness_gate_violation_sustained(
            &record,
            READINESS_GATE_GRACE_SECS,
            now
        ));
    }
}
