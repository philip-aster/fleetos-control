//! Workload controller — expands WorkloadSpecs into PodSpecs and schedules them.
//!
//! CR-CTRL-9 scheduling parity:
//! - Pending pods across all given specs are ordered by (priority desc,
//!   pod_id asc) before scheduling.
//! - Taint/toleration filtering is enforced by the scheduler engine.
//! - Preemption: a pending pod with `priority > 0` that failed scheduling
//!   may evict strictly-lower-priority pods from a node where it would then
//!   fit. Victims lose placement + ordinal slot and are re-scheduled on a
//!   later cycle. SEAM: preemption does not consult a disruption budget yet;
//!   CR-CTRL-6 plugs the `DisruptionGuard` in at `apply_preemption`.
use super::ControllerError;
use crate::raft::records::NodeTaint;
use crate::raft::{AuditedCommand, FleetosCommand, FleetosRaftConfig};
use crate::scheduler::{
    ClusterState, OrdinalTracker, PendingPod, Placement, PreemptionPlan, ScheduleDecision,
    Scheduler, engine::DefaultScheduler, ordinal::OrdinalAssignment, taints,
};
use crate::storage::StorageEngine;
use crate::watch::pod_event_store::PodEventEmitter;
use fleetos_core::proto::state::PodEvent;
use fleetos_core::proto::workload::WorkloadSpec;
use fleetos_core::spiffe::PodId;
use openraft::Raft;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

pub struct WorkloadController {
    storage: Arc<StorageEngine>,
    ordinal_tracker: Arc<OrdinalTracker>,
    scheduler: DefaultScheduler,
    raft: Arc<Raft<FleetosRaftConfig>>,
    dummy_ip_allocator: Arc<crate::dummy_ip::allocator::DummyIpAllocator>,
    pod_event_emitter: Arc<PodEventEmitter>,
    /// CR-CTRL-9: replicated operator taints, keyed by node_id.
    node_taints: fjall::Keyspace,
}

impl WorkloadController {
    pub fn new(
        storage: Arc<StorageEngine>,
        ordinal_tracker: Arc<OrdinalTracker>,
        raft: Arc<Raft<FleetosRaftConfig>>,
        dummy_ip_allocator: Arc<crate::dummy_ip::allocator::DummyIpAllocator>,
        pod_event_emitter: Arc<PodEventEmitter>,
        node_taints: fjall::Keyspace,
    ) -> Self {
        Self {
            storage,
            ordinal_tracker,
            scheduler: DefaultScheduler::new(),
            raft,
            dummy_ip_allocator,
            pod_event_emitter,
            node_taints,
        }
    }

    /// Reconcile a single WorkloadSpec (cron-trigger path).
    pub async fn reconcile(&self, spec: &WorkloadSpec) -> Result<(), ControllerError> {
        self.reconcile_all(std::slice::from_ref(spec)).await
    }

    /// Batch reconcile: collect pending pods across all specs, order by
    /// priority, schedule, preempt where justified, allocate service IPs.
    pub async fn reconcile_all(&self, specs: &[WorkloadSpec]) -> Result<(), ControllerError> {
        if specs.is_empty() {
            return Ok(());
        }
        let cluster_state = self.build_cluster_state()?;

        // Pass 1: collect pending pods across all specs.
        let mut pending: Vec<PendingPod> = Vec::new();
        for spec in specs {
            let replicas: BTreeMap<String, u32> =
                spec.replicas.iter().map(|(k, v)| (k.clone(), *v)).collect();
            for (role_str, count) in &replicas {
                for ordinal in 0..*count {
                    let existing = self.ordinal_tracker.get_assignment(
                        &spec.tenant_id,
                        &spec.workload_id,
                        role_str,
                        ordinal,
                    )?;
                    if existing.is_some() {
                        continue;
                    }
                    let pod_id =
                        PodId::new(format!("{}-{}-{}", spec.workload_id, role_str, ordinal));
                    let pod_spec = self.build_pod_spec(
                        spec,
                        &pod_id,
                        &spec.tenant_id,
                        &spec.workload_id,
                        role_str,
                        ordinal,
                    );
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
                    pending.push(PendingPod {
                        pod_id: pod_id.as_str().to_string(),
                        tenant_id: spec.tenant_id.clone(),
                        service: spec.workload_id.clone(),
                        role: role_str.clone(),
                        ordinal,
                        resources,
                        previous_node: None,
                        priority: pod_spec.priority,
                        tolerations: pod_spec.tolerations.clone(),
                    });
                }
            }
        }

        // Pass 2: priority-aware ordering (CR-CTRL-9).
        order_pending(&mut pending);

        // Pass 3: schedule in order.
        let mut unscheduled: Vec<PendingPod> = Vec::new();
        for pod in pending {
            match self.scheduler.schedule(&pod, &cluster_state) {
                Ok(decision) => {
                    self.commit_scheduling(&pod, &decision).await?;
                }
                Err(e) => {
                    // Ordinal intentionally NOT recorded here so the next
                    // reconcile retries scheduling for this slot.
                    tracing::warn!(
                        pod_id = %pod.pod_id, error = %e,
                        "scheduling failed, will retry on next reconcile"
                    );
                    // CR-CTRL-7: FailedScheduling is the one pod event control owns.
                    self.pod_event_emitter.emit(PodEvent {
                        pod_id: pod.pod_id.clone(),
                        node_id: String::new(),
                        event_type: "FailedScheduling".to_owned(),
                        reason: "Unschedulable".to_owned(),
                        message: e.to_string(),
                        timestamp_unix: 0,
                        count: 1,
                    });
                    unscheduled.push(pod);
                }
            }
        }

        // Pass 4: preemption for priority > 0 pods (CR-CTRL-9).
        if !unscheduled.is_empty() {
            let priorities = workload_priority_map(specs);
            for pod in unscheduled.iter().filter(|p| p.priority > 0) {
                if let Some(plan) = find_preemption_plan(pod, &cluster_state, &|p: &Placement| {
                    *priorities
                        .get(&(p.tenant_id.clone(), p.service.clone()))
                        .unwrap_or(&0)
                }) {
                    self.apply_preemption(pod, &plan).await?;
                }
            }
        }

        // Pass 5: dummy service addresses (idempotent, S-9).
        for spec in specs {
            self.allocate_service_addresses(spec).await?;
        }
        Ok(())
    }

    /// CR-CTRL-9: deterministic priority ordering — higher priority first,
    /// pod_id ascending as the tiebreak.
    pub fn order_pending(pending: &mut [PendingPod]) {
        order_pending(pending);
    }

    /// Record the ordinal assignment and commit the placement via Raft.
    async fn commit_scheduling(
        &self,
        pod: &PendingPod,
        decision: &ScheduleDecision,
    ) -> Result<(), ControllerError> {
        let assignment = OrdinalAssignment {
            tenant_id: pod.tenant_id.clone(),
            service: pod.service.clone(),
            role: pod.role.clone(),
            ordinal: pod.ordinal,
            current_pod_id: Some(pod.pod_id.clone()),
            current_node_id: Some(decision.node_id.to_string()),
        };
        self.raft
            .client_write(AuditedCommand::system(
                FleetosCommand::RecordOrdinalAssignment { record: assignment },
            ))
            .await
            .map_err(|e| ControllerError::Raft(e.to_string()))?;
        let placement = Placement {
            pod_id: pod.pod_id.clone(),
            tenant_id: pod.tenant_id.clone(),
            service: pod.service.clone(),
            role: pod.role.clone(),
            ordinal: pod.ordinal,
            node_id: decision.node_id.clone(),
            resources: pod.resources,
        };
        self.raft
            .client_write(AuditedCommand::system(FleetosCommand::CommitPlacement {
                record: placement,
            }))
            .await
            .map_err(|e| ControllerError::Raft(e.to_string()))?;
        tracing::info!(
            tenant = %pod.tenant_id, service = %pod.service, role = %pod.role,
            ordinal = pod.ordinal, pod_id = %pod.pod_id,
            node = %decision.node_id, "scheduled PodSpec"
        );
        Ok(())
    }

    /// CR-CTRL-9: evict preemption victims, then place the preemptor.
    /// SEAM: CR-CTRL-6's DisruptionGuard plugs in here (victims are
    /// involuntary evictions; budgets will gate them once they land).
    async fn apply_preemption(
        &self,
        pod: &PendingPod,
        plan: &PreemptionPlan,
    ) -> Result<(), ControllerError> {
        for victim in &plan.victims {
            self.pod_event_emitter.emit(PodEvent {
                pod_id: victim.pod_id.clone(),
                node_id: victim.node_id.to_string(),
                event_type: "Evicting".to_owned(),
                reason: "Preemption".to_owned(),
                message: format!("preempted by {}", pod.pod_id),
                timestamp_unix: 0,
                count: 1,
            });
            self.raft
                .client_write(AuditedCommand::system(FleetosCommand::RemovePlacement {
                    pod_id: victim.pod_id.clone(),
                }))
                .await
                .map_err(|e| ControllerError::Raft(e.to_string()))?;
            let freed = OrdinalAssignment {
                tenant_id: victim.tenant_id.clone(),
                service: victim.service.clone(),
                role: victim.role.clone(),
                ordinal: victim.ordinal,
                current_pod_id: None,
                current_node_id: None,
            };
            self.raft
                .client_write(AuditedCommand::system(
                    FleetosCommand::RecordOrdinalAssignment { record: freed },
                ))
                .await
                .map_err(|e| ControllerError::Raft(e.to_string()))?;
        }
        let decision = ScheduleDecision {
            node_id: plan.node_id.clone(),
            pod_id: pod.pod_id.clone(),
            score_breakdown: Default::default(),
        };
        self.commit_scheduling(pod, &decision).await?;
        tracing::info!(
            pod_id = %pod.pod_id, node = %plan.node_id, victims = plan.victims.len(),
            "preemption applied"
        );
        Ok(())
    }

    /// S-9: ensure dummy service addresses for every (tenant, service, role).
    async fn allocate_service_addresses(&self, spec: &WorkloadSpec) -> Result<(), ControllerError> {
        let replicas: BTreeMap<String, u32> =
            spec.replicas.iter().map(|(k, v)| (k.clone(), *v)).collect();
        for role_str in replicas.keys() {
            if self
                .dummy_ip_allocator
                .get_service_address(&spec.tenant_id, &spec.workload_id, role_str)
                .map_err(ControllerError::DummyIp)?
                .is_none()
            {
                let (block, address) = self
                    .dummy_ip_allocator
                    .compute_service_address_allocation(
                        &spec.tenant_id,
                        &spec.workload_id,
                        role_str,
                    )
                    .map_err(ControllerError::DummyIp)?;
                self.raft
                    .client_write(AuditedCommand::system(
                        FleetosCommand::AllocateServiceAddress { block, address },
                    ))
                    .await
                    .map_err(|e| ControllerError::Raft(e.to_string()))?;
                tracing::info!(
                    tenant = %spec.tenant_id, workload = %spec.workload_id, role = %role_str,
                    "allocated dummy service address"
                );
            }
        }
        Ok(())
    }

    /// Build the scheduler's cluster view, including replicated node taints.
    fn build_cluster_state(&self) -> Result<ClusterState, ControllerError> {
        let node_records = self
            .storage
            .list_node_records()
            .map_err(ControllerError::Storage)?;
        let placements = self
            .storage
            .list_placements()
            .map_err(ControllerError::Storage)?;
        let mut taints: HashMap<String, Vec<NodeTaint>> = HashMap::new();
        for guard in self.node_taints.prefix(Vec::<u8>::new()) {
            let (key, value) = guard
                .into_inner()
                .map_err(|e| ControllerError::Storage(crate::storage::StorageError::Storage(e)))?;
            if let Ok(node_taints) = postcard::from_bytes::<Vec<NodeTaint>>(value.as_ref()) {
                taints.insert(
                    String::from_utf8_lossy(key.as_ref()).to_string(),
                    node_taints,
                );
            }
        }
        Ok(ClusterState::build(&node_records, placements, &taints))
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
    ) -> fleetos_core::proto::workload::PodSpec {
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

/// CR-CTRL-9: deterministic priority ordering — higher priority first,
/// pod_id ascending as the tiebreak.
pub fn order_pending(pending: &mut [PendingPod]) {
    pending.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.pod_id.cmp(&b.pod_id))
    });
}

/// (tenant_id, workload_id) -> PodSpec.priority for preemption victim ranking.
pub fn workload_priority_map(specs: &[WorkloadSpec]) -> HashMap<(String, String), i32> {
    specs
        .iter()
        .map(|s| {
            (
                (s.tenant_id.clone(), s.workload_id.clone()),
                s.pod_spec.as_ref().map(|p| p.priority).unwrap_or(0),
            )
        })
        .collect()
}

/// CR-CTRL-9 preemption analysis — pure and deterministic.
///
/// Finds the best (node, victims) pair such that evicting strictly-lower-
/// priority pods lets `pod` fit. Best = fewest victims, then lowest victim
/// priority sum, then node_id string. Returns None if no node works.
pub fn find_preemption_plan(
    pod: &PendingPod,
    state: &ClusterState,
    workload_priority: &dyn Fn(&Placement) -> i32,
) -> Option<PreemptionPlan> {
    let mut best: Option<PreemptionPlan> = None;
    for node in state.schedulable_nodes() {
        if !taints::passes_taint_filter(&pod.tolerations, &node.taints) {
            continue;
        }
        // Eligible victims: strictly lower priority, deterministic order
        // (priority asc, then pod_id asc).
        let mut candidates: Vec<Placement> = state
            .placements_on_node(&node.node_id)
            .into_iter()
            .filter(|p| workload_priority(p) < pod.priority)
            .cloned()
            .collect();
        candidates.sort_by(|a, b| {
            workload_priority(a)
                .cmp(&workload_priority(b))
                .then_with(|| a.pod_id.cmp(&b.pod_id))
        });
        let mut available = node.available;
        let mut victims: Vec<Placement> = Vec::new();
        for victim in candidates {
            if pod.resources.fits_within(&available) {
                break;
            }
            available = available.add(&victim.resources);
            victims.push(victim);
        }
        if !pod.resources.fits_within(&available) {
            continue; // does not fit even after all eligible victims
        }
        let plan = PreemptionPlan {
            node_id: node.node_id.clone(),
            victims,
        };
        let better = match &best {
            None => true,
            Some(b) => {
                let sum = |p: &PreemptionPlan| -> i64 {
                    p.victims.iter().map(|v| workload_priority(v) as i64).sum()
                };
                (plan.victims.len(), sum(&plan), plan.node_id.to_string())
                    < (b.victims.len(), sum(b), b.node_id.to_string())
            }
        };
        if better {
            best = Some(plan);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::{NodeInfo, ResourceSpec};
    use fleetos_core::spiffe::SpiffeId;

    fn node(id: &str, cpu_avail: u64, taints: Vec<NodeTaint>) -> NodeInfo {
        NodeInfo {
            node_id: format!("spiffe://t.internal/ns/system/node/{}", id)
                .parse::<SpiffeId>()
                .unwrap(),
            capacity: ResourceSpec {
                cpu_millicores: 4000,
                memory_bytes: 8 * 1024 * 1024 * 1024,
            },
            available: ResourceSpec {
                cpu_millicores: cpu_avail,
                memory_bytes: 8 * 1024 * 1024 * 1024,
            },
            failure_domain: "zone-a".to_owned(),
            schedulable: true,
            pod_count: 1,
            taints,
        }
    }

    fn placement(pod: &str, service: &str, node: &str, cpu: u64) -> Placement {
        Placement {
            pod_id: pod.to_owned(),
            tenant_id: "t1".to_owned(),
            service: service.to_owned(),
            role: "r".to_owned(),
            ordinal: 0,
            node_id: format!("spiffe://t.internal/ns/system/node/{}", node)
                .parse::<SpiffeId>()
                .unwrap(),
            resources: ResourceSpec {
                cpu_millicores: cpu,
                memory_bytes: 512 * 1024 * 1024,
            },
        }
    }

    fn pending(pod: &str, priority: i32, cpu: u64) -> PendingPod {
        PendingPod {
            pod_id: pod.to_owned(),
            tenant_id: "t1".to_owned(),
            service: "web".to_owned(),
            role: "r".to_owned(),
            ordinal: 0,
            resources: ResourceSpec {
                cpu_millicores: cpu,
                memory_bytes: 512 * 1024 * 1024,
            },
            previous_node: None,
            priority,
            tolerations: vec![],
        }
    }

    #[test]
    fn order_pending_priority_then_pod_id() {
        let mut pods = vec![
            pending("b-pod", 1, 100),
            pending("a-pod", 5, 100),
            pending("c-pod", 5, 100),
            pending("d-pod", 0, 100),
        ];
        order_pending(&mut pods);
        let ids: Vec<&str> = pods.iter().map(|p| p.pod_id.as_str()).collect();
        assert_eq!(ids, vec!["a-pod", "c-pod", "b-pod", "d-pod"]);
    }

    #[test]
    fn preemption_requires_strictly_lower_priority_victims() {
        let state = ClusterState {
            nodes: vec![node("n1", 0, vec![])],
            placements: vec![placement("victim", "db", "n1", 1000)],
        };
        let prio = |p: &Placement| if p.service == "db" { 5 } else { 0 };
        // Equal priority: never preempt.
        let pod_equal = pending("new", 5, 1000);
        assert!(find_preemption_plan(&pod_equal, &state, &prio).is_none());
        // Higher priority: preempts.
        let pod_higher = pending("new", 6, 1000);
        let plan = find_preemption_plan(&pod_higher, &state, &prio).unwrap();
        assert_eq!(plan.victims.len(), 1);
        assert_eq!(plan.victims[0].pod_id, "victim");
    }

    #[test]
    fn preemption_prefers_fewer_victims_then_lower_priority_sum() {
        let state = ClusterState {
            nodes: vec![node("n1", 0, vec![]), node("n2", 0, vec![])],
            placements: vec![
                // n1: one medium victim freeing enough.
                placement("v-med", "db", "n1", 2000),
                // n2: two low-priority victims needed.
                placement("v-lo-a", "cache", "n2", 1000),
                placement("v-lo-b", "cache", "n2", 1000),
            ],
        };
        let prio = |p: &Placement| match p.service.as_str() {
            "db" => 4,
            _ => 1,
        };
        let pod = pending("new", 9, 2000);
        let plan = find_preemption_plan(&pod, &state, &prio).unwrap();
        assert_eq!(plan.victims.len(), 1, "fewest victims wins");
        assert_eq!(plan.victims[0].pod_id, "v-med");
    }

    #[test]
    fn no_preemption_when_nothing_fits() {
        let state = ClusterState {
            nodes: vec![node("n1", 0, vec![])],
            placements: vec![placement("victim", "db", "n1", 500)],
        };
        let prio = |_p: &Placement| 1;
        let pod = pending("new", 9, 4000); // bigger than node capacity
        assert!(find_preemption_plan(&pod, &state, &prio).is_none());
    }

    #[test]
    fn preemption_skips_tainted_nodes_pod_cannot_tolerate() {
        let state = ClusterState {
            nodes: vec![node(
                "n1",
                0,
                vec![NodeTaint {
                    key: "maint".to_owned(),
                    value: String::new(),
                    effect: "NoSchedule".to_owned(),
                    time_added_unix: 0,
                }],
            )],
            placements: vec![placement("victim", "db", "n1", 2000)],
        };
        let prio = |_p: &Placement| 1;
        let pod = pending("new", 9, 1000);
        assert!(find_preemption_plan(&pod, &state, &prio).is_none());
    }

    #[test]
    fn preemption_plan_is_deterministic_100x() {
        let state = ClusterState {
            nodes: vec![node("n1", 0, vec![]), node("n2", 100, vec![])],
            placements: vec![
                placement("v-a", "db", "n1", 1000),
                placement("v-b", "db", "n1", 1000),
                placement("v-c", "cache", "n2", 500),
            ],
        };
        let prio = |p: &Placement| if p.service == "db" { 3 } else { 1 };
        let pod = pending("new", 9, 1500);
        let first = find_preemption_plan(&pod, &state, &prio).unwrap();
        for _ in 0..100 {
            let again = find_preemption_plan(&pod, &state, &prio).unwrap();
            assert_eq!(again, first);
        }
    }

    #[test]
    fn workload_priority_map_defaults_to_zero() {
        let spec = WorkloadSpec {
            tenant_id: "t1".to_owned(),
            workload_id: "web".to_owned(),
            ..Default::default()
        };
        let map = workload_priority_map(&[spec]);
        assert_eq!(map[&("t1".to_owned(), "web".to_owned())], 0);
    }
}
