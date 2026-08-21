//! Main scheduling engine.
//!
//! Orchestrates the scheduling decision by applying filters and scorers
//! in a deterministic order:
//!
//! 1. **Filter phase** (eliminate unsuitable nodes):
//!    - Node must be schedulable
//!    - Node must have sufficient resources (bin-packing)
//!    - Anti-affinity must be satisfied
//!
//! 2. **Score phase** (rank remaining nodes):
//!    - Topology spread (prefer nodes with fewer pods from same tenant)
//!    - Bin-packing efficiency (prefer nodes that minimize fragmentation)
//!
//! 3. **Select** the highest-scoring node.
//!
//! Determinism: given the same `ClusterState`, the engine must always
//! produce the same decision. This is critical for Raft consistency.

use super::{
    ClusterState, PendingPod, ScheduleDecision, Scheduler, SchedulerError, ScoreBreakdown,
    anti_affinity, binpack, topology,
};

/// The default scheduler engine.
///
/// Applies filters and scorers in a fixed, deterministic order.
pub struct DefaultScheduler {
    /// Anti-affinity configuration.
    anti_affinity_config: anti_affinity::AntiAffinityConfig,

    /// Topology spread configuration.
    topology_config: topology::TopologyConfig,

    /// Bin-packing strategy.
    binpack_strategy: binpack::BinpackStrategy,
}

impl DefaultScheduler {
    pub fn new() -> Self {
        Self {
            anti_affinity_config: anti_affinity::AntiAffinityConfig::default(),
            topology_config: topology::TopologyConfig::default(),
            binpack_strategy: binpack::BinpackStrategy::MostAllocated,
        }
    }

    /// Filter phase: eliminate nodes that cannot host the pod.
    fn filter_nodes<'a>(
        &self,
        pod: &PendingPod,
        state: &'a ClusterState,
    ) -> Vec<&'a super::NodeInfo> {
        let mut candidates = Vec::new();

        for node in state.schedulable_nodes() {
            // Filter 1: Resource capacity
            if !pod.resources.fits_within(&node.available) {
                continue;
            }

            // Filter 2: Anti-affinity
            if !anti_affinity::check_anti_affinity(pod, node, state, &self.anti_affinity_config) {
                continue;
            }

            candidates.push(node);
        }

        candidates
    }

    /// Score phase: rank candidate nodes.
    fn score_nodes<'a>(
        &self,
        pod: &PendingPod,
        candidates: &[&'a super::NodeInfo],
        state: &ClusterState,
    ) -> Vec<(ScoreBreakdown, &'a super::NodeInfo)> {
        let mut scored: Vec<(ScoreBreakdown, &'a super::NodeInfo)> = Vec::new();

        for node in candidates {
            let mut breakdown = ScoreBreakdown {
                anti_affinity_pass: true,
                resource_fit: true,
                ..Default::default()
            };

            // Score 1: Topology spread
            breakdown.topology_score =
                topology::score_topology_spread(pod, node, state, &self.topology_config);

            // Score 2: Bin-packing efficiency
            breakdown.binpack_score =
                binpack::score_binpack(&pod.resources, node, self.binpack_strategy);

            scored.push((breakdown, node));
        }

        // Sort by combined score (topology first, then binpack as tiebreaker).
        // Deterministic ordering is critical for Raft consistency.
        scored.sort_by(|a, b| {
            let a_total = a.0.topology_score * 1000.0 + a.0.binpack_score;
            let b_total = b.0.topology_score * 1000.0 + b.0.binpack_score;

            b_total
                .partial_cmp(&a_total)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.1.node_id.to_string().cmp(&b.1.node_id.to_string()))
        });

        scored
    }
}

impl Scheduler for DefaultScheduler {
    fn schedule(
        &self,
        pod: &PendingPod,
        state: &ClusterState,
    ) -> Result<ScheduleDecision, SchedulerError> {
        // Phase 1: Filter
        let candidates = self.filter_nodes(pod, state);

        if candidates.is_empty() {
            return Err(SchedulerError::NoSuitableNode {
                pod_id: pod.pod_id.clone(),
                reason: "no nodes passed all filters (capacity + anti-affinity)".to_owned(),
            });
        }

        // Phase 2: Score
        let scored = self.score_nodes(pod, &candidates, state);

        // Phase 3: Select the best node
        let (best_breakdown, best_node) =
            scored
                .first()
                .ok_or_else(|| SchedulerError::NoSuitableNode {
                    pod_id: pod.pod_id.clone(),
                    reason: "scoring produced no results".to_owned(),
                })?;

        Ok(ScheduleDecision {
            node_id: best_node.node_id.clone(),
            pod_id: pod.pod_id.clone(),
            score_breakdown: best_breakdown.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::ResourceSpec;

    fn make_node(id: &str, cpu: u64, mem: u64) -> super::super::NodeInfo {
        super::super::NodeInfo {
            node_id: format!("spiffe://test.internal/ns/system/node/{}", id)
                .parse()
                .unwrap(),
            capacity: ResourceSpec {
                cpu_millicores: cpu,
                memory_bytes: mem,
            },
            available: ResourceSpec {
                cpu_millicores: cpu,
                memory_bytes: mem,
            },
            failure_domain: "zone-a".to_owned(),
            schedulable: true,
            pod_count: 0,
        }
    }

    fn make_pod(id: &str, service: &str, role: &str, ordinal: u32) -> PendingPod {
        PendingPod {
            pod_id: id.to_owned(),
            tenant_id: "tenant-1".to_owned(),
            service: service.to_owned(),
            role: role.to_owned(),
            ordinal,
            resources: ResourceSpec {
                cpu_millicores: 500,
                memory_bytes: 512 * 1024 * 1024,
            },
            previous_node: None,
        }
    }

    #[test]
    fn schedules_to_available_node() {
        let scheduler = DefaultScheduler::new();
        let state = ClusterState {
            nodes: vec![make_node("node-1", 4000, 8 * 1024 * 1024 * 1024)],
            placements: vec![],
        };

        let pod = make_pod("pod-1", "web", "primary", 0);
        let decision = scheduler.schedule(&pod, &state).unwrap();

        assert_eq!(
            decision.node_id.to_string(),
            "spiffe://test.internal/ns/system/node/node-1"
        );
    }

    #[test]
    fn rejects_when_no_capacity() {
        let scheduler = DefaultScheduler::new();
        let state = ClusterState {
            nodes: vec![super::super::NodeInfo {
                node_id: "spiffe://test.internal/ns/system/node/node-1"
                    .parse()
                    .unwrap(),
                capacity: ResourceSpec {
                    cpu_millicores: 100,
                    memory_bytes: 64 * 1024 * 1024,
                },
                available: ResourceSpec {
                    cpu_millicores: 100,
                    memory_bytes: 64 * 1024 * 1024,
                },
                failure_domain: "zone-a".to_owned(),
                schedulable: true,
                pod_count: 0,
            }],
            placements: vec![],
        };

        let pod = make_pod("pod-1", "web", "primary", 0);
        let result = scheduler.schedule(&pod, &state);

        assert!(matches!(result, Err(SchedulerError::NoSuitableNode { .. })));
    }

    #[test]
    fn rejects_cordoned_node() {
        let scheduler = DefaultScheduler::new();
        let state = ClusterState {
            nodes: vec![super::super::NodeInfo {
                node_id: "spiffe://test.internal/ns/system/node/node-1"
                    .parse()
                    .unwrap(),
                capacity: ResourceSpec {
                    cpu_millicores: 4000,
                    memory_bytes: 8 * 1024 * 1024 * 1024,
                },
                available: ResourceSpec {
                    cpu_millicores: 4000,
                    memory_bytes: 8 * 1024 * 1024 * 1024,
                },
                failure_domain: "zone-a".to_owned(),
                schedulable: false, // Cordoned
                pod_count: 0,
            }],
            placements: vec![],
        };

        let pod = make_pod("pod-1", "web", "primary", 0);
        let result = scheduler.schedule(&pod, &state);

        assert!(matches!(result, Err(SchedulerError::NoSuitableNode { .. })));
    }
}
