//! Topology spread scoring.
//!
//! Balances tenant workloads across available agents.
//! This is a SCORE, not a filter — nodes with better distribution
//! get higher scores, but poorly-distributed nodes aren't eliminated.

use super::{ClusterState, NodeInfo, PendingPod};

/// Topology spread configuration.
#[derive(Debug, Clone)]
pub struct TopologyConfig {
    /// Weight for tenant distribution scoring.
    /// Higher weight means stronger preference for spreading tenants.
    pub tenant_spread_weight: f64,

    /// Weight for overall pod distribution.
    /// Higher weight means stronger preference for nodes with fewer pods.
    pub pod_spread_weight: f64,
}

impl Default for TopologyConfig {
    fn default() -> Self {
        Self {
            tenant_spread_weight: 1.0,
            pod_spread_weight: 0.5,
        }
    }
}

/// Score a node for topology spread.
///
/// Higher score = better distribution (prefer this node).
/// Score is normalized to [0.0, 1.0] range.
pub fn score_topology_spread(
    pod: &PendingPod,
    node: &NodeInfo,
    state: &ClusterState,
    config: &TopologyConfig,
) -> f64 {
    let mut score = 0.0;

    // Score 1: Tenant distribution.
    // Prefer nodes with fewer pods from the same tenant.
    let tenant_pods_on_node = state
        .placements_on_node(&node.node_id)
        .iter()
        .filter(|p| p.tenant_id == pod.tenant_id)
        .count();

    let total_tenant_pods = state.placements_for_tenant(&pod.tenant_id).len();
    let total_nodes = state.nodes.len().max(1);

    // Ideal distribution: tenant_pods / total_nodes per node.
    // Score is higher when the node has fewer than the ideal.
    let ideal_per_node = total_tenant_pods as f64 / total_nodes as f64;
    let tenant_score = if tenant_pods_on_node as f64 <= ideal_per_node {
        1.0
    } else {
        // Penalize proportionally to how much we exceed the ideal.
        let excess = tenant_pods_on_node as f64 - ideal_per_node;
        (1.0 - (excess / (ideal_per_node + 1.0))).max(0.0)
    };

    score += tenant_score * config.tenant_spread_weight;

    // Score 2: Overall pod distribution.
    // Prefer nodes with fewer total pods (spread load).
    let pod_count = node.pod_count as f64;
    let max_pods = state.nodes.iter().map(|n| n.pod_count).max().unwrap_or(1) as f64;

    let pod_score = if max_pods > 0.0 {
        1.0 - (pod_count / max_pods)
    } else {
        1.0
    };

    score += pod_score * config.pod_spread_weight;

    // Normalize to [0, 1]
    let max_possible = config.tenant_spread_weight + config.pod_spread_weight;
    if max_possible > 0.0 {
        score / max_possible
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::ResourceSpec;

    fn make_node(id: &str, pod_count: u32) -> NodeInfo {
        NodeInfo {
            node_id: format!("spiffe://test.internal/ns/system/node/{}", id)
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
            schedulable: true,
            pod_count,
        }
    }

    #[test]
    fn empty_node_scores_higher_than_busy_node() {
        let config = TopologyConfig::default();
        let empty_node = make_node("node-1", 0);
        let busy_node = make_node("node-2", 10);

        let state = ClusterState {
            nodes: vec![empty_node.clone(), busy_node.clone()],
            placements: vec![],
        };

        let pod = PendingPod {
            pod_id: "pod-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            service: "web".to_owned(),
            role: "primary".to_owned(),
            ordinal: 0,
            resources: ResourceSpec::zero(),
            previous_node: None,
        };

        let empty_score = score_topology_spread(&pod, &empty_node, &state, &config);
        let busy_score = score_topology_spread(&pod, &busy_node, &state, &config);

        assert!(empty_score > busy_score);
    }

    #[test]
    fn node_with_fewer_same_tenant_pods_scores_higher() {
        let config = TopologyConfig::default();
        let node_a = make_node("node-1", 2);
        let node_b = make_node("node-2", 2);

        // node-1 has 2 pods from tenant-1, node-2 has 0
        let placements = vec![
            super::super::Placement {
                pod_id: "pod-a".to_owned(),
                tenant_id: "tenant-1".to_owned(),
                service: "web".to_owned(),
                role: "primary".to_owned(),
                ordinal: 0,
                node_id: node_a.node_id.clone(),
                resources: ResourceSpec::zero(),
            },
            super::super::Placement {
                pod_id: "pod-b".to_owned(),
                tenant_id: "tenant-1".to_owned(),
                service: "web".to_owned(),
                role: "replica".to_owned(),
                ordinal: 0,
                node_id: node_a.node_id.clone(),
                resources: ResourceSpec::zero(),
            },
        ];

        let state = ClusterState {
            nodes: vec![node_a.clone(), node_b.clone()],
            placements,
        };

        let pod = PendingPod {
            pod_id: "pod-c".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            service: "web".to_owned(),
            role: "replica".to_owned(),
            ordinal: 1,
            resources: ResourceSpec::zero(),
            previous_node: None,
        };

        let score_a = score_topology_spread(&pod, &node_a, &state, &config);
        let score_b = score_topology_spread(&pod, &node_b, &state, &config);

        // node_b has fewer tenant-1 pods, so it should score higher
        assert!(score_b > score_a);
    }
}
