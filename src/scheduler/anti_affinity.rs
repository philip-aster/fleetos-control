//! Anti-affinity enforcement.
//!
//! If a role is `replica`, it must not be scheduled on the same physical node
//! (or failure domain/zone) as the `primary` or another `replica` of the same service.
//!
//! This is a FILTER, not a score — nodes violating anti-affinity are eliminated
//! entirely from the candidate set.

use super::{ClusterState, NodeInfo, PendingPod};

/// Anti-affinity configuration.
#[derive(Debug, Clone)]
pub struct AntiAffinityConfig {
    /// Whether to enforce anti-affinity across failure domains (zones).
    /// If true, replicas of the same service cannot be in the same zone
    /// as the primary or sibling replicas.
    pub cross_zone: bool,

    /// Roles that require anti-affinity.
    /// Default: ["replica"] — replicas must be spread.
    pub enforced_roles: Vec<String>,
}

impl Default for AntiAffinityConfig {
    fn default() -> Self {
        Self {
            cross_zone: true,
            enforced_roles: vec!["replica".to_owned()],
        }
    }
}

/// Check if a pod can be placed on a node without violating anti-affinity.
///
/// Returns true if placement is allowed, false if it violates anti-affinity.
pub fn check_anti_affinity(
    pod: &PendingPod,
    node: &NodeInfo,
    state: &ClusterState,
    config: &AntiAffinityConfig,
) -> bool {
    // Only enforce anti-affinity for configured roles.
    if !config.enforced_roles.contains(&pod.role) {
        return true;
    }

    // Get all placements of the same service.
    let same_service = state.placements_for_service(&pod.service);

    for placement in same_service {
        // Check 1: Same physical node — always a violation for enforced roles.
        if placement.node_id == node.node_id {
            return false;
        }

        // Check 2: Same failure domain (if cross-zone enforcement is enabled).
        if config.cross_zone {
            if let Some(placement_node) = state.find_node(&placement.node_id) {
                if placement_node.failure_domain == node.failure_domain {
                    return false;
                }
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::ResourceSpec;

    fn make_node(id: &str, zone: &str) -> NodeInfo {
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
            failure_domain: zone.to_owned(),
            schedulable: true,
            pod_count: 1,
        }
    }

    fn make_placement(service: &str, role: &str, node_id: &str) -> super::super::Placement {
        super::super::Placement {
            pod_id: format!("{}-{}", service, role),
            tenant_id: "tenant-1".to_owned(),
            service: service.to_owned(),
            role: role.to_owned(),
            ordinal: 0,
            node_id: format!("spiffe://test.internal/ns/system/node/{}", node_id)
                .parse()
                .unwrap(),
            resources: ResourceSpec {
                cpu_millicores: 500,
                memory_bytes: 512 * 1024 * 1024,
            },
        }
    }

    #[test]
    fn replica_rejected_on_same_node_as_primary() {
        let config = AntiAffinityConfig::default();
        let node = make_node("node-1", "zone-a");

        let state = ClusterState {
            nodes: vec![node.clone()],
            placements: vec![make_placement("db", "primary", "node-1")],
        };

        let pod = PendingPod {
            pod_id: "db-replica-0".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            service: "db".to_owned(),
            role: "replica".to_owned(),
            ordinal: 0,
            resources: ResourceSpec {
                cpu_millicores: 500,
                memory_bytes: 512 * 1024 * 1024,
            },
            previous_node: None,
        };

        assert!(!check_anti_affinity(&pod, &node, &state, &config));
    }

    #[test]
    fn replica_rejected_in_same_zone_as_primary() {
        let config = AntiAffinityConfig::default();
        let node_a = make_node("node-1", "zone-a");
        let node_b = make_node("node-2", "zone-a"); // Same zone

        let state = ClusterState {
            nodes: vec![node_a.clone(), node_b.clone()],
            placements: vec![make_placement("db", "primary", "node-1")],
        };

        let pod = PendingPod {
            pod_id: "db-replica-0".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            service: "db".to_owned(),
            role: "replica".to_owned(),
            ordinal: 0,
            resources: ResourceSpec {
                cpu_millicores: 500,
                memory_bytes: 512 * 1024 * 1024,
            },
            previous_node: None,
        };

        // node-2 is in the same zone as node-1 (where primary is)
        assert!(!check_anti_affinity(&pod, &node_b, &state, &config));
    }

    #[test]
    fn replica_allowed_in_different_zone() {
        let config = AntiAffinityConfig::default();
        let node_a = make_node("node-1", "zone-a");
        let node_b = make_node("node-2", "zone-b"); // Different zone

        let state = ClusterState {
            nodes: vec![node_a.clone(), node_b.clone()],
            placements: vec![make_placement("db", "primary", "node-1")],
        };

        let pod = PendingPod {
            pod_id: "db-replica-0".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            service: "db".to_owned(),
            role: "replica".to_owned(),
            ordinal: 0,
            resources: ResourceSpec {
                cpu_millicores: 500,
                memory_bytes: 512 * 1024 * 1024,
            },
            previous_node: None,
        };

        // node-2 is in a different zone — allowed
        assert!(check_anti_affinity(&pod, &node_b, &state, &config));
    }

    #[test]
    fn primary_not_subject_to_anti_affinity() {
        let config = AntiAffinityConfig::default();
        let node = make_node("node-1", "zone-a");

        let state = ClusterState {
            nodes: vec![node.clone()],
            placements: vec![make_placement("db", "replica", "node-1")],
        };

        let pod = PendingPod {
            pod_id: "db-primary-0".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            service: "db".to_owned(),
            role: "primary".to_owned(),
            ordinal: 0,
            resources: ResourceSpec {
                cpu_millicores: 500,
                memory_bytes: 512 * 1024 * 1024,
            },
            previous_node: None,
        };

        // Primary is not in the enforced_roles list, so anti-affinity doesn't apply
        assert!(check_anti_affinity(&pod, &node, &state, &config));
    }
}
