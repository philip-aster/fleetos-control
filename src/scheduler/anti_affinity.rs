//! Anti-affinity enforcement.
//!
//! If a role requires anti-affinity (configurable), it must not be scheduled on
//! the same physical node (or failure domain/zone) as another instance of the
//! same service with that role.
//!
//! This is a FILTER, not a score — nodes violating anti-affinity are eliminated
//! entirely from the candidate set.

use super::{ClusterState, NodeInfo, PendingPod};

/// Anti-affinity configuration.
#[derive(Debug, Clone)]
pub struct AntiAffinityConfig {
    /// Whether to enforce anti-affinity across failure domains (zones).
    /// If true, instances of the same (service, role) cannot be in the same zone.
    pub cross_zone: bool,

    /// Roles that require anti-affinity.
    /// Default: `["replica"]` — replicas must be spread.
    /// This is configurable because roles are user-defined.
    pub enforced_roles: Vec<String>,
}

impl Default for AntiAffinityConfig {
    fn default() -> Self {
        Self {
            cross_zone: true,
            // Default to "replica" as a reasonable starting point,
            // but operators can configure this for their own role names.
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

    // Get all placements of the same service with the same role.
    let same_service_role = state.placements_for_service_role(&pod.service, &pod.role);

    for placement in same_service_role {
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
    fn enforced_role_rejected_on_same_node() {
        let config = AntiAffinityConfig::default(); // enforces "replica"
        let node = make_node("node-1", "zone-a");

        let state = ClusterState {
            nodes: vec![node.clone()],
            placements: vec![make_placement("db", "replica", "node-1")],
        };

        let pod = PendingPod {
            pod_id: "db-replica-0".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            service: "db".to_owned(),
            role: "replica".to_owned(), // matches enforced_roles
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
    fn non_enforced_role_allowed_on_same_node() {
        let config = AntiAffinityConfig::default(); // enforces "replica"
        let node = make_node("node-1", "zone-a");

        let state = ClusterState {
            nodes: vec![node.clone()],
            placements: vec![make_placement("db", "primary", "node-1")],
        };

        let pod = PendingPod {
            pod_id: "db-primary-0".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            service: "db".to_owned(),
            role: "primary".to_owned(), // NOT in enforced_roles
            ordinal: 0,
            resources: ResourceSpec {
                cpu_millicores: 500,
                memory_bytes: 512 * 1024 * 1024,
            },
            previous_node: None,
        };

        // "primary" is not in enforced_roles, so anti-affinity doesn't apply
        assert!(check_anti_affinity(&pod, &node, &state, &config));
    }

    #[test]
    fn custom_enforced_role() {
        let config = AntiAffinityConfig {
            cross_zone: true,
            enforced_roles: vec!["shard".to_owned()], // custom role name
        };
        let node = make_node("node-1", "zone-a");

        let state = ClusterState {
            nodes: vec![node.clone()],
            placements: vec![make_placement("db", "shard", "node-1")],
        };

        let pod = PendingPod {
            pod_id: "db-shard-0".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            service: "db".to_owned(),
            role: "shard".to_owned(), // matches custom enforced_roles
            ordinal: 0,
            resources: ResourceSpec {
                cpu_millicores: 500,
                memory_bytes: 512 * 1024 * 1024,
            },
            previous_node: None,
        };

        assert!(!check_anti_affinity(&pod, &node, &state, &config));
    }
}
