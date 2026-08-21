//! Resource bin-packing.
//!
//! Tracks CPU/Memory requests and enforces strict bin-packing.
//! Tracks per-node capacity and rejects scheduling when insufficient.
//!
//! Two strategies:
//! - `MostAllocated`: Prefer nodes that are already heavily utilized
//!   (consolidates workloads, leaves more nodes free for scaling down).
//! - `LeastAllocated`: Prefer nodes with the most free capacity
//!   (spreads load, reduces contention on individual nodes).

use super::{NodeInfo, ResourceSpec};

/// Bin-packing strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinpackStrategy {
    /// Prefer nodes that are already heavily utilized.
    /// Consolidates workloads onto fewer nodes.
    MostAllocated,

    /// Prefer nodes with the most free capacity.
    /// Spreads load across nodes.
    LeastAllocated,
}

/// Check if a node has sufficient resources for a pod.
///
/// This is a hard filter — if resources don't fit, the node is eliminated.
pub fn check_resource_fit(pod_resources: &ResourceSpec, node: &NodeInfo) -> bool {
    pod_resources.fits_within(&node.available)
}

/// Score a node for bin-packing efficiency.
///
/// Higher score = better fit according to the strategy.
/// Score is normalized to [0.0, 1.0] range.
pub fn score_binpack(
    pod_resources: &ResourceSpec,
    node: &NodeInfo,
    strategy: BinpackStrategy,
) -> f64 {
    // Calculate utilization after placing the pod.
    let cpu_after = node.capacity.cpu_millicores.saturating_sub(
        node.available
            .cpu_millicores
            .saturating_sub(pod_resources.cpu_millicores),
    );
    let mem_after = node.capacity.memory_bytes.saturating_sub(
        node.available
            .memory_bytes
            .saturating_sub(pod_resources.memory_bytes),
    );

    let cpu_utilization = if node.capacity.cpu_millicores > 0 {
        cpu_after as f64 / node.capacity.cpu_millicores as f64
    } else {
        0.0
    };

    let mem_utilization = if node.capacity.memory_bytes > 0 {
        mem_after as f64 / node.capacity.memory_bytes as f64
    } else {
        0.0
    };

    // Combined utilization (weighted average).
    let combined_utilization = (cpu_utilization + mem_utilization) / 2.0;

    match strategy {
        BinpackStrategy::MostAllocated => {
            // Higher utilization = higher score (prefer packed nodes).
            combined_utilization
        }
        BinpackStrategy::LeastAllocated => {
            // Lower utilization = higher score (prefer empty nodes).
            1.0 - combined_utilization
        }
    }
}

/// Calculate the remaining resources on a node after placing a pod.
pub fn remaining_after_placement(node: &NodeInfo, pod_resources: &ResourceSpec) -> ResourceSpec {
    node.available.subtract(pod_resources)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(cpu_capacity: u64, mem_capacity: u64, cpu_used: u64, mem_used: u64) -> NodeInfo {
        NodeInfo {
            node_id: "spiffe://test.internal/ns/system/node/node-1"
                .parse()
                .unwrap(),
            capacity: ResourceSpec {
                cpu_millicores: cpu_capacity,
                memory_bytes: mem_capacity,
            },
            available: ResourceSpec {
                cpu_millicores: cpu_capacity - cpu_used,
                memory_bytes: mem_capacity - mem_used,
            },
            failure_domain: "zone-a".to_owned(),
            schedulable: true,
            pod_count: 0,
        }
    }

    #[test]
    fn resource_fit_passes_when_sufficient() {
        let node = make_node(4000, 8 * 1024 * 1024 * 1024, 1000, 1024 * 1024 * 1024);
        let pod = ResourceSpec {
            cpu_millicores: 500,
            memory_bytes: 512 * 1024 * 1024,
        };

        assert!(check_resource_fit(&pod, &node));
    }

    #[test]
    fn resource_fit_fails_when_insufficient_cpu() {
        let node = make_node(4000, 8 * 1024 * 1024 * 1024, 3800, 0);
        let pod = ResourceSpec {
            cpu_millicores: 500,
            memory_bytes: 512 * 1024 * 1024,
        };

        assert!(!check_resource_fit(&pod, &node));
    }

    #[test]
    fn resource_fit_fails_when_insufficient_memory() {
        let node = make_node(4000, 8 * 1024 * 1024 * 1024, 0, 7 * 1024 * 1024 * 1024);
        let pod = ResourceSpec {
            cpu_millicores: 500,
            memory_bytes: 2 * 1024 * 1024 * 1024,
        };

        assert!(!check_resource_fit(&pod, &node));
    }

    #[test]
    fn most_allocated_prefers_busy_nodes() {
        let busy_node = make_node(4000, 8 * 1024 * 1024 * 1024, 3000, 6 * 1024 * 1024 * 1024);
        let empty_node = make_node(4000, 8 * 1024 * 1024 * 1024, 0, 0);

        let pod = ResourceSpec {
            cpu_millicores: 500,
            memory_bytes: 512 * 1024 * 1024,
        };

        let busy_score = score_binpack(&pod, &busy_node, BinpackStrategy::MostAllocated);
        let empty_score = score_binpack(&pod, &empty_node, BinpackStrategy::MostAllocated);

        assert!(busy_score > empty_score);
    }

    #[test]
    fn least_allocated_prefers_empty_nodes() {
        let busy_node = make_node(4000, 8 * 1024 * 1024 * 1024, 3000, 6 * 1024 * 1024 * 1024);
        let empty_node = make_node(4000, 8 * 1024 * 1024 * 1024, 0, 0);

        let pod = ResourceSpec {
            cpu_millicores: 500,
            memory_bytes: 512 * 1024 * 1024,
        };

        let busy_score = score_binpack(&pod, &busy_node, BinpackStrategy::LeastAllocated);
        let empty_score = score_binpack(&pod, &empty_node, BinpackStrategy::LeastAllocated);

        assert!(empty_score > busy_score);
    }
}
