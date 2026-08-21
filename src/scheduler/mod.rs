//! Scheduler Engine — Module 3.
//!
//! Places workloads (Containerd containers and Cloud Hypervisor MicroVMs)
//! onto `fleetos-agent` nodes.
//!
//! Key invariants:
//! - Ordinal is controller-assigned, never caller-submitted
//! - Ordinal preservation: `(service, role, ordinal)` is a stable slot
//!   replaced-in-place on failure, never a fungible pool
//! - Anti-affinity: `replica` must not land on same node/failure-domain
//!   as `primary` or sibling replicas
//! - Strict bin-packing: reject scheduling when insufficient resources
//! - Topology spread: balance tenant workloads across agents

pub mod anti_affinity;
pub mod binpack;
pub mod engine;
pub mod ordinal;
pub mod topology;

pub use ordinal::OrdinalTracker;
use thiserror::Error;

use fleetos_core::spiffe::SpiffeId;

/// Errors from scheduling operations.
#[derive(Debug, Error)]
pub enum SchedulerError {
    #[error("no suitable node found for pod {pod_id}: {reason}")]
    NoSuitableNode { pod_id: String, reason: String },

    #[error("anti-affinity violation: {0}")]
    AntiAffinityViolation(String),

    #[error(
        "insufficient resources on node {node_id}: requested {requested}, available {available}"
    )]
    InsufficientResources {
        node_id: String,
        requested: String,
        available: String,
    },

    #[error("node {0} is not schedulable")]
    NodeNotSchedulable(String),

    #[error("ordinal conflict: {0}")]
    OrdinalConflict(String),

    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),

    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),
}

/// Resource specification for a single pod.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ResourceSpec {
    /// CPU in millicores (1000 = 1 core).
    pub cpu_millicores: u64,
    /// Memory in bytes.
    pub memory_bytes: u64,
}

impl ResourceSpec {
    pub fn zero() -> Self {
        Self {
            cpu_millicores: 0,
            memory_bytes: 0,
        }
    }

    pub fn fits_within(&self, available: &ResourceSpec) -> bool {
        self.cpu_millicores <= available.cpu_millicores
            && self.memory_bytes <= available.memory_bytes
    }

    pub fn subtract(&self, other: &ResourceSpec) -> ResourceSpec {
        ResourceSpec {
            cpu_millicores: self.cpu_millicores.saturating_sub(other.cpu_millicores),
            memory_bytes: self.memory_bytes.saturating_sub(other.memory_bytes),
        }
    }

    pub fn add(&self, other: &ResourceSpec) -> ResourceSpec {
        ResourceSpec {
            cpu_millicores: self.cpu_millicores + other.cpu_millicores,
            memory_bytes: self.memory_bytes + other.memory_bytes,
        }
    }
}

/// A node in the cluster as seen by the scheduler.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeInfo {
    /// The node's SPIFFE ID.
    pub node_id: SpiffeId,

    /// Total capacity of this node.
    pub capacity: ResourceSpec,

    /// Currently available (unallocated) resources.
    pub available: ResourceSpec,

    /// Failure domain / availability zone.
    pub failure_domain: String,

    /// Whether this node is currently schedulable.
    /// A cordoned node rejects new placements but keeps existing pods.
    pub schedulable: bool,

    /// Number of pods currently scheduled on this node.
    pub pod_count: u32,
}

/// A current placement: which pod is on which node.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Placement {
    /// The pod's unique ID.
    pub pod_id: String,

    /// The tenant this pod belongs to.
    pub tenant_id: String,

    /// The service name.
    pub service: String,

    /// The workload role (primary, replica, etc.).
    pub role: String,

    /// The ordinal (stable across restarts).
    pub ordinal: u32,

    /// The node this pod is placed on.
    pub node_id: SpiffeId,

    /// Resources requested by this pod.
    pub resources: ResourceSpec,
}

/// The scheduler's view of the entire cluster state.
///
/// This is a snapshot used for a single scheduling decision.
/// It is NOT shared mutable state — each scheduling call gets a fresh view.
#[derive(Debug, Clone)]
pub struct ClusterState {
    /// All known nodes.
    pub nodes: Vec<NodeInfo>,

    /// All current placements.
    pub placements: Vec<Placement>,
}

impl ClusterState {
    /// Get all placements for a specific service.
    pub fn placements_for_service(&self, service: &str) -> Vec<&Placement> {
        self.placements
            .iter()
            .filter(|p| p.service == service)
            .collect()
    }

    /// Get all placements for a specific (service, role) pair.
    pub fn placements_for_service_role(&self, service: &str, role: &str) -> Vec<&Placement> {
        self.placements
            .iter()
            .filter(|p| p.service == service && p.role == role)
            .collect()
    }

    /// Get all placements on a specific node.
    pub fn placements_on_node(&self, node_id: &SpiffeId) -> Vec<&Placement> {
        self.placements
            .iter()
            .filter(|p| &p.node_id == node_id)
            .collect()
    }

    /// Get all placements for a specific tenant.
    pub fn placements_for_tenant(&self, tenant_id: &str) -> Vec<&Placement> {
        self.placements
            .iter()
            .filter(|p| p.tenant_id == tenant_id)
            .collect()
    }

    /// Find a node by its SPIFFE ID.
    pub fn find_node(&self, node_id: &SpiffeId) -> Option<&NodeInfo> {
        self.nodes.iter().find(|n| &n.node_id == node_id)
    }

    /// Get all schedulable nodes.
    pub fn schedulable_nodes(&self) -> Vec<&NodeInfo> {
        self.nodes.iter().filter(|n| n.schedulable).collect()
    }
}

/// A scheduling decision: which node a pod should be placed on.
#[derive(Debug, Clone)]
pub struct ScheduleDecision {
    /// The selected node.
    pub node_id: SpiffeId,

    /// The pod being scheduled.
    pub pod_id: String,

    /// Scoring metadata for audit/debugging.
    pub score_breakdown: ScoreBreakdown,
}

/// Score breakdown for transparency and debugging.
#[derive(Debug, Clone, Default)]
pub struct ScoreBreakdown {
    /// Bin-packing efficiency score (higher = better utilization).
    pub binpack_score: f64,

    /// Topology spread score (higher = better distribution).
    pub topology_score: f64,

    /// Anti-affinity compliance (true = passes, false = filtered out).
    pub anti_affinity_pass: bool,

    /// Resource fit (true = sufficient capacity).
    pub resource_fit: bool,
}

/// The scheduler trait.
///
/// Implementations must be deterministic given the same `ClusterState` input.
/// Non-determinism would cause Raft state divergence across control nodes.
pub trait Scheduler: Send + Sync {
    /// Schedule a pod onto a node.
    ///
    /// The pod already has its ordinal assigned (by `workload_controller`).
    /// The scheduler's job is to find a suitable node, not to assign ordinals.
    fn schedule(
        &self,
        pod: &PendingPod,
        state: &ClusterState,
    ) -> Result<ScheduleDecision, SchedulerError>;
}

/// A pod awaiting scheduling.
///
/// This is the scheduler's input — a `PodSpec` that has been expanded
/// by `workload_controller` with its ordinal already assigned.
#[derive(Debug, Clone)]
pub struct PendingPod {
    /// The pod's unique ID.
    pub pod_id: String,

    /// The tenant this pod belongs to.
    pub tenant_id: String,

    /// The service name.
    pub service: String,

    /// The workload role (primary, replica, etc.).
    pub role: String,

    /// The ordinal (already assigned by workload_controller).
    pub ordinal: u32,

    /// Resources requested by this pod.
    pub resources: ResourceSpec,

    /// If this is a reschedule (pod died, needs replacement),
    /// the node it was previously on (for anti-affinity awareness).
    pub previous_node: Option<SpiffeId>,
}
