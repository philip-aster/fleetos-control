//! Owned, postcard-serializable records carried by `FleetosCommand` variants.
//!
//! Every record is fully self-contained. The leader computes ALL non-deterministic
//! values BEFORE proposing the command — random tokens/nonces, envelope encryption,
//! timestamps, derived IDs, free-block selection — so that state-machine application
//! is bit-for-bit deterministic across every node. The state machine never generates
//! randomness, reads a clock, or derives an ID on its own.

use serde::{Deserialize, Serialize};

/// Lifecycle status of a registered node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    Active,
    Cordoned,
    Evicted,
}

/// A registered fleet node (agent / router / gateway / control).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    pub node_id: String,
    /// Proto `NodeKind` value (0=control, 1=agent, 2=router, 3=gateway, 4=fleetctl_proxy).
    pub node_kind: u8,
    pub status: NodeStatus,
    pub schedulable: bool,
    pub last_heartbeat: i64,
    pub registered_at: i64,
    /// Total CPU capacity in millicores. Reported by the agent on registration/heartbeat.
    pub capacity_cpu_millicores: u64,
    /// Total memory capacity in bytes. Reported by the agent on registration/heartbeat.
    pub capacity_memory_bytes: u64,
    /// Failure domain / availability zone for topology spread and anti-affinity.
    pub failure_domain: String,
}

/// A tenant namespace record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantRecord {
    pub tenant_id: String,
    pub created_at: i64,
}

/// A submitted workload specification.
///
/// `spec_bytes` is the prost-encoded `fleetos_core::proto::workload::WorkloadSpec`,
/// preserved verbatim so the workload controller can reconstruct the full template
/// (including the embedded PodSpec) on whichever node is leader.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadSpecRecord {
    pub tenant_id: String,
    pub workload_id: String,
    pub spec_bytes: Vec<u8>,
}

/// A submitted cron workload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronWorkloadRecord {
    pub tenant_id: String,
    pub cron_workload_id: String,
    pub schedule_expression: String,
    /// prost-encoded `CronWorkload`, preserved verbatim.
    pub spec_bytes: Vec<u8>,
}

/// A SAG rule to upsert. `rule_bytes` is the postcard-encoded
/// `fleetos_core::policy::SagRule`; `rule_id` is the deterministic `SagRuleId`
/// computed by the leader via `policy::compiler::rule_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SagRuleRecord {
    pub rule_id: String,
    pub rule_bytes: Vec<u8>,
}

/// A secret to store. The leader performs envelope encryption and ACL construction
/// (both involve randomness / policy decisions) and proposes the serialized results;
/// the state machine only persists them. Re-sealing on rotation is a new `StoreSecret`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecord {
    pub key: String,
    /// postcard-encoded `secrets::crypto::EnvelopeSecret`.
    pub envelope_bytes: Vec<u8>,
    /// postcard-encoded `secrets::acl::SecretAcl`.
    pub acl_bytes: Vec<u8>,
}

/// A revoked node SVID (G-4 / CR-5). Stored keyed by SPIFFE ID string.
///
/// Enforcement is set-membership only; `expires_at_unix` exists solely so the
/// replicated `PruneExpiredRevokedSvids` command can bound the set without any
/// wall-clock reads in the state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedSvidRecord {
    pub spiffe_id: String,
    pub expires_at_unix: i64,
}

/// Context for replicated audit logging (G-2 / G-3).
///
/// Captured by the leader BEFORE proposing so application is deterministic.
/// Travels inside the replicated command so the audit record commits in the
/// same batch as the mutation it describes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditContext {
    /// Unique per-request correlation ID (G-3).
    pub request_id: String,
    /// SPIFFE ID of the caller, or "system" for controller-initiated actions.
    pub actor: String,
    /// The resource being acted on (tenant_id, workload_id, node_id, etc.).
    pub target: String,
    /// Unix timestamp captured by the leader (deterministic across nodes).
    pub timestamp_unix: u64,
}

/// A single replicated audit log entry, keyed by MonotonicVersion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// The MonotonicVersion of the mutation this entry describes.
    pub version: u64,
    pub request_id: String,
    pub actor: String,
    /// Command name, derived by the state machine from the applied command.
    pub action: String,
    pub target: String,
    pub timestamp_unix: u64,
}

/// Replicated checkpoint marking the last scheduled time a cron workload was
/// triggered. Lets any Raft leader continue a cron schedule after failover (G-11).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CronCheckpointRecord {
    pub tenant_id: String,
    pub cron_workload_id: String,
    /// Unix timestamp of the last scheduled time that was triggered.
    pub last_triggered_at_unix: i64,
}
