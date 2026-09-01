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

/// An operator access grant (CR-8). Replicated via Raft so any leader can
/// enforce it. Keyed by `grant_id` (hex of `OperatorGrantId::of_grant`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OperatorAccessGrantRecord {
    pub grant_id: String,
    pub operator_id: String,
    pub granted_by: String,
    pub granted_at_unix: u64,
    pub expires_at_unix: u64,
    pub cluster_admin: bool,
    pub read_only: bool,
    pub tenants: Vec<String>,
}

/// A workload liveness/readiness report (G-10). Upserted by pod_id so the
/// keyspace stays bounded at one record per live pod.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WorkloadStatusRecord {
    pub pod_id: String,
    pub workload_id: String,
    pub tenant_id: String,
    pub ready: bool,
    pub live: bool,
    pub observed_at_unix: i64,
}

/// A tenant resource quota (CR-7). Replicated via Raft so any leader can
/// enforce it. Keyed by `tenant_id`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TenantQuotaRecord {
    pub tenant_id: String,
    pub max_cpu_millicores: u64,
    pub max_memory_bytes: u64,
    pub max_workloads: u32,
}

/// A control node's listener addresses, so any node can redirect a joiner
/// to the current leader's Data/Control endpoint (V-2 leader-directed attestation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlNodeAddressRecord {
    pub node_id: u64,
    pub dc_addr: String,
    pub raft_addr: String,
}

/// Lifecycle state of an EK registration (secure attestation, CR-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EkRegistrationState {
    /// EK registered, node has not yet completed attestation.
    Pending,
    /// Node attested and joined.
    Joined,
    /// EK revoked.
    Revoked,
}

/// A registered node Endorsement Key (secure attestation, CR-10).
///
/// The EK is the cryptographic identity token. Registered out-of-band by an
/// operator (AdminService.RegisterNodeEk), replicated via Raft, and matched
/// when a node requests credential activation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEkRecord {
    /// Canonical id: lowercase hex of `EkFingerprint`. This is the storage key.
    pub ek_fingerprint: String,
    /// EK public key (SPKI DER, canonical form per CR-11).
    pub ek_pub: Vec<u8>,
    /// EK certificate (DER). Empty if registered by public key only.
    pub ek_cert_der: Vec<u8>,
    /// Optional pre-bound node SPIFFE ID. Empty until attestation binds it.
    pub node_id: String,
    pub registered_at: i64,
    /// Optional expiry (unix seconds). None = no expiry.
    pub expires_at: Option<i64>,
    pub state: EkRegistrationState,
}
