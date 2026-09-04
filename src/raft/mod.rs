//! Raft consensus layer backed by `openraft` 0.9.25 + `fjall`.
//!
//! This module provides:
//! - Type configuration (`FleetosRaftConfig`)
//! - Log storage (`store::FjallLogStorage`)
//! - State machine (`state_machine::FjallStateMachine`)
//! - Tonic-based network transport (`network::TonicRaftNetwork`)
//! - Initialization / bootstrap logic
pub mod entry;
pub mod error;
pub mod network;
pub mod records;
pub mod server;
pub mod snapshot;
pub mod state_machine;
pub mod store;

use openraft::Vote;
use openraft::declare_raft_types;
use std::io::Cursor;
use std::sync::Arc;

/// Application-level command replicated through the Raft log.
///
/// Every variant carries fully-computed, owned data so application by the state
/// machine is deterministic across all nodes. Any non-deterministic work (random
/// token/nonce generation, envelope encryption, timestamp capture, ID derivation,
/// free-block selection) is done by the leader BEFORE proposing the command.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum FleetosCommand {
    // --- Tenant lifecycle ---
    CreateTenant {
        record: records::TenantRecord,
    },
    DeleteTenant {
        tenant_id: String,
    },
    // --- Workloads ---
    SubmitWorkloadSpec {
        record: records::WorkloadSpecRecord,
    },
    /// Delete a workload spec and all its placements/ordinal assignments.
    DeleteWorkload {
        tenant_id: String,
        workload_id: String,
    },
    /// Update a workload's replica counts. The state machine applies the new
    /// spec, removes excess placements, and frees their ordinal slots.
    ScaleWorkload {
        record: records::WorkloadSpecRecord,
    },
    /// Set or replace the resource quota for a tenant (CR-7).
    SetTenantQuota {
        record: records::TenantQuotaRecord,
    },
    SubmitCronWorkload {
        record: records::CronWorkloadRecord,
        checkpoint: records::CronCheckpointRecord,
    },
    /// Atomically store a triggered cron run AND advance its checkpoint in one
    /// Raft entry (G-11). Prevents double-trigger and lost runs across failover.
    TriggerCronWorkload {
        workload_record: records::WorkloadSpecRecord,
        checkpoint: records::CronCheckpointRecord,
    },
    /// Upsert the latest liveness/readiness report for a pod (G-10).
    /// Keyed by pod_id so the keyspace stays bounded.
    UpsertWorkloadStatus {
        record: records::WorkloadStatusRecord,
    },
    // --- Attestation / join ---
    MintJoinToken {
        record: crate::attestation::join_token::JoinTokenRecord,
    },
    ConsumeJoinToken {
        token: Vec<u8>,
    },
    SetPcrPolicy {
        record: crate::attestation::pcr_policy::PcrPolicy,
    },
    // --- Nodes ---
    RegisterNode {
        record: records::NodeRecord,
    },
    /// Evicts a node, revokes ALL its delegations, removes its placements,
    /// and records its own SVID as revoked — atomically (G-4 / CR-5).
    EvictNode {
        node_id: String,
        svid_expires_at_unix: i64,
    },
    /// Remove revoked-SVID entries whose expiry is past `cutoff_unix`.
    /// The leader supplies the cutoff so application stays deterministic.
    PruneExpiredRevokedSvids {
        cutoff_unix: i64,
    },
    SetNodeSchedulable {
        node_id: String,
        schedulable: bool,
    },
    // --- Delegations (degraded mode) ---
    /// Upsert into active_delegations. Covers both issuance and refresh (a refresh
    /// is an upsert with recomputed issued_at / expires_at / refresh_at).
    IssueDelegation {
        record: crate::delegation::DelegationRecord,
    },
    RevokeDelegation {
        node_id: String,
        delegation_id: String,
    },
    // --- SAG policy ---
    UpsertSagRule {
        record: records::SagRuleRecord,
    },
    DeleteSagRule {
        rule_id: String,
    },
    // --- Dummy IP ---
    AllocateTenantBlock {
        record: crate::dummy_ip::allocator::TenantBlock,
    },
    /// The leader has already picked the address and incremented `block.next_offset`;
    /// both the updated block and the assignment are written atomically.
    AllocateServiceAddress {
        block: crate::dummy_ip::allocator::TenantBlock,
        address: crate::dummy_ip::allocator::ServiceAddress,
    },
    // --- Secrets ---
    StoreSecret {
        record: records::SecretRecord,
        target_spiffe_id: String,
    },
    /// Grant a SPIFFE ID access to an existing secret's ACL (atomic
    /// read-modify-write in the state machine).
    GrantSecretAccess {
        tenant_id: String,
        key: String,
        spiffe_id: String,
    },
    /// Revoke a SPIFFE ID's access to an existing secret's ACL.
    RevokeSecretAccess {
        tenant_id: String,
        key: String,
        spiffe_id: String,
    },
    // --- Scheduler / placement ---
    RecordOrdinalAssignment {
        record: crate::scheduler::ordinal::OrdinalAssignment,
    },
    CommitPlacement {
        record: crate::scheduler::Placement,
    },
    /// Remove a placement by pod_id (scale-down / deletion).
    RemovePlacement {
        pod_id: String,
    },
    /// Atomically reassign the pod_id of the placement occupying the given
    /// (tenant, service, role, ordinal) slot — replace-in-place semantics.
    ReassignPodId {
        tenant_id: String,
        service: String,
        role: String,
        ordinal: u32,
        new_pod_id: String,
    },
    // --- Provisioning ---
    StoreNodePool {
        record: crate::provisioning::NodePoolRecord,
    },
    DeleteNodePool {
        pool_id: String,
    },

    /// Register a control node's listener addresses (V-2 leader-directed attestation).
    RegisterControlAddress {
        record: records::ControlNodeAddressRecord,
    },

    /// Upsert the SVID version for a SpiffeId (leader-only issuance, V-4c).
    /// The leader computes the next version and proposes it; the state machine
    /// writes it to the `svids` keyspace. This makes SVID versions replicated
    /// state, consistent across all nodes, and snapshot-safe.
    UpsertSvidVersion {
        record: crate::ca::SvidRecord,
    },

    // --- Operator JIT access (CR-8) ---
    GrantOperatorAccess {
        record: records::OperatorAccessGrantRecord,
    },
    RevokeOperatorAccess {
        grant_id: String,
    },

    /// Register a node Endorsement Key for secure attestation (CR-10).
    RegisterNodeEk {
        record: records::NodeEkRecord,
    },
    /// Transition an EK registration Pending → Joined and bind the node id.
    ActivateNodeEk {
        ek_fingerprint: String,
        node_id: String,
    },
    /// Revoke an EK registration.
    RevokeNodeEk {
        ek_fingerprint: String,
    },
}

/// Wraps a `FleetosCommand` with optional audit context so the audit record
/// is replicated in the same Raft entry as the mutation (G-2 / G-3).
///
/// Commands proposed by the AdminService carry `Some(ctx)`; internal/system
/// proposals may carry `None`, in which case the state machine still logs the
/// action with a "system" actor.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditedCommand {
    pub cmd: FleetosCommand,
    pub audit: Option<records::AuditContext>,
}

impl AuditedCommand {
    /// Convenience for system/controller-initiated commands with no request context.
    pub fn system(cmd: FleetosCommand) -> Self {
        Self { cmd, audit: None }
    }
}

/// Application-level response returned after applying a command.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FleetosResponse {
    pub version: u64,
}

// Raft type configuration for fleetos-control.
declare_raft_types!(
    pub FleetosRaftConfig:
        D            = AuditedCommand,
        R            = FleetosResponse,
        NodeId       = u64,
        Node         = openraft::BasicNode,
        Entry        = openraft::Entry<FleetosRaftConfig>,
        SnapshotData = Cursor<Vec<u8>>,
);

/// Payload for `RaftTransport.RequestJoin` (postcard-serialized into RaftRpc.payload).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JoinRequestPayload {
    /// Raft node ID the joiner will use (derived from its node name).
    pub node_id: u64,
    /// Address of the joiner's raft transport listener.
    pub address: String,
    /// The joiner's Data/Control listener address (V-2).
    pub dc_address: String,
}

/// Response payload for `RaftTransport.RequestJoin`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JoinResponsePayload {
    /// True if the node was added as learner (caught up) and promoted to voter.
    pub success: bool,
    /// If the contacted node is not the leader, the leader's raft address
    /// so the joiner can retry against it.
    pub leader_address: Option<String>,
}

/// Wire format for snapshot transmission over the Raft transport.
///
/// Carries the leader's current `Vote` explicitly so the follower can verify
/// the request comes from the current leader. Deriving the vote from
/// `meta.last_log_id.leader_id.term` is incorrect — that term may lag the
/// leader's current term after an election.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SnapshotWire {
    pub meta: openraft::SnapshotMeta<u64, openraft::BasicNode>,
    pub data: Vec<u8>,
    pub vote: Vote<u64>,
}

/// Derive a deterministic Raft node ID from a stable string handle.
///
/// Both manual join (`join.rs` via `init_raft_cluster`) and the provisioning
/// CONTROL-pool manager use this so the leader and the joining node always
/// agree on the node ID.
pub fn derive_raft_node_id(handle: &str) -> u64 {
    let hash = blake3::hash(handle.as_bytes());
    let bytes = hash.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Connect a RaftTransportClient over TLS (used by the join membership leg).
pub async fn connect_raft_client_tls(
    endpoint: String,
    tls_config: tonic::transport::ClientTlsConfig,
) -> Result<RaftTransportClient<tonic::transport::Channel>, Box<dyn std::error::Error + Send + Sync>>
{
    let channel = tonic::transport::Channel::from_shared(endpoint)
        .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e))?
        .tls_config(tls_config)
        .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e))?
        .connect()
        .await
        .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e))?;
    Ok(RaftTransportClient::new(channel))
}

/// Shared handle to the running Raft node.
#[derive(Clone)]
pub struct RaftHandle {
    pub raft: Arc<openraft::Raft<FleetosRaftConfig>>,
}

// Include the generated proto types for the internal Raft transport.
pub mod raft_proto {
    tonic::include_proto!("fleetos.raft");
}

// Re-export the generated types for convenience.
pub use raft_proto::RaftRpc;
pub use raft_proto::raft_transport_client::RaftTransportClient;
pub use raft_proto::raft_transport_server::RaftTransport as RaftTransportService;
