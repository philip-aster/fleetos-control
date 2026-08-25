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
    SubmitCronWorkload {
        record: records::CronWorkloadRecord,
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
    /// Evicts a node AND revokes ALL of its delegations in a single batch.
    /// This is one command (not two) so the one-to-many eviction invariant is atomic.
    EvictNode {
        node_id: String,
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
    },
    // --- Scheduler / placement ---
    RecordOrdinalAssignment {
        record: crate::scheduler::ordinal::OrdinalAssignment,
    },
    CommitPlacement {
        record: crate::scheduler::Placement,
    },
    // --- Provisioning ---
    StoreNodePool {
        record: crate::provisioning::NodePoolRecord,
    },
    DeleteNodePool {
        pool_id: String,
    },
}

/// Application-level response returned after applying a command.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FleetosResponse {
    pub version: u64,
}

// Raft type configuration for fleetos-control.
declare_raft_types!(
    pub FleetosRaftConfig:
        D            = FleetosCommand,
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
