//! Raft consensus layer backed by `openraft` 0.9.25 + `fjall`.
//!
//! This module provides:
//! - Type configuration (`FleetosRaftConfig`)
//! - Log storage (`store::RedbLogStorage`)
//! - State machine (`state_machine::RedbStateMachine`)
//! - Tonic-based network transport (`network::TonicRaftNetwork`)
//! - Initialization / bootstrap logic

pub mod entry;
pub mod error;
pub mod network;
pub mod server;
pub mod snapshot;
pub mod state_machine;
pub mod store;

use std::io::Cursor;
use std::sync::Arc;

use openraft::declare_raft_types;

/// Application-level command that gets replicated through the Raft log.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum FleetosCommand {
    /// Placeholder — will be expanded as controllers are implemented.
    Noop,
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
