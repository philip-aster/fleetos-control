use openraft::declare_raft_types;
use serde::{Deserialize, Serialize};
use std::io::Cursor;

/// Client Request Commands applied to the Raft state machine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientRequest {
    PutPod { id: String, data: Vec<u8> },
    DeletePod { id: String },
    PutPolicy { key: String, data: Vec<u8> },
    DeletePolicy { key: String },
}

/// Client Response returned after state machine commit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientResponse {
    Success { message: String },
    Value(Option<Vec<u8>>),
}

// Declare the Raft type configuration for OpenRaft 0.9
declare_raft_types!(
    pub TypeConfig:
        D = ClientRequest,
        R = ClientResponse,
        NodeId = u64,
        Node = openraft::BasicNode,
        Entry = openraft::Entry<TypeConfig>,
        SnapshotData = Cursor<Vec<u8>>,
);

pub type NodeId = u64;
pub type FleetRaft = openraft::Raft<TypeConfig>;
