use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ClientRequest {
    PutWorkload {
        key: String,
        data: Vec<u8>,
    },
    DeleteWorkload {
        key: String,
    },
    RegisterNode {
        node_id: String,
        metadata: Vec<u8>,
    },
    EvictNode {
        node_id: String,
    },
    UpsertDummyIp {
        key: String,
        ip_data: Vec<u8>,
    },
    StoreDelegationKey {
        composite_key: String,
        node_id: String,
        key_data: Vec<u8>,
    },
    RevokeDelegationKeys {
        node_id: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientResponse {
    pub success: bool,
    pub version: u64,
    pub message: String,
}
