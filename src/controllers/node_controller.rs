use super::ControllerError;
use crate::raft::{FleetosCommand, FleetosRaftConfig};
use fleetos_core::spiffe::SpiffeId;
use openraft::Raft;
use std::sync::Arc;

pub struct NodeController {
    raft: Arc<Raft<FleetosRaftConfig>>,
}

impl NodeController {
    pub fn new(raft: Arc<Raft<FleetosRaftConfig>>) -> Self {
        Self { raft }
    }

    /// Evict a node: propose `EvictNode`; the state machine marks it evicted,
    /// revokes ALL its delegations, and removes its placements atomically.
    pub async fn evict_node(&self, node_id: &SpiffeId) -> Result<(), ControllerError> {
        let node_id_str = node_id.to_string();
        tracing::warn!(node_id = %node_id_str, "evicting node");
        self.raft
            .client_write(FleetosCommand::EvictNode {
                node_id: node_id_str,
            })
            .await
            .map_err(|e| ControllerError::Raft(e.to_string()))?;
        Ok(())
    }

    pub async fn handle_heartbeat(&self, node_id: &SpiffeId) -> Result<(), ControllerError> {
        tracing::debug!(node_id = %node_id, "heartbeat received");
        Ok(())
    }
}
