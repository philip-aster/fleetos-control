use super::ControllerError;
use crate::raft::{FleetosCommand, FleetosRaftConfig};
use fleetos_core::spiffe::SpiffeId;
use openraft::Raft;
use std::sync::Arc;
use time::OffsetDateTime;

pub struct NodeController {
    raft: Arc<Raft<FleetosRaftConfig>>,
    node_svid_ttl_secs: u64,
}

impl NodeController {
    pub fn new(raft: Arc<Raft<FleetosRaftConfig>>, node_svid_ttl_secs: u64) -> Self {
        Self {
            raft,
            node_svid_ttl_secs,
        }
    }

    /// Evict a node: propose `EvictNode`; the state machine marks it evicted,
    /// revokes ALL its delegations, removes its placements, and records its
    /// own SVID as revoked — atomically. Then prune expired revoked SVIDs.
    pub async fn evict_node(&self, node_id: &SpiffeId) -> Result<(), ControllerError> {
        let node_id_str = node_id.to_string();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let svid_expires_at_unix = now + self.node_svid_ttl_secs as i64;
        tracing::warn!(node_id = %node_id_str, "evicting node");
        self.raft
            .client_write(crate::raft::AuditedCommand::system(
                FleetosCommand::EvictNode {
                    node_id: node_id_str,
                    svid_expires_at_unix,
                },
            ))
            .await
            .map_err(|e| ControllerError::Raft(e.to_string()))?;
        // Prune expired revoked SVIDs. The cutoff is replicated, so every node
        // prunes the same entries (deterministic). Hygiene only — enforcement
        // does not depend on it.
        self.raft
            .client_write(crate::raft::AuditedCommand::system(
                FleetosCommand::PruneExpiredRevokedSvids { cutoff_unix: now },
            ))
            .await
            .map_err(|e| ControllerError::Raft(e.to_string()))?;
        Ok(())
    }

    pub async fn handle_heartbeat(&self, node_id: &SpiffeId) -> Result<(), ControllerError> {
        tracing::debug!(node_id = %node_id, "heartbeat received");
        Ok(())
    }
}
