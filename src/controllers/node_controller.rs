//! Node controller — node lifecycle and eviction.
use super::ControllerError;
use crate::delegation::revocation::DelegationRevocationStore;
use crate::storage::StorageEngine;
use crate::watch::broadcast::{BroadcastHub, SagUpdateEvent};
use fleetos_core::MonotonicVersion;
use fleetos_core::spiffe::SpiffeId;
use std::sync::Arc;

/// The node controller.
pub struct NodeController {
    storage: Arc<StorageEngine>,
    delegation_revocation: Arc<DelegationRevocationStore>,
    broadcast_hub: Arc<BroadcastHub>,
}

impl NodeController {
    pub fn new(
        storage: Arc<StorageEngine>,
        delegation_revocation: Arc<DelegationRevocationStore>,
        broadcast_hub: Arc<BroadcastHub>,
    ) -> Self {
        Self {
            storage,
            delegation_revocation,
            broadcast_hub,
        }
    }

    /// Evict a node from the cluster.
    pub async fn evict_node(&self, node_id: &SpiffeId) -> Result<(), ControllerError> {
        let node_id_str = node_id.to_string();
        tracing::warn!(node_id = %node_id_str, "evicting node");

        // 1. Mark node as evicted in storage.
        self.storage
            .mark_node_evicted(&node_id_str)
            .map_err(ControllerError::Storage)?;

        // 2. Revoke all delegations for this node (one-to-many).
        let revoked_ids = self.delegation_revocation.revoke_all_for_node(node_id)?;
        tracing::info!(
            node_id = %node_id_str,
            revoked_count = revoked_ids.len(),
            "delegations revoked for evicted node"
        );

        // 3. Broadcast the updated revoked_delegation_ids set via SagUpdateEvent.
        let full_revoked_set = self.delegation_revocation.get_revoked_set()?;
        let revoked_bytes: Vec<Vec<u8>> = full_revoked_set
            .iter()
            .map(|id| id.as_bytes().to_vec())
            .collect();

        self.broadcast_hub.publish_sag_update(SagUpdateEvent {
            version: MonotonicVersion::new(0),
            rules_bytes: Vec::new(), // No rule changes, just revocation update
            revoked_delegation_ids: revoked_bytes,
        });

        // 4. Reschedule all pods that were on this evicted node.
        let placements = self
            .storage
            .get_placements_for_node(node_id)
            .map_err(ControllerError::Storage)?;

        for placement in placements {
            // Remove the old placement.
            self.storage
                .delete_placement(&placement.pod_id)
                .map_err(ControllerError::Storage)?;

            tracing::info!(
                pod_id = %placement.pod_id,
                old_node = %node_id_str,
                "placement removed, pending reschedule"
            );
        }

        Ok(())
    }

    /// Handle a node heartbeat.
    pub async fn handle_heartbeat(&self, node_id: &SpiffeId) -> Result<(), ControllerError> {
        tracing::debug!(node_id = %node_id, "heartbeat received");
        Ok(())
    }
}
