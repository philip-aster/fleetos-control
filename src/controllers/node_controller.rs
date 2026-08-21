//! Node controller — node lifecycle and eviction.

use std::sync::Arc;

use fleetos_core::spiffe::SpiffeId;

use super::ControllerError;
use crate::delegation::revocation::DelegationRevocationStore;
use crate::storage::StorageEngine;
use crate::watch::broadcast::BroadcastHub;

/// The node controller.
pub struct NodeController {
    /// Storage engine for node registry operations.
    /// TODO: Used for marking nodes as evicted, querying placements for rescheduling.
    #[allow(dead_code)]
    storage: Arc<StorageEngine>,

    delegation_revocation: Arc<DelegationRevocationStore>,

    /// Broadcast hub for publishing revoked delegations and membership changes.
    /// TODO: Used to broadcast the full revoked_delegation_ids set after eviction.
    #[allow(dead_code)]
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

        // TODO: Mark node as evicted in storage.
        // self.storage.mark_node_evicted(node_id)?;

        // Revoke all delegations for this node (one-to-many).
        let revoked_ids = self.delegation_revocation.revoke_all_for_node(node_id)?;

        tracing::info!(
            node_id = %node_id_str,
            revoked_count = revoked_ids.len(),
            "delegations revoked for evicted node"
        );

        // TODO: Broadcast the updated revoked_delegation_ids set.
        // let full_revoked_set = self.delegation_revocation.get_revoked_set()?;
        // self.broadcast_hub.publish_watch_event(
        //     WatchEvent::RevokedDelegations {
        //         revoked_ids: full_revoked_set,
        //         version: current_version,
        //     }
        // );

        // TODO: Reschedule all pods that were on this evicted node.
        // let placements = self.storage.get_placements_for_node(node_id)?;
        // for placement in placements {
        //     self.pod_controller.reconcile_dead_pod(...).await?;
        // }

        Ok(())
    }

    /// Handle a node heartbeat.
    pub async fn handle_heartbeat(&self, node_id: &SpiffeId) -> Result<(), ControllerError> {
        // TODO: Update last-seen timestamp in storage.
        // self.storage.update_heartbeat(node_id)?;
        tracing::debug!(node_id = %node_id, "heartbeat received");
        Ok(())
    }
}
