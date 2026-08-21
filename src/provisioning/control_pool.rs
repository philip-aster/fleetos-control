//! CONTROL node pool management — openraft membership changes.
//!
//! CONTROL-kind node pools need distinct reconciliation logic from
//! AGENT/ROUTER/GATEWAY pools. Scaling the control plane is an openraft
//! membership change (add-learner → promote), never a naive spin-up-and-walk-away.
//!
//! Flow for new CONTROL nodes:
//! 1. Provider creates the node (via ReconcileNodePool)
//! 2. Node boots, uses bootstrap_payload Join Token to attest
//! 3. Node gets a signed SVID (IdKind::Control)
//! 4. We add it as an openraft learner (it starts catching up on the log)
//! 5. Once the learner has caught up, we promote it to voter (joins quorum)

use std::sync::Arc;

use fleetos_core::proto::provisioning::NodePoolStatus;

use super::{NodeLifecycleState, NodePoolRecord, ProvisioningError};
use crate::attestation::join_token::NodeKind;

/// Manages CONTROL pool → openraft membership transitions.
pub struct ControlPoolManager {
    // TODO: Add openraft Raft handle for membership changes.
    // raft: Raft<FleetosRaftConfig>,

    // TODO: Add storage for tracking which control nodes have been
    // added as learners / promoted to voters.
    #[allow(dead_code)]
    storage: Arc<crate::storage::StorageEngine>,
}

impl ControlPoolManager {
    pub fn new(storage: Arc<crate::storage::StorageEngine>) -> Self {
        Self { storage }
    }

    /// Handle the status of a CONTROL pool.
    ///
    /// Checks for new RUNNING control nodes that aren't yet Raft members,
    /// and initiates the add-learner → promote flow.
    pub async fn handle_control_pool_status(
        &self,
        pool: &NodePoolRecord,
        status: &NodePoolStatus,
    ) -> Result<(), ProvisioningError> {
        debug_assert_eq!(pool.node_kind, NodeKind::Control);

        for node in &status.nodes {
            let state = NodeLifecycleState::from_proto(node.state);

            match state {
                NodeLifecycleState::Running => {
                    // Check if this node is already a Raft member.
                    // If not, initiate the add-learner → promote flow.
                    self.ensure_raft_membership(&node.provider_handle).await?;
                }
                NodeLifecycleState::Terminated => {
                    // If this node was a Raft member, remove it from the cluster.
                    self.remove_raft_membership(&node.provider_handle).await?;
                }
                NodeLifecycleState::Pending => {
                    // Node is still being created. Nothing to do yet.
                    tracing::debug!(
                        pool_id = %pool.pool_id,
                        provider_handle = %node.provider_handle,
                        "control node pending"
                    );
                }
            }
        }

        Ok(())
    }

    /// Ensure a control node is a Raft member.
    ///
    /// If the node is not yet a member, add it as a learner.
    /// If it's a learner that has caught up, promote it to voter.
    async fn ensure_raft_membership(&self, provider_handle: &str) -> Result<(), ProvisioningError> {
        // TODO: Check if this provider_handle corresponds to a known Raft member.
        // This requires cross-referencing the provider_handle with the node's
        // SpiffeId (which we get after the node attests and joins).
        //
        // Flow:
        // 1. Look up the node's SpiffeId from the provider_handle
        //    (stored during attestation/join).
        // 2. Check if the SpiffeId is already a Raft voter or learner.
        // 3. If not a member: add as learner via raft.add_learner()
        // 4. If a learner that has caught up: promote via raft.promote_learner()

        tracing::debug!(
            provider_handle = %provider_handle,
            "checking raft membership for control node"
        );

        // TODO: Implement actual openraft membership changes:
        //
        // let node_id = self.lookup_node_id(provider_handle)?;
        // let membership = self.raft.metrics().borrow().membership_state.clone();
        //
        // if !membership.contains(&node_id) {
        //     // Add as learner
        //     self.raft.add_learner(node_id, node_config).await
        //         .map_err(|e| ProvisioningError::Raft(e.to_string()))?;
        //     tracing::info!(node = %node_id, "added as raft learner");
        // } else if membership.is_learner(&node_id) && self.has_caught_up(&node_id)? {
        //     // Promote to voter
        //     self.raft.promote_learner(node_id).await
        //         .map_err(|e| ProvisioningError::Raft(e.to_string()))?;
        //     tracing::info!(node = %node_id, "promoted to raft voter");
        // }

        Ok(())
    }

    /// Remove a control node from the Raft cluster.
    ///
    /// Called when a CONTROL node is TERMINATED.
    async fn remove_raft_membership(&self, provider_handle: &str) -> Result<(), ProvisioningError> {
        // TODO: Remove the node from the Raft membership.
        // This is a critical operation — removing a voter changes the quorum.
        // Must be done carefully to avoid losing quorum.
        //
        // let node_id = self.lookup_node_id(provider_handle)?;
        // self.raft.remove_learner(node_id).await
        //     .map_err(|e| ProvisioningError::Raft(e.to_string()))?;

        tracing::warn!(
            provider_handle = %provider_handle,
            "control node terminated, removing from raft membership"
        );

        Ok(())
    }
}
