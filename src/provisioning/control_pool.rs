//! CONTROL node pool management — openraft membership changes.
use super::{NodeLifecycleState, NodePoolRecord, ProvisioningError};
use crate::attestation::join_token::NodeKind;
use crate::raft::FleetosRaftConfig;
use crate::storage::StorageEngine;
use fleetos_core::proto::provisioning::NodePoolStatus;
use openraft::{ChangeMembers, Raft};
use std::collections::BTreeSet;
use std::sync::Arc;

/// Manages CONTROL pool → openraft membership transitions.
pub struct ControlPoolManager {
    raft: Arc<Raft<FleetosRaftConfig>>,
    #[allow(dead_code)]
    storage: Arc<StorageEngine>,
}

impl ControlPoolManager {
    pub fn new(raft: Arc<Raft<FleetosRaftConfig>>, storage: Arc<StorageEngine>) -> Self {
        Self { raft, storage }
    }

    /// Derive a deterministic Raft node ID from a provider handle.
    /// Shared with the manual join path (raft::derive_raft_node_id) so both
    /// always agree on node IDs.
    fn derive_node_id(provider_handle: &str) -> u64 {
        crate::raft::derive_raft_node_id(provider_handle)
    }

    /// Handle the status of a CONTROL pool.
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
                    self.ensure_raft_membership(&node.provider_handle).await?;
                }
                NodeLifecycleState::Terminated => {
                    self.remove_raft_membership(&node.provider_handle).await?;
                }
                NodeLifecycleState::Pending => {
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
    async fn ensure_raft_membership(&self, provider_handle: &str) -> Result<(), ProvisioningError> {
        let node_id = Self::derive_node_id(provider_handle);

        let metrics = self.raft.metrics().borrow().clone();
        let membership = &metrics.membership_config.membership();

        // Check if already a voter
        let voters: BTreeSet<u64> = membership.voter_ids().collect();
        if voters.contains(&node_id) {
            tracing::debug!(
                provider_handle = %provider_handle,
                node_id = %node_id,
                "already a raft voter"
            );
            return Ok(());
        }

        // Check if already a learner
        let learners: BTreeSet<u64> = membership.learner_ids().collect();
        if learners.contains(&node_id) {
            // Already a learner — promote to voter
            tracing::info!(
                provider_handle = %provider_handle,
                node_id = %node_id,
                "promoting learner to voter"
            );

            let mut new_voters = voters.clone();
            new_voters.insert(node_id);

            let change = ChangeMembers::AddVoters(
                std::iter::once((
                    node_id,
                    openraft::BasicNode {
                        addr: String::new(),
                    },
                ))
                .collect(),
            );

            self.raft
                .change_membership(change, false)
                .await
                .map_err(|e| ProvisioningError::Raft(e.to_string()))?;

            tracing::info!(node_id = %node_id, "promoted to raft voter");
            return Ok(());
        }

        // Not a member at all — add as learner
        tracing::info!(
            provider_handle = %provider_handle,
            node_id = %node_id,
            "adding as raft learner"
        );

        let node_config = openraft::BasicNode {
            addr: String::new(),
        };

        self.raft
            .add_learner(node_id, node_config, false)
            .await
            .map_err(|e| ProvisioningError::Raft(e.to_string()))?;

        tracing::info!(node_id = %node_id, "added as raft learner");
        Ok(())
    }

    /// Remove a control node from the Raft cluster.
    async fn remove_raft_membership(&self, provider_handle: &str) -> Result<(), ProvisioningError> {
        let node_id = Self::derive_node_id(provider_handle);

        let metrics = self.raft.metrics().borrow().clone();
        let membership = &metrics.membership_config.membership();

        let voters: BTreeSet<u64> = membership.voter_ids().collect();
        let learners: BTreeSet<u64> = membership.learner_ids().collect();

        if !voters.contains(&node_id) && !learners.contains(&node_id) {
            tracing::debug!(
                provider_handle = %provider_handle,
                node_id = %node_id,
                "not a raft member, nothing to remove"
            );
            return Ok(());
        }

        if !voters.contains(&node_id) && !learners.contains(&node_id) {
            tracing::debug!(
                provider_handle = %provider_handle,
                node_id = %node_id,
                "not a raft member, nothing to remove"
            );
            return Ok(());
        }

        // G-15: quorum guard — never remove a voter if it would break the cluster.
        if voters.contains(&node_id) && !removal_preserves_quorum(voters.len()) {
            tracing::warn!(
                provider_handle = %provider_handle,
                node_id = %node_id,
                voter_count = voters.len(),
                "refusing to remove voter: quorum would be lost"
            );
            return Err(ProvisioningError::Raft(format!(
                "refusing to remove voter {}: would break quorum ({} voters)",
                node_id,
                voters.len()
            )));
        }

        tracing::warn!(
            provider_handle = %provider_handle,
            node_id = %node_id,
            "removing from raft membership"
        );

        let mut to_remove = BTreeSet::new();
        to_remove.insert(node_id);

        let change = ChangeMembers::RemoveNodes(to_remove);

        self.raft
            .change_membership(change, false)
            .await
            .map_err(|e| ProvisioningError::Raft(e.to_string()))?;

        tracing::info!(node_id = %node_id, "removed from raft membership");
        Ok(())
    }
}

/// Quorum guard (G-15): removing a voter is safe only if the remaining voter
/// set still holds a majority of the current set AND at least 3 voters stay.
/// Learner removal is unaffected (learners don't count toward quorum).
fn removal_preserves_quorum(current_voters: usize) -> bool {
    if current_voters <= 3 {
        return false; // never shrink a 3-or-fewer voter cluster
    }
    let remaining = current_voters - 1;
    let majority = current_voters / 2 + 1;
    remaining >= majority
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_guard_truth_table() {
        assert!(!removal_preserves_quorum(0));
        assert!(!removal_preserves_quorum(1));
        assert!(!removal_preserves_quorum(2));
        assert!(!removal_preserves_quorum(3)); // floor: keep 3+
        assert!(removal_preserves_quorum(4)); // 4 -> 3 ok
        assert!(removal_preserves_quorum(5)); // 5 -> 4 ok
    }
}
