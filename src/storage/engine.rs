//! Unified storage engine interface.

use fjall::Keyspace;

/// Unified storage engine providing access to all keyspaces.
///
/// This is the main entry point for storage operations across the system.
/// Each module gets access to the specific keyspaces it needs.
pub struct StorageEngine {
    pub raft_log: Keyspace,
    pub raft_log_meta: Keyspace,
    pub nodes: Keyspace,
    pub placements: Keyspace,
    pub workloads: Keyspace,
    pub delegations: Keyspace,
    pub delegations_revoked: Keyspace,
    pub join_tokens: Keyspace,
    pub pcr_policies: Keyspace,
    pub dummy_ips: Keyspace,
    pub secrets: Keyspace,
    pub sags: Keyspace,
}

impl StorageEngine {
    pub fn new(
        raft_log: Keyspace,
        raft_log_meta: Keyspace,
        nodes: Keyspace,
        placements: Keyspace,
        workloads: Keyspace,
        delegations: Keyspace,
        delegations_revoked: Keyspace,
        join_tokens: Keyspace,
        pcr_policies: Keyspace,
        dummy_ips: Keyspace,
        secrets: Keyspace,
        sags: Keyspace,
    ) -> Self {
        Self {
            raft_log,
            raft_log_meta,
            nodes,
            placements,
            workloads,
            delegations,
            delegations_revoked,
            join_tokens,
            pcr_policies,
            dummy_ips,
            secrets,
            sags,
        }
    }
}
