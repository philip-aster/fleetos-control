//! fjall-backed storage layer.
//!
//! Single database directory, multiple keyspaces (column families). This is critical for the
//! atomic-apply invariant: Raft log entry → fjall write → version increment →
//! broadcast diff, all within one WriteBatch.

pub mod engine;
pub mod schema;
pub mod tables;
pub mod version;

pub use engine::StorageEngine;
use fjall::{Database, KeyspaceCreateOptions};
use std::path::Path;
use std::sync::Arc;

/// Open the fjall database at the given path.
///
/// Local disk only — never a network filesystem.
pub fn open_database(path: &Path) -> Result<Arc<Database>, StorageError> {
    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(StorageError::CreateDir)?;
    }

    let db = Database::builder(path).open().map_err(StorageError::Open)?;
    Ok(Arc::new(db))
}

/// Initialize all required keyspaces.
pub fn init_keyspaces(db: &Database) -> Result<Keyspaces, StorageError> {
    let opts = KeyspaceCreateOptions::default;

    Ok(Keyspaces {
        version: db
            .keyspace(tables::VERSION_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        raft_log: db
            .keyspace(tables::RAFT_LOG_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        raft_log_meta: db
            .keyspace(tables::RAFT_LOG_META_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        raft_state: db
            .keyspace(tables::RAFT_STATE_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        raft_snapshot: db
            .keyspace(tables::RAFT_SNAPSHOT_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        nodes: db
            .keyspace(tables::NODE_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        svids: db
            .keyspace(tables::SVID_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        sag_rules: db
            .keyspace(tables::SAG_RULE_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        join_tokens: db
            .keyspace(tables::JOIN_TOKEN_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        revoked_delegations: db
            .keyspace(tables::REVOKED_DELEGATION_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        active_delegations: db
            .keyspace(tables::ACTIVE_DELEGATION_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        ordinals: db
            .keyspace(tables::ORDINAL_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        placements: db
            .keyspace(tables::PLACEMENT_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        tenants: db
            .keyspace(tables::TENANT_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        workloads: db
            .keyspace(tables::WORKLOAD_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        secrets: db
            .keyspace(tables::SECRET_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        dummy_ips: db
            .keyspace(tables::DUMMY_IP_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        pcr_policies: db
            .keyspace(tables::PCR_POLICY_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        router_assignments: db
            .keyspace(tables::ROUTER_ASSIGNMENT_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        node_pools: db
            .keyspace(tables::NODE_POOL_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        trust_bundles: db
            .keyspace(tables::TRUST_BUNDLE_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        nonces: db
            .keyspace(tables::NONCE_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        nonce_claims: db
            .keyspace(tables::NONCE_CLAIM_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        svid_grants: db
            .keyspace(tables::SVID_GRANT_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
        revoked_svids: db
            .keyspace(tables::REVOKED_SVID_KEYSPACE, opts)
            .map_err(StorageError::Open)?,
    })
}

/// All keyspaces used by fleetos-control.
#[derive(Clone)]
pub struct Keyspaces {
    pub version: fjall::Keyspace,
    pub raft_log: fjall::Keyspace,
    pub raft_log_meta: fjall::Keyspace,
    pub raft_state: fjall::Keyspace,
    pub raft_snapshot: fjall::Keyspace,
    pub nodes: fjall::Keyspace,
    pub svids: fjall::Keyspace,
    pub sag_rules: fjall::Keyspace,
    pub join_tokens: fjall::Keyspace,
    pub revoked_delegations: fjall::Keyspace,
    pub active_delegations: fjall::Keyspace,
    pub ordinals: fjall::Keyspace,
    pub placements: fjall::Keyspace,
    pub tenants: fjall::Keyspace,
    pub workloads: fjall::Keyspace,
    pub secrets: fjall::Keyspace,
    pub dummy_ips: fjall::Keyspace,
    pub pcr_policies: fjall::Keyspace,
    pub router_assignments: fjall::Keyspace,
    pub node_pools: fjall::Keyspace,
    pub trust_bundles: fjall::Keyspace,
    pub nonces: fjall::Keyspace,
    pub nonce_claims: fjall::Keyspace,
    pub svid_grants: fjall::Keyspace,
    pub revoked_svids: fjall::Keyspace,
}

impl Keyspaces {
    /// Returns all keyspaces that must be included in Raft snapshots.
    ///
    /// Excludes `raft_log` and `raft_log_meta` — openraft manages log
    /// truncation separately via snapshot metadata. Includes `raft_state`
    /// because it carries `last_applied` and `last_membership`.
    pub fn snapshot_keyspaces(&self) -> Vec<(&'static str, &fjall::Keyspace)> {
        vec![
            (tables::VERSION_KEYSPACE, &self.version),
            (tables::NODE_KEYSPACE, &self.nodes),
            (tables::SVID_KEYSPACE, &self.svids),
            (tables::SAG_RULE_KEYSPACE, &self.sag_rules),
            (tables::JOIN_TOKEN_KEYSPACE, &self.join_tokens),
            (
                tables::REVOKED_DELEGATION_KEYSPACE,
                &self.revoked_delegations,
            ),
            (tables::ACTIVE_DELEGATION_KEYSPACE, &self.active_delegations),
            (tables::ORDINAL_KEYSPACE, &self.ordinals),
            (tables::PLACEMENT_KEYSPACE, &self.placements),
            (tables::TENANT_KEYSPACE, &self.tenants),
            (tables::WORKLOAD_KEYSPACE, &self.workloads),
            (tables::SECRET_KEYSPACE, &self.secrets),
            (tables::DUMMY_IP_KEYSPACE, &self.dummy_ips),
            (tables::PCR_POLICY_KEYSPACE, &self.pcr_policies),
            (tables::ROUTER_ASSIGNMENT_KEYSPACE, &self.router_assignments),
            (tables::NODE_POOL_KEYSPACE, &self.node_pools),
            (tables::RAFT_STATE_KEYSPACE, &self.raft_state),
            (tables::TRUST_BUNDLE_KEYSPACE, &self.trust_bundles),
            (tables::REVOKED_SVID_KEYSPACE, &self.revoked_svids),
        ]
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("failed to create database directory: {0}")]
    CreateDir(std::io::Error),

    #[error("failed to open fjall database: {0}")]
    Open(#[source] fjall::Error),

    #[error("storage error: {0}")]
    Storage(#[source] fjall::Error),

    #[error("serialization error: {0}")]
    Serialization(#[source] postcard::Error),

    #[error("key not found: {0}")]
    NotFound(String),
}
