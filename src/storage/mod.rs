//! fjall-backed storage layer.
//!
//! Single database directory, multiple keyspaces (column families). This is critical for the
//! atomic-apply invariant: Raft log entry → fjall write → version increment →
//! broadcast diff, all within one WriteBatch.

pub mod schema;
pub mod tables;
pub mod version;

use std::path::Path;
use std::sync::Arc;

use fjall::{Database, KeyspaceCreateOptions};

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
    })
}

/// All keyspaces used by fleetos-control.
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
