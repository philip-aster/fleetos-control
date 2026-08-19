//! redb-backed storage layer.
//!
//! Single database file, multiple table namespaces. This is critical for the
//! atomic-apply invariant: Raft log entry → redb write → version increment →
//! broadcast diff, all within one transaction.

pub mod schema;
pub mod tables;
pub mod version;

use std::path::Path;
use std::sync::Arc;

/// Open the redb database at the given path.
///
/// Local disk only — never a network filesystem.
pub fn open_database(path: &Path) -> Result<Arc<redb::Database>, StorageError> {
    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(StorageError::CreateDir)?;
    }

    let db = redb::Database::create(path).map_err(StorageError::Open)?;
    Ok(Arc::new(db))
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("failed to create database directory: {0}")]
    CreateDir(std::io::Error),

    #[error("failed to open redb database: {0}")]
    Open(#[source] redb::DatabaseError),

    #[error("transaction error: {0}")]
    Transaction(#[source] redb::TransactionError),

    #[error("table error: {0}")]
    Table(#[source] redb::TableError),

    #[error("storage error: {0}")]
    Storage(#[source] redb::StorageError),

    #[error("serialization error: {0}")]
    Serialization(#[source] postcard::Error),

    #[error("key not found: {0}")]
    NotFound(String),
}
