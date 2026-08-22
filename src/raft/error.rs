//! Error types for the Raft layer.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RaftError {
    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),

    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("openraft error: {0}")]
    Openraft(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("raft not initialized")]
    NotInitialized,

    #[error("transport error: {0}")]
    Transport(String),
}

impl From<RaftError> for openraft::StorageError<u64> {
    fn from(e: RaftError) -> Self {
        // StorageError::IO is a struct variant with a named `source` field.
        // StorageIOError::write() is the general-purpose write error constructor
        // that accepts impl Into<AnyError> (RaftError implements std::error::Error
        // via thiserror, so &e satisfies the Into<AnyError> bound).
        openraft::StorageError::IO {
            source: openraft::StorageIOError::write(&e),
        }
    }
}
