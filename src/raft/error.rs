use thiserror::Error;

#[derive(Error, Debug)]
pub enum RaftStoreError {
    #[error("Database error: {0}")]
    Database(#[from] redb::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
