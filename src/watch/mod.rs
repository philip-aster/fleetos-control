//! Watch API & State Distribution — Module 5.
//!
//! Broadcasts state changes to all downstream components via gRPC server-streaming.
//!
//! Services implemented (matching fleetos-core proto definitions exactly):
//! - `PolicyService` (agents): SAG rules + revoked delegation IDs
//! - `WatchService` (all): SecretRotationNotification stream
//! - `SecretService` (agents): pull-based FetchSecret (unary)
//! - `SchedulerService` (agents): WatchSchedule streaming WorkloadAssignments
//! - `RouterAssignmentService` (routers): WatchRoutes streaming RouteEntries

pub mod broadcast;
pub mod policy_stream;
pub mod router_assignment;
pub mod scheduler_stream;
pub mod secret_service;
pub mod watch_service;

use thiserror::Error;

/// Errors from watch/streaming operations.
#[derive(Debug, Error)]
pub enum WatchError {
    #[error("broadcast channel closed")]
    ChannelClosed,

    #[error("broadcast send failed: {0}")]
    SendFailed(String),

    #[error("secret not found: {0}")]
    SecretNotFound(String),

    #[error("secret access denied for {spiffe_id} on key {secret_key}")]
    SecretAccessDenied {
        secret_key: String,
        spiffe_id: String,
    },

    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),

    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("secret error: {0}")]
    Secret(#[from] crate::secrets::SecretError),
}
