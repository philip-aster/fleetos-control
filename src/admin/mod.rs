//! Admin API — Module 6.
//!
//! The *only* API surface for `fleetctl-proxy`. Implements the `AdminService`
//! gRPC server defined in `admin.proto`.
//!
//! **Authorization constraint (critical):**
//! - Reject any caller whose SVID `kind` is not `ctrl` (i.e., `fleetctl-proxy`'s identity kind).
//! - A valid `sa` or `node` SVID hitting this endpoint must be rejected at the
//!   TLS/mTLS layer, not just at the application layer.
//! - This enforces the trust-domain boundary between the admin overlay and the
//!   data/control overlay. The two overlays are separated by trust domain for
//!   blast-radius isolation.
//!
//! **Trust domain routing:**
//! AdminService always validates against the Admin-domain trust bundle.
//! This is structural — based on which gRPC listener a connection arrived on —
//! not something to inspect per-request from the peer's claimed trust domain.

pub mod authz;
pub mod service;

use thiserror::Error;

/// Errors from admin operations.
#[derive(Debug, Error)]
pub enum AdminError {
    #[error("unauthorized: caller SVID kind is not ctrl")]
    Unauthorized,

    #[error("tenant already exists: {0}")]
    TenantAlreadyExists(String),

    #[error("tenant not found: {0}")]
    TenantNotFound(String),

    #[error("invalid workload spec: {0}")]
    InvalidWorkloadSpec(String),

    #[error("invalid cron workload: {0}")]
    InvalidCronWorkload(String),

    #[error("invalid node kind: {0}")]
    InvalidNodeKind(String),

    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),

    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("attestation error: {0}")]
    Attestation(#[from] crate::attestation::AttestationError),

    #[error("dummy IP error: {0}")]
    DummyIp(#[from] crate::dummy_ip::DummyIpError),

    #[error("controller error: {0}")]
    Controller(#[from] crate::controllers::ControllerError),
}
