//! TLS/mTLS configuration and trust domain enforcement.
//!
//! FleetOS uses two independent trust domains for blast-radius isolation:
//! - **Data/Control**: control ↔ agent/router/gateway, Raft peers
//! - **Admin**: fleetctl ↔ fleetctl-proxy ↔ control
//!
//! Routing is structural: which gRPC listener a connection arrived on determines
//! the trust domain. No per-request SVID inspection is needed.

pub mod mtls;
pub mod trust_domains;

use thiserror::Error;

/// Errors from TLS/mTLS operations.
#[derive(Debug, Error)]
pub enum TlsError {
    #[error("rustls error: {0}")]
    Rustls(String),

    #[error("certificate error: {0}")]
    Certificate(String),

    #[error("trust domain mismatch: expected {expected}, got {actual}")]
    TrustDomainMismatch { expected: String, actual: String },

    #[error("identity kind rejected: expected {expected}, got {actual}")]
    IdentityKindMismatch { expected: String, actual: String },

    #[error("no SPIFFE URI SAN found in peer certificate")]
    NoSpiffeSan,

    #[error("failed to parse SPIFFE ID: {0}")]
    SpiffeParse(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("no valid certificate found in chain")]
    NoCertificate,
}

/// Connection info extracted from the TLS handshake.
///
/// Carries the authenticated peer's SpiffeId from the TLS layer into the
/// application layer. Tonic makes this available in request extensions
/// when the stream implements `Connected`.
#[derive(Debug, Clone)]
pub struct PeerConnectInfo {
    /// Authenticated peer SpiffeId. `None` for unauthenticated connections,
    /// which are only possible on listeners with optional client auth
    /// (the Data/Control listener, for the pre-SVID attestation flow).
    pub spiffe_id: Option<fleetos_core::spiffe::SpiffeId>,
}
