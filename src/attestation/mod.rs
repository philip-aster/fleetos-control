//! Attestation module — the entry point for nodes joining the cluster.
//!
//! Flow:
//! 1. Node connects to Data/Control listener (unauthenticated initially)
//! 2. Control plane issues a nonce challenge
//! 3. Node attests (TPM quote or Apple SE attestation) bound to the nonce
//! 4. Control plane validates attestation + PCR values
//! 5. On success: issue Join Token → node uses it to get a signed SVID
//! 6. Node reconnects with its SVID for all subsequent communication
//!
//! VSOCK attestation is NOT our concern — `fleetos-agent` verifies
//! `fleetos-guest-init` quotes. We only verify the agent's TPM quote.

pub mod apple_se;
pub mod grpc_service;
pub mod join_token;
pub mod nonce;
pub mod pcr_policy;
pub mod tpm;
use thiserror::Error;

use fleetos_core::spiffe::SpiffeId;

/// Errors from attestation operations.
#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("nonce error: {0}")]
    Nonce(String),

    #[error("quote verification failed: {0}")]
    QuoteVerification(String),

    #[error("PCR policy mismatch: {0}")]
    PcrMismatch(String),

    #[error("join token error: {0}")]
    JoinToken(String),

    #[error("join token already consumed (single-use violation)")]
    JoinTokenAlreadyUsed,

    #[error("join token not found")]
    JoinTokenNotFound,

    #[error("attestation backend not available: {0}")]
    BackendUnavailable(String),

    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),

    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// The attestation backend type a node is using.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AttestationBackend {
    /// TPM 2.0 (fleetos-agent, fleetos-router, fleetos-gateway on Linux)
    Tpm,
    /// Apple Secure Enclave (fleetctl on macOS)
    AppleSe,
}

/// Result of a successful attestation.
#[derive(Debug, Clone)]
pub struct AttestationResult {
    /// The node's SPIFFE ID (derived from attestation evidence).
    pub node_id: SpiffeId,

    /// Which backend was used.
    pub backend: AttestationBackend,

    /// Whether PCR values matched the expected policy.
    pub pcr_validated: bool,

    /// Timestamp of successful attestation.
    pub attested_at: time::OffsetDateTime,
}
