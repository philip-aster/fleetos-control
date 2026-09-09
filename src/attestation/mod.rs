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
pub mod ek_cert;
pub mod grpc_service;
pub mod join_token;
pub mod nonce;
pub mod pcr_policy;
pub mod tpm;

use thiserror::Error;

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
    #[error("rate limit exceeded: {0}")]
    RateLimited(String),
    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),
    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Const hex decoder for root-fingerprint pins (R-2 provenance).
///
/// Shared by `ek_cert.rs` and `apple_se.rs` so pin decoding has a single
/// source of truth. Fails the build at compile time on a malformed pin.
pub(crate) const fn decode_hex_32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64, "root fingerprint must be 64 hex chars");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_nibble(b[2 * i]) << 4) | hex_nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

pub(crate) const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("invalid hex character in root fingerprint"),
    }
}
