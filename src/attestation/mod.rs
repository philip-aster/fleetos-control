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

/// The attestation service orchestrates the full join flow.
pub struct AttestationService {
    nonce_manager: nonce::NonceManager,
    join_token_store: join_token::JoinTokenStore,
    pcr_store: pcr_policy::PcrPolicyStore,
}

impl AttestationService {
    pub fn new(
        join_tokens_keyspace: fjall::Keyspace,
        pcr_policies_keyspace: fjall::Keyspace,
    ) -> Self {
        Self {
            nonce_manager: nonce::NonceManager::new(),
            join_token_store: join_token::JoinTokenStore::new(join_tokens_keyspace),
            pcr_store: pcr_policy::PcrPolicyStore::new(pcr_policies_keyspace),
        }
    }

    /// Issue a fresh nonce for an attestation challenge.
    ///
    /// Every attestation attempt requires a nonce we generated.
    /// A captured quote from a previous join is worthless without the matching nonce.
    pub fn issue_nonce(&self) -> Result<Vec<u8>, AttestationError> {
        self.nonce_manager.generate()
    }

    /// Validate a nonce that was previously issued.
    ///
    /// Returns true if the nonce is valid and has not been used.
    /// Consumes the nonce (single-use).
    pub fn validate_nonce(&self, nonce: &[u8]) -> Result<bool, AttestationError> {
        self.nonce_manager.validate_and_consume(nonce)
    }

    /// Generate a new join token for a specific node kind.
    ///
    /// Called by `AdminService.GenerateJoinToken`.
    pub fn generate_join_token(
        &self,
        node_kind: join_token::NodeKind,
    ) -> Result<Vec<u8>, AttestationError> {
        self.join_token_store.generate(node_kind)
    }

    /// Validate and consume a join token (strict single-use).
    ///
    /// Called during the attestation flow after quote verification.
    pub fn consume_join_token(
        &self,
        token: &[u8],
    ) -> Result<join_token::JoinTokenRecord, AttestationError> {
        self.join_token_store.validate_and_consume(token)
    }

    /// Get the expected PCR values for a node.
    ///
    /// Called during TPM quote verification to check if the node's
    /// firmware/bootloader/kernel measurements match the expected policy.
    pub fn get_expected_pcrs(
        &self,
        node_id: &str,
    ) -> Result<Option<Vec<tpm::PcrValue>>, AttestationError> {
        self.pcr_store.get_expected_pcrs(node_id)
    }
}
