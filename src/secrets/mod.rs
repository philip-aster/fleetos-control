//! Secrets module — at-rest encryption + ACL matrix.
//!
//! Two layers, both owned here:
//! 1. **At-rest encryption** (`crypto.rs`): envelope encryption, DEK-per-secret
//!    wrapped by a master key. This is durable storage that survives recipient
//!    SVID rotation — `fleetos-core::crypto::seal()` alone is insufficient because
//!    it only does point-to-point delivery sealing (unreadable once the recipient rotates).
//! 2. **ACL matrix** (`acl.rs`): SPIFFE-ID authorization, checked BEFORE either
//!    encryption layer is touched.
//!
//! Delivery sealing (point-to-point, keyed to a recipient's current SVID pubkey)
//! is a separate concern handled by `fleetos_core::crypto::seal()` in the watch layer —
//! `SecretStore::fetch_secret` returns plaintext that the caller then seals for delivery.

pub mod acl;
pub mod crypto;

use thiserror::Error;
use zeroize::Zeroizing;

use fleetos_core::spiffe::SpiffeId;

/// Errors from secret operations.
#[derive(Debug, Error)]
pub enum SecretError {
    #[error("access denied: {spiffe_id} is not authorized for secret {secret_key}")]
    AccessDenied {
        secret_key: String,
        spiffe_id: String,
    },

    #[error("secret not found: {0}")]
    NotFound(String),

    #[error("invalid DEK length: expected 32, got {0}")]
    InvalidDekLength(usize),

    #[error("invalid master key length: expected 32, got {0}")]
    InvalidMasterKeyLength(usize),

    #[error("invalid nonce length: expected 12, got {0}")]
    InvalidNonceLength(usize),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("decryption error: {0}")]
    Decryption(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),

    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),
}

/// Key prefix for envelope-encrypted secret records.
const SECRET_KEY_PREFIX: &str = "secret:";
/// Key prefix for per-secret ACL records.
const ACL_KEY_PREFIX: &str = "acl:";

/// High-level secret storage combining ACL authorization and at-rest encryption.
///
/// Enforces the ordering invariant: **ACL is checked before any decryption happens.**
pub struct SecretStore {
    keyspace: fjall::Keyspace,
    master_key: Box<dyn crypto::MasterKeyProvider>,
}

impl SecretStore {
    pub fn new(keyspace: fjall::Keyspace, master_key: Box<dyn crypto::MasterKeyProvider>) -> Self {
        Self {
            keyspace,
            master_key,
        }
    }

    /// Fetch a secret's plaintext, checking ACL authorization first.
    ///
    /// Returns `Zeroizing` plaintext. The caller is responsible for delivery-sealing
    /// (via `fleetos_core::crypto::seal`) if sending to a recipient.
    pub fn fetch_secret(
        &self,
        secret_key: &str,
        requesting: &SpiffeId,
    ) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        // 1. Check ACL FIRST — before touching any encryption layer.
        let acl = self.load_acl(secret_key)?;
        acl.authorize(secret_key, requesting)?;

        // 2. Load and decrypt the secret.
        let envelope = self
            .load_envelope(secret_key)?
            .ok_or_else(|| SecretError::NotFound(secret_key.to_owned()))?;

        crypto::decrypt_at_rest(&envelope, self.master_key.as_ref())
    }

    /// Prepare a secret for storage: encrypt at rest and build the ACL.
    ///
    /// Returns `(envelope_bytes, acl_bytes)` ready to be proposed via Raft.
    /// Does NOT write to disk — the caller proposes via Raft and the state
    /// machine persists. This keeps envelope encryption (non-deterministic)
    /// on the leader, preserving the atomic-apply invariant.
    pub fn prepare_secret(
        &self,
        secret_key: &str,
        plaintext: &[u8],
        authorized: &[SpiffeId],
    ) -> Result<(Vec<u8>, Vec<u8>), SecretError> {
        let envelope = crypto::encrypt_at_rest(plaintext, self.master_key.as_ref())?;
        let envelope_bytes =
            postcard::to_allocvec(&envelope).map_err(SecretError::Serialization)?;
        let mut acl = acl::SecretAcl::new();
        for spiffe_id in authorized {
            acl.grant(secret_key, spiffe_id);
        }
        let acl_bytes = postcard::to_allocvec(&acl).map_err(SecretError::Serialization)?;
        Ok((envelope_bytes, acl_bytes))
    }

    fn load_acl(&self, secret_key: &str) -> Result<acl::SecretAcl, SecretError> {
        let key = format!("{}{}", ACL_KEY_PREFIX, secret_key);
        match self
            .keyspace
            .get(key.as_bytes())
            .map_err(|e| SecretError::Storage(crate::storage::StorageError::Storage(e)))?
        {
            Some(bytes) => postcard::from_bytes(&bytes).map_err(SecretError::Serialization),
            // No ACL record = empty ACL = deny all (default deny).
            None => Ok(acl::SecretAcl::new()),
        }
    }

    fn load_envelope(
        &self,
        secret_key: &str,
    ) -> Result<Option<crypto::EnvelopeSecret>, SecretError> {
        let key = format!("{}{}", SECRET_KEY_PREFIX, secret_key);
        match self
            .keyspace
            .get(key.as_bytes())
            .map_err(|e| SecretError::Storage(crate::storage::StorageError::Storage(e)))?
        {
            Some(bytes) => {
                let envelope: crypto::EnvelopeSecret =
                    postcard::from_bytes(&bytes).map_err(SecretError::Serialization)?;
                Ok(Some(envelope))
            }
            None => Ok(None),
        }
    }
}
