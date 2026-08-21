//! Envelope encryption for secrets at rest.
//!
//! Design:
//! - Each secret gets its own DEK (Data Encryption Key).
//! - The DEK encrypts the secret value (ChaCha20-Poly1305).
//! - The DEK itself is wrapped (encrypted) by the master key.
//! - This lets us re-seal for new/rotated recipients without re-encrypting
//!   the secret value: unwrap DEK → decrypt → re-seal with `fleetos_core::crypto::seal`.
//!
//! NOTE: master-key rotation (re-wrapping every stored DEK under a new master key)
//! is NOT supported in v1. If `master.key` is rotated on disk, stored DEKs will fail
//! to unwrap until a re-wrap migration is implemented.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::Rng;
use zeroize::Zeroizing;

use super::SecretError;

/// Length of a DEK in bytes (256-bit key for ChaCha20-Poly1305).
const DEK_LENGTH: usize = 32;
/// Length of a master key in bytes (256-bit).
const MASTER_KEY_LENGTH: usize = 32;
/// Length of a nonce in bytes (96-bit for ChaCha20Poly1305).
const NONCE_LENGTH: usize = 12;

/// A Data Encryption Key.
///
/// Wraps its bytes in `Zeroizing` so the key material is scrubbed from memory on
/// drop — matching the project's established discipline (`crypto::unseal()` returns
/// `Zeroizing<Vec<u8>>`).
#[derive(Clone)]
pub struct Dek {
    bytes: Zeroizing<Vec<u8>>,
}

impl Dek {
    /// Generate a fresh random DEK.
    pub fn generate() -> Result<Self, SecretError> {
        let mut bytes = vec![0u8; DEK_LENGTH];
        rand::rng().fill_bytes(&mut bytes);
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    /// Create a DEK from raw bytes (used when unwrapping).
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SecretError> {
        if bytes.len() != DEK_LENGTH {
            return Err(SecretError::InvalidDekLength(bytes.len()));
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    /// Access the raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A DEK that has been wrapped (encrypted) by the master key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WrappedDek {
    /// Nonce used for wrapping.
    pub nonce: Vec<u8>,
    /// The wrapped (encrypted) DEK bytes.
    pub ciphertext: Vec<u8>,
}

/// Trait for master-key providers.
///
/// Deliberately does NOT expose `get_master_key()` — a real KMS backend never lets
/// raw key material leave the KMS boundary, and that's the whole point of keeping
/// this pluggable. `wrap_dek`/`unwrap_dek` are the correct KMS-compatible operations.
pub trait MasterKeyProvider: Send + Sync {
    /// Wrap (encrypt) a DEK under the master key.
    fn wrap_dek(&self, dek: &Dek) -> Result<WrappedDek, SecretError>;

    /// Unwrap (decrypt) a DEK using the master key.
    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Dek, SecretError>;
}

/// File-based master key provider (v1 default).
///
/// Loads a 32-byte master key from a file. The raw key is held in `Zeroizing`
/// memory and never exposed via the `MasterKeyProvider` trait interface.
pub struct FileMasterKey {
    raw_key: Zeroizing<Vec<u8>>,
}

impl FileMasterKey {
    /// Load a master key from a file.
    pub fn load(path: &std::path::Path) -> Result<Self, SecretError> {
        let bytes = std::fs::read(path).map_err(SecretError::Io)?;
        if bytes.len() != MASTER_KEY_LENGTH {
            return Err(SecretError::InvalidMasterKeyLength(bytes.len()));
        }
        Ok(Self {
            raw_key: Zeroizing::new(bytes),
        })
    }

    /// Generate a new master key and write it to a file (0600 on Unix).
    pub fn generate(path: &std::path::Path) -> Result<Self, SecretError> {
        let mut bytes = vec![0u8; MASTER_KEY_LENGTH];
        rand::rng().fill_bytes(&mut bytes);

        std::fs::write(path, &bytes).map_err(SecretError::Io)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(SecretError::Io)?;
        }

        Ok(Self {
            raw_key: Zeroizing::new(bytes),
        })
    }

    /// Build a cipher from the in-memory raw key.
    ///
    /// Key length has already been validated at construction time (load/generate),
    /// so `new_from_slice`'s `InvalidLength` result is unreachable here.
    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new_from_slice(&self.raw_key)
            .expect("master key length validated at construction")
    }
}

impl MasterKeyProvider for FileMasterKey {
    fn wrap_dek(&self, dek: &Dek) -> Result<WrappedDek, SecretError> {
        let mut nonce_bytes = vec![0u8; NONCE_LENGTH];
        rand::rng().fill_bytes(&mut nonce_bytes);

        // Use TryInto instead of the deprecated from_slice
        let nonce: &Nonce = nonce_bytes
            .as_slice()
            .try_into()
            .expect("nonce length is 12");

        let ciphertext = self
            .cipher()
            .encrypt(nonce, dek.as_bytes())
            .map_err(|e| SecretError::Encryption(e.to_string()))?;

        Ok(WrappedDek {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Dek, SecretError> {
        if wrapped.nonce.len() != NONCE_LENGTH {
            return Err(SecretError::InvalidNonceLength(wrapped.nonce.len()));
        }

        // Use TryInto instead of the deprecated from_slice
        let nonce: &Nonce = wrapped
            .nonce
            .as_slice()
            .try_into()
            .expect("nonce length pre-validated");

        let plaintext = self
            .cipher()
            .decrypt(nonce, wrapped.ciphertext.as_slice())
            .map_err(|e| SecretError::Decryption(e.to_string()))?;

        Dek::from_bytes(plaintext)
    }
}

/// An envelope-encrypted secret, as stored at rest.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnvelopeSecret {
    /// The DEK, wrapped by the master key.
    pub wrapped_dek: WrappedDek,
    /// Nonce used to encrypt the secret value.
    pub nonce: Vec<u8>,
    /// The secret value, encrypted with the DEK.
    pub ciphertext: Vec<u8>,
}

/// Encrypt a secret value for at-rest storage (envelope encryption).
pub fn encrypt_at_rest(
    plaintext: &[u8],
    master_key: &dyn MasterKeyProvider,
) -> Result<EnvelopeSecret, SecretError> {
    // 1. Generate a fresh DEK.
    let dek = Dek::generate()?;

    // 2. Encrypt the secret value with the DEK.
    let mut nonce_bytes = vec![0u8; NONCE_LENGTH];
    rand::rng().fill_bytes(&mut nonce_bytes);

    let nonce: &Nonce = nonce_bytes
        .as_slice()
        .try_into()
        .expect("nonce length is 12");

    let cipher = ChaCha20Poly1305::new_from_slice(dek.as_bytes())
        .expect("DEK length is enforced by Dek::generate");
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| SecretError::Encryption(e.to_string()))?;

    // 3. Wrap the DEK with the master key.
    let wrapped_dek = master_key.wrap_dek(&dek)?;

    Ok(EnvelopeSecret {
        wrapped_dek,
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt an envelope-encrypted secret. Returns `Zeroizing` plaintext.
pub fn decrypt_at_rest(
    envelope: &EnvelopeSecret,
    master_key: &dyn MasterKeyProvider,
) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    // 1. Unwrap the DEK.
    let dek = master_key.unwrap_dek(&envelope.wrapped_dek)?;

    // 2. Decrypt the secret value.
    if envelope.nonce.len() != NONCE_LENGTH {
        return Err(SecretError::InvalidNonceLength(envelope.nonce.len()));
    }

    let nonce: &Nonce = envelope
        .nonce
        .as_slice()
        .try_into()
        .expect("nonce length pre-validated");

    let cipher = ChaCha20Poly1305::new_from_slice(dek.as_bytes())
        .expect("DEK length is enforced by Dek::from_bytes");
    let plaintext = cipher
        .decrypt(nonce, envelope.ciphertext.as_slice())
        .map_err(|e| SecretError::Decryption(e.to_string()))?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_master_key() -> FileMasterKey {
        let mut bytes = vec![0u8; MASTER_KEY_LENGTH];
        rand::rng().fill_bytes(&mut bytes);
        FileMasterKey {
            raw_key: Zeroizing::new(bytes),
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let master_key = test_master_key();
        let plaintext = b"super secret value";

        let envelope = encrypt_at_rest(plaintext, &master_key).unwrap();
        let decrypted = decrypt_at_rest(&envelope, &master_key).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn wrong_master_key_fails() {
        let master_key = test_master_key();
        let wrong_key = test_master_key();
        let plaintext = b"super secret value";

        let envelope = encrypt_at_rest(plaintext, &master_key).unwrap();
        let result = decrypt_at_rest(&envelope, &wrong_key);

        assert!(result.is_err());
    }

    #[test]
    fn dek_must_be_32_bytes() {
        let result = Dek::from_bytes(vec![0u8; 16]);
        assert!(matches!(result, Err(SecretError::InvalidDekLength(16))));
    }
}
