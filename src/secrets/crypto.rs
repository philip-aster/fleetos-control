use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Wrapper around a 256-bit key that zeroizes memory on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).expect("Failed to sample OS random bytes");
        Self(key)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailure,
    #[error("Decryption failed or ciphertext tampered")]
    DecryptionFailure,
    #[error("Invalid nonce length")]
    InvalidNonce,
}

#[derive(Clone)]
pub struct CryptoEngine {
    key: SecretKey,
}

impl CryptoEngine {
    pub fn new(key: SecretKey) -> Self {
        Self { key }
    }

    /// Encrypts plaintext payload returning `(nonce_bytes, ciphertext)`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let cipher =
            Aes256Gcm::new_from_slice(&self.key.0).map_err(|_| CryptoError::EncryptionFailure)?;

        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes).map_err(|_| CryptoError::EncryptionFailure)?;
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailure)?;

        Ok((nonce_bytes.to_vec(), ciphertext))
    }

    /// Decrypts ciphertext using the provided 12-byte nonce.
    pub fn decrypt(&self, nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if nonce_bytes.len() != 12 {
            return Err(CryptoError::InvalidNonce);
        }

        let cipher =
            Aes256Gcm::new_from_slice(&self.key.0).map_err(|_| CryptoError::DecryptionFailure)?;

        let nonce_array: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidNonce)?;
        let nonce = Nonce::from(nonce_array);

        cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailure)
    }
}
