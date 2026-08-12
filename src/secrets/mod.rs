pub mod acl;
pub mod crypto;

use std::collections::HashMap;
use std::sync::RwLock;

pub use acl::{AclEvaluator, Action};
pub use crypto::{CryptoEngine, CryptoError, SecretKey};

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("Access denied for path '{path}' performing action '{action:?}'")]
    AccessDenied { path: String, action: Action },
    #[error("Secret not found at path: {0}")]
    NotFound(String),
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),
}

#[derive(Clone)]
pub struct EncryptedEnvelope {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// In-memory secret store backed by AES-256-GCM encryption and ACL verification.
pub struct SecretStore {
    crypto: CryptoEngine,
    acl: AclEvaluator,
    storage: RwLock<HashMap<String, EncryptedEnvelope>>,
}

impl SecretStore {
    pub fn new(crypto: CryptoEngine, acl: AclEvaluator) -> Self {
        Self {
            crypto,
            acl,
            storage: RwLock::new(HashMap::new()),
        }
    }

    /// Stores a secret at the given path if permitted.
    pub fn set_secret(&self, path: &str, secret_value: &[u8]) -> Result<(), SecretError> {
        if !self.acl.check_permission(path, Action::Write) {
            return Err(SecretError::AccessDenied {
                path: path.to_string(),
                action: Action::Write,
            });
        }

        let (nonce, ciphertext) = self.crypto.encrypt(secret_value)?;
        let envelope = EncryptedEnvelope { nonce, ciphertext };

        let mut store = self.storage.write().unwrap();
        store.insert(path.to_string(), envelope);
        Ok(())
    }

    /// Retrieves and decrypts a secret from the given path if permitted.
    pub fn get_secret(&self, path: &str) -> Result<Vec<u8>, SecretError> {
        if !self.acl.check_permission(path, Action::Read) {
            return Err(SecretError::AccessDenied {
                path: path.to_string(),
                action: Action::Read,
            });
        }

        let store = self.storage.read().unwrap();
        let envelope = store
            .get(path)
            .ok_or_else(|| SecretError::NotFound(path.to_string()))?;

        let decrypted = self.crypto.decrypt(&envelope.nonce, &envelope.ciphertext)?;
        Ok(decrypted)
    }

    /// Deletes a secret at the given path if permitted.
    pub fn delete_secret(&self, path: &str) -> Result<(), SecretError> {
        if !self.acl.check_permission(path, Action::Delete) {
            return Err(SecretError::AccessDenied {
                path: path.to_string(),
                action: Action::Delete,
            });
        }

        let mut store = self.storage.write().unwrap();
        if store.remove(path).is_none() {
            return Err(SecretError::NotFound(path.to_string()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secrets_flow() {
        let key = SecretKey::generate();
        let crypto = CryptoEngine::new(key);

        let mut acl = AclEvaluator::new();
        acl.add_rule("prod/*", &[Action::Read, Action::Write]);

        let store = SecretStore::new(crypto, acl);

        // Store secret
        store
            .set_secret("prod/db_pass", b"super_secret_password")
            .unwrap();

        // Retrieve secret
        let fetched = store.get_secret("prod/db_pass").unwrap();
        assert_eq!(fetched, b"super_secret_password");

        // Attempt unauthorized read
        assert!(store.get_secret("dev/db_pass").is_err());
    }
}
