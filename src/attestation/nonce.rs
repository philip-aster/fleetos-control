//! Nonce generation and validation for hardware attestation.
//!
//! Nonces are persisted to a fjall keyspace so pending attestations survive
//! control-plane restarts. Each nonce is single-use and carries a TTL.
use std::time::Duration;

use parking_lot::Mutex;
use rand::Rng;
use time::OffsetDateTime;

use super::AttestationError;

/// Manages attestation nonces with TTL expiry, backed by fjall.
pub struct NonceManager {
    /// Keyspace mapping nonce bytes -> expiry unix timestamp (i64 BE bytes).
    keyspaces: fjall::Keyspace,
    /// TTL for nonces.
    ttl: Duration,
    /// Serializes get+remove so a nonce cannot be consumed twice by
    /// concurrent requests on the same node.
    consume_lock: Mutex<()>,
}

impl NonceManager {
    pub fn new(keyspaces: fjall::Keyspace) -> Self {
        Self {
            keyspaces,
            ttl: Duration::from_secs(300),
            consume_lock: Mutex::new(()),
        }
    }

    /// Generate a fresh 32-byte nonce and persist it with its expiry.
    pub fn generate_nonce(&self) -> Result<Vec<u8>, AttestationError> {
        // Opportunistic cleanup of expired nonces (best-effort).
        let _ = self.sweep_expired();

        let mut nonce = vec![0u8; 32];
        rand::rng().fill_bytes(&mut nonce);

        let expires_at = OffsetDateTime::now_utc().unix_timestamp() + self.ttl.as_secs() as i64;
        self.keyspaces
            .insert(nonce.as_slice(), expires_at.to_be_bytes().as_slice())
            .map_err(|e| AttestationError::Nonce(format!("nonce storage failed: {}", e)))?;

        Ok(nonce)
    }

    /// Validate a nonce and consume it (single-use).
    ///
    /// Returns `true` if the nonce was known and unexpired, `false` otherwise.
    /// The nonce is removed either way.
    pub fn validate_and_consume(&self, nonce: &[u8]) -> Result<bool, AttestationError> {
        let _guard = self.consume_lock.lock();

        let value = match self
            .keyspaces
            .get(nonce)
            .map_err(|e| AttestationError::Nonce(format!("nonce lookup failed: {}", e)))?
        {
            Some(v) => v,
            None => return Ok(false),
        };

        // Single-use: remove before validating.
        self.keyspaces
            .remove(nonce)
            .map_err(|e| AttestationError::Nonce(format!("nonce removal failed: {}", e)))?;

        let bytes: [u8; 8] = value
            .as_ref()
            .try_into()
            .map_err(|_| AttestationError::Nonce("corrupt nonce expiry".to_owned()))?;
        let expires_at = i64::from_be_bytes(bytes);

        Ok(OffsetDateTime::now_utc().unix_timestamp() <= expires_at)
    }

    /// Remove expired nonces.
    fn sweep_expired(&self) -> Result<(), AttestationError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut expired_keys = Vec::new();
        for guard in self.keyspaces.prefix(Vec::<u8>::new()) {
            let Ok((key, value)) = guard.into_inner() else {
                continue;
            };
            let Ok(bytes): Result<[u8; 8], _> = value.as_ref().try_into() else {
                continue;
            };
            if i64::from_be_bytes(bytes) < now {
                expired_keys.push(key.to_vec());
            }
        }
        for key in expired_keys {
            self.keyspaces
                .remove(key)
                .map_err(|e| AttestationError::Nonce(format!("nonce sweep failed: {}", e)))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_nonce_manager(name: &str) -> (std::sync::Arc<fjall::Database>, NonceManager) {
        let dir = std::env::temp_dir().join(format!(
            "fleetos-nonce-test-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let db = crate::storage::open_database(&dir).unwrap();
        let keyspaces = crate::storage::init_keyspaces(&db).unwrap();
        (db, NonceManager::new(keyspaces.nonces.clone()))
    }

    #[test]
    fn generated_nonces_are_unique() {
        let (_db, manager) = test_nonce_manager("unique");
        let n1 = manager.generate_nonce().unwrap();
        let n2 = manager.generate_nonce().unwrap();
        assert_ne!(n1, n2);
    }

    #[test]
    fn nonce_is_single_use() {
        let (_db, manager) = test_nonce_manager("single-use");
        let nonce = manager.generate_nonce().unwrap();
        assert!(manager.validate_and_consume(&nonce).unwrap());
        assert!(!manager.validate_and_consume(&nonce).unwrap());
    }

    #[test]
    fn unknown_nonce_is_rejected() {
        let (_db, manager) = test_nonce_manager("unknown");
        assert!(!manager.validate_and_consume(b"unknown-nonce").unwrap());
    }
}
