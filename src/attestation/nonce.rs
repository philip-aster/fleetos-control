//! Nonce management for attestation challenges.
//!
//! Security-critical: we generate the nonce, every verify() call requires
//! a fresh nonce we supplied. Never reuse a nonce. A captured quote from
//! a previous join is worthless without the matching nonce.

use std::collections::HashSet;
use std::sync::Arc;

use super::AttestationError;
use parking_lot::RwLock;
use rand::Rng;

/// Length of attestation nonces in bytes (256 bits).
const NONCE_LENGTH: usize = 32;

/// Maximum age of a nonce before it expires (5 minutes).
/// Prevents accumulation of stale nonces if a node never completes attestation.
const NONCE_TTL_SECS: u64 = 300;

/// Manages attestation nonces.
///
/// Nonces are generated on demand, stored until consumed or expired.
/// Each nonce is single-use: once validated, it is removed from the pool.
pub struct NonceManager {
    /// Pending nonces awaiting consumption.
    pending: Arc<RwLock<HashSet<Vec<u8>>>>,

    /// Creation timestamps for expiry tracking.
    timestamps: Arc<RwLock<std::collections::HashMap<Vec<u8>, time::OffsetDateTime>>>,
}

impl NonceManager {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(RwLock::new(HashSet::new())),
            timestamps: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Generate a fresh cryptographically-random nonce.
    ///
    /// The nonce is stored internally until consumed or expired.
    pub fn generate(&self) -> Result<Vec<u8>, AttestationError> {
        let mut nonce = vec![0u8; NONCE_LENGTH];
        rand::rng().fill_bytes(&mut nonce);

        let now = time::OffsetDateTime::now_utc();

        self.pending.write().insert(nonce.clone());
        self.timestamps.write().insert(nonce.clone(), now);

        // Opportunistically clean expired nonces.
        self.cleanup_expired();

        Ok(nonce)
    }

    /// Validate and consume a nonce.
    ///
    /// Returns true if the nonce was valid (previously issued, not expired, not consumed).
    /// The nonce is removed from the pool regardless of outcome (single-use).
    pub fn validate_and_consume(&self, nonce: &[u8]) -> Result<bool, AttestationError> {
        let mut pending = self.pending.write();
        let mut timestamps = self.timestamps.write();

        if !pending.contains(nonce) {
            return Ok(false);
        }

        // Check expiry.
        if let Some(created_at) = timestamps.get(nonce) {
            let elapsed = time::OffsetDateTime::now_utc() - *created_at;
            if elapsed.whole_seconds() > NONCE_TTL_SECS as i64 {
                // Expired — remove and reject.
                pending.remove(nonce);
                timestamps.remove(nonce);
                return Ok(false);
            }
        }

        // Valid — consume it (single-use).
        pending.remove(nonce);
        timestamps.remove(nonce);
        Ok(true)
    }

    /// Remove expired nonces from the pool.
    fn cleanup_expired(&self) {
        let now = time::OffsetDateTime::now_utc();
        let mut pending = self.pending.write();
        let mut timestamps = self.timestamps.write();

        let expired: Vec<Vec<u8>> = timestamps
            .iter()
            .filter(|(_, created_at)| (now - **created_at).whole_seconds() > NONCE_TTL_SECS as i64)
            .map(|(nonce, _)| nonce.clone())
            .collect();

        for nonce in expired {
            pending.remove(&nonce);
            timestamps.remove(&nonce);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_is_single_use() {
        let manager = NonceManager::new();
        let nonce = manager.generate().unwrap();

        // First use succeeds.
        assert!(manager.validate_and_consume(&nonce).unwrap());

        // Second use fails (already consumed).
        assert!(!manager.validate_and_consume(&nonce).unwrap());
    }

    #[test]
    fn unknown_nonce_is_rejected() {
        let manager = NonceManager::new();
        let fake_nonce = vec![0u8; NONCE_LENGTH];

        assert!(!manager.validate_and_consume(&fake_nonce).unwrap());
    }

    #[test]
    fn generated_nonces_are_unique() {
        let manager = NonceManager::new();
        let n1 = manager.generate().unwrap();
        let n2 = manager.generate().unwrap();

        assert_ne!(n1, n2);
    }
}
