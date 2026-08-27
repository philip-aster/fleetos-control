//! Join Token management.
//!
//! Join Tokens are cryptographically random, stored in fjall, and strictly
//! single-use. Once a token is used for attestation, it is deleted.
//! A second attempt to use it is rejected.
//!
//! Flow:
//! 1. `fleetctl` requests token via `AdminService.GenerateJoinToken`
//! 2. We mint it, store it in fjall, return it to fleetctl
//! 3. Node presents token during attestation
//! 4. We validate it, consume it (delete from storage), proceed with SVID signing

use super::AttestationError;
use fjall::Keyspace;
use rand::Rng;

/// Length of join tokens in bytes (256 bits).
const TOKEN_LENGTH: usize = 32;

/// Default join-token TTL: 24 hours (Master findings M-2/S-11).
///
/// Until hardware-quote signature verification lands, possession of a join
/// token is the SOLE gate to cluster membership. Tokens must therefore be
/// both single-use AND time-bounded.
pub const DEFAULT_JOIN_TOKEN_TTL_SECS: u16 = 3600;

/// A stored join token with metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JoinTokenRecord {
    /// The token bytes (used as the key in storage).
    pub token: Vec<u8>,

    /// What kind of node this token is for.
    pub node_kind: NodeKind,

    /// When the token was created.
    pub created_at: i64,

    /// Optional expiry timestamp (unix seconds). None = no expiry.
    pub expires_at: Option<i64>,

    /// Whether this token has been consumed.
    pub consumed: bool,
}

/// The kind of node a join token is issued for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NodeKind {
    Agent,
    Router,
    Gateway,
    Control,
    FleetctlProxy,
}

/// Manages join token storage and lifecycle.
pub struct JoinTokenStore {
    keyspace: Keyspace,
    /// TTL applied to minted tokens.
    ttl_secs: u16,
}

impl JoinTokenStore {
    pub fn new(keyspace: Keyspace) -> Self {
        Self::with_ttl(keyspace, DEFAULT_JOIN_TOKEN_TTL_SECS)
    }

    /// Override the token TTL (config-driven or test hook).
    pub fn with_ttl(keyspace: Keyspace, ttl_secs: u16) -> Self {
        Self { keyspace, ttl_secs }
    }

    /// Compute a new join token record (read-only/random-gen).
    ///
    /// The caller must propose this to Raft; the state machine performs the
    /// actual write to the join_tokens keyspace.
    pub fn compute_token_record(
        &self,
        node_kind: NodeKind,
    ) -> Result<JoinTokenRecord, AttestationError> {
        let mut token = vec![0u8; TOKEN_LENGTH];
        rand::rng().fill_bytes(&mut token);
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        Ok(JoinTokenRecord {
            token,
            node_kind,
            created_at: now,
            expires_at: Some(now + self.ttl_secs as i64),
            consumed: false,
        })
    }

    /// Validate and consume a join token (strict single-use).
    ///
    /// If the token exists and has not been consumed:
    ///   - Mark it as consumed (delete from storage)
    ///   - Return the token record
    ///
    /// If the token doesn't exist or was already consumed:
    ///   - Return an error
    pub fn validate_and_consume(&self, token: &[u8]) -> Result<JoinTokenRecord, AttestationError> {
        let bytes = self
            .keyspace
            .get(token)
            .map_err(|e| AttestationError::Storage(crate::storage::StorageError::Storage(e)))?
            .ok_or(AttestationError::JoinTokenNotFound)?;

        let record: JoinTokenRecord =
            postcard::from_bytes(&bytes).map_err(AttestationError::Serialization)?;

        if record.consumed {
            return Err(AttestationError::JoinTokenAlreadyUsed);
        }

        // Check expiry.
        if let Some(expires_at) = record.expires_at {
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            if now > expires_at {
                // Expired — delete and reject.
                self.keyspace.remove(token).map_err(|e| {
                    AttestationError::Storage(crate::storage::StorageError::Storage(e))
                })?;
                return Err(AttestationError::JoinToken("token expired".to_owned()));
            }
        }

        // Consume: delete from storage (strict single-use).
        self.keyspace
            .remove(token)
            .map_err(|e| AttestationError::Storage(crate::storage::StorageError::Storage(e)))?;

        tracing::info!(
            node_kind = ?record.node_kind,
            "join token consumed"
        );

        Ok(record)
    }

    /// List all active (unconsumed) join tokens.
    ///
    /// Used by `AdminService.ListJoinTokens` for operator visibility.
    pub fn list_active(&self) -> Result<Vec<JoinTokenRecord>, AttestationError> {
        let mut tokens = Vec::new();

        // Empty prefix scans the entire keyspace — intentional here, since
        // this keyspace holds only join tokens and we need all of them.
        // The prefix() iterator yields Guard items directly, not Result.
        for guard in self.keyspace.prefix(Vec::<u8>::new()) {
            // Guard::value() returns Result<&Slice, &fjall::Error>.
            // The error is a reference we can't move into StorageError,
            // so map it to a JoinToken error via Display instead.
            let value = guard
                .value()
                .map_err(|e| AttestationError::JoinToken(format!("storage read error: {}", e)))?;

            if let Ok(record) = postcard::from_bytes::<JoinTokenRecord>(value.as_ref()) {
                if !record.consumed {
                    tokens.push(record);
                }
            }
        }

        Ok(tokens)
    }

    /// Remove expired tokens. Runs opportunistically on every mint; also
    /// available for maintenance paths. Returns the number removed.
    pub fn sweep_expired(&self) -> Result<usize, AttestationError> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut expired_keys = Vec::new();
        for guard in self.keyspace.prefix(Vec::<u8>::new()) {
            let Ok(value) = guard.value() else {
                continue;
            };
            if let Ok(record) = postcard::from_bytes::<JoinTokenRecord>(value.as_ref()) {
                if !record.consumed && record.expires_at.is_some_and(|exp| now > exp) {
                    expired_keys.push(record.token);
                }
            }
        }
        for key in &expired_keys {
            self.keyspace
                .remove(key.as_slice())
                .map_err(|e| AttestationError::Storage(crate::storage::StorageError::Storage(e)))?;
        }
        if !expired_keys.is_empty() {
            tracing::debug!(count = expired_keys.len(), "swept expired join tokens");
        }
        Ok(expired_keys.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store(name: &str, ttl_secs: u16) -> (std::sync::Arc<fjall::Database>, JoinTokenStore) {
        let dir = std::env::temp_dir().join(format!(
            "fleetos-join-token-test-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let db = crate::storage::open_database(&dir).unwrap();
        let keyspaces = crate::storage::init_keyspaces(&db).unwrap();
        (
            db,
            JoinTokenStore::with_ttl(keyspaces.join_tokens.clone(), ttl_secs),
        )
    }

    #[test]
    fn token_length_is_correct() {
        assert_eq!(TOKEN_LENGTH, 32);
    }

    #[test]
    fn default_ttl_is_1_hour() {
        assert_eq!(DEFAULT_JOIN_TOKEN_TTL_SECS, 3600);
    }

    #[test]
    fn generated_token_carries_expiry() {
        let (_db, store) = test_store("expiry", DEFAULT_JOIN_TOKEN_TTL_SECS);
        // Minting is Raft-replicated; compute_token_record returns the record
        // the leader proposes via FleetosCommand::MintJoinToken.
        let record = store.compute_token_record(NodeKind::Agent).unwrap();
        assert_eq!(
            record.expires_at,
            Some(record.created_at + DEFAULT_JOIN_TOKEN_TTL_SECS as i64),
            "token must expire at created_at + ttl"
        );
    }

    #[test]
    fn expired_token_is_rejected_and_removed() {
        let (_db, store) = test_store("expired", DEFAULT_JOIN_TOKEN_TTL_SECS);

        // Manually insert an already-expired token to avoid sleeping in tests.
        let token = vec![0xAA; TOKEN_LENGTH];
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let record = JoinTokenRecord {
            token: token.clone(),
            node_kind: NodeKind::Agent,
            created_at: now - (DEFAULT_JOIN_TOKEN_TTL_SECS as i64 + 7200),
            expires_at: Some(now - DEFAULT_JOIN_TOKEN_TTL_SECS as i64), // expired 1 hour ago
            consumed: false,
        };
        let serialized = postcard::to_allocvec(&record).unwrap();
        store
            .keyspace
            .insert(token.as_slice(), serialized.as_slice())
            .unwrap();

        let result = store.validate_and_consume(&token);
        assert!(matches!(result, Err(AttestationError::JoinToken(_))));
        // Expired tokens must be deleted — no retry path.
        assert!(store.keyspace.get(&token).unwrap().is_none());
    }

    #[test]
    fn sweep_removes_expired_tokens_only() {
        let (_db, store) = test_store("sweep", DEFAULT_JOIN_TOKEN_TTL_SECS);
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        // 1. Insert an expired token manually.
        let expired_token = vec![0xAA; TOKEN_LENGTH];
        let expired_record = JoinTokenRecord {
            token: expired_token.clone(),
            node_kind: NodeKind::Agent,
            created_at: now - (DEFAULT_JOIN_TOKEN_TTL_SECS as i64 + 7200),
            expires_at: Some(now - DEFAULT_JOIN_TOKEN_TTL_SECS as i64),
            consumed: false,
        };
        let serialized = postcard::to_allocvec(&expired_record).unwrap();
        store
            .keyspace
            .insert(expired_token.as_slice(), serialized.as_slice())
            .unwrap();

        // 2. Insert a live token.
        let live_token = vec![0xBB; TOKEN_LENGTH];
        let live_record = JoinTokenRecord {
            token: live_token.clone(),
            node_kind: NodeKind::Router,
            created_at: now,
            expires_at: Some(now + DEFAULT_JOIN_TOKEN_TTL_SECS as i64),
            consumed: false,
        };
        let serialized = postcard::to_allocvec(&live_record).unwrap();
        store
            .keyspace
            .insert(live_token.as_slice(), serialized.as_slice())
            .unwrap();

        let swept = store.sweep_expired().unwrap();
        assert_eq!(swept, 1);
        assert!(store.keyspace.get(&expired_token).unwrap().is_none());
        assert!(store.keyspace.get(&live_token).unwrap().is_some());
    }
}
