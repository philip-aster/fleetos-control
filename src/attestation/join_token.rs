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
}

impl JoinTokenStore {
    pub fn new(keyspace: Keyspace) -> Self {
        Self { keyspace }
    }

    /// Generate a new cryptographically-random join token.
    ///
    /// The token is stored in fjall and returned to the caller.
    pub fn generate(&self, node_kind: NodeKind) -> Result<Vec<u8>, AttestationError> {
        let mut token = vec![0u8; TOKEN_LENGTH];
        rand::rng().fill_bytes(&mut token);

        let record = JoinTokenRecord {
            token: token.clone(),
            node_kind,
            created_at: time::OffsetDateTime::now_utc().unix_timestamp(),
            expires_at: None,
            consumed: false,
        };

        let serialized = postcard::to_allocvec(&record).map_err(AttestationError::Serialization)?;
        self.keyspace
            .insert(token.as_slice(), serialized.as_slice())
            .map_err(|e| AttestationError::Storage(crate::storage::StorageError::Storage(e)))?;

        tracing::info!(
            node_kind = ?node_kind,
            "generated join token"
        );

        Ok(token)
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
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Integration tests require a real fjall database.
    // Unit tests for token generation logic would go here.

    #[test]
    fn token_length_is_correct() {
        assert_eq!(TOKEN_LENGTH, 32);
    }
}
