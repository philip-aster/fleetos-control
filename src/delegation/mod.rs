//! Delegation lifecycle management.
//!
//! Implements the degraded-mode delegation system:
//! - Issue `DelegatedSigningKey` to nodes (placement-verified)
//! - Track active delegations with 4-hour TTL
//! - Refresh at 75% elapsed (3 hours) while control is reachable
//! - Revoke on node eviction (one-to-many per node)
//! - Broadcast revoked set over `WatchService`
//!
//! Security invariants:
//! - `fleetos-core::sign_svid_delegated` enforces renewal-only semantics
//! - `fleetos-control` enforces placement verification at issuance time
//! - Revocation is fast-cutoff defense-in-depth on top of the 4-hour TTL

pub mod id;
pub mod revocation;
pub mod ttl;

use thiserror::Error;

use fleetos_core::spiffe::SpiffeId;

/// Errors from delegation operations.
#[derive(Debug, Error)]
pub enum DelegationError {
    #[error("delegation ID computation error: {0}")]
    IdComputation(String),

    #[error("delegation not found: {0}")]
    NotFound(String),

    #[error("delegation expired")]
    Expired,

    #[error("delegation already revoked")]
    AlreadyRevoked,

    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),

    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("time error: {0}")]
    Time(String),
}

/// A delegation record stored in the active delegations table.
///
/// Note: `SpiffeId` now implements `Serialize`/`Deserialize` directly in
/// `fleetos-core` (serializing as a flat string), so we can store it natively.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DelegationRecord {
    /// The delegation ID (composite key suffix).
    pub delegation_id: String,

    /// The node holding this delegation.
    pub node_id: SpiffeId,

    /// The workload SVID this key can renew.
    pub target_svid_id: SpiffeId,

    /// The ordinal of the target workload.
    pub target_ordinal: Option<u32>,

    /// When this delegation was issued.
    pub issued_at: i64,

    /// When this delegation expires (issued_at + 4 hours).
    pub expires_at: i64,

    /// When this delegation should be refreshed (issued_at + 3 hours).
    pub refresh_at: i64,
}

impl DelegationRecord {
    /// Check if this delegation has expired.
    pub fn is_expired(&self) -> bool {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        now >= self.expires_at
    }

    /// Check if this delegation is due for refresh.
    pub fn should_refresh(&self) -> bool {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        now >= self.refresh_at
    }

    /// Remaining time before expiry (in seconds).
    pub fn time_until_expiry(&self) -> i64 {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        (self.expires_at - now).max(0)
    }
}
