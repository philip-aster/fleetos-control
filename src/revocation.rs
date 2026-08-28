//! SVID revocation enforcement (G-4 / CR-5).
//!
//! Evicted nodes' SVIDs are added to a revoked set and broadcast via
//! `SagUpdate.revoked_spiffe_ids`. This module provides the local check used
//! by fleetos-control's own mTLS listeners to reject revoked peers.

/// Returns true if the given SPIFFE ID is in the revoked-SVID set.
///
/// Enforcement is fail-closed and checks set membership only; the replicated
/// `PruneExpiredRevokedSvids` command is what removes entries past their TTL,
/// keeping the set bounded without introducing wall-clock reads here.
pub fn is_svid_revoked(keyspace: &fjall::Keyspace, spiffe_id: &str) -> bool {
    match keyspace.get(spiffe_id.as_bytes()) {
        Ok(opt) => opt.is_some(),
        Err(_) => true, // fail closed on storage error
    }
}
