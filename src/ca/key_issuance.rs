//! Delegated signing key issuance.

use std::sync::Arc;

use fleetos_core::spiffe::SpiffeId;
use parking_lot::RwLock;
use redb::ReadableDatabase;

use super::CaError;
use super::trust_bundle::TrustBundle;

/// Parameters for issuing a delegated signing key.
pub struct DelegationRequest {
    pub node_id: SpiffeId,
    pub target_svid_id: SpiffeId,
    pub target_ordinal: Option<u32>,
    pub ttl_secs: u64,
}

/// A signed delegated signing key bundle.
pub struct DelegatedKeyBundle {
    pub key_bytes: Vec<u8>,
    pub delegation_id: String,
}

/// Issue a delegated signing key after verifying placement.
pub fn issue_delegated_key(
    request: &DelegationRequest,
    _trust_bundle: &RwLock<TrustBundle>,
    placement_verifier: &dyn PlacementVerifier,
) -> Result<DelegatedKeyBundle, CaError> {
    // Step 1: Verify placement (security-critical).
    placement_verifier.verify_placement(
        &request.node_id,
        &request.target_svid_id,
        request.target_ordinal,
    )?;

    // Step 2: Generate the delegation ID.
    let issued_at = time::OffsetDateTime::now_utc();
    let delegation_id = format!(
        "{}:{}:{}:{}",
        request.node_id,
        request.target_svid_id,
        request.target_ordinal.unwrap_or(0),
        issued_at.unix_timestamp()
    );

    // Step 3: Sign the delegation with the CA root.
    // TODO: Implement actual DelegatedSigningKey construction using fleetos-core types.
    // This requires:
    // 1. Generate an Ed25519 or ECDSA P-256 keypair for the delegated key
    // 2. Create a DelegatedSigningKey struct with:
    //    - node_id, target_svid_id, target_ordinal
    //    - key material (private key for signing, public key for verification)
    //    - expiry (issued_at + ttl)
    //    - ordinal field (from request.target_ordinal)
    // 3. Sign the delegation metadata with the root CA
    // 4. Serialize and return

    tracing::info!(
        node_id = %request.node_id,
        target_svid_id = %request.target_svid_id,
        target_ordinal = ?request.target_ordinal,
        delegation_id = %delegation_id,
        "issued delegated signing key"
    );

    Ok(DelegatedKeyBundle {
        key_bytes: Vec::new(), // TODO: actual serialized DelegatedSigningKey
        delegation_id,
    })
}

/// Trait for verifying that a workload is placed on a specific node.
pub trait PlacementVerifier {
    fn verify_placement(
        &self,
        node_id: &SpiffeId,
        target_svid_id: &SpiffeId,
        target_ordinal: Option<u32>,
    ) -> Result<(), CaError>;
}

/// Placement verifier backed by redb storage.
pub struct StoragePlacementVerifier {
    db: Arc<redb::Database>,
}

impl PlacementVerifier for StoragePlacementVerifier {
    fn verify_placement(
        &self,
        node_id: &SpiffeId,
        target_svid_id: &SpiffeId,
        target_ordinal: Option<u32>,
    ) -> Result<(), CaError> {
        // begin_read returns redb::TransactionError → wrap in StorageError::Transaction
        let txn = self
            .db
            .begin_read()
            .map_err(|e| CaError::Storage(crate::storage::StorageError::Transaction(e)))?;

        // open_table returns redb::TableError → wrap in StorageError::Table
        let _table = txn
            .open_table(crate::storage::tables::PLACEMENT_TABLE)
            .map_err(|e| CaError::Storage(crate::storage::StorageError::Table(e)))?;

        // TODO: Implement actual placement lookup.

        tracing::debug!(
            node_id = %node_id,
            target_svid_id = %target_svid_id,
            target_ordinal = ?target_ordinal,
            "placement verification (placeholder — always passes)"
        );

        Ok(())
    }
}
