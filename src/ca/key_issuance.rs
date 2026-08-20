//! Delegated signing key issuance.

use fjall::Keyspace;
use fleetos_core::spiffe::SpiffeId;
use parking_lot::RwLock;

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

/// Placement verifier backed by fjall storage.
pub struct StoragePlacementVerifier {
    /// Will be used when implementing actual placement lookup
    /// (querying placements keyspace to verify node hosts the workload).
    #[allow(dead_code)]
    placements_keyspace: Keyspace,
}

impl StoragePlacementVerifier {
    pub fn new(placements_keyspace: Keyspace) -> Self {
        Self {
            placements_keyspace,
        }
    }
}

impl PlacementVerifier for StoragePlacementVerifier {
    fn verify_placement(
        &self,
        node_id: &SpiffeId,
        target_svid_id: &SpiffeId,
        target_ordinal: Option<u32>,
    ) -> Result<(), CaError> {
        // Query the placements keyspace to verify that target_svid_id/target_ordinal
        // is actually scheduled on node_id.

        // TODO: Implement actual placement lookup.
        // The placements keyspace maps PodId -> placement info (including node_id).
        // We need to:
        // 1. Find the PodId for target_svid_id + target_ordinal
        // 2. Look up its placement
        // 3. Verify the placement's node_id matches the requesting node_id
        //
        // For now, we return Ok(()) as a placeholder — this MUST be implemented
        // before production use, as it's the security-critical check.

        tracing::debug!(
            node_id = %node_id,
            target_svid_id = %target_svid_id,
            target_ordinal = ?target_ordinal,
            "placement verification (placeholder — always passes)"
        );

        Ok(())
    }
}
