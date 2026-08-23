//! Delegated signing key issuance.

use fjall::Keyspace;
use fleetos_core::spiffe::SpiffeId;
use parking_lot::RwLock;

use super::CaError;
use super::trust_bundle::TrustBundle;

use fleetos_core::spiffe::DelegatedSigningKey;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use time::OffsetDateTime;
use zeroize::Zeroizing; // Adjust path if your fleetos-core puts it elsewhere

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

pub fn issue_delegated_key(
    request: &DelegationRequest,
    trust_bundle: &RwLock<TrustBundle>,
    placement_verifier: &dyn PlacementVerifier,
) -> Result<DelegatedKeyBundle, CaError> {
    // Step 1: Verify placement (security-critical).
    placement_verifier.verify_placement(
        &request.node_id,
        &request.target_svid_id,
        request.target_ordinal,
    )?;

    // Step 2: Generate the delegation ID using the tested helper.
    // CRITICAL: Uses `|` separator because SpiffeIds contain `:`.
    let issued_at = time::OffsetDateTime::now_utc();
    let delegation_id = crate::delegation::id::compute_delegation_id(
        &request.node_id.to_string(),
        &request.target_svid_id.to_string(),
        request.target_ordinal,
        issued_at,
    )
    .map_err(|e| CaError::Validation(format!("delegation ID computation failed: {}", e)))?;

    // Step 3: Generate a keypair for the delegated signing key.
    let delegated_key_pair =
        KeyPair::generate().map_err(|e| CaError::KeyGeneration(e.to_string()))?;

    // Step 4: Build intermediate CA certificate with NameConstraints.
    // rcgen 0.14.9 requires a typed empty vec for subject_alt_names
    let mut intermediate_params =
        CertificateParams::new(Vec::<String>::new()).map_err(CaError::Rcgen)?;

    // Set DN
    let mut dn = DistinguishedName::new();
    dn.push(
        DnType::CommonName,
        format!("FleetOS Delegated CA ({})", request.node_id),
    );
    dn.push(DnType::OrganizationName, "FleetOS");
    intermediate_params.distinguished_name = dn;

    // This is a CA certificate (but constrained via NameConstraints)
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    // CA key usages
    intermediate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    // Validity window: 4 hours
    let not_before = OffsetDateTime::now_utc();
    let not_after = not_before + time::Duration::seconds(request.ttl_secs as i64);
    intermediate_params.not_before = not_before;
    intermediate_params.not_after = not_after;

    // CRITICAL: Add NameConstraints to restrict URI SAN to trust domain
    let name_constraints_ext =
        crate::ca::name_constraints::build_uri_name_constraints(&request.node_id.trust_domain)
            .map_err(|e| CaError::Validation(format!("failed to build NameConstraints: {}", e)))?;

    intermediate_params
        .custom_extensions
        .push(name_constraints_ext);

    // Step 5: Sign the intermediate cert with the root CA.
    let bundle = trust_bundle.read();
    let issuer = Issuer::new(bundle.current_params.clone(), &bundle.current_key);
    let intermediate_cert = intermediate_params
        .signed_by(&delegated_key_pair, &issuer)
        .map_err(CaError::Rcgen)?;

    // Step 6: Build the DelegatedSigningKey
    let expires_at = issued_at + time::Duration::seconds(request.ttl_secs as i64);
    let delegated_key = DelegatedSigningKey {
        node_id: request.node_id.clone(),
        target_svid_id: request.target_svid_id.clone(),
        target_ordinal: request.target_ordinal,
        issued_at_unix: issued_at.unix_timestamp() as u64,
        expires_at_unix: expires_at.unix_timestamp() as u64,
        signing_key: Zeroizing::new(delegated_key_pair.serialize_der()),
        intermediate_cert_der: intermediate_cert.der().to_vec(),
    };

    // Step 7: Serialize the DelegatedSigningKey.
    // Since DelegatedSigningKey from fleetos-core doesn't implement Serialize,
    // we use a shadow struct with identical field names and types to produce
    // a postcard byte layout that matches fleetos-core's Deserialize impl.
    #[derive(serde::Serialize)]
    struct DelegatedSigningKeyShadow<'a> {
        node_id: &'a str,
        target_svid_id: &'a str,
        target_ordinal: Option<u32>,
        issued_at_unix: u64,
        expires_at_unix: u64,
        signing_key: &'a [u8],
        intermediate_cert_der: &'a [u8],
    }

    let node_id_str = delegated_key.node_id.to_string();
    let target_svid_str = delegated_key.target_svid_id.to_string();

    let shadow = DelegatedSigningKeyShadow {
        node_id: &node_id_str,
        target_svid_id: &target_svid_str,
        target_ordinal: delegated_key.target_ordinal,
        issued_at_unix: delegated_key.issued_at_unix,
        expires_at_unix: delegated_key.expires_at_unix,
        signing_key: &delegated_key.signing_key,
        intermediate_cert_der: &delegated_key.intermediate_cert_der,
    };

    let key_bytes = postcard::to_allocvec(&shadow).map_err(CaError::Serialization)?;

    tracing::info!(
        node_id = %request.node_id,
        target_svid_id = %request.target_svid_id,
        target_ordinal = ?request.target_ordinal,
        delegation_id = %delegation_id,
        "issued delegated signing key"
    );

    Ok(DelegatedKeyBundle {
        key_bytes,
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

        for guard in self.placements_keyspace.prefix(Vec::<u8>::new()) {
            let value = guard
                .value()
                .map_err(|e| CaError::Storage(crate::storage::StorageError::Storage(e)))?;

            let Ok(placement) = postcard::from_bytes::<crate::scheduler::Placement>(value.as_ref())
            else {
                continue; // Skip malformed entries
            };

            // Must be on the requesting node
            if placement.node_id != *node_id {
                continue;
            }

            // Ordinal must match when the delegation is ordinal-scoped
            if let Some(ordinal) = target_ordinal {
                if placement.ordinal != ordinal {
                    continue;
                }
            }

            // Reconstruct the workload SVID implied by this placement
            // A workload SVID is spiffe://<td>/ns/<tenant>/sa/<service>
            let candidate = SpiffeId::new(
                &target_svid_id.trust_domain,
                &placement.tenant_id,
                fleetos_core::spiffe::IdKind::Sa,
                &placement.service,
            );

            if candidate == *target_svid_id {
                return Ok(());
            }
        }

        Err(CaError::PlacementVerification {
            node_id: node_id.to_string(),
            target_svid_id: target_svid_id.to_string(),
            target_ordinal: target_ordinal.unwrap_or(0),
        })
    }
}
