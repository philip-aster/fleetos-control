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
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));

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
    let ca_cert_der_type =
        rustls::pki_types::CertificateDer::from(bundle.current_cert_der.as_slice());
    let issuer = Issuer::from_ca_cert_der(&ca_cert_der_type, &bundle.current_key)
        .map_err(|e| CaError::Signing(format!("failed to construct issuer: {}", e)))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::trust_bundle::TrustBundle;
    use x509_parser::prelude::ParsedExtension;

    /// Deserialization mirror of `fleetos_core::spiffe::DelegatedSigningKey`.
    ///
    /// The core struct carries no serde derives (its key material is opaque by
    /// design — the fleetos-core addendum confirms core never parses it), so
    /// tests read back the postcard layout via a shadow with identical field
    /// names and types. Postcard serializes `&str`/`String` and `&[u8]`/
    /// `Vec<u8>` identically, so this round-trips exactly.
    #[derive(serde::Deserialize)]
    struct DelegatedSigningKeyMirror {
        node_id: String,
        target_svid_id: String,
        target_ordinal: Option<u32>,
        issued_at_unix: u64,
        expires_at_unix: u64,
        signing_key: Vec<u8>,
        intermediate_cert_der: Vec<u8>,
    }

    /// Test-only verifier that always passes placement, so these tests
    /// isolate certificate-capability behavior from issuance gating.
    struct AlwaysPlace;
    impl PlacementVerifier for AlwaysPlace {
        fn verify_placement(
            &self,
            _node_id: &SpiffeId,
            _target_svid_id: &SpiffeId,
            _target_ordinal: Option<u32>,
        ) -> Result<(), CaError> {
            Ok(())
        }
    }

    fn delegation_request() -> DelegationRequest {
        DelegationRequest {
            node_id: "spiffe://fleet.example.internal/ns/system/node/agent-1"
                .parse()
                .unwrap(),
            target_svid_id: "spiffe://fleet.example.internal/ns/tenant-1/sa/db"
                .parse()
                .unwrap(),
            target_ordinal: Some(0),
            ttl_secs: 3600,
        }
    }

    /// Issue a delegated key against a fresh root and read back the issued
    /// postcard layout so tests inspect the real artifact.
    fn issue_and_deserialize() -> DelegatedSigningKeyMirror {
        let bundle = TrustBundle::generate_root("fleet.example.internal").unwrap();
        let trust_bundle = RwLock::new(bundle);
        let issued =
            issue_delegated_key(&delegation_request(), &trust_bundle, &AlwaysPlace).unwrap();
        postcard::from_bytes(&issued.key_bytes)
            .expect("issued bytes must deserialize into the delegated-key layout")
    }

    /// M-1 regression: the delegated intermediate must carry
    /// pathLenConstraint = 0. Under `Unconstrained`, a compromised agent
    /// could mint sub-CAs; the constraint makes that structurally impossible.
    #[test]
    fn delegated_intermediate_is_path_length_constrained() {
        let key = issue_and_deserialize();

        let (_, cert) = x509_parser::parse_x509_certificate(&key.intermediate_cert_der)
            .expect("intermediate cert must parse");

        let bc = cert
            .extensions()
            .iter()
            .find_map(|ext| match ext.parsed_extension() {
                ParsedExtension::BasicConstraints(bc) => Some(bc),
                _ => None,
            })
            .expect("intermediate cert must carry BasicConstraints");

        assert!(bc.ca, "delegated intermediate must be a CA");
        assert_eq!(
            bc.path_len_constraint,
            Some(0),
            "pathLenConstraint must be 0 — sub-CA chaining must be impossible"
        );
    }

    /// The constraint must not break the legitimate path: signing an
    /// end-entity workload SVID under a pathLen=0 intermediate.
    ///
    /// NOTE: builds a minimal CSR directly (SPIFFE URI SAN only) rather than
    /// via `rcgen_impl::build_csr`, because `build_csr` embeds the FleetOS
    /// custom OID extensions and `sign_with_delegated_key` currently cannot
    /// parse custom-extension CSRs (separate pre-existing gap, tracked as a
    /// new finding). The minimal CSR is enough to prove pathLen=0 does not
    /// block end-entity signing.
    #[test]
    fn delegated_intermediate_still_signs_end_entity_svids() {
        let key = issue_and_deserialize();

        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut csr_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        csr_params.subject_alt_names.push(rcgen::SanType::URI(
            "spiffe://fleet.example.internal/ns/tenant-1/sa/db"
                .to_string()
                .try_into()
                .unwrap(),
        ));
        let csr_der = csr_params
            .serialize_request(&key_pair)
            .unwrap()
            .der()
            .to_vec();

        let signed = crate::ca::delegated::sign_with_delegated_key(
            &csr_der,
            key.signing_key.as_slice(),
            &key.intermediate_cert_der,
        )
        .expect("end-entity signing under a pathLen=0 intermediate must succeed");
        assert!(!signed.is_empty());
    }

    /// The postcard wire layout must round-trip through the mirror with every
    /// field intact — this is the contract any consumer of
    /// `DelegatedKeyResponse.key_material` parses against (fleetos-agent's
    /// degraded-mode renewal path, per the ledger).
    #[test]
    fn delegated_key_wire_layout_round_trips() {
        let request = delegation_request();
        let key = issue_and_deserialize();

        assert_eq!(key.node_id, request.node_id.to_string());
        assert_eq!(key.target_svid_id, request.target_svid_id.to_string());
        assert_eq!(key.target_ordinal, Some(0));
        assert!(key.issued_at_unix > 0);
        assert_eq!(
            key.expires_at_unix - key.issued_at_unix,
            request.ttl_secs,
            "expiry must be exactly issued_at + ttl_secs"
        );
    }
}
