//! Hand-rolled NameConstraints extension with URI subtree support.
//!
//! `rcgen`'s `GeneralSubtree` enum lacks a URI variant, but SPIFFE IDs are URI SANs.
//! We manually DER-encode the NameConstraints extension with a `uniformResourceIdentifier`
//! subtree, then inject it as a CustomExtension. This avoids dependency on the
//! `x509-cert` crate's shifting API surface.

use super::CaError;
use rcgen::CustomExtension;

/// Build a NameConstraints extension that restricts URI SANs to a specific trust domain.
///
/// The permitted subtree is: `spiffe://<trust-domain>/`
/// This prevents a compromised agent from minting SVIDs with different trust domains.
pub fn build_uri_name_constraints(trust_domain: &str) -> Result<CustomExtension, CaError> {
    let uri = format!("spiffe://{}/", trust_domain);
    let uri_bytes = uri.as_bytes();

    // Manual DER encoding of NameConstraints with one permitted URI subtree.
    // GeneralName: uniformResourceIdentifier [6] IMPLICIT IA5String
    let mut general_name = vec![0x86];
    general_name.push(uri_bytes.len() as u8);
    general_name.extend_from_slice(uri_bytes);

    // GeneralSubtree: SEQUENCE { base GeneralName }
    let mut general_subtree = vec![0x30];
    general_subtree.push(general_name.len() as u8);
    general_subtree.extend_from_slice(&general_name);

    // GeneralSubtrees: SEQUENCE OF GeneralSubtree
    let mut general_subtrees = vec![0x30];
    general_subtrees.push(general_subtree.len() as u8);
    general_subtrees.extend_from_slice(&general_subtree);

    // permittedSubtrees: [0] IMPLICIT GeneralSubtrees
    let mut permitted = vec![0xA0];
    permitted.push(general_subtrees.len() as u8);
    permitted.extend_from_slice(&general_subtrees);

    // NameConstraints: SEQUENCE { permittedSubtrees }
    let mut name_constraints = vec![0x30];
    name_constraints.push(permitted.len() as u8);
    name_constraints.extend_from_slice(&permitted);

    // OID for NameConstraints: 2.5.29.30
    // rcgen's from_oid_content takes &[u64] directly — no ObjectIdentifier construction needed.
    let mut ext = CustomExtension::from_oid_content(&[2, 5, 29, 30], name_constraints);
    ext.set_criticality(true); // NameConstraints MUST be critical per RFC 5280

    Ok(ext)
}
