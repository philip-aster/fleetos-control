//! EK certificate chain validation (Step 8 / ATT-EKVAL).
//!
//! Validates a TPM Endorsement Key certificate against a configurable set of
//! trusted manufacturer CA certificates, walking the chain manually with
//! `x509-parser` and verifying each link's signature.
//!
//! Chain model: EK leaf -> [bundled manufacturer CA]* -> trust anchor.
//! The walk terminates when it reaches a certificate present in the trusted
//! store; every hop's signature is verified cryptographically. Anything that
//! cannot be chained to a trusted anchor is rejected fail-closed.
//!
//! SECURITY GATE: `bundled_manufacturer_roots()` ships EMPTY. Until real
//! manufacturer roots are added, every EK certificate chain is rejected. This
//! is intentional — secure attestation must never accept an unknown issuer.

use super::AttestationError;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::X509Certificate;

/// Maximum chain depth before we bail out (cycle / abuse guard).
const MAX_CHAIN_DEPTH: usize = 8;

/// A trusted manufacturer CA certificate (DER-encoded). Members of the root
/// store serve as chain trust anchors.
#[derive(Debug, Clone)]
pub struct TrustedRoot {
    /// Human-readable label for logging/diagnostics.
    pub label: String,
    /// DER-encoded CA certificate.
    pub der: Vec<u8>,
}

/// Configurable set of trusted manufacturer CA certificates.
pub struct ManufacturerRootStore {
    roots: Vec<TrustedRoot>,
}

impl ManufacturerRootStore {
    /// Build a store from an explicit set of trusted roots (test / operator
    /// injection point).
    pub fn new(roots: Vec<TrustedRoot>) -> Self {
        Self { roots }
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    fn contains_der(&self, der: &[u8]) -> bool {
        self.roots.iter().any(|r| r.der.as_slice() == der)
    }

    /// Find a trusted cert whose subject matches the given issuer name.
    fn find_by_subject(
        &self,
        issuer_name: &x509_parser::x509::X509Name<'_>,
    ) -> Option<&TrustedRoot> {
        for root in &self.roots {
            if let Ok((_, cert)) = parse_x509_certificate(&root.der) {
                if cert.subject() == issuer_name {
                    return Some(root);
                }
            }
        }
        None
    }
}

/// The production root set.
pub fn bundled_manufacturer_roots() -> Vec<TrustedRoot> {
    vec![
        TrustedRoot {
            label: "Intel TPM EK Root".to_owned(),
            der: include_bytes!("./roots/intel_ek_root.der").to_vec(),
        },
        TrustedRoot {
            label: "AMD TPM EK Root".to_owned(),
            der: include_bytes!("./roots/amd_ek_root.der").to_vec(),
        },
    ]
}

/// Validate an EK certificate chain against the bundled manufacturer roots.
/// This is the path production callers use.
pub fn validate_ek_cert_chain(ek_cert_der: &[u8]) -> Result<(), AttestationError> {
    let store = ManufacturerRootStore::new(bundled_manufacturer_roots());
    validate_ek_cert_chain_with(ek_cert_der, &store)
}

/// Validate an EK certificate chain against an explicit root store. Tests and
/// operator-configured stores use this directly.
pub fn validate_ek_cert_chain_with(
    ek_cert_der: &[u8],
    store: &ManufacturerRootStore,
) -> Result<(), AttestationError> {
    if store.is_empty() {
        return Err(AttestationError::QuoteVerification(
            "no trusted manufacturer roots configured; rejecting EK cert (fail-closed)".to_owned(),
        ));
    }
    if ek_cert_der.is_empty() {
        return Err(AttestationError::QuoteVerification(
            "empty EK certificate".to_owned(),
        ));
    }

    // Parse and time-check the leaf.
    let (_, leaf) = parse_x509_certificate(ek_cert_der)
        .map_err(|e| AttestationError::QuoteVerification(format!("EK cert parse failed: {}", e)))?;
    check_validity_period(&leaf)?;

    // Walk leaf -> issuer -> ... -> trusted anchor.
    let mut current_der: &[u8] = ek_cert_der;
    for _depth in 0..MAX_CHAIN_DEPTH {
        let (_, current) = parse_x509_certificate(current_der).map_err(|e| {
            AttestationError::QuoteVerification(format!("chain cert parse failed: {}", e))
        })?;

        // Reached a configured trust anchor.
        if store.contains_der(current_der) {
            return Ok(());
        }

        // Find the issuer among trusted certs.
        let issuer_root = store.find_by_subject(current.issuer()).ok_or_else(|| {
            AttestationError::QuoteVerification(format!(
                "EK cert issuer not in trusted manufacturer roots: {}",
                current.issuer()
            ))
        })?;

        // Verify this link's signature against the issuer's public key.
        let (_, issuer_cert) = parse_x509_certificate(&issuer_root.der).map_err(|e| {
            AttestationError::QuoteVerification(format!("trusted root parse failed: {}", e))
        })?;
        current
            .verify_signature(Some(&issuer_cert.subject_pki))
            .map_err(|e| {
                AttestationError::QuoteVerification(format!(
                    "EK cert signature does not match its issuer: {}",
                    e
                ))
            })?;
        check_validity_period(&issuer_cert)?;

        // Move up the chain.
        current_der = &issuer_root.der;
    }

    Err(AttestationError::QuoteVerification(
        "EK cert chain exceeded maximum depth".to_owned(),
    ))
}

/// Reject certs outside their validity window. Fail-closed on unparseable times.
fn check_validity_period(cert: &X509Certificate<'_>) -> Result<(), AttestationError> {
    let now_unix = time::OffsetDateTime::now_utc().unix_timestamp();
    let validity = cert.validity();
    // x509-parser 0.18: timestamp() returns i64 directly.
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    if now_unix < not_before || now_unix > not_after {
        return Err(AttestationError::QuoteVerification(format!(
            "EK cert outside validity period (now={}, not_before={}, not_after={})",
            now_unix, not_before, not_after
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    };

    fn make_ca(cn: &str) -> (KeyPair, rcgen::Certificate) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        let cert = params.self_signed(&key).unwrap();
        (key, cert)
    }

    fn make_leaf_signed_by(
        cn: &str,
        issuer_key: &KeyPair,
        issuer_cert: &rcgen::Certificate,
    ) -> rcgen::Certificate {
        let leaf_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        let issuer = Issuer::from_ca_cert_der(issuer_cert.der(), issuer_key).unwrap();
        params.signed_by(&leaf_key, &issuer).unwrap()
    }

    #[test]
    fn leaf_chaining_to_trusted_root_is_accepted() {
        let (root_key, root_cert) = make_ca("Test TPM Manufacturer Root");
        let leaf = make_leaf_signed_by("EK Leaf", &root_key, &root_cert);
        let store = ManufacturerRootStore::new(vec![TrustedRoot {
            label: "test-root".to_owned(),
            der: root_cert.der().to_vec(),
        }]);
        assert!(validate_ek_cert_chain_with(leaf.der().as_ref(), &store).is_ok());
    }

    #[test]
    fn leaf_signed_by_unknown_root_is_rejected() {
        let (root_key, root_cert) = make_ca("Untrusted Root");
        let leaf = make_leaf_signed_by("EK Leaf", &root_key, &root_cert);
        let (_other_key, other_cert) = make_ca("Other Trusted Root");
        let store = ManufacturerRootStore::new(vec![TrustedRoot {
            label: "other-root".to_owned(),
            der: other_cert.der().to_vec(),
        }]);
        assert!(validate_ek_cert_chain_with(leaf.der().as_ref(), &store).is_err());
    }

    #[test]
    fn empty_store_rejects_everything() {
        let (root_key, root_cert) = make_ca("Root");
        let leaf = make_leaf_signed_by("EK Leaf", &root_key, &root_cert);
        let store = ManufacturerRootStore::new(vec![]);
        assert!(validate_ek_cert_chain_with(leaf.der().as_ref(), &store).is_err());
    }

    #[test]
    fn bundled_root_set_contains_parseable_manufacturer_roots() {
        let roots = bundled_manufacturer_roots();

        assert!(
            !roots.is_empty(),
            "manufacturer root bundle must not be empty once configured"
        );

        assert!(
            roots
                .iter()
                .any(|r| r.label.to_ascii_lowercase().contains("intel")),
            "Intel EK root must be bundled"
        );

        assert!(
            roots
                .iter()
                .any(|r| r.label.to_ascii_lowercase().contains("amd")),
            "AMD EK root must be bundled"
        );

        for root in roots {
            let (_, cert) = x509_parser::parse_x509_certificate(&root.der)
                .unwrap_or_else(|e| panic!("failed to parse bundled root {}: {}", root.label, e));

            assert!(
                cert.subject() == cert.issuer()
                    || root.label.to_ascii_lowercase().contains("infineon"),
                "bundled root {} should be self-signed unless explicitly pinned as an intermediate",
                root.label
            );
        }
    }
}
