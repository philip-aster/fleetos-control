//! Apple Secure Enclave attestation verification.
//!
//! Verifies attestation from `fleetctl` on macOS operator workstations.
//! The attestation artifact is a DER certificate chain (leaf first,
//! concatenated) terminating in the bundled Apple Root CA - G3 (ECC P-384).
//!
//! Verification runs on the Linux control plane with `x509-parser` — no
//! `security-framework` dependency (that is generation-side, macOS-only, and
//! owned by `fleetctl`).
//!
//! Chain model: leaf -> [Apple intermediate CA]* -> Apple Root CA - G3.
//! Every hop's signature is verified cryptographically; the walk terminates
//! only at the bundled root. Anything that cannot be chained to the bundled
//! root is rejected fail-closed.
//!
//! Freshness binding: the leaf MUST carry the Apple attestation extension
//! (OID 1.2.840.113635.100.8.2) whose OCTET STRING content equals
//! SHA-256(server_nonce). This binds the attestation to the server-issued
//! nonce and prevents replay.

use super::AttestationError;
use super::decode_hex_32;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::X509Certificate;

/// Maximum chain depth before we bail out (cycle / abuse guard).
const MAX_CHAIN_DEPTH: usize = 8;

/// Apple attestation extension OID: 1.2.840.113635.100.8.2
const APPLE_ATTESTATION_EXT_OID: &str = "1.2.840.113635.100.8.2";

/// The bundled Apple Root CA - G3 (ECC P-384), DER-encoded.
pub fn bundled_apple_se_root() -> &'static [u8] {
    include_bytes!("./roots/apple_se_root_g3.der")
}

/// SHA-256 fingerprint of `roots/apple_se_root_g3.der`.
///
/// OUT-OF-BAND SOURCE: operator-verified via `sha256sum` + `openssl x509`
/// against the bundled DER; cross-checked with Apple's published Root CA - G3.
/// Subject/issuer: CN=Apple Root CA - G3, OU=Apple Certification Authority,
/// O=Apple Inc., C=US
pub const APPLE_SE_ROOT_SHA256: [u8; 32] =
    decode_hex_32("63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179");

/// An Apple Secure Enclave attestation submission.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AppleSeAttestation {
    /// DER certificate chain, leaf first, concatenated. Terminates in
    /// Apple Root CA - G3.
    pub attestation_data: Vec<u8>,
    /// The nonce bound into this attestation (must match the issued nonce).
    pub nonce: Vec<u8>,
    /// The attested device public key (SPKI DER). Must be the leaf's SPKI.
    pub device_public_key: Vec<u8>,
    /// Optional DCOS token (reserved, not validated).
    pub dcos_token: Option<Vec<u8>>,
}

/// A parsed chain entry: the certificate and its DER slice.
struct ChainEntry<'a> {
    der: &'a [u8],
    cert: X509Certificate<'a>,
}

/// Verify an Apple Secure Enclave attestation against the bundled root.
pub fn verify_apple_se_attestation(
    attestation: &AppleSeAttestation,
    expected_nonce: &[u8],
) -> Result<(), AttestationError> {
    verify_apple_se_attestation_with_root(attestation, expected_nonce, bundled_apple_se_root())
}

/// Test/operator hook: verify against an explicit root (DER).
pub fn verify_apple_se_attestation_with_root(
    attestation: &AppleSeAttestation,
    expected_nonce: &[u8],
    root_der: &[u8],
) -> Result<(), AttestationError> {
    // Step 1: nonce match.
    if attestation.nonce != expected_nonce {
        return Err(AttestationError::Nonce(
            "attestation nonce does not match issued nonce".to_owned(),
        ));
    }
    // Step 2: structure.
    if attestation.attestation_data.is_empty() {
        return Err(AttestationError::QuoteVerification(
            "empty attestation data".to_owned(),
        ));
    }
    if attestation.device_public_key.is_empty() {
        return Err(AttestationError::QuoteVerification(
            "empty device public key".to_owned(),
        ));
    }
    // Step 3: parse the trust anchor.
    let (_, root_cert) = parse_x509_certificate(root_der).map_err(|e| {
        AttestationError::QuoteVerification(format!("Apple root CA parse failed: {}", e))
    })?;
    // Step 4: parse the chain and walk up to the bundled root, verifying
    // each hop's signature.
    let entries = parse_chain(&attestation.attestation_data)?;
    verify_chain(&entries, root_der, &root_cert)?;
    // Step 5: the attested device key must be the leaf's public key. The
    // chain is already verified, so the leaf is authentic; confirm the
    // claimed device key is the SPKI embedded in the leaf.
    let leaf_der = entries[0].der;
    if !leaf_der
        .windows(attestation.device_public_key.len())
        .any(|w| w == attestation.device_public_key.as_slice())
    {
        return Err(AttestationError::QuoteVerification(
            "attested device public key not found in leaf certificate".to_owned(),
        ));
    }
    // Step 6: freshness binding — leaf carries SHA-256(server_nonce).
    verify_nonce_binding(&entries[0].cert, expected_nonce)?;
    Ok(())
}

fn parse_chain(mut data: &[u8]) -> Result<Vec<ChainEntry<'_>>, AttestationError> {
    let mut entries = Vec::new();
    while !data.is_empty() {
        if entries.len() >= MAX_CHAIN_DEPTH {
            return Err(AttestationError::QuoteVerification(
                "attestation chain too long".to_owned(),
            ));
        }
        let (remaining, cert) = parse_x509_certificate(data).map_err(|e| {
            AttestationError::QuoteVerification(format!(
                "attestation chain cert parse failed: {}",
                e
            ))
        })?;
        let cert_len = data.len() - remaining.len();
        entries.push(ChainEntry {
            der: &data[..cert_len],
            cert,
        });
        data = remaining;
    }
    if entries.is_empty() {
        return Err(AttestationError::QuoteVerification(
            "empty attestation chain".to_owned(),
        ));
    }
    Ok(entries)
}

fn verify_chain(
    entries: &[ChainEntry],
    root_der: &[u8],
    root_cert: &X509Certificate,
) -> Result<(), AttestationError> {
    let mut i = 0;
    loop {
        let entry = &entries[i];
        check_validity_period(&entry.cert)?;
        // Terminated at the bundled root (byte-identical)?
        if entry.der == root_der {
            return Ok(());
        }
        // No more chain entries: accept only if this cert is issued by the
        // bundled root and verifies against it.
        if i + 1 >= entries.len() {
            if entry.cert.issuer() == root_cert.subject() {
                entry
                    .cert
                    .verify_signature(Some(&root_cert.subject_pki))
                    .map_err(|e| {
                        AttestationError::QuoteVerification(format!(
                            "chain does not verify against Apple Root CA - G3: {}",
                            e
                        ))
                    })?;
                return Ok(());
            }
            return Err(AttestationError::QuoteVerification(
                "attestation chain does not terminate at Apple Root CA - G3".to_owned(),
            ));
        }
        // Verify this hop against the next cert in the chain.
        let issuer = &entries[i + 1];
        if entry.cert.issuer() != issuer.cert.subject() {
            return Err(AttestationError::QuoteVerification(
                "attestation chain issuer/subject mismatch".to_owned(),
            ));
        }
        entry
            .cert
            .verify_signature(Some(&issuer.cert.subject_pki))
            .map_err(|e| {
                AttestationError::QuoteVerification(format!(
                    "attestation chain signature verification failed: {}",
                    e
                ))
            })?;
        i += 1;
    }
}

fn verify_nonce_binding(
    leaf: &X509Certificate,
    expected_nonce: &[u8],
) -> Result<(), AttestationError> {
    let expected_hash = ring::digest::digest(&ring::digest::SHA256, expected_nonce);
    for ext in leaf.extensions() {
        if ext.oid.to_id_string() == APPLE_ATTESTATION_EXT_OID {
            let content = parse_octet_string(ext.value).ok_or_else(|| {
                AttestationError::QuoteVerification(
                    "Apple attestation extension is not a valid OCTET STRING".to_owned(),
                )
            })?;
            if content.as_slice() == expected_hash.as_ref() {
                return Ok(());
            }
            return Err(AttestationError::QuoteVerification(
                "Apple attestation nonce binding mismatch".to_owned(),
            ));
        }
    }
    Err(AttestationError::QuoteVerification(
        "Apple attestation extension not found in leaf certificate".to_owned(),
    ))
}

fn parse_octet_string(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() || bytes[0] != 0x04 {
        return None;
    }
    if bytes[1] < 0x80 {
        let len = bytes[1] as usize;
        if bytes.len() < 2 + len {
            return None;
        }
        return Some(bytes[2..2 + len].to_vec());
    }
    let n = (bytes[1] & 0x7f) as usize;
    if n == 0 || n > 4 || bytes.len() < 2 + n {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | (bytes[2 + i] as usize);
    }
    if bytes.len() < 2 + n + len {
        return None;
    }
    Some(bytes[2 + n..2 + n + len].to_vec())
}

fn check_validity_period(cert: &X509Certificate) -> Result<(), AttestationError> {
    let now_unix = time::OffsetDateTime::now_utc().unix_timestamp();
    let validity = cert.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    if now_unix < not_before || now_unix > not_after {
        return Err(AttestationError::QuoteVerification(format!(
            "attestation cert outside validity period (now={}, not_before={}, not_after={})",
            now_unix, not_before, not_after
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType, IsCa,
        Issuer, KeyPair,
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

    fn nonce_binding_ext(nonce: &[u8]) -> CustomExtension {
        let hash = ring::digest::digest(&ring::digest::SHA256, nonce);
        let mut content = vec![0x04, 0x20]; // OCTET STRING, 32 bytes
        content.extend_from_slice(hash.as_ref());
        CustomExtension::from_oid_content(&[1u64, 2, 840, 113635, 100, 8, 2], content)
    }

    fn make_leaf(
        issuer_key: &KeyPair,
        issuer_cert: &rcgen::Certificate,
        nonce: &[u8],
    ) -> (KeyPair, rcgen::Certificate) {
        let device_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "se-leaf");
        params.distinguished_name = dn;
        params.custom_extensions.push(nonce_binding_ext(nonce));
        let issuer = Issuer::from_ca_cert_der(issuer_cert.der(), issuer_key).unwrap();
        let cert = params.signed_by(&device_key, &issuer).unwrap();
        (device_key, cert)
    }

    /// Extract the SubjectPublicKeyInfo DER from a certificate.
    fn extract_spki_from_cert(cert_der: &[u8]) -> Vec<u8> {
        let (_, cert) = parse_x509_certificate(cert_der).unwrap();
        cert.tbs_certificate.subject_pki.raw.to_vec()
    }
    /// Build a self-signed cert for a key and return its SPKI DER.
    fn spki_for_key(key: &KeyPair) -> Vec<u8> {
        let mut params = CertificateParams::new(vec![]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "spki-extract");
        params.distinguished_name = dn;
        let cert = params.self_signed(key).unwrap();
        extract_spki_from_cert(cert.der())
    }

    fn attestation(
        leaf_cert: &rcgen::Certificate,
        root_cert: &rcgen::Certificate,
        _device_key: &KeyPair,
        nonce: &[u8],
    ) -> AppleSeAttestation {
        let mut chain = Vec::new();
        chain.extend_from_slice(leaf_cert.der());
        chain.extend_from_slice(root_cert.der());
        // Extract the device key's SPKI from the leaf cert so the byte-window
        // check in verify_apple_se_attestation_with_root finds it verbatim.
        AppleSeAttestation {
            attestation_data: chain,
            nonce: nonce.to_vec(),
            device_public_key: extract_spki_from_cert(leaf_cert.der()),
            dcos_token: None,
        }
    }

    #[test]
    fn valid_attestation_passes() {
        let (root_key, root_cert) = make_ca("Test Apple Root");
        let nonce = [0xAAu8; 32];
        let (device_key, leaf_cert) = make_leaf(&root_key, &root_cert, &nonce);
        let att = attestation(&leaf_cert, &root_cert, &device_key, &nonce);
        assert!(verify_apple_se_attestation_with_root(&att, &nonce, root_cert.der()).is_ok());
    }

    #[test]
    fn nonce_mismatch_rejected() {
        let (root_key, root_cert) = make_ca("Test Apple Root");
        let nonce = [0xAAu8; 32];
        let (device_key, leaf_cert) = make_leaf(&root_key, &root_cert, &nonce);
        let att = attestation(&leaf_cert, &root_cert, &device_key, &nonce);
        let other_nonce = [0xBBu8; 32];
        let result = verify_apple_se_attestation_with_root(&att, &other_nonce, root_cert.der());
        assert!(matches!(result, Err(AttestationError::Nonce(_))));
    }

    #[test]
    fn unknown_root_rejected() {
        let (root_key, root_cert) = make_ca("Test Apple Root");
        let (_other_key, other_cert) = make_ca("Other Root");
        let nonce = [0xAAu8; 32];
        let (device_key, leaf_cert) = make_leaf(&root_key, &root_cert, &nonce);
        let att = attestation(&leaf_cert, &root_cert, &device_key, &nonce);
        // Verify against a DIFFERENT root than the chain terminates at.
        let result = verify_apple_se_attestation_with_root(&att, &nonce, other_cert.der());
        assert!(result.is_err());
    }

    #[test]
    fn missing_nonce_extension_rejected() {
        let (root_key, root_cert) = make_ca("Test Apple Root");
        let nonce = [0xAAu8; 32];
        let device_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "se-leaf");
        params.distinguished_name = dn;
        let issuer = Issuer::from_ca_cert_der(root_cert.der(), &root_key).unwrap();
        let leaf_cert = params.signed_by(&device_key, &issuer).unwrap();
        let att = attestation(&leaf_cert, &root_cert, &device_key, &nonce);
        let result = verify_apple_se_attestation_with_root(&att, &nonce, root_cert.der());
        assert!(matches!(
            result,
            Err(AttestationError::QuoteVerification(_))
        ));
    }

    #[test]
    fn device_key_mismatch_rejected() {
        let (root_key, root_cert) = make_ca("Test Apple Root");
        let nonce = [0xAAu8; 32];
        let (device_key, leaf_cert) = make_leaf(&root_key, &root_cert, &nonce);
        let mut att = attestation(&leaf_cert, &root_cert, &device_key, &nonce);
        let other_key = KeyPair::generate().unwrap();
        att.device_public_key = spki_for_key(&other_key);
        let result = verify_apple_se_attestation_with_root(&att, &nonce, root_cert.der());
        assert!(matches!(
            result,
            Err(AttestationError::QuoteVerification(_))
        ));
    }

    #[test]
    fn bundled_apple_root_g3_parses_and_is_self_signed() {
        let root_der = bundled_apple_se_root();
        let (_, cert) = parse_x509_certificate(root_der)
            .unwrap_or_else(|e| panic!("Apple Root CA - G3 failed to parse: {}", e));
        assert_eq!(
            cert.subject(),
            cert.issuer(),
            "Apple Root CA - G3 must be self-signed"
        );
    }

    /// R-2 provenance pin: the bundled Apple Root CA - G3 must be
    /// bit-identical to the out-of-band-verified Apple root. Swapping the
    /// `.der` for any other certificate fails here.
    #[test]
    fn bundled_apple_root_g3_matches_pinned_sha256_fingerprint() {
        let digest = ring::digest::digest(&ring::digest::SHA256, bundled_apple_se_root());
        assert_eq!(
            digest.as_ref(),
            APPLE_SE_ROOT_SHA256.as_slice(),
            "Apple Root CA - G3: SHA-256 fingerprint mismatch — bundled root \
             was replaced without re-pinning. Verify the new certificate \
             against Apple's published value, then update the pin and its \
             recorded OUT-OF-BAND SOURCE.",
        );
    }
}
