//! X.509 certificate signing implementation using `rcgen` + `rustls`.
use super::CaError;
use super::oid;
use fleetos_core::spiffe::SpiffeId;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::CertificateDer;
use time::OffsetDateTime;
use zeroize::Zeroizing;

/// Identity kinds that can be signed by the CA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvidKind {
    Control,
    Node,
    Workload,
    Admin,
}

/// Parameters for building a CSR or signing an SVID.
pub struct SvidParams {
    pub spiffe_id: String,
    pub kind: SvidKind,
    pub role: Option<String>,
    pub ordinal: Option<u32>,
    pub degraded: bool,
    pub ttl_secs: u64,
}

/// A generated keypair + CSR bundle.
pub struct CsrBundle {
    pub csr_pem: String,
    pub csr_der: Vec<u8>,
    pub private_key: Zeroizing<Vec<u8>>,
    pub key_pair: KeyPair,
}

/// Generate a new keypair and produce a CSR.
pub fn build_csr(params: &SvidParams) -> Result<CsrBundle, CaError> {
    let key_pair = KeyPair::generate().map_err(|e| CaError::KeyGeneration(e.to_string()))?;

    let mut cert_params = CertificateParams::new(vec![]).map_err(CaError::Rcgen)?;

    // Set the SPIFFE ID as a URI SAN.
    let spiffe_uri = params
        .spiffe_id
        .clone()
        .try_into()
        .map_err(|_| CaError::Validation("invalid SPIFFE ID for URI SAN".to_owned()))?;
    cert_params.subject_alt_names.push(SanType::URI(spiffe_uri));

    // Control SVIDs additionally carry the trust domain as a DNS SAN so the
    // raft transport can satisfy hostname verification (Step 17 / S-2). The
    // CA preserves CSR SANs when signing, so this flows through submit_csr.
    if params.kind == SvidKind::Control {
        if let Ok(spiffe) = params.spiffe_id.parse::<SpiffeId>() {
            if let Ok(dns) = Ia5String::try_from(spiffe.trust_domain.clone()) {
                cert_params.subject_alt_names.push(SanType::DnsName(dns));
            }
        }
    }

    // Set distinguished name.
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, params.spiffe_id.as_str());
    cert_params.distinguished_name = dn;

    // Key Usage: Digital Signature.
    cert_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

    // Extended Key Usage: Client Auth + Server Auth (for mTLS).
    cert_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];

    // Not a CA certificate.
    cert_params.is_ca = IsCa::NoCa;

    // CONTRACT: the CSR carries ONLY the SPIFFE URI SAN + standard extensions.
    // FleetOS custom OID extensions (role/ordinal/degraded) are deliberately NOT
    // embedded here: rcgen 0.14.9's CertificateSigningRequestParams::from_der
    // rejects CSRs with unknown custom extensions, which would break sign_csr /
    // sign_with_delegated_key. The CA stamps those extensions at signing time
    // (sign_csr adds degraded=false; sign_with_delegated_key adds degraded=true
    // plus role/ordinal). Do not re-add custom extensions to the CSR.

    // Generate CSR.
    let csr = cert_params
        .serialize_request(&key_pair)
        .map_err(CaError::Rcgen)?;

    let csr_pem = csr.pem().map_err(CaError::Rcgen)?;
    let csr_der = csr.der().to_vec();

    // Extract private key bytes.
    let private_key = Zeroizing::new(key_pair.serialize_der());

    Ok(CsrBundle {
        csr_pem,
        csr_der,
        private_key,
        key_pair,
    })
}

/// A signed SVID certificate.
pub struct SignedSvid {
    pub cert_pem: String,
    pub cert_der: Vec<u8>,
    pub private_key_der: Zeroizing<Vec<u8>>,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

/// Sign an SVID certificate using the CA root keypair and certificate DER.
pub fn sign_svid(
    params: &SvidParams,
    ca_key_pair: &KeyPair,
    ca_cert_der: &[u8],
) -> Result<SignedSvid, CaError> {
    // Build the leaf certificate parameters.
    let mut leaf_params = CertificateParams::new(vec![]).map_err(CaError::Rcgen)?;

    // SPIFFE ID as URI SAN.
    let spiffe_uri = params
        .spiffe_id
        .clone()
        .try_into()
        .map_err(|_| CaError::Validation("invalid SPIFFE ID for URI SAN".to_owned()))?;
    leaf_params.subject_alt_names.push(SanType::URI(spiffe_uri));

    // Control SVIDs additionally carry the trust domain as a DNS SAN so the
    // raft transport (which dials peers by IP) can satisfy rustls hostname
    // verification via tonic's `domain_name`. See Step 17 (S-2).
    if params.kind == SvidKind::Control {
        if let Ok(spiffe) = params.spiffe_id.parse::<SpiffeId>() {
            if let Ok(dns) = Ia5String::try_from(spiffe.trust_domain.clone()) {
                leaf_params.subject_alt_names.push(SanType::DnsName(dns));
            }
        }
    }

    // DN with CN = SPIFFE ID.
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, params.spiffe_id.as_str());
    leaf_params.distinguished_name = dn;

    // Key Usage.
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

    // Extended Key Usage for mTLS.
    leaf_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];

    // Not a CA.
    leaf_params.is_ca = IsCa::NoCa;

    // Validity window: now to now + TTL.
    let not_before = OffsetDateTime::now_utc();
    let not_after = not_before + time::Duration::seconds(params.ttl_secs as i64);
    leaf_params.not_before = not_before;
    leaf_params.not_after = not_after;

    // Custom OID extensions.
    if let Some(ref role) = params.role {
        leaf_params
            .custom_extensions
            .push(oid::role_extension(role));
    }
    if let Some(ordinal) = params.ordinal {
        leaf_params
            .custom_extensions
            .push(oid::ordinal_extension(ordinal));
    }
    leaf_params
        .custom_extensions
        .push(oid::degraded_extension(params.degraded));

    // Generate a fresh keypair for the leaf.
    let leaf_key_pair = KeyPair::generate().map_err(|e| CaError::KeyGeneration(e.to_string()))?;

    // Extract the private key before signing.
    let private_key_der = Zeroizing::new(leaf_key_pair.serialize_der());

    // Construct the Issuer from the CA's certificate DER and key.
    let ca_cert_der_type = CertificateDer::from(ca_cert_der);
    let issuer = Issuer::from_ca_cert_der(&ca_cert_der_type, ca_key_pair)
        .map_err(|e| CaError::Signing(format!("failed to construct issuer: {}", e)))?;

    // Sign the leaf certificate with the CA.
    let leaf_cert = leaf_params
        .signed_by(&leaf_key_pair, &issuer)
        .map_err(CaError::Rcgen)?;

    let cert_pem = leaf_cert.pem();
    let cert_der = leaf_cert.der().to_vec();

    Ok(SignedSvid {
        cert_pem,
        cert_der,
        private_key_der,
        not_before,
        not_after,
    })
}

/// Generate a self-signed root CA certificate.
pub fn generate_root_ca(trust_domain: &str) -> Result<(KeyPair, CertificateParams), CaError> {
    let key_pair = KeyPair::generate().map_err(|e| CaError::KeyGeneration(e.to_string()))?;

    let mut params = CertificateParams::new(vec![]).map_err(CaError::Rcgen)?;

    // DN for the root CA.
    let mut dn = DistinguishedName::new();
    dn.push(
        DnType::CommonName,
        format!("FleetOS Root CA ({})", trust_domain),
    );
    dn.push(DnType::OrganizationName, "FleetOS");
    params.distinguished_name = dn;

    // This is a CA certificate.
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    // CA key usages.
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    // Long validity for root CA (10 years).
    let not_before = OffsetDateTime::now_utc();
    let not_after = not_before + time::Duration::days(365 * 10);
    params.not_before = not_before;
    params.not_after = not_after;

    Ok((key_pair, params))
}

/// Extract the SPIFFE ID URI from a DER-encoded CSR.
///
/// Parses the CSR and returns the first URI SAN that starts with "spiffe://".
/// Used by the CA service to identify which SpiffeId is requesting an SVID
/// so it can track the SVID version.
pub fn extract_spiffe_id_from_csr(csr_der: &[u8]) -> Result<String, CaError> {
    use rcgen::CertificateSigningRequestParams;
    use rustls::pki_types::CertificateSigningRequestDer;

    let csr_der_type = CertificateSigningRequestDer::from(csr_der);
    let csr_params = CertificateSigningRequestParams::from_der(&csr_der_type)
        .map_err(|e| CaError::Signing(format!("failed to parse CSR: {}", e)))?;

    for san in &csr_params.params.subject_alt_names {
        if let rcgen::SanType::URI(uri) = san {
            let uri_str = uri.to_string();
            if uri_str.starts_with("spiffe://") {
                return Ok(uri_str);
            }
        }
    }

    Err(CaError::Validation(
        "no SPIFFE URI SAN found in CSR".to_owned(),
    ))
}

/// Sign a CSR using the CA root keypair and certificate DER.
pub fn sign_csr(
    csr_der: &[u8],
    ca_key_pair: &KeyPair,
    ca_cert_der: &[u8],
    ttl_secs: u64,
) -> Result<Vec<u8>, CaError> {
    use rcgen::CertificateSigningRequestParams;
    use rustls::pki_types::CertificateSigningRequestDer;

    // 1. Parse the CSR to extract params and public key.
    let csr_der_type = CertificateSigningRequestDer::from(csr_der);
    let csr_params = CertificateSigningRequestParams::from_der(&csr_der_type)
        .map_err(|e| CaError::Signing(format!("failed to parse CSR: {}", e)))?;

    // 2. Create Issuer from the CA's certificate DER and key.
    let ca_cert_der_type = CertificateDer::from(ca_cert_der);
    let issuer = Issuer::from_ca_cert_der(&ca_cert_der_type, ca_key_pair)
        .map_err(|e| CaError::Signing(format!("failed to construct issuer: {}", e)))?;

    let mut final_params = csr_params.params;
    let not_before = OffsetDateTime::now_utc();
    let not_after = not_before + time::Duration::seconds(ttl_secs as i64);
    final_params.not_before = not_before;
    final_params.not_after = not_after;

    // Normal CA issuance is never degraded. Stamp the marker here (the CSR no
    // longer carries it — see build_csr contract).
    final_params
        .custom_extensions
        .push(oid::degraded_extension(false));

    let cert = final_params
        .signed_by(&csr_params.public_key, &issuer)
        .map_err(CaError::Rcgen)?;

    Ok(cert.der().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::trust_bundle::TrustBundle;

    /// Regression for the CSR-parsing defect: a CSR produced by build_csr must
    /// round-trip through sign_csr. Previously build_csr embedded FleetOS custom
    /// OID extensions, which rcgen's from_der rejects.
    #[test]
    fn build_csr_then_sign_csr_round_trips() {
        let bundle = TrustBundle::generate_root("test.example.internal").unwrap();
        let csr_params = SvidParams {
            spiffe_id: "spiffe://test.example.internal/ns/system/control/c1".to_owned(),
            kind: SvidKind::Control,
            role: None,
            ordinal: None,
            degraded: false,
            ttl_secs: 3600,
        };
        let csr = build_csr(&csr_params).unwrap();
        let cert_der = sign_csr(
            &csr.csr_der,
            &bundle.current_key,
            &bundle.current_cert_der,
            3600,
        )
        .expect("sign_csr must accept a build_csr-produced CSR");
        assert!(!cert_der.is_empty());
        // The issued SVID must validate against the issuing bundle.
        assert!(bundle.validate_svid(&cert_der).unwrap());
    }
}
