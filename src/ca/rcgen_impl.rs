//! X.509 certificate signing implementation using `rcgen` + `rustls`.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::CaError;
use super::oid;

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
    pub private_key: Zeroizing<Vec<u8>>,
    pub key_pair: KeyPair,
}

/// Generate a new keypair and produce a CSR.
pub fn build_csr(params: &SvidParams) -> Result<CsrBundle, CaError> {
    let key_pair = KeyPair::generate().map_err(|e| CaError::KeyGeneration(e.to_string()))?;

    let mut cert_params = CertificateParams::new(vec![]).map_err(CaError::Rcgen)?;

    // Set the SPIFFE ID as a URI SAN.
    // SanType::URI expects Ia5String; use try_into() to convert without naming the type.
    let spiffe_uri = params
        .spiffe_id
        .clone()
        .try_into()
        .map_err(|_| CaError::Validation("invalid SPIFFE ID for URI SAN".to_owned()))?;
    cert_params.subject_alt_names.push(SanType::URI(spiffe_uri));

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

    // Add custom OID extensions.
    if let Some(ref role) = params.role {
        cert_params
            .custom_extensions
            .push(oid::role_extension(role));
    }
    if let Some(ordinal) = params.ordinal {
        cert_params
            .custom_extensions
            .push(oid::ordinal_extension(ordinal));
    }
    cert_params
        .custom_extensions
        .push(oid::degraded_extension(params.degraded));

    // Generate CSR.
    let csr = cert_params
        .serialize_request(&key_pair)
        .map_err(CaError::Rcgen)?;
    // CertificateSigningRequest::pem() returns Result<String, Error>
    let csr_pem = csr.pem().map_err(CaError::Rcgen)?;

    // Extract private key bytes.
    let private_key = Zeroizing::new(key_pair.serialize_der());

    Ok(CsrBundle {
        csr_pem,
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

/// Sign an SVID certificate using the CA root keypair.
pub fn sign_svid(
    params: &SvidParams,
    ca_key_pair: &KeyPair,
    ca_cert_params: &CertificateParams,
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

    // Construct the Issuer from the CA's params and key.
    let issuer = Issuer::new(ca_cert_params.clone(), ca_key_pair);

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

/// Sign a CSR using the CA root keypair.
///
/// This is the CSR-based SVID issuance path used by the CaService gRPC endpoint.
/// The agent generates a keypair, creates a CSR with its SPIFFE ID as URI SAN,
/// and submits it here. The CA signs the CSR and returns the certificate.
///
/// The agent retains its own private key — only the certificate is returned.
pub fn sign_csr(
    csr_der: &[u8],
    ca_key_pair: &KeyPair,
    ca_cert_params: &CertificateParams,
    ttl_secs: u64,
) -> Result<Vec<u8>, CaError> {
    use rcgen::CertificateSigningRequestParams;
    use rustls::pki_types::CertificateSigningRequestDer;

    // 1. Parse the CSR to extract params and public key.
    let csr_der_type = CertificateSigningRequestDer::from(csr_der);
    let csr_params = CertificateSigningRequestParams::from_der(&csr_der_type)
        .map_err(|e| CaError::Signing(format!("failed to parse CSR: {}", e)))?;

    // 2. Create Issuer from the CA's params and key.
    let issuer = Issuer::new(ca_cert_params.clone(), ca_key_pair);

    // 3. Set validity window on the leaf params.
    let mut final_params = csr_params.params;
    let not_before = OffsetDateTime::now_utc();
    let not_after = not_before + time::Duration::seconds(ttl_secs as i64);
    final_params.not_before = not_before;
    final_params.not_after = not_after;

    // 4. Sign the certificate with the CA using the CSR's public key.
    let cert = final_params
        .signed_by(&csr_params.public_key, &issuer)
        .map_err(CaError::Rcgen)?;

    Ok(cert.der().to_vec())
}
