//! Delegated SVID signing — the final signing step for `sign_svid_delegated`.
//!
//! When the control plane is unavailable, a node uses its `DelegatedSigningKey`
//! to renew workload SVIDs locally. The security checks (delegation-key
//! expiration, node ID scope match, validity-window bounding) execute in
//! `fleetos-core` — this module provides only the raw signing logic.

use super::CaError;
use super::oid;
use rcgen::{CertificateSigningRequestParams, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, CertificateSigningRequestDer};

/// Sign a CSR using a delegated signing key.
///
/// This performs CA-style signing: we take the CSR's public key and subject,
/// build a certificate around it, and sign with the delegated key.
pub fn sign_with_delegated_key(
    csr_der: &[u8],
    delegated_key_der: &[u8],
    delegated_cert_der: &[u8],
) -> Result<Vec<u8>, CaError> {
    // 1. Parse the CSR to extract params and public key
    // rcgen 0.14.9 uses pki-types for DER wrappers
    let csr_der_type = CertificateSigningRequestDer::from(csr_der);
    let csr_params = CertificateSigningRequestParams::from_der(&csr_der_type)
        .map_err(|e| CaError::Signing(format!("failed to parse CSR: {}", e)))?;

    // 2. Parse the delegated private key
    // Convert DER to PEM for rcgen's from_pem (safest cross-version compatibility)
    let delegated_key_pem = der_to_pem(delegated_key_der, "PRIVATE KEY")?;
    let delegated_key = KeyPair::from_pem(&delegated_key_pem)
        .map_err(|e| CaError::Signing(format!("failed to parse delegated key: {}", e)))?;

    // 3. Construct Issuer from the delegated certificate DER
    let delegated_cert_der_type = CertificateDer::from(delegated_cert_der);
    let issuer = Issuer::from_ca_cert_der(&delegated_cert_der_type, &delegated_key)
        .map_err(|e| CaError::Signing(format!("failed to construct issuer: {}", e)))?;

    // 4. Add degraded-mode OID extension to the certificate params
    let mut final_params = csr_params.params;
    final_params
        .custom_extensions
        .push(oid::degraded_extension(true));

    // 5. Sign the certificate with the delegated key using the CSR's public key
    // CertificateParams::signed_by takes the subject's public key and the issuer
    let cert = final_params
        .signed_by(&csr_params.public_key, &issuer)
        .map_err(CaError::Rcgen)?;

    // 6. Return the DER-encoded certificate
    Ok(cert.der().to_vec())
}

/// Convert DER bytes to PEM format.
fn der_to_pem(der: &[u8], label: &str) -> Result<String, CaError> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let b64 = STANDARD.encode(der);
    let mut pem = String::new();
    pem.push_str(&format!("-----BEGIN {}-----\n", label));
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    Ok(pem)
}
