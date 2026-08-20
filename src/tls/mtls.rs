//! mTLS configuration builders for both trust domains.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, ServerConfig};
use x509_parser::prelude::*;

use super::TlsError;
use super::trust_domains::TrustDomainRole;

/// TLS configuration for a gRPC listener.
pub struct MtlsConfig {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
    pub trust_bundle_pem: String,
    pub role: TrustDomainRole,
}

/// Build a `rustls::ServerConfig` for a gRPC listener with mTLS enforcement.
pub fn build_server_config(mtls: &MtlsConfig) -> Result<ServerConfig, TlsError> {
    let mut root_store = rustls::RootCertStore::empty();
    let certs = rustls_pemfile::certs(&mut mtls.trust_bundle_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Certificate(format!("failed to parse trust bundle PEM: {}", e)))?;

    for cert in certs {
        root_store.add(cert).map_err(|e| {
            TlsError::Certificate(format!("failed to add cert to root store: {}", e))
        })?;
    }

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| TlsError::Certificate(format!("failed to build client verifier: {}", e)))?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(mtls.cert_chain.clone(), mtls.private_key.clone_key())
        .map_err(|e| TlsError::Rustls(format!("failed to build server config: {}", e)))?;

    Ok(config)
}

/// Build a `rustls::ClientConfig` for outbound connections.
pub fn build_client_config(mtls: &MtlsConfig) -> Result<ClientConfig, TlsError> {
    let mut root_store = rustls::RootCertStore::empty();
    let certs = rustls_pemfile::certs(&mut mtls.trust_bundle_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Certificate(format!("failed to parse trust bundle PEM: {}", e)))?;

    for cert in certs {
        root_store.add(cert).map_err(|e| {
            TlsError::Certificate(format!("failed to add cert to root store: {}", e))
        })?;
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(mtls.cert_chain.clone(), mtls.private_key.clone_key())
        .map_err(|e| TlsError::Rustls(format!("failed to build client config: {}", e)))?;

    Ok(config)
}

/// Extract the SPIFFE URI SAN from a DER-encoded certificate.
///
/// Properly parses the X.509 structure using `x509-parser`:
/// 1. Parse the DER certificate
/// 2. Find the SubjectAltName extension (OID 2.5.29.17)
/// 3. Iterate GeneralNames looking for URI entries
/// 4. Return the first URI that starts with "spiffe://"
///
/// A SPIFFE-compliant certificate has exactly one URI SAN containing the SPIFFE ID.
pub fn extract_spiffe_uri_san(cert_der: &[u8]) -> Result<String, TlsError> {
    // Parse the DER-encoded certificate.
    let (_, cert) = parse_x509_certificate(cert_der)
        .map_err(|e| TlsError::Certificate(format!("failed to parse certificate: {}", e)))?;

    // Find the SubjectAlternativeName extension.
    let san_ext = cert
        .extensions()
        .iter()
        .find(|ext| {
            matches!(
                ext.parsed_extension(),
                &ParsedExtension::SubjectAlternativeName(_)
            )
        })
        .ok_or(TlsError::NoSpiffeSan)?;

    // Extract the parsed SubjectAlternativeName.
    let san = match san_ext.parsed_extension() {
        ParsedExtension::SubjectAlternativeName(san) => san,
        _ => return Err(TlsError::NoSpiffeSan),
    };

    // Iterate GeneralNames looking for a URI entry with "spiffe://" prefix.
    for general_name in &san.general_names {
        if let GeneralName::URI(uri) = general_name {
            if uri.starts_with("spiffe://") {
                return Ok(uri.to_string());
            }
        }
    }

    Err(TlsError::NoSpiffeSan)
}

/// Extract all SPIFFE URI SANs from a DER-encoded certificate.
///
/// Used for validation — a well-formed SVID should have exactly one,
/// but we return all for completeness.
pub fn extract_all_spiffe_uri_sans(cert_der: &[u8]) -> Result<Vec<String>, TlsError> {
    let (_, cert) = parse_x509_certificate(cert_der)
        .map_err(|e| TlsError::Certificate(format!("failed to parse certificate: {}", e)))?;

    let san_ext = cert
        .extensions()
        .iter()
        .find(|ext| {
            matches!(
                ext.parsed_extension(),
                &ParsedExtension::SubjectAlternativeName(_)
            )
        })
        .ok_or(TlsError::NoSpiffeSan)?;

    let san = match san_ext.parsed_extension() {
        ParsedExtension::SubjectAlternativeName(san) => san,
        _ => return Err(TlsError::NoSpiffeSan),
    };

    let mut uris = Vec::new();
    for general_name in &san.general_names {
        if let GeneralName::URI(uri) = general_name {
            if uri.starts_with("spiffe://") {
                uris.push(uri.to_string());
            }
        }
    }

    if uris.is_empty() {
        Err(TlsError::NoSpiffeSan)
    } else {
        Ok(uris)
    }
}

/// Extract the custom OID extensions from a certificate.
///
/// Returns (role, ordinal, is_degraded) if present.
/// Uses the FleetOS OID arcs defined in `ca/oid.rs`.
pub fn extract_fleetos_extensions(cert_der: &[u8]) -> Result<FleetosExtensions, TlsError> {
    let (_, cert) = parse_x509_certificate(cert_der)
        .map_err(|e| TlsError::Certificate(format!("failed to parse certificate: {}", e)))?;

    let mut role: Option<String> = None;
    let mut ordinal: Option<u32> = None;
    let mut is_degraded: bool = false;

    for ext in cert.extensions() {
        let oid_str = ext.oid.to_string();

        match oid_str.as_str() {
            // FleetOS Role OID: 1.3.6.1.4.1.66561.1.1
            "1.3.6.1.4.1.66561.1.1" => {
                role = Some(String::from_utf8_lossy(ext.value).to_string());
            }
            // FleetOS Degraded marker OID: 1.3.6.1.4.1.66561.1.2
            "1.3.6.1.4.1.66561.1.2" => {
                // ASN.1 BOOLEAN: tag(0x01) length(0x01) value(0xFF or 0x00)
                is_degraded = ext.value.len() >= 3 && ext.value[2] == 0xFF;
            }
            // FleetOS Ordinal OID: 1.3.6.1.4.1.66561.1.3
            "1.3.6.1.4.1.66561.1.3" => {
                if let Ok(s) = std::str::from_utf8(ext.value) {
                    ordinal = s.parse::<u32>().ok();
                }
            }
            _ => {}
        }
    }

    Ok(FleetosExtensions {
        role,
        ordinal,
        is_degraded,
    })
}

/// FleetOS-specific X.509 extensions extracted from a certificate.
#[derive(Debug, Clone, Default)]
pub struct FleetosExtensions {
    pub role: Option<String>,
    pub ordinal: Option<u32>,
    pub is_degraded: bool,
}
