//! mTLS configuration builders for both trust domains.

use std::sync::Arc;

use parking_lot::RwLock;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ServerConfig};

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
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
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

/// Build a `rustls::ServerConfig` with OPTIONAL client authentication.
///
/// Used by the Data/Control listener: attestation is inherently pre-SVID,
/// so joiners connect without a client certificate. Peers that DO present
/// a certificate are still fully validated against the trust bundle.
pub fn build_server_config_optional_auth(mtls: &MtlsConfig) -> Result<ServerConfig, TlsError> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
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
        .allow_unauthenticated()
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
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
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

/// Hot-swappable server certificate resolver for SVID renewal (G-5).
#[derive(Debug)]
pub struct DynamicCertResolver {
    key: Arc<RwLock<Arc<CertifiedKey>>>,
}

impl DynamicCertResolver {
    pub fn new(initial: CertifiedKey) -> Self {
        Self {
            key: Arc::new(RwLock::new(Arc::new(initial))),
        }
    }

    pub fn update(&self, new_key: CertifiedKey) {
        *self.key.write() = Arc::new(new_key);
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.key.read().clone())
    }
}

/// Build a `CertifiedKey` from raw DER cert + private key bytes.
pub fn certified_key_from_der(cert_der: &[u8], key_der: &[u8]) -> Result<CertifiedKey, TlsError> {
    let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_der.to_vec()),
    );
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&private_key)
        .map_err(|e| TlsError::Certificate(format!("signing key parse failed: {}", e)))?;
    Ok(CertifiedKey::new(
        vec![rustls::pki_types::CertificateDer::from(cert_der.to_vec())],
        signing_key,
    ))
}

/// Like `build_server_config` but uses a dynamic cert resolver for hot-swap.
pub fn build_server_config_dynamic(
    trust_bundle_pem: &str,
    resolver: Arc<DynamicCertResolver>,
) -> Result<rustls::ServerConfig, TlsError> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    let mut root_store = rustls::RootCertStore::empty();
    let certs = rustls_pemfile::certs(&mut trust_bundle_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Certificate(format!("PEM parse error: {}", e)))?;
    for cert in certs {
        root_store
            .add(cert)
            .map_err(|e| TlsError::Certificate(format!("root store add failed: {}", e)))?;
    }
    let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| TlsError::Certificate(format!("client verifier build failed: {}", e)))?;
    Ok(rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_cert_resolver(resolver))
}

/// Like `build_server_config_optional_auth` but uses a dynamic cert resolver.
pub fn build_server_config_optional_auth_dynamic(
    trust_bundle_pem: &str,
    resolver: Arc<DynamicCertResolver>,
) -> Result<rustls::ServerConfig, TlsError> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    let mut root_store = rustls::RootCertStore::empty();
    let certs = rustls_pemfile::certs(&mut trust_bundle_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Certificate(format!("PEM parse error: {}", e)))?;
    for cert in certs {
        root_store
            .add(cert)
            .map_err(|e| TlsError::Certificate(format!("root store add failed: {}", e)))?;
    }
    let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
        .allow_unauthenticated()
        .build()
        .map_err(|e| TlsError::Certificate(format!("client verifier build failed: {}", e)))?;
    Ok(rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_cert_resolver(resolver))
}
