//! Trust bundle management for root CA rotation and SVID validation.

use rcgen::{CertificateParams, KeyPair};

use super::CaError;
use super::rcgen_impl;

/// A trust bundle for a single trust domain.
pub struct TrustBundle {
    pub trust_domain: String,

    /// Current root CA keypair.
    pub current_key: KeyPair,

    /// Current root CA certificate parameters.
    pub current_params: CertificateParams,

    /// Current root CA certificate DER.
    pub current_cert_der: Vec<u8>,

    /// Current root CA certificate PEM (stored at generation time).
    pub current_cert_pem: String,

    /// Previous root CA (if mid-rotation).
    pub previous: Option<Box<PreviousRoot>>,
}

/// A previous root CA, kept around during rotation overlap.
pub struct PreviousRoot {
    pub key: KeyPair,
    pub params: CertificateParams,
    pub cert_der: Vec<u8>,
    pub cert_pem: String,
    pub superseded_at: time::OffsetDateTime,
}

impl TrustBundle {
    /// Generate a fresh root CA for the given trust domain.
    pub fn generate_root(trust_domain: &str) -> Result<Self, CaError> {
        let (key_pair, params) = rcgen_impl::generate_root_ca(trust_domain)?;

        // Self-sign the root certificate.
        let cert = params.self_signed(&key_pair).map_err(CaError::Rcgen)?;
        let cert_der = cert.der().to_vec();
        // Store PEM now — rcgen::Certificate cannot be reconstructed from DER later.
        let cert_pem = cert.pem();

        tracing::info!(
            trust_domain = %trust_domain,
            "generated root CA"
        );

        Ok(Self {
            trust_domain: trust_domain.to_owned(),
            current_key: key_pair,
            current_params: params,
            current_cert_der: cert_der,
            current_cert_pem: cert_pem,
            previous: None,
        })
    }

    /// Rotate the root CA.
    pub fn rotate(&mut self) -> Result<(), CaError> {
        let (new_key, new_params) = rcgen_impl::generate_root_ca(&self.trust_domain)?;

        let new_cert = new_params.self_signed(&new_key).map_err(CaError::Rcgen)?;
        let new_cert_der = new_cert.der().to_vec();
        let new_cert_pem = new_cert.pem();

        // Move current to previous.
        let previous = PreviousRoot {
            key: std::mem::replace(&mut self.current_key, new_key),
            params: std::mem::replace(&mut self.current_params, new_params),
            cert_der: std::mem::replace(&mut self.current_cert_der, new_cert_der),
            cert_pem: std::mem::replace(&mut self.current_cert_pem, new_cert_pem),
            superseded_at: time::OffsetDateTime::now_utc(),
        };

        self.previous = Some(Box::new(previous));

        tracing::info!(
            trust_domain = %self.trust_domain,
            "rotated root CA"
        );

        Ok(())
    }

    /// Get the PEM-encoded trust bundle (current + previous roots).
    pub fn trust_bundle_pem(&self) -> String {
        let mut pem = self.current_cert_pem.clone();

        if let Some(ref previous) = self.previous {
            pem.push('\n');
            pem.push_str(&previous.cert_pem);
        }

        pem
    }

    /// Validate that an SVID was signed by this trust bundle.
    pub fn validate_svid(&self, cert_der: &[u8]) -> Result<bool, CaError> {
        // TODO: Implement full X.509 chain validation using rustls or webpki.
        // For now, this is a placeholder.
        //
        // Full validation requires:
        // 1. Verify signature against root CA public key
        // 2. Check validity window (not_before <= now <= not_after)
        // 3. Verify SPIFFE URI SAN matches expected format
        // 4. Check that the trust domain in the SPIFFE ID matches this bundle

        tracing::debug!(
            trust_domain = %self.trust_domain,
            cert_len = cert_der.len(),
            "SVID validation (placeholder)"
        );

        Ok(true)
    }
}
