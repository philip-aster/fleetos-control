//! Trust bundle management for root CA rotation and SVID validation.
use super::CaError;
use super::rcgen_impl;
use rcgen::KeyPair;

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;

/// A trust bundle for a single trust domain.
pub struct TrustBundle {
    pub trust_domain: String,
    /// Current root CA keypair.
    pub current_key: KeyPair,
    /// Current root CA certificate DER.
    pub current_cert_der: Vec<u8>,
    /// Current root CA certificate PEM.
    pub current_cert_pem: String,
    /// Previous root CA (if mid-rotation).
    pub previous: Option<Box<PreviousRoot>>,
}

/// A previous root CA, kept around during rotation overlap.
pub struct PreviousRoot {
    pub key: KeyPair,
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
        let cert_pem = cert.pem();

        tracing::info!(
            trust_domain = %trust_domain,
            "generated root CA"
        );

        Ok(Self {
            trust_domain: trust_domain.to_owned(),
            current_key: key_pair,
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
    ///
    /// Full X.509 chain validation via rustls's webpki-backed client cert
    /// verifier: cryptographic signature verification, validity window,
    /// basic constraints, and NameConstraints enforcement against the
    /// root(s) in this bundle. Then verifies the SPIFFE URI SAN belongs
    /// to this trust domain.
    ///
    /// Returns `Ok(true)` when the SVID is valid for this bundle,
    /// `Ok(false)` when validation fails (wrong chain, expired, or SPIFFE
    /// URI outside this trust domain), and `Err` for operational failures
    /// (malformed roots, verifier construction, broken system clock).
    pub fn validate_svid(&self, cert_der: &[u8]) -> Result<bool, CaError> {
        // Ensure a process-level crypto provider is installed. `main` installs
        // one at startup, but tests (and any other caller) may not.
        // `install_default` is a no-op if one is already installed.
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }

        // 1. Build a root store from this bundle's roots (current + previous,
        //    so SVIDs issued before a rotation still validate mid-overlap).
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(CertificateDer::from(self.current_cert_der.as_slice()))
            .map_err(|e| CaError::TrustBundle(format!("invalid root certificate: {}", e)))?;
        if let Some(ref previous) = self.previous {
            root_store
                .add(CertificateDer::from(previous.cert_der.as_slice()))
                .map_err(|e| {
                    CaError::TrustBundle(format!("invalid previous root certificate: {}", e))
                })?;
        }

        // 2. Build the webpki-backed verifier.
        let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| CaError::TrustBundle(format!("failed to build verifier: {}", e)))?;

        // Fail-closed if the system clock is before the unix epoch: `now`
        // collapses to epoch 0, every certificate appears not-yet-valid,
        // and validation returns Ok(false).
        let now = UnixTime::since_unix_epoch(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default(),
        );

        // 3. Validate the chain: signature, validity window, basic
        //    constraints, NameConstraints. SVIDs are signed directly by the
        //    root, so there are no intermediates.
        if verifier
            .verify_client_cert(&CertificateDer::from(cert_der), &[], now)
            .is_err()
        {
            return Ok(false);
        }

        // 4. Verify the SPIFFE URI SAN belongs to this trust domain.
        //    (webpki validates the chain to the anchor, not URI contents.)
        let spiffe_uri = match crate::tls::mtls::extract_spiffe_uri_san(cert_der) {
            Ok(uri) => uri,
            Err(_) => return Ok(false),
        };
        let expected_prefix = format!("spiffe://{}/", self.trust_domain);
        if !spiffe_uri.starts_with(&expected_prefix) {
            return Ok(false);
        }

        tracing::debug!(
            trust_domain = %self.trust_domain,
            spiffe_uri = %spiffe_uri,
            "SVID validated"
        );

        Ok(true)
    }

    /// Serialize this trust bundle into a persistable record.
    pub fn to_record(&self) -> Result<TrustBundleRecord, CaError> {
        let current_key_pem = self.current_key.serialize_pem();

        let previous = match &self.previous {
            Some(prev) => {
                let key_pem = prev.key.serialize_pem();
                Some(Box::new(PreviousRootRecord {
                    key_pem,
                    cert_der: prev.cert_der.clone(),
                    cert_pem: prev.cert_pem.clone(),
                    superseded_at_unix: prev.superseded_at.unix_timestamp(),
                }))
            }
            None => None,
        };

        Ok(TrustBundleRecord {
            trust_domain: self.trust_domain.clone(),
            current_key_pem,
            current_cert_der: self.current_cert_der.clone(),
            current_cert_pem: self.current_cert_pem.clone(),
            previous,
        })
    }

    /// Reconstruct a `TrustBundle` from a persisted record.
    pub fn from_record(record: &TrustBundleRecord) -> Result<Self, CaError> {
        let current_key = KeyPair::from_pem(&record.current_key_pem).map_err(CaError::Rcgen)?;

        let previous = match &record.previous {
            Some(prev_record) => {
                let key = KeyPair::from_pem(&prev_record.key_pem).map_err(CaError::Rcgen)?;
                Some(Box::new(PreviousRoot {
                    key,
                    cert_der: prev_record.cert_der.clone(),
                    cert_pem: prev_record.cert_pem.clone(),
                    superseded_at: time::OffsetDateTime::from_unix_timestamp(
                        prev_record.superseded_at_unix,
                    )
                    .map_err(|e| CaError::TrustBundle(format!("invalid timestamp: {}", e)))?,
                }))
            }
            None => None,
        };

        Ok(Self {
            trust_domain: record.trust_domain.clone(),
            current_key,
            current_cert_der: record.current_cert_der.clone(),
            current_cert_pem: record.current_cert_pem.clone(),
            previous,
        })
    }
}

/// Serializable record for persisting a trust bundle to storage.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustBundleRecord {
    pub trust_domain: String,
    pub current_key_pem: String,
    pub current_cert_der: Vec<u8>,
    pub current_cert_pem: String,
    pub previous: Option<Box<PreviousRootRecord>>,
}

/// Serializable record for a previous root CA.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PreviousRootRecord {
    pub key_pem: String,
    pub cert_der: Vec<u8>,
    pub cert_pem: String,
    pub superseded_at_unix: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::rcgen_impl::{SvidKind, SvidParams};

    fn sign_test_svid(bundle: &TrustBundle, spiffe_id: &str) -> crate::ca::rcgen_impl::SignedSvid {
        let params = SvidParams {
            spiffe_id: spiffe_id.to_owned(),
            kind: SvidKind::Workload,
            role: Some("replica".to_owned()),
            ordinal: Some(0),
            degraded: false,
            ttl_secs: 3600,
        };
        crate::ca::rcgen_impl::sign_svid(&params, &bundle.current_key, &bundle.current_cert_der)
            .unwrap()
    }

    #[test]
    fn svid_signed_by_bundle_validates() {
        let bundle = TrustBundle::generate_root("test.example.internal").unwrap();
        let svid = sign_test_svid(&bundle, "spiffe://test.example.internal/ns/tenant-1/sa/db");
        assert!(bundle.validate_svid(&svid.cert_der).unwrap());
    }

    #[test]
    fn svid_from_foreign_ca_is_rejected() {
        let bundle = TrustBundle::generate_root("test.example.internal").unwrap();
        let foreign = TrustBundle::generate_root("other.example.internal").unwrap();
        let svid = sign_test_svid(
            &foreign,
            "spiffe://other.example.internal/ns/tenant-1/sa/db",
        );
        // Chain does not terminate at this bundle's root.
        assert!(!bundle.validate_svid(&svid.cert_der).unwrap());
    }

    #[test]
    fn svid_with_wrong_trust_domain_is_rejected() {
        // Cert chains to our root, but claims a SPIFFE URI outside our
        // trust domain. Chain passes; domain check must catch it.
        let bundle = TrustBundle::generate_root("test.example.internal").unwrap();
        let svid = sign_test_svid(&bundle, "spiffe://evil.example.internal/ns/tenant-1/sa/db");
        assert!(!bundle.validate_svid(&svid.cert_der).unwrap());
    }
}
