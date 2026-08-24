//! Trust bundle management for root CA rotation and SVID validation.
use super::CaError;
use super::rcgen_impl;
use rcgen::KeyPair;

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
    pub fn validate_svid(&self, cert_der: &[u8]) -> Result<bool, CaError> {
        // TODO: Implement full X.509 chain validation using rustls or webpki.
        tracing::debug!(
            trust_domain = %self.trust_domain,
            cert_len = cert_der.len(),
            "SVID validation (placeholder)"
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
