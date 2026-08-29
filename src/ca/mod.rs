//! Certificate Authority implementation for fleetos-control.
//!
//! Two independent CAs for blast-radius isolation:
//! - **Data/Control CA**: signs SVIDs for nodes, workloads, and control-plane components
//! - **Admin CA**: signs SVIDs for admin/`fleetctl` clients
//!
//! Both CAs are independent root keypairs with separate trust bundles.
//! A compromise of one does not compromise the other.

pub mod delegated;
pub mod grpc_service;
pub mod key_issuance;
pub mod name_constraints;
pub mod oid;
pub mod rcgen_impl;
pub mod renewal;
pub mod trust_bundle;
use crate::ca::trust_bundle::TrustBundleRecord;
use std::sync::Arc;

use parking_lot::RwLock;
use thiserror::Error;

use crate::config::ControlConfig;

use self::trust_bundle::TrustBundle;

/// SVID version record stored in the `svids` keyspace.
///
/// Tracks the current SVID version for each SpiffeId. Incremented on every
/// `submit_csr` issuance. Used by `SecretService` for replay protection:
/// secrets sealed for a given version can only be fetched by a certificate
/// at or above that version.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SvidRecord {
    /// The SpiffeId this record tracks.
    pub spiffe_id: String,
    /// Current SVID version (incremented on each rotation/issuance).
    pub svid_version: u64,
    /// Unix timestamp of the most recent issuance.
    pub issued_at_unix: i64,
}

/// TTL for single-use CSR issuance grants (Master finding M-3, join path).
/// Long enough to cover CSR generation + signing round-trip; short enough
/// to bound exposure of an unused grant.
pub const SVID_GRANT_TTL_SECS: i64 = 300;

/// Single-use issuance grant written by `submit_quote` on successful
/// attestation (Master finding M-3).
///
/// Stored in the `svid_grants` keyspace keyed by the attested SPIFFE ID
/// string. `CaServiceImpl::submit_csr` consumes it when an unauthenticated
/// caller (the join flow — no SVID yet) presents a CSR for exactly this
/// identity. One grant, one issuance, five minutes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SvidGrantRecord {
    /// The attested SPIFFE ID — the only identity this grant can issue.
    pub spiffe_id: String,
    /// Node kind from the consumed join token (audit context).
    pub node_kind: u8,
    pub granted_at: i64,
    pub expires_at: i64,
}

/// Errors from CA operations.
#[derive(Debug, Error)]
pub enum CaError {
    #[error("rcgen error: {0}")]
    Rcgen(#[from] rcgen::Error),

    #[error("key generation error: {0}")]
    KeyGeneration(String),

    #[error("signing error: {0}")]
    Signing(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("trust bundle error: {0}")]
    TrustBundle(String),

    #[error(
        "placement verification failed: node {node_id} does not host {target_svid_id}/{target_ordinal}"
    )]
    PlacementVerification {
        node_id: String,
        target_svid_id: String,
        target_ordinal: u32,
    },

    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),

    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// The dual-root CA service.
///
/// Holds both the Data/Control and Admin trust bundles, each with their own
/// independent root keypair and rotation schedule.
pub struct CaService {
    /// Data/Control trust domain CA.
    pub data_control: Arc<RwLock<TrustBundle>>,

    /// Admin trust domain CA.
    pub admin: Arc<RwLock<TrustBundle>>,
}

impl CaService {
    /// Initialize the CA service in bootstrap mode.
    ///
    /// Generates both root CAs from scratch, encrypts them with the master key,
    /// and persists them to the `trust_bundles` keyspace.
    pub fn bootstrap(
        config: &ControlConfig,
        trust_bundles_keyspace: fjall::Keyspace,
        master_key: &dyn crate::secrets::crypto::MasterKeyProvider,
    ) -> Result<Self, CaError> {
        tracing::info!("bootstrapping dual-root CA");

        let data_control = TrustBundle::generate_root(&config.trust_domains.data_control)?;
        let admin = TrustBundle::generate_root(&config.trust_domains.admin)?;

        // Persist both trust bundles encrypted at rest.
        Self::persist_bundle(&data_control, &trust_bundles_keyspace, master_key)?;
        Self::persist_bundle(&admin, &trust_bundles_keyspace, master_key)?;

        tracing::info!(
            data_control_td = %config.trust_domains.data_control,
            admin_td = %config.trust_domains.admin,
            "dual-root CA bootstrapped and persisted"
        );

        Ok(Self {
            data_control: Arc::new(RwLock::new(data_control)),
            admin: Arc::new(RwLock::new(admin)),
        })
    }

    /// Load CA from persisted state (for restarting control nodes).
    ///
    /// Reads the encrypted trust bundles from the `trust_bundles` keyspace,
    /// decrypts them with the master key, and reconstructs the `TrustBundle` objects.
    pub fn load(
        config: &ControlConfig,
        trust_bundles_keyspace: fjall::Keyspace,
        master_key: &dyn crate::secrets::crypto::MasterKeyProvider,
    ) -> Result<Self, CaError> {
        tracing::info!("loading dual-root CA from persisted state");

        let data_control = Self::load_bundle(
            &config.trust_domains.data_control,
            &trust_bundles_keyspace,
            master_key,
        )?;
        let admin = Self::load_bundle(
            &config.trust_domains.admin,
            &trust_bundles_keyspace,
            master_key,
        )?;

        tracing::info!(
            data_control_td = %config.trust_domains.data_control,
            admin_td = %config.trust_domains.admin,
            "dual-root CA loaded from storage"
        );

        Ok(Self {
            data_control: Arc::new(RwLock::new(data_control)),
            admin: Arc::new(RwLock::new(admin)),
        })
    }

    /// Initialize the CA service, choosing bootstrap or load based on config.
    pub fn init(
        config: &ControlConfig,
        trust_bundles_keyspace: fjall::Keyspace,
        master_key: &dyn crate::secrets::crypto::MasterKeyProvider,
    ) -> Result<Self, CaError> {
        // Check if trust bundles already exist in storage.
        let dc_key = format!("bundle:{}", config.trust_domains.data_control);
        let exists = trust_bundles_keyspace
            .get(dc_key.as_bytes())
            .map_err(|e| CaError::Storage(crate::storage::StorageError::Storage(e)))?
            .is_some();

        if exists {
            Self::load(config, trust_bundles_keyspace, master_key)
        } else {
            Self::bootstrap(config, trust_bundles_keyspace, master_key)
        }
    }

    /// Persist a trust bundle encrypted at rest.
    fn persist_bundle(
        bundle: &TrustBundle,
        keyspace: &fjall::Keyspace,
        master_key: &dyn crate::secrets::crypto::MasterKeyProvider,
    ) -> Result<(), CaError> {
        let record = bundle.to_record()?;
        let serialized = postcard::to_allocvec(&record).map_err(CaError::Serialization)?;

        // Encrypt the serialized record using envelope encryption.
        let envelope = crate::secrets::crypto::encrypt_at_rest(&serialized, master_key)
            .map_err(|e| CaError::TrustBundle(format!("encryption failed: {}", e)))?;

        let envelope_bytes = postcard::to_allocvec(&envelope).map_err(CaError::Serialization)?;

        let key = format!("bundle:{}", bundle.trust_domain);
        keyspace
            .insert(key.as_bytes(), envelope_bytes.as_slice())
            .map_err(|e| CaError::Storage(crate::storage::StorageError::Storage(e)))?;

        tracing::debug!(trust_domain = %bundle.trust_domain, "trust bundle persisted");
        Ok(())
    }

    /// Load and decrypt a trust bundle from storage.
    fn load_bundle(
        trust_domain: &str,
        keyspace: &fjall::Keyspace,
        master_key: &dyn crate::secrets::crypto::MasterKeyProvider,
    ) -> Result<TrustBundle, CaError> {
        let key = format!("bundle:{}", trust_domain);
        let envelope_bytes = keyspace
            .get(key.as_bytes())
            .map_err(|e| CaError::Storage(crate::storage::StorageError::Storage(e)))?
            .ok_or_else(|| {
                CaError::TrustBundle(format!("trust bundle not found for {}", trust_domain))
            })?;

        let envelope: crate::secrets::crypto::EnvelopeSecret =
            postcard::from_bytes(&envelope_bytes).map_err(CaError::Serialization)?;

        let decrypted = crate::secrets::crypto::decrypt_at_rest(&envelope, master_key)
            .map_err(|e| CaError::TrustBundle(format!("decryption failed: {}", e)))?;

        let record: TrustBundleRecord =
            postcard::from_bytes(&decrypted).map_err(CaError::Serialization)?;

        TrustBundle::from_record(&record)
    }
}
