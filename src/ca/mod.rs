//! Certificate Authority implementation for fleetos-control.
//!
//! Two independent CAs for blast-radius isolation:
//! - **Data/Control CA**: signs SVIDs for nodes, workloads, and control-plane components
//! - **Admin CA**: signs SVIDs for admin/`fleetctl` clients
//!
//! Both CAs are independent root keypairs with separate trust bundles.
//! A compromise of one does not compromise the other.

pub mod delegated;
pub mod key_issuance;
pub mod name_constraints;
pub mod oid;
pub mod rcgen_impl;
pub mod trust_bundle;

use std::sync::Arc;

use parking_lot::RwLock;
use thiserror::Error;

use crate::config::ControlConfig;

use self::trust_bundle::TrustBundle;

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
    /// Initialize the CA service.
    ///
    /// In bootstrap mode: generates both root CAs from scratch.
    /// In join mode: loads existing trust bundles from storage (after attestation).
    pub fn bootstrap(config: &ControlConfig) -> Result<Self, CaError> {
        tracing::info!("bootstrapping dual-root CA");

        let data_control = TrustBundle::generate_root(&config.trust_domains.data_control)?;
        let admin = TrustBundle::generate_root(&config.trust_domains.admin)?;

        tracing::info!(
            data_control_td = %config.trust_domains.data_control,
            admin_td = %config.trust_domains.admin,
            "dual-root CA bootstrapped"
        );

        Ok(Self {
            data_control: Arc::new(RwLock::new(data_control)),
            admin: Arc::new(RwLock::new(admin)),
        })
    }

    /// Load CA from persisted state (for non-bootstrap nodes after joining).
    pub fn load(_db: Arc<fjall::Database>, _config: &ControlConfig) -> Result<Self, CaError> {
        // TODO: Load trust bundles from fjall after attestation + join.
        // For now, this is a placeholder — bootstrap is the only path implemented.
        Err(CaError::TrustBundle("load not yet implemented".to_owned()))
    }
}
