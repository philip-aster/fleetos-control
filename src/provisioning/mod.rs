//! Cloud Provider Integration — Module 7.
//!
//! Outbound-only gRPC client to an externally-implemented `ProvisioningService`.
//! Cloud providers run out-of-repo shim services that we poll.
//!
//! **Design constraints:**
//! - Outbound-only: we dial the provider's shim, never accept inbound.
//! - Poll-based: we poll `GetNodePoolStatus` on a reconciliation loop.
//! - `bootstrap_payload` is opaque to the provider (Join Token + node-kind config).
//! - CONTROL pools need distinct logic: openraft membership change, not naive spin-up.
//!
//! **API-agnostic contract:** FleetOS defines the specification (NodePoolSpec,
//! NodePoolStatus, lifecycle states). Cloud providers implement the
//! ProvisioningService gRPC server using their own APIs. Any provider can
//! hook into FleetOS by implementing three RPCs against a stable proto contract.

pub mod client;
pub mod control_pool;
pub mod reconcile;

use thiserror::Error;

use crate::attestation::join_token::NodeKind;

/// Errors from provisioning operations.
#[derive(Debug, Error)]
pub enum ProvisioningError {
    #[error("provider endpoint not configured")]
    EndpointNotConfigured,

    #[error("gRPC transport error: {0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("gRPC status error: {0}")]
    GrpcStatus(#[from] tonic::Status),

    #[error("invalid node kind value: {0}")]
    InvalidNodeKind(i32),

    #[error("invalid provider endpoint: {0}")]
    InvalidEndpoint(String),

    #[error("pool not found: {0}")]
    PoolNotFound(String),

    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),

    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("attestation error: {0}")]
    Attestation(#[from] crate::attestation::AttestationError),

    #[error("raft error: {0}")]
    Raft(String),
}

/// Provisioning configuration, parsed from `control.example.toml`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProvisioningConfig {
    /// gRPC endpoint of the cloud provider shim.
    /// Empty string means provisioning is disabled.
    pub endpoint: String,

    /// Reconciliation interval in seconds.
    /// Matches the existing `provision_poll_interval_secs` config key.
    pub poll_interval_secs: u64,
}

impl Default for ProvisioningConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            poll_interval_secs: 30,
        }
    }
}

impl ProvisioningConfig {
    /// Returns true if provisioning is enabled (endpoint is configured).
    pub fn is_enabled(&self) -> bool {
        !self.endpoint.is_empty()
    }
}

/// A node pool record, stored in fjall for persistence across restarts.
///
/// The `bootstrap_payload` is NOT stored here — it's constructed fresh each
/// reconciliation cycle with a new Join Token.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodePoolRecord {
    pub pool_id: String,
    pub node_kind: NodeKind,
    pub desired_count: u32,
    pub vcpus: u32,
    pub memory_mb: u32,
    pub disk_gb: u32,
    pub region_hint: String,
}

/// The bootstrap payload passed to provisioned nodes.
///
/// Opaque to the provider — they pass it through untouched.
/// Contains a Join Token (for attestation) and node-kind config.
/// Serialized with postcard.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BootstrapPayload {
    /// Cryptographically random join token for attestation.
    pub join_token: Vec<u8>,
    /// Node kind (matches our internal NodeKind enum).
    pub node_kind: u8,
}

impl BootstrapPayload {
    /// Serialize the payload to bytes for the proto `bootstrap_payload` field.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProvisioningError> {
        postcard::to_allocvec(self).map_err(ProvisioningError::Serialization)
    }
}

/// Convert internal NodeKind to proto i32 value.
///
/// Proto enum: CONTROL=0, AGENT=1, ROUTER=2, GATEWAY=3, FLEETCTL_PROXY=4
pub fn node_kind_to_proto(kind: &NodeKind) -> i32 {
    match kind {
        NodeKind::Control => 0,
        NodeKind::Agent => 1,
        NodeKind::Router => 2,
        NodeKind::Gateway => 3,
        NodeKind::FleetctlProxy => 4,
    }
}

/// Convert proto i32 value to internal NodeKind.
pub fn node_kind_from_proto(value: i32) -> Result<NodeKind, ProvisioningError> {
    match value {
        0 => Ok(NodeKind::Control),
        1 => Ok(NodeKind::Agent),
        2 => Ok(NodeKind::Router),
        3 => Ok(NodeKind::Gateway),
        4 => Ok(NodeKind::FleetctlProxy),
        other => Err(ProvisioningError::InvalidNodeKind(other)),
    }
}

/// Node lifecycle state from the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeLifecycleState {
    Pending,
    Running,
    Terminated,
}

impl NodeLifecycleState {
    pub fn from_proto(value: i32) -> Self {
        match value {
            0 => NodeLifecycleState::Pending,
            1 => NodeLifecycleState::Running,
            2 => NodeLifecycleState::Terminated,
            _ => NodeLifecycleState::Pending, // Unknown states treated as pending
        }
    }
}
