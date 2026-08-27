// SPDX-License-Identifier: Apache-2.0

//! Configuration for `fleetos-control`, loaded from `control.example.toml` (or a
//! path supplied via `--config`).
//!
//! SVID TTL policy is owned HERE, not in `fleetos-core`. `fleetos-core` defines
//! the types; this crate defines the lifetimes.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ControlConfig {
    /// Identity of this control node.
    pub node: NodeConfig,

    /// Raft cluster settings.
    pub cluster: ClusterConfig,

    /// fjall storage.
    pub storage: StorageConfig,

    /// Two independent trust domains.
    pub trust_domains: TrustDomainConfig,

    /// SVID TTL and rotation policy.
    pub svid: SvidTtlConfig,

    /// Dummy-IP allocation.
    pub dummy_ip: DummyIpConfig,

    /// At-rest secret encryption.
    pub secrets: SecretsConfig,

    /// Attestation and join-token custody.
    #[serde(default)]
    pub attestation: AttestationConfig,

    /// gRPC listener addresses.
    pub listeners: ListenerConfig,

    /// Cloud provisioning poll interval.
    #[serde(default = "default_provision_poll")]
    pub provision_poll_interval_secs: u64,

    pub provisioning: ProvisioningConfig,

    #[serde(default)]
    pub health: HealthConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProvisioningConfig {
    /// gRPC endpoint of the cloud provider shim.
    /// Empty string means provisioning is disabled.
    #[serde(default)]
    pub endpoint: String,

    /// Reconciliation interval in seconds.
    #[serde(default = "default_provision_poll")]
    pub poll_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HealthConfig {
    /// Seconds after which a node with no heartbeat is evicted.
    /// Default 3600 (1 hour, matching SVID TTL).
    #[serde(default = "default_node_lease_timeout")]
    pub node_lease_timeout_secs: i64,
    /// Interval between node health checks.
    #[serde(default = "default_node_check_interval")]
    pub node_check_interval_secs: u64,
    /// Interval between pod reconciliation checks.
    #[serde(default = "default_pod_check_interval")]
    pub pod_check_interval_secs: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            node_lease_timeout_secs: default_node_lease_timeout(),
            node_check_interval_secs: default_node_check_interval(),
            pod_check_interval_secs: default_pod_check_interval(),
        }
    }
}

fn default_node_lease_timeout() -> i64 {
    3600
}
fn default_node_check_interval() -> u64 {
    15
}
fn default_pod_check_interval() -> u64 {
    20
}

fn default_provision_poll() -> u64 {
    30
}

// ---------------------------------------------------------------------------
// Node identity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    /// Human-readable name for this control node.
    pub name: String,
}

// ---------------------------------------------------------------------------
// Cluster / Raft
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ClusterConfig {
    /// "bootstrap" for the one-time first node, "join" for all others.
    pub mode: ClusterMode,

    /// For `join` mode: Data/Control address of an existing control node
    /// (attestation + CA endpoints).
    #[serde(default)]
    pub join_target: Option<String>,

    /// For `join` mode: raft transport address of an existing control node
    /// (where RaftTransport.RequestJoin is served).
    #[serde(default)]
    pub join_raft_target: Option<String>,

    /// For `join` mode: single-use join token minted via AdminService.
    #[serde(default)]
    pub join_token: String,

    /// For `bootstrap` mode: initial single-node Raft cluster.
    /// Addresses MUST be raft transport addresses (listeners.raft).
    /// Ignored in join mode.
    #[serde(default)]
    pub initial_members: Vec<RaftMemberConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClusterMode {
    Bootstrap,
    Join,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RaftMemberConfig {
    pub id: u64,
    pub address: String,
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    /// Path to the fjall database directory. Local disk only — never a network filesystem.
    pub fjall_path: PathBuf,
}

// ---------------------------------------------------------------------------
// Trust domains
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct TrustDomainConfig {
    /// SPIFFE trust domain for the Data/Control overlay.
    /// e.g. "fleet.example.internal"
    pub data_control: String,

    /// SPIFFE trust domain for the Admin overlay.
    /// e.g. "fleet-admin.example.internal"
    pub admin: String,
}

// ---------------------------------------------------------------------------
// SVID TTL policy (owned by this crate, NOT fleetos-core)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct SvidTtlConfig {
    #[serde(default = "default_workload_ttl")]
    pub workload_ttl_secs: u64,

    #[serde(default = "default_node_ttl")]
    pub node_ttl_secs: u64,

    #[serde(default = "default_admin_ttl")]
    pub admin_ttl_secs: u64,

    #[serde(default = "default_delegated_key_ttl")]
    pub delegated_key_ttl_secs: u64,

    /// Fraction of TTL at which refresh is triggered. Default 0.75 (75%).
    #[serde(default = "default_refresh_fraction")]
    pub refresh_fraction: f64,
}

impl Default for SvidTtlConfig {
    fn default() -> Self {
        Self {
            workload_ttl_secs: default_workload_ttl(),
            node_ttl_secs: default_node_ttl(),
            admin_ttl_secs: default_admin_ttl(),
            delegated_key_ttl_secs: default_delegated_key_ttl(),
            refresh_fraction: default_refresh_fraction(),
        }
    }
}

impl SvidTtlConfig {
    pub fn workload_ttl(&self) -> Duration {
        Duration::from_secs(self.workload_ttl_secs)
    }

    pub fn node_ttl(&self) -> Duration {
        Duration::from_secs(self.node_ttl_secs)
    }

    pub fn admin_ttl(&self) -> Duration {
        Duration::from_secs(self.admin_ttl_secs)
    }

    pub fn delegated_key_ttl(&self) -> Duration {
        Duration::from_secs(self.delegated_key_ttl_secs)
    }

    /// Duration after which the workload SVID should be refreshed (~45 min default).
    pub fn workload_refresh_at(&self) -> Duration {
        let ms = (self.workload_ttl_secs as f64 * self.refresh_fraction * 1000.0) as u64;
        Duration::from_millis(ms)
    }

    /// Duration after which the node SVID should be refreshed.
    pub fn node_refresh_at(&self) -> Duration {
        let ms = (self.node_ttl_secs as f64 * self.refresh_fraction * 1000.0) as u64;
        Duration::from_millis(ms)
    }

    /// Duration after which the admin SVID should be refreshed (~18 hr default).
    pub fn admin_refresh_at(&self) -> Duration {
        let ms = (self.admin_ttl_secs as f64 * self.refresh_fraction * 1000.0) as u64;
        Duration::from_millis(ms)
    }

    /// Duration after which the delegated signing key should be refreshed (~3 hr default).
    pub fn delegated_key_refresh_at(&self) -> Duration {
        let ms = (self.delegated_key_ttl_secs as f64 * self.refresh_fraction * 1000.0) as u64;
        Duration::from_millis(ms)
    }
}

fn default_workload_ttl() -> u64 {
    3600 // 1 hour
}

fn default_node_ttl() -> u64 {
    3600 // 1 hour
}

fn default_admin_ttl() -> u64 {
    86400 // 24 hours
}

fn default_delegated_key_ttl() -> u64 {
    14400 // 4 hours
}

fn default_refresh_fraction() -> f64 {
    0.75
}

// ---------------------------------------------------------------------------
// Dummy-IP allocation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct DummyIpConfig {
    /// The outer address space. Fixed at 240.0.0.0/4 for v1.
    #[serde(default = "default_dummy_ip_space")]
    pub space: String,

    /// CIDR prefix length per tenant block. Default /16 (65,536 addresses,
    /// supporting up to 4,096 tenants).
    ///
    /// Do NOT use /8 — it exhausts the entire 240.0.0.0/4 space after 16 tenants.
    #[serde(default = "default_tenant_block_prefix")]
    pub tenant_block_prefix: u8,
}

impl Default for DummyIpConfig {
    fn default() -> Self {
        Self {
            space: default_dummy_ip_space(),
            tenant_block_prefix: default_tenant_block_prefix(),
        }
    }
}

fn default_dummy_ip_space() -> String {
    "240.0.0.0/4".to_owned()
}

fn default_tenant_block_prefix() -> u8 {
    16
}

// ---------------------------------------------------------------------------
// Secrets at-rest encryption
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct SecretsConfig {
    /// Path to the master key file for envelope encryption (FileMasterKey).
    /// For v1, this is a raw key file. Future: KMS-backed via MasterKeyProvider trait.
    pub master_key_path: PathBuf,
}

// ---------------------------------------------------------------------------
// Attestation
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Deserialize)]
pub struct AttestationConfig {
    /// TTL for single-use join tokens (Master findings M-2/S-11).
    /// Until hardware-quote signature verification lands, join-token
    /// possession is the sole gate to cluster membership, so tokens must
    /// expire. Default 1 hour.
    #[serde(default = "default_join_token_ttl_secs")]
    pub join_token_ttl_secs: u16,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            join_token_ttl_secs: default_join_token_ttl_secs(),
        }
    }
}

fn default_join_token_ttl_secs() -> u16 {
    3600
}

// ---------------------------------------------------------------------------
// gRPC listeners
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ListenerConfig {
    /// Address for the Data/Control overlay listener.
    /// Serves: PolicyService, WatchService, SchedulerService,
    ///        RouterAssignmentService, SecretService, AttestationService, CaService.
    pub data_control: String,

    /// Address for the Admin overlay listener.
    /// Serves: AdminService only. Gated to `ctrl` SVID kind.
    pub admin: String,

    /// Address for Raft peer RPC (internal, Data/Control trust domain, `control` kind).
    pub raft: String,
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

impl ControlConfig {
    /// Load configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw =
            std::fs::read_to_string(path).map_err(|e| ConfigError::Io(path.to_path_buf(), e))?;
        let config: ControlConfig =
            toml::from_str(&raw).map_err(|e| ConfigError::Parse(path.to_path_buf(), e))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        // Dummy-IP prefix sanity: must be within 240.0.0.0/4 bounds.
        // The outer space is /4, so per-tenant prefix must be > 4.
        // Warn against /8 (exhausts after 16 tenants).
        if self.dummy_ip.tenant_block_prefix <= 4 {
            return Err(ConfigError::Validation(format!(
                "tenant_block_prefix must be > 4 (outer space is /4), got {}",
                self.dummy_ip.tenant_block_prefix
            )));
        }
        if self.dummy_ip.tenant_block_prefix == 8 {
            // /8 only supports 16 tenants — reject explicitly.
            return Err(ConfigError::Validation(
                "tenant_block_prefix /8 exhausts 240.0.0.0/4 after 16 tenants; \
                 use /16 (default) or larger prefix"
                    .to_owned(),
            ));
        }
        if self.dummy_ip.tenant_block_prefix > 30 {
            return Err(ConfigError::Validation(format!(
                "tenant_block_prefix /{} leaves too few addresses per tenant",
                self.dummy_ip.tenant_block_prefix
            )));
        }

        // SVID TTL sanity.
        if self.svid.refresh_fraction <= 0.0 || self.svid.refresh_fraction >= 1.0 {
            return Err(ConfigError::Validation(format!(
                "refresh_fraction must be in (0.0, 1.0), got {}",
                self.svid.refresh_fraction
            )));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {0}: {1}")]
    Io(PathBuf, std::io::Error),

    #[error("failed to parse config file {0}: {1}")]
    Parse(PathBuf, #[source] toml::de::Error),

    #[error("config validation failed: {0}")]
    Validation(String),
}
