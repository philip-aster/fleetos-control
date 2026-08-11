use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// gRPC listening address for fleetos-control services
    pub grpc_bind_addr: SocketAddr,

    /// OpenRaft peer-to-peer listening address
    pub raft_bind_addr: SocketAddr,

    /// Unique OpenRaft Node ID for this control plane replica
    pub node_id: u64,

    /// Path to persistent Redb database file
    pub db_path: PathBuf,

    /// Master key for ChaCha20-Poly1305 AEAD envelope encryption (32 bytes)
    pub master_key: [u8; 32],

    /// SPIFFE Trust Domain
    pub trust_domain: String,

    /// Initial peer cluster map (Node ID -> gRPC address)
    #[serde(default)]
    pub initial_cluster_peers: Vec<ClusterPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterPeer {
    pub node_id: u64,
    pub addr: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            grpc_bind_addr: "0.0.0.0:9090".parse().unwrap(),
            raft_bind_addr: "0.0.0.0:9091".parse().unwrap(),
            node_id: 1,
            db_path: PathBuf::from("/var/lib/fleetos/control.redb"),
            master_key: [0x42; 32],
            trust_domain: "fleetos.mesh".to_string(),
            initial_cluster_peers: vec![],
        }
    }
}

impl Config {
    /// Loads configuration from file if available, falling back to defaults,
    /// and applies environment variable overrides.
    pub fn load_from_env() -> Self {
        let mut config = if let Ok(path) = std::env::var("FLEETOS_CONFIG_PATH") {
            Self::load_from_file(path).unwrap_or_default()
        } else if std::path::Path::new("config/control.toml").exists() {
            Self::load_from_file("config/control.toml").unwrap_or_default()
        } else if std::path::Path::new("config/control.example.toml").exists() {
            Self::load_from_file("config/control.example.toml").unwrap_or_default()
        } else {
            Self::default()
        };

        if let Ok(addr_str) = std::env::var("FLEETOS_GRPC_BIND_ADDR") {
            if let Ok(addr) = addr_str.parse() {
                config.grpc_bind_addr = addr;
            }
        }

        if let Ok(addr_str) = std::env::var("FLEETOS_RAFT_BIND_ADDR") {
            if let Ok(addr) = addr_str.parse() {
                config.raft_bind_addr = addr;
            }
        }

        if let Ok(id_str) = std::env::var("FLEETOS_NODE_ID") {
            if let Ok(id) = id_str.parse() {
                config.node_id = id;
            }
        }

        if let Ok(db_str) = std::env::var("FLEETOS_DB_PATH") {
            config.db_path = PathBuf::from(db_str);
        }

        if let Ok(domain_str) = std::env::var("FLEETOS_TRUST_DOMAIN") {
            config.trust_domain = domain_str;
        }

        config
    }

    /// Loads configuration from a TOML file path
    pub fn load_from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, String> {
        let path_ref = path.as_ref();
        let content = std::fs::read_to_string(path_ref)
            .map_err(|e| format!("Failed to read config file '{}': {}", path_ref.display(), e))?;

        toml::from_str(&content).map_err(|e| {
            format!(
                "Failed to parse config TOML from '{}': {}",
                path_ref.display(),
                e
            )
        })
    }
}
