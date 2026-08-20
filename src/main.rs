//! `fleetos-control` entrypoint.
//!
//! Phase 1: config loading + fjall initialization.
//! Raft, gRPC servers, controllers, and provisioning will be wired in
//! subsequent phases as each module is implemented.

use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "fleetos-control", about = "FleetOS Control Plane Brain")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, default_value = "control.example.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    tracing::info!(config = %cli.config.display(), "loading configuration");
    let config = fleetos_control::config::ControlConfig::load(&cli.config)?;

    tracing::info!(
        node_name = %config.node.name,
        cluster_mode = ?config.cluster.mode,
        fjall_path = %config.storage.fjall_path.display(),
        trust_domain_dc = %config.trust_domains.data_control,
        trust_domain_admin = %config.trust_domains.admin,
        workload_ttl_secs = config.svid.workload_ttl_secs,
        dummy_ip_prefix = config.dummy_ip.tenant_block_prefix,
        "configuration loaded successfully"
    );

    // --- Open fjall database (directory-based) ---
    let db = fleetos_control::storage::open_database(&config.storage.fjall_path)?;
    tracing::info!("fjall database opened");

    // --- Initialize all keyspaces ---
    let keyspaces = fleetos_control::storage::init_keyspaces(&db)?;
    tracing::info!("fjall keyspaces initialized");

    // --- Initialize versioned state ---
    // VersionedState now takes the specific `version` keyspace, not the whole DB.
    let _state = fleetos_control::storage::version::VersionedState::new(keyspaces.version.clone());

    tracing::info!(
        "versioned state initialized at version {:?}",
        _state.current_version()
    );

    // TODO(phase2): Initialize or join Raft cluster
    // let raft_handle = fleetos_control::raft::init(&config, db.clone(), keyspaces).await?;

    // TODO(phase3): Start gRPC servers (Data/Control + Admin listeners)
    // let data_control_listener = fleetos_control::watch::serve_data_control(...).await?;
    // let admin_listener = fleetos_control::admin::serve_admin(...).await?;

    // TODO(phase4): Start controllers (leader-gated)
    // let controllers_handle = fleetos_control::controllers::spawn(...).await?;

    // TODO(phase5): Start provisioning reconciliation loop
    // let provisioning_handle = fleetos_control::provisioning::spawn_reconciler(...).await?;

    tracing::info!("fleetos-control phase 1 complete, awaiting shutdown");

    // Wait for shutdown signal.
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");

    Ok(())
}
