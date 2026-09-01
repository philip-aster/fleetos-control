//! Poll-based reconciliation loop.
//!
//! Every `reconcile_interval_seconds` (default 30s):
//! 1. Load all NodePoolRecords from fjall
//! 2. For each pool, poll GetNodePoolStatus for actual state
//! 3. Compare actual vs desired, push ReconcileNodePool if mismatch
//! 4. For CONTROL pools, additionally handle openraft membership changes
//!
//! Error handling: log and continue. Provider failures are transient;
//! the next cycle will retry. We never crash on provider errors.
use super::client::ProvisioningClient;
use super::control_pool::ControlPoolManager;
use super::{
    BootstrapPayload, NodeLifecycleState, NodePoolRecord, ProvisioningConfig, ProvisioningError,
};
use crate::attestation::join_token::{JoinTokenStore, NodeKind};
use openraft::Raft;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// The provisioning reconciler.
///
/// Runs a poll-based loop that reconciles node pools against the provider.
/// Only runs when this node is the Raft leader (leader-gated).
pub struct ProvisioningReconciler {
    config: ProvisioningConfig,
    client: ProvisioningClient,
    join_token_store: Arc<JoinTokenStore>,
    control_pool_manager: Arc<ControlPoolManager>,
    storage: Arc<crate::storage::StorageEngine>,
    raft: Arc<Raft<crate::raft::FleetosRaftConfig>>,
}

impl ProvisioningReconciler {
    pub async fn new(
        config: ProvisioningConfig,
        join_token_store: Arc<JoinTokenStore>,
        control_pool_manager: Arc<ControlPoolManager>,
        storage: Arc<crate::storage::StorageEngine>,
        raft: Arc<Raft<crate::raft::FleetosRaftConfig>>,
    ) -> Result<Self, ProvisioningError> {
        if !config.is_enabled() {
            return Err(ProvisioningError::EndpointNotConfigured);
        }

        let client = ProvisioningClient::connect(&config.endpoint).await?;

        Ok(Self {
            config,
            client,
            join_token_store,
            control_pool_manager,
            storage,
            raft,
        })
    }

    /// Run the reconciliation loop.
    ///
    /// This task runs for the lifetime of the process (while leader).
    /// It polls the provider every `reconcile_interval_seconds`.
    pub async fn run_loop(&mut self, mut shutdown: watch::Receiver<bool>) {
        let interval_duration = Duration::from_secs(self.config.poll_interval_secs);
        let mut interval = tokio::time::interval(interval_duration);
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("provisioning reconciler shutting down");
                        return;
                    }
                }
                _ = interval.tick() => {
                    if let Err(e) = self.reconcile_all().await {
                        tracing::error!(error = %e, "provisioning reconciliation cycle failed");
                    }
                }
            }
        }
    }

    /// Reconcile all stored node pools.
    async fn reconcile_all(&mut self) -> Result<(), ProvisioningError> {
        // Load all pool records from fjall.
        let pools = self.load_pools()?;

        for pool in &pools {
            if let Err(e) = self.reconcile_pool(pool).await {
                // Log and continue to next pool. Don't let one pool's
                // failure block the others.
                tracing::error!(
                    pool_id = %pool.pool_id,
                    error = %e,
                    "failed to reconcile pool"
                );
            }
        }

        Ok(())
    }

    /// Reconcile a single node pool.
    async fn reconcile_pool(&mut self, pool: &NodePoolRecord) -> Result<(), ProvisioningError> {
        // 1. Poll actual state from the provider.
        let status = self.client.get_node_pool_status(&pool.pool_id).await?;

        // 2. Count RUNNING nodes.
        let running_count = status
            .nodes
            .iter()
            .filter(|n| NodeLifecycleState::from_proto(n.state) == NodeLifecycleState::Running)
            .count() as u32;

        tracing::debug!(
            pool_id = %pool.pool_id,
            desired = pool.desired_count,
            running = running_count,
            "pool status"
        );

        if running_count != pool.desired_count {
            let bootstrap_payload = self.build_bootstrap_payload(pool.node_kind).await?;
            let _status = self
                .client
                .reconcile_node_pool(pool, bootstrap_payload)
                .await?;

            tracing::info!(
                pool_id = %pool.pool_id,
                desired = pool.desired_count,
                "pushed reconcile to provider"
            );
        }

        // 4. For CONTROL pools, handle openraft membership changes.
        if pool.node_kind == NodeKind::Control {
            self.control_pool_manager
                .handle_control_pool_status(pool, &status)
                .await?;
        }

        Ok(())
    }

    async fn build_bootstrap_payload(
        &mut self,
        node_kind: NodeKind,
    ) -> Result<Vec<u8>, ProvisioningError> {
        let record = self.join_token_store.compute_token_record(node_kind)?;
        let token = record.token.clone();
        self.raft
            .client_write(crate::raft::AuditedCommand::system(
                crate::raft::FleetosCommand::MintJoinToken { record },
            ))
            .await
            .map_err(|e| ProvisioningError::Raft(e.to_string()))?;
        let payload = BootstrapPayload {
            join_token: token,
            node_kind: node_kind as u8,
        };
        payload.to_bytes()
    }

    /// Load all node pool records from the `node_pools` keyspace.
    ///
    /// Each record is stored with `pool_id` as the key and postcard-serialized
    /// `NodePoolRecord` as the value. A full prefix scan retrieves all pools.
    fn load_pools(&self) -> Result<Vec<NodePoolRecord>, ProvisioningError> {
        let mut records = Vec::new();

        // prefix() with empty prefix scans the entire keyspace.
        // Guard::value() moves the guard, so access it once.
        for guard in self.storage.node_pools.prefix(Vec::<u8>::new()) {
            let value = guard.value().map_err(|e| {
                ProvisioningError::Storage(crate::storage::StorageError::Storage(e))
            })?;

            if let Ok(record) = postcard::from_bytes::<NodePoolRecord>(value.as_ref()) {
                records.push(record);
            } else {
                tracing::warn!("skipping malformed node pool record");
            }
        }

        Ok(records)
    }
}
