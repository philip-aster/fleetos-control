use crate::grpc::state_service::FleetStateService;
use crate::scheduler::{FleetScheduler, NodeInfo};
use fleetos_core::PodSpec;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tracing::{error, info, warn};

pub struct PodController {
    state_service: Arc<FleetStateService>,
    scheduler: Arc<FleetScheduler>,
}

impl PodController {
    pub fn new(state_service: Arc<FleetStateService>, scheduler: Arc<FleetScheduler>) -> Self {
        Self {
            state_service,
            scheduler,
        }
    }

    /// Primary worker loop scanning for unassigned/pending pods and running reconciliation
    pub async fn run_reconciliation_loop(&self) -> Result<(), String> {
        info!("PodController reconciliation loop initialized");

        loop {
            if let Err(e) = self.reconcile_pending_pods().await {
                error!("Error during pod reconciliation tick: {}", e);
            }

            // Reconciliation tick interval
            sleep(Duration::from_secs(2)).await;
        }
    }

    /// Inspects Redb state machine for unscheduled pods and assigns them via FleetScheduler
    async fn reconcile_pending_pods(&self) -> Result<(), String> {
        // Query active cluster nodes to evaluate available capacity
        let active_nodes = self.fetch_active_nodes().await?;

        if active_nodes.is_empty() {
            return Ok(());
        }

        // Fetch pending pods needing node assignment
        let pending_pods = self.fetch_pending_pods().await?;

        for pod in pending_pods {
            info!("Reconciling pending Pod '{}'...", pod.id);

            match self
                .scheduler
                .schedule_pod(pod.clone(), &active_nodes)
                .await
            {
                Ok((assigned_node, revision)) => {
                    info!(
                        "PodController -> Pod '{}' successfully assigned to Node '{}' (Raft Revision: {})",
                        pod.id, assigned_node, revision
                    );

                    // Cleanup pending marker upon successful dispatch
                    let pending_key = format!("/pods/pending/{}", pod.id);
                    let _ = self.state_service.delete_key(&pending_key).await;
                }
                Err(err_msg) => {
                    warn!(
                        "PodController -> Unable to schedule Pod '{}': {}",
                        pod.id, err_msg
                    );
                }
            }
        }

        Ok(())
    }

    /// Fetches active nodes and their resource capacities from state storage
    async fn fetch_active_nodes(&self) -> Result<HashMap<String, NodeInfo>, String> {
        // Reads node state keys under prefix "/nodes/"
        let entries = self.state_service.get_prefix("/nodes/").await?;
        let mut nodes = HashMap::new();

        for (key_bytes, val_bytes) in entries {
            let key = String::from_utf8_lossy(&key_bytes);
            if key.ends_with("/info") {
                if let Ok(node_info) = serde_json::from_slice::<NodeInfo>(&val_bytes) {
                    nodes.insert(node_info.node_id.clone(), node_info);
                }
            }
        }

        Ok(nodes)
    }

    /// Reads all pending PodSpecs submitted under prefix "/pods/pending/"
    async fn fetch_pending_pods(&self) -> Result<Vec<PodSpec>, String> {
        let entries = self.state_service.get_prefix("/pods/pending/").await?;
        let mut pods = Vec::new();

        for (_key, val_bytes) in entries {
            if let Ok(pod) = serde_json::from_slice::<PodSpec>(&val_bytes) {
                pods.push(pod);
            }
        }

        Ok(pods)
    }
}
