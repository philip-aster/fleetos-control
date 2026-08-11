use crate::grpc::state_service::FleetStateService;
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tracing::{error, info, warn};

pub struct NodeController {
    state_service: Arc<FleetStateService>,
    heartbeat_timeout_secs: u64,
}

impl NodeController {
    pub fn new(state_service: Arc<FleetStateService>) -> Self {
        Self {
            state_service,
            heartbeat_timeout_secs: 15,
        }
    }

    /// Runs continuous node health check monitoring
    pub async fn run_monitoring_loop(&self) -> Result<(), String> {
        info!("NodeController health monitoring loop initialized");

        loop {
            if let Err(e) = self.reconcile_node_health().await {
                error!("Error during node health reconciliation tick: {}", e);
            }

            sleep(Duration::from_secs(5)).await;
        }
    }

    /// Evaluates node heartbeat freshness and marks unresponsive nodes as Unhealthy
    async fn reconcile_node_health(&self) -> Result<(), String> {
        let entries = self.state_service.get_prefix("/nodes/").await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (key_bytes, val_bytes) in entries {
            let key = String::from_utf8_lossy(&key_bytes);

            if key.ends_with("/heartbeat") {
                if let Ok(last_seen) = String::from_utf8(val_bytes)
                    .map_err(|e| e.to_string())
                    .and_then(|s| s.parse::<u64>().map_err(|e| e.to_string()))
                {
                    let node_id = key
                        .trim_start_matches("/nodes/")
                        .trim_end_matches("/heartbeat");

                    if now.saturating_sub(last_seen) > self.heartbeat_timeout_secs {
                        warn!(
                            "NodeController -> Node '{}' failed heartbeat check (Last seen {}s ago). Marking UNHEALTHY.",
                            node_id,
                            now.saturating_sub(last_seen)
                        );

                        // Update node status in state storage
                        let status_key = format!("/nodes/{}/status", node_id);
                        let _ = self
                            .state_service
                            .put_bytes(&status_key, b"UNHEALTHY")
                            .await;
                    }
                }
            }
        }

        Ok(())
    }
}
