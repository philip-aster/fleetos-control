use crate::grpc::state_service::FleetStateService;
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tracing::{error, info, warn};

pub struct SecretController {
    state_service: Arc<FleetStateService>,
    rotation_check_interval_secs: u64,
}

impl SecretController {
    pub fn new(state_service: Arc<FleetStateService>) -> Self {
        Self {
            state_service,
            rotation_check_interval_secs: 60,
        }
    }

    /// Background worker loop checking for secret rotation schedules and TTL expirations
    pub async fn run_rotation_loop(&self) -> Result<(), String> {
        info!("SecretController rotation worker loop initialized");

        loop {
            if let Err(e) = self.reconcile_secret_rotations().await {
                error!("Error during secret rotation reconciliation tick: {}", e);
            }

            sleep(Duration::from_secs(self.rotation_check_interval_secs)).await;
        }
    }

    /// Scans `/secrets/rotation/` prefix in state storage to trigger automated secret rotation
    async fn reconcile_secret_rotations(&self) -> Result<(), String> {
        let entries = self.state_service.get_prefix("/secrets/rotation/").await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (key_bytes, val_bytes) in entries {
            let key = String::from_utf8_lossy(&key_bytes);

            if let Ok(next_rotation_ts) = String::from_utf8(val_bytes)
                .map_err(|e| e.to_string())
                .and_then(|s| s.parse::<u64>().map_err(|e| e.to_string()))
            {
                if now >= next_rotation_ts {
                    let secret_id = key.trim_start_matches("/secrets/rotation/");
                    warn!(
                        "SecretController -> Secret '{}' reached scheduled rotation epoch ({}). Broad-casting rotation signal.",
                        secret_id, next_rotation_ts
                    );

                    // Broadcast a rotation signal key to state storage so agents re-fetch updated envelope payloads
                    let signal_key = format!("/secrets/signals/{}/rotate", secret_id);
                    let rotation_payload = format!("{{\"rotated_at\": {}}}", now);
                    let _ = self
                        .state_service
                        .put_bytes(&signal_key, rotation_payload.as_bytes())
                        .await;
                }
            }
        }

        Ok(())
    }
}
