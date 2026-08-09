use std::sync::Arc;
use tracing::info;

use crate::grpc::state_service::{FleetStateService, StateChangeEvent};
use crate::storage::models::{PodSpec, RuntimeEngine};
use fleetos_core::proto::state::EventType;

pub struct PodDispatcher {
    state_service: Arc<FleetStateService>,
}

impl PodDispatcher {
    pub fn new(state_service: Arc<FleetStateService>) -> Self {
        Self { state_service }
    }

    /// Serializes and dispatches a scheduled PodSpec to its assigned target node
    pub async fn dispatch_pod(&self, target_node_id: &str, pod: PodSpec) -> Result<(), String> {
        let pod_bytes = serde_json::to_vec(&pod)
            .map_err(|e| format!("Failed to serialize PodSpec '{}': {}", pod.id, e))?;

        let key = format!("/pods/{}/{}", target_node_id, pod.id).into_bytes();

        match &pod.runtime {
            RuntimeEngine::CloudHypervisor(cfg) => {
                info!(
                    "PodDispatcher -> Node '{}': Dispatching Pod '{}' [CloudHypervisor MicroVM | vCPUs: {}, RAM: {}MB]",
                    target_node_id, pod.id, cfg.vcpus, cfg.memory_mb
                );
            }
            RuntimeEngine::Containerd(cfg) => {
                info!(
                    "PodDispatcher -> Node '{}': Dispatching Pod '{}' [Containerd OCI | snapshotter: '{}']",
                    target_node_id, pod.id, cfg.snapshotter
                );
            }
        }

        self.state_service.broadcast_change(StateChangeEvent {
            revision: 1, // Mapped to Raft log index upon commit
            event_type: EventType::Put,
            key,
            value: pod_bytes,
        });

        Ok(())
    }
}
