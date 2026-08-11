use crate::grpc::state_service::FleetStateService;
use fleetos_core::proto::state::{PutRequest, state_service_server::StateService};
use fleetos_core::{PodSpec, RuntimeEngine};
use std::sync::Arc;
use tonic::Request;
use tracing::info;

pub struct PodDispatcher {
    state_service: Arc<FleetStateService>,
}

impl PodDispatcher {
    pub fn new(state_service: Arc<FleetStateService>) -> Self {
        Self { state_service }
    }

    /// Serializes and dispatches a scheduled PodSpec to its assigned target node
    /// through Raft consensus write-through.
    pub async fn dispatch_pod(&self, target_node_id: &str, pod: PodSpec) -> Result<u64, String> {
        let pod_bytes = serde_json::to_vec(&pod)
            .map_err(|e| format!("Failed to serialize PodSpec '{}': {}", pod.id, e))?;

        let key = format!("/pods/{}/{}", target_node_id, pod.id);

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

        // Write through FleetStateService to guarantee entry is committed to OpenRaft
        // log and broadcasted with its canonical log index (revision).
        let put_req = Request::new(PutRequest {
            key: key.into_bytes(),
            value: pod_bytes,
        });

        let response = self.state_service.put(put_req).await.map_err(|status| {
            format!("Raft commit failed during dispatch: {}", status.message())
        })?;

        Ok(response.into_inner().revision)
    }
}
