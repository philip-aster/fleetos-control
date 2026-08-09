use crate::raft::{ClientRequest, FleetRaft};
use fleetos_core::proto::state::{
    EventType, GetRequest, GetResponse, PutRequest, PutResponse, WatchRequest, WatchResponse,
    state_service_server::StateService,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

pub struct FleetStateService {
    raft: FleetRaft,
}

impl FleetStateService {
    pub fn new(raft: FleetRaft) -> Self {
        Self { raft }
    }
}

#[tonic::async_trait]
impl StateService for FleetStateService {
    type WatchStream = ReceiverStream<Result<WatchResponse, Status>>;

    async fn watch(
        &self,
        request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let req = request.into_inner();
        let prefix = String::from_utf8_lossy(&req.key_prefix).to_string();

        info!(
            "Node '{}' (SPIFFE ID: '{}') connected to Watch stream with prefix: '{}' starting at revision {}",
            req.node_id, req.spiffe_id, prefix, req.start_revision
        );

        let (tx, rx) = mpsc::channel(128);

        // Spawn background task pushing initial eBPF network policy updates down to agent
        tokio::spawn(async move {
            let initial_event = WatchResponse {
                revision: 1,
                event_type: EventType::Put as i32,
                key: b"/policies/default".to_vec(),
                value: vec![0x01, 0x00, 0x00, 0x00], // Allow action
            };

            if let Err(e) = tx.send(Ok(initial_event)).await {
                warn!("Agent disconnected from Watch stream: {}", e);
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get(&self, _request: Request<GetRequest>) -> Result<Response<GetResponse>, Status> {
        Ok(Response::new(GetResponse {
            value: vec![],
            revision: 0,
        }))
    }

    async fn put(&self, request: Request<PutRequest>) -> Result<Response<PutResponse>, Status> {
        let req = request.into_inner();
        let key_str = String::from_utf8_lossy(&req.key).to_string();

        let client_req = if key_str.starts_with("/policies/") {
            ClientRequest::PutPolicy {
                key: key_str.trim_start_matches("/policies/").to_string(),
                data: req.value,
            }
        } else {
            let pod_id = key_str.trim_start_matches("/pods/").to_string();
            ClientRequest::PutPod {
                id: pod_id,
                data: req.value,
            }
        };

        match self.raft.client_write(client_req).await {
            Ok(client_write_response) => {
                let revision = client_write_response.log_id.index;
                Ok(Response::new(PutResponse { revision }))
            }
            Err(e) => Err(Status::internal(format!(
                "Failed to commit transaction to Raft cluster: {:?}",
                e
            ))),
        }
    }
}
