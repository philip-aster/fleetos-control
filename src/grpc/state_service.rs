use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::raft::{ClientRequest, FleetRaft};
use fleetos_core::proto::state::{
    EventType, GetRequest, GetResponse, PutRequest, PutResponse, WatchRequest, WatchResponse,
    state_service_server::StateService,
};

const STATE_MACHINE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("state_machine");

/// Internal event published over the broadcast channel upon successful state changes
#[derive(Clone, Debug)]
pub struct StateChangeEvent {
    pub revision: u64,
    pub event_type: EventType,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

pub struct FleetStateService {
    raft: FleetRaft,
    db: Arc<Database>,
    tx: broadcast::Sender<StateChangeEvent>,
}

impl FleetStateService {
    pub fn new(raft: FleetRaft, db: Arc<Database>) -> Self {
        // Channel size capacity of 1024 events
        let (tx, _) = broadcast::channel(1024);
        Self { raft, db, tx }
    }
}

#[tonic::async_trait]
impl StateService for FleetStateService {
    type WatchStream = tokio_stream::wrappers::ReceiverStream<Result<WatchResponse, Status>>;

    async fn watch(
        &self,
        request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let req = request.into_inner();
        let prefix = req.key_prefix.clone();
        let prefix_str = String::from_utf8_lossy(&prefix).to_string();

        info!(
            "Node '{}' (SPIFFE ID: '{}') subscribed to Watch stream [prefix: '{}'] starting at revision {}",
            req.node_id, req.spiffe_id, prefix_str, req.start_revision
        );

        let mut rx = BroadcastStream::new(self.tx.subscribe());
        let (out_tx, out_rx) = tokio::sync::mpsc::channel(128);

        tokio::spawn(async move {
            while let Some(msg) = rx.next().await {
                match msg {
                    Ok(event) => {
                        // Filter events matching the agent's key prefix
                        if event.key.starts_with(&prefix) {
                            let watch_res = WatchResponse {
                                revision: event.revision,
                                event_type: event.event_type as i32,
                                key: event.key,
                                value: event.value,
                            };

                            if out_tx.send(Ok(watch_res)).await.is_err() {
                                warn!("Agent disconnected from Watch stream");
                                break;
                            }
                        }
                    }
                    Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                        warn!("Watch subscriber lagged by {} messages", n);
                    }
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            out_rx,
        )))
    }

    async fn get(&self, request: Request<GetRequest>) -> Result<Response<GetResponse>, Status> {
        let req = request.into_inner();
        let key_str = String::from_utf8_lossy(&req.key).to_string();

        let read_tx = self
            .db
            .begin_read()
            .map_err(|e| Status::internal(format!("Failed to begin Redb read tx: {:?}", e)))?;

        let table = read_tx.open_table(STATE_MACHINE_TABLE).map_err(|e| {
            Status::internal(format!("Failed to open state_machine table: {:?}", e))
        })?;

        if let Some(access_guard) = table
            .get(key_str.as_str())
            .map_err(|e| Status::internal(format!("Failed to read key from Redb: {:?}", e)))?
        {
            Ok(Response::new(GetResponse {
                value: access_guard.value().to_vec(),
                revision: 1,
            }))
        } else {
            Err(Status::not_found(format!("Key '{}' not found", key_str)))
        }
    }

    async fn put(&self, request: Request<PutRequest>) -> Result<Response<PutResponse>, Status> {
        let req = request.into_inner();
        let key_str = String::from_utf8_lossy(&req.key).to_string();
        let val_bytes = req.value.clone();

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

                // Broadcast change event to active Watch stream subscribers
                let _ = self.tx.send(StateChangeEvent {
                    revision,
                    event_type: EventType::Put,
                    key: req.key,
                    value: val_bytes,
                });

                Ok(Response::new(PutResponse { revision }))
            }
            Err(e) => Err(Status::internal(format!(
                "Failed to commit transaction to Raft cluster: {:?}",
                e
            ))),
        }
    }
}
