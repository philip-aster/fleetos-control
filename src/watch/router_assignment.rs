//! RouterAssignmentService implementation — WatchRoutes stream for routers.
//!
//! Streams routing table updates to routers. Each RouteEntry maps a
//! destination (SVID + role) to the agent node hosting it.
//!
//! Routers use this to build their user-space `dashmap` routing table,
//! mapping destination identities to the agent nodes that host them.
use super::broadcast::BroadcastHub;
use fleetos_core::proto::state::RouterAssignmentService;
use fleetos_core::proto::state::{RouteEntry, RouteUpdate, WatchRequest};
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

/// Internal representation of a route entry, serialized into
/// `RouteUpdateEvent.routes_bytes` by the state machine.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RouteEntryRecord {
    /// The destination workload's SPIFFE ID.
    pub destination_svid: String,
    /// The destination workload's role (e.g., "primary", "replica").
    pub destination_role: String,
    /// The agent node hosting this destination (SPIFFE ID of the agent).
    pub target_agent_svid: String,
}

/// The RouterAssignmentService gRPC implementation.
pub struct RouterAssignmentServiceImpl {
    hub: Arc<BroadcastHub>,
}

impl RouterAssignmentServiceImpl {
    pub fn new(hub: Arc<BroadcastHub>) -> Self {
        Self { hub }
    }
}

#[tonic::async_trait]
impl RouterAssignmentService for RouterAssignmentServiceImpl {
    type WatchRoutesStream =
        Pin<Box<dyn Stream<Item = Result<RouteUpdate, Status>> + Send + 'static>>;

    async fn watch_routes(
        &self,
        _request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchRoutesStream>, Status> {
        let mut rx = self.hub.subscribe_routes();
        let stream = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(update) => {
                        let routes = match deserialize_routes(&update.routes_bytes) {
                            Ok(r) => r,
                            Err(e) => {
                                tracing::error!(error = %e, "failed to deserialize routes");
                                continue;
                            }
                        };
                        let route_update = RouteUpdate {
                            version: update.version.get(),
                            routes,
                        };
                        yield Ok(route_update);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(lagged = n, "routes subscriber lagged");
                        continue;
                    }
                }
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }
}

/// Deserialize route entries from internal postcard format to proto messages.
fn deserialize_routes(bytes: &[u8]) -> Result<Vec<RouteEntry>, super::WatchError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let records: Vec<RouteEntryRecord> =
        postcard::from_bytes(bytes).map_err(super::WatchError::Serialization)?;
    Ok(records
        .into_iter()
        .map(|r| RouteEntry {
            destination_svid: r.destination_svid,
            destination_role: r.destination_role,
            target_agent_svid: r.target_agent_svid,
        })
        .collect())
}
