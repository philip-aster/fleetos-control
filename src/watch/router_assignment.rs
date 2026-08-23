//! RouterAssignmentService implementation — WatchRoutes stream for routers.

use super::broadcast::BroadcastHub;
use fleetos_core::proto::state::RouterAssignmentService;
use fleetos_core::proto::state::{RouteUpdate, WatchRequest};
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

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
                        // TODO: Implement proper deserialization to proto RouteEntry.
                        let route_update = RouteUpdate {
                            version: update.version.get(),
                            routes: Vec::new(), // Placeholder
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
