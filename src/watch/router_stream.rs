//! PolicyService stream for routers.
//!
//! Routers receive the raw ServiceAuthorizationGraph directly — NOT compiled
//! eBPF struct payloads. They use this for their user-space `dashmap`
//! in-flight ACL cache.
//!
//! This is a separate stream handler that filters for router connections
//! (identified by their SVID kind at the mTLS layer).

use std::pin::Pin;
use std::sync::Arc;

use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use fleetos_core::proto::state::{SagSchemaUpdate, WatchRequest};

use super::broadcast::BroadcastHub;

/// Stream SAG schema updates to routers.
///
/// Note: This uses the same PolicyService trait but returns different content
/// based on the caller's identity kind (router vs agent). The mTLS layer
/// determines which handler path is taken.
pub struct RouterPolicyStreamImpl {
    hub: Arc<BroadcastHub>,
}

impl RouterPolicyStreamImpl {
    pub fn new(hub: Arc<BroadcastHub>) -> Self {
        Self { hub }
    }

    /// Stream SAG schema updates to a connected router.
    pub async fn stream_sag_schema(
        &self,
        _request: Request<WatchRequest>,
    ) -> Result<Response<Pin<Box<dyn Stream<Item = Result<SagSchemaUpdate, Status>> + Send>>>, Status>
    {
        let mut rx = self.hub.subscribe_router_policy();

        let stream = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(update) => {
                        let schema_update = SagSchemaUpdate {
                            sag_bytes: update.sag_bytes,
                            version: update.version.get(),
                        };
                        yield Ok(schema_update);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(lagged = n, "router policy subscriber lagged");
                        continue;
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }
}
