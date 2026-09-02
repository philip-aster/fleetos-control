//! WatchService implementation — unified WatchEvents stream.
//!
//! Per the proto, WatchEvent currently only carries SecretRotationNotification.
//! Agents subscribe to this stream to learn when secrets have rotated,
//! then pull the new secret via SecretService.FetchSecret.

use std::pin::Pin;
use std::sync::Arc;

use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use fleetos_core::proto::fleetos::watch_event;
use fleetos_core::proto::state::{
    SecretRotationNotification, SvidRotationNotification, WatchEvent as ProtoWatchEvent,
    WatchRequest, WatchService,
};

use super::broadcast::BroadcastHub;

/// The WatchService gRPC implementation.
pub struct WatchServiceImpl {
    hub: Arc<BroadcastHub>,
}

impl WatchServiceImpl {
    pub fn new(hub: Arc<BroadcastHub>) -> Self {
        Self { hub }
    }
}

#[tonic::async_trait]
impl WatchService for WatchServiceImpl {
    type WatchEventsStream =
        Pin<Box<dyn Stream<Item = Result<ProtoWatchEvent, Status>> + Send + 'static>>;

    async fn watch_events(
        &self,
        _request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchEventsStream>, Status> {
        let mut rx = self.hub.subscribe_watch();
        let stream = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let proto_event = match event {
                            super::broadcast::WatchEvent::SecretRotationNotification {
                                spiffe_id,
                                version: _,
                            } => ProtoWatchEvent {
                                event: Some(watch_event::Event::SecretRotation(
                                    SecretRotationNotification { spiffe_id },
                                )),
                            },
                            super::broadcast::WatchEvent::SvidRotation {
                                spiffe_id,
                                version,
                            } => ProtoWatchEvent {
                                event: Some(watch_event::Event::SvidRotation(
                                    SvidRotationNotification {
                                        spiffe_id,
                                        svid_version: version.get(),
                                    },
                                )),
                            },
                        };
                        yield Ok(proto_event);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(lagged = n, "watch subscriber lagged, skipping messages");
                        continue;
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }
}
