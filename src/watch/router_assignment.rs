//! RouterAssignmentService — WatchRoutes stream.
//!
//! CR-CTRL-5 CONTRACT: agents are sanctioned consumers of `WatchRoutes` in
//! addition to routers. An agent subscribes here to populate its dummy-IP
//! route maps (DUMMY_IP_ROUTE_MAP / SRC_IDENTITY_MAP / LOCAL_WORKLOADS) and
//! `/etc/hosts`; it then reports router connectivity via the CR-CTRL-3
//! readiness gate. This service performs no caller filtering beyond listener
//! mTLS, so any authenticated Data/Control peer may subscribe. Do NOT add a
//! separate agent-facing route stream — this is the single consumption path.
//!
//! `RouteEntry.dummy_ip` is emitted as the canonical u32 value; the
//! big-endian eBPF-map conversion is agent-side (`HostOrderIpv4::from_network`).

use super::broadcast::BroadcastHub;
use fleetos_core::proto::state::{RouteEntry, RouteUpdate, RouterAssignmentService, WatchRequest};
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

/// Internal representation of a route entry, serialized into
/// `RouteUpdateEvent.routes_bytes` by the state machine.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RouteEntryRecord {
    pub destination_svid: String,
    pub destination_role: String,
    pub target_agent_svid: String,
    pub dummy_ip: u32,
}

/// The RouterAssignmentService gRPC implementation.
pub struct RouterAssignmentServiceImpl {
    hub: Arc<BroadcastHub>,
    placements: fjall::Keyspace,
    dummy_ips: fjall::Keyspace,
    versioned_state: crate::storage::version::VersionedState,
    data_trust_domain: String,
}

impl RouterAssignmentServiceImpl {
    pub fn new(
        hub: Arc<BroadcastHub>,
        placements: fjall::Keyspace,
        dummy_ips: fjall::Keyspace,
        versioned_state: crate::storage::version::VersionedState,
        data_trust_domain: String,
    ) -> Self {
        Self {
            hub,
            placements,
            dummy_ips,
            versioned_state,
            data_trust_domain,
        }
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
        // ORDERING (adjudication Q6): subscribe FIRST, then read committed
        // state, then yield frame one, then stream deltas.
        let mut rx = self.hub.subscribe_routes();

        let routes_bytes = super::snapshot::build_routes_snapshot(
            &self.placements,
            &self.dummy_ips,
            &self.data_trust_domain,
        );

        let frame_one = match deserialize_routes(&routes_bytes) {
            Ok(routes) => RouteUpdate {
                version: self.versioned_state.current_version().get(),
                routes,
            },
            Err(e) => {
                tracing::error!(error = %e, "failed to build initial routes frame");
                return Err(Status::internal("failed to build initial routes frame"));
            }
        };

        let stream = async_stream::stream! {
            yield Ok(frame_one);
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
                        yield Ok(RouteUpdate {
                            version: update.version.get(),
                            routes,
                        });
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
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
            dummy_ip: r.dummy_ip,
        })
        .collect())
}
