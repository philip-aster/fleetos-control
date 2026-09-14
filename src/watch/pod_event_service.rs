//! PodEventService implementation — pod lifecycle events (CR-CORE-8 / CR-CTRL-7).
//!
//! Mounted on BOTH listeners; authz is per-method by caller kind, which is
//! structural for the dual-listener model:
//! - `ReportPodEvents` (Data/Control listener): node-kind callers only, and
//!   every event's `node_id` must equal the caller's identity. One spoofed
//!   event poisons the whole batch → reject all.
//! - `WatchPodEvents` (Admin listener): operator/ctrl callers only. The
//!   `tenant_id` filter is honored via pod→placement resolution.
//!   LIMITATION (documented): grant-based tenant enforcement is pending —
//!   cluster admins see everything; the tenant filter is caller-supplied.
//!
//! Events are leader-local and never Raft-replicated (see `pod_event_store`).
//! No initial frame: pod events are ephemeral telemetry, not replayable state.
use std::pin::Pin;
use std::sync::Arc;

use fleetos_core::proto::state::{
    PodEvent, PodEventService, ReportPodEventsRequest, ReportPodEventsResponse,
    WatchPodEventsRequest,
};
use fleetos_core::spiffe::{IdKind, SpiffeId};
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use super::broadcast::BroadcastHub;
use super::pod_event_store::{PodEventEmitter, is_valid_event_type, now_unix};
use crate::scheduler::Placement;
use crate::tls::PeerConnectInfo;

#[derive(Clone)]
pub struct PodEventServiceImpl {
    emitter: Arc<PodEventEmitter>,
    hub: Arc<BroadcastHub>,
    placements: fjall::Keyspace,
}

impl PodEventServiceImpl {
    pub fn new(
        emitter: Arc<PodEventEmitter>,
        hub: Arc<BroadcastHub>,
        placements: fjall::Keyspace,
    ) -> Self {
        Self {
            emitter,
            hub,
            placements,
        }
    }
}

/// Resolve the tenant that owns a pod via the placements keyspace.
fn resolve_pod_tenant(placements: &fjall::Keyspace, pod_id: &str) -> Option<String> {
    let value = placements.get(pod_id.as_bytes()).ok().flatten()?;
    let placement: Placement = postcard::from_bytes(value.as_ref()).ok()?;
    Some(placement.tenant_id)
}

#[tonic::async_trait]
impl PodEventService for PodEventServiceImpl {
    async fn report_pod_events(
        &self,
        request: Request<ReportPodEventsRequest>,
    ) -> Result<Response<ReportPodEventsResponse>, Status> {
        // CRITICAL: extract peer identity BEFORE into_inner() consumes the Request.
        let caller = request
            .extensions()
            .get::<PeerConnectInfo>()
            .and_then(|info| info.spiffe_id.clone())
            .ok_or_else(|| Status::unauthenticated("no peer identity found"))?;

        let req = request.into_inner();

        // Node identities only.
        if caller.kind != IdKind::Node {
            return Err(Status::permission_denied(
                "pod events may only be reported by node identities",
            ));
        }

        if req.events.is_empty() {
            return Ok(Response::new(ReportPodEventsResponse {}));
        }

        // Validate the ENTIRE batch before accepting any of it: one spoofed
        // event poisons the whole batch.
        for event in &req.events {
            if event.pod_id.is_empty() {
                return Err(Status::invalid_argument("event.pod_id cannot be empty"));
            }
            let event_node: SpiffeId = event
                .node_id
                .parse()
                .map_err(|_| Status::invalid_argument("event.node_id is not a valid SPIFFE ID"))?;
            if event_node != caller {
                return Err(Status::permission_denied(
                    "event.node_id does not match the caller identity",
                ));
            }
            if !is_valid_event_type(&event.event_type) {
                return Err(Status::invalid_argument(format!(
                    "unknown event_type '{}'",
                    event.event_type
                )));
            }
        }

        // Normalize count/timestamp, then fan out.
        let now = now_unix();
        let events: Vec<PodEvent> = req
            .events
            .into_iter()
            .map(|mut e| {
                if e.count == 0 {
                    e.count = 1;
                }
                if e.timestamp_unix == 0 {
                    e.timestamp_unix = now;
                }
                e
            })
            .collect();

        self.emitter.emit_batch(events);

        Ok(Response::new(ReportPodEventsResponse {}))
    }

    type WatchPodEventsStream =
        Pin<Box<dyn Stream<Item = Result<PodEvent, Status>> + Send + 'static>>;

    async fn watch_pod_events(
        &self,
        request: Request<WatchPodEventsRequest>,
    ) -> Result<Response<Self::WatchPodEventsStream>, Status> {
        let caller = request
            .extensions()
            .get::<PeerConnectInfo>()
            .and_then(|info| info.spiffe_id.clone())
            .ok_or_else(|| Status::unauthenticated("no peer identity found"))?;

        // Operator/ctrl only (structurally lands on the Admin listener).
        match caller.kind {
            IdKind::Operator | IdKind::Ctrl => {}
            _ => {
                return Err(Status::permission_denied(
                    "pod event streams are restricted to operator/ctrl identities",
                ));
            }
        }

        let req = request.into_inner();
        let pod_filter = if req.pod_id.is_empty() {
            None
        } else {
            Some(req.pod_id)
        };
        let tenant_filter = if req.tenant_id.is_empty() {
            None
        } else {
            Some(req.tenant_id)
        };

        let mut rx = self.hub.subscribe_pod_events();
        let placements = self.placements.clone();

        let stream = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        if let Some(ref pod_id) = pod_filter {
                            if &event.pod_id != pod_id {
                                continue;
                            }
                        }
                        if let Some(ref tenant_id) = tenant_filter {
                            match resolve_pod_tenant(&placements, &event.pod_id) {
                                Some(t) if t == *tenant_id => {}
                                _ => continue,
                            }
                        }
                        yield Ok(event);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(lagged = n, "pod event subscriber lagged");
                        continue;
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::{Placement, ResourceSpec};
    use crate::watch::pod_event_store::PodEventStore;
    use tokio_stream::StreamExt;

    const NODE_ID: &str = "spiffe://fleet.example.internal/ns/system/node/agent-1";
    const OTHER_NODE_ID: &str = "spiffe://fleet.example.internal/ns/system/node/agent-2";
    const OPERATOR_ID: &str = "spiffe://fleet-admin.example.internal/ns/system/operator/alice";
    const CTRL_ID: &str = "spiffe://fleet-admin.example.internal/ns/system/ctrl/fleetctl-proxy";
    const SA_ID: &str = "spiffe://fleet.example.internal/ns/tenant-1/sa/db";

    fn setup(
        name: &str,
    ) -> (
        Arc<fjall::Database>,
        crate::storage::Keyspaces,
        PodEventServiceImpl,
        Arc<BroadcastHub>,
        Arc<PodEventEmitter>,
    ) {
        let dir = std::env::temp_dir().join(format!(
            "fleetos-pod-event-test-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let db = crate::storage::open_database(&dir).unwrap();
        let keyspaces = crate::storage::init_keyspaces(&db).unwrap();
        let hub = BroadcastHub::new();
        let store = PodEventStore::new();
        let emitter = Arc::new(PodEventEmitter::new(store, hub.clone()));
        let svc =
            PodEventServiceImpl::new(emitter.clone(), hub.clone(), keyspaces.placements.clone());
        (db, keyspaces, svc, hub, emitter)
    }

    fn report_request(caller: &str, events: Vec<PodEvent>) -> Request<ReportPodEventsRequest> {
        let mut request = Request::new(ReportPodEventsRequest { events });
        request.extensions_mut().insert(PeerConnectInfo {
            spiffe_id: Some(caller.parse().unwrap()),
        });
        request
    }

    fn agent_event(pod: &str) -> PodEvent {
        PodEvent {
            pod_id: pod.to_owned(),
            node_id: NODE_ID.to_owned(),
            event_type: "Started".to_owned(),
            reason: String::new(),
            message: String::new(),
            timestamp_unix: 0,
            count: 0,
        }
    }

    #[tokio::test]
    async fn node_caller_reports_own_events() {
        let (_db, _ks, svc, hub, _emitter) = setup("own-events");
        let mut rx = hub.subscribe_pod_events();
        svc.report_pod_events(report_request(NODE_ID, vec![agent_event("pod-1")]))
            .await
            .expect("report should succeed");
        let event = rx.recv().await.unwrap();
        assert_eq!(event.pod_id, "pod-1");
        assert_eq!(event.count, 1);
        assert!(event.timestamp_unix > 0, "emitter must fill timestamp");
    }

    #[tokio::test]
    async fn mixed_node_batch_is_rejected_wholesale() {
        let (_db, _ks, svc, _hub, _emitter) = setup("mixed-batch");
        let mut foreign = agent_event("pod-2");
        foreign.node_id = OTHER_NODE_ID.to_owned();
        let err = svc
            .report_pod_events(report_request(NODE_ID, vec![agent_event("pod-1"), foreign]))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn non_node_caller_is_rejected() {
        let (_db, _ks, svc, _hub, _emitter) = setup("non-node");
        let err = svc
            .report_pod_events(report_request(OPERATOR_ID, vec![agent_event("pod-1")]))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn unauthenticated_caller_is_rejected() {
        let (_db, _ks, svc, _hub, _emitter) = setup("unauth");
        let err = svc
            .report_pod_events(Request::new(ReportPodEventsRequest {
                events: vec![agent_event("pod-1")],
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn unknown_event_type_is_rejected() {
        let (_db, _ks, svc, _hub, _emitter) = setup("unknown-type");
        let mut event = agent_event("pod-1");
        event.event_type = "Exploded".to_owned();
        let err = svc
            .report_pod_events(report_request(NODE_ID, vec![event]))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn watch_requires_operator_or_ctrl() {
        let (_db, _ks, svc, _hub, _emitter) = setup("watch-authz");

        for rejected in [NODE_ID, SA_ID] {
            let mut request = Request::new(WatchPodEventsRequest::default());
            request.extensions_mut().insert(PeerConnectInfo {
                spiffe_id: Some(rejected.parse().unwrap()),
            });
            let err = svc.watch_pod_events(request).await.err().unwrap();
            assert_eq!(err.code(), tonic::Code::PermissionDenied);
        }
        for accepted in [OPERATOR_ID, CTRL_ID] {
            let mut request = Request::new(WatchPodEventsRequest::default());
            request.extensions_mut().insert(PeerConnectInfo {
                spiffe_id: Some(accepted.parse().unwrap()),
            });
            assert!(svc.watch_pod_events(request).await.is_ok());
        }
    }

    #[tokio::test]
    async fn watch_filters_by_tenant_via_placements() {
        let (_db, keyspaces, svc, _hub, emitter) = setup("watch-tenant");

        // Seed a placement so pod→tenant resolution works.
        let placement = Placement {
            pod_id: "db-replica-0".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            service: "db".to_owned(),
            role: "replica".to_owned(),
            ordinal: 0,
            node_id: NODE_ID.parse().unwrap(),
            resources: ResourceSpec {
                cpu_millicores: 500,
                memory_bytes: 512 * 1024 * 1024,
            },
        };
        let bytes = postcard::to_allocvec(&placement).unwrap();
        keyspaces
            .placements
            .insert(placement.pod_id.as_bytes(), bytes.as_slice())
            .unwrap();

        let mut request = Request::new(WatchPodEventsRequest {
            pod_id: String::new(),
            tenant_id: "tenant-1".to_owned(),
        });
        request.extensions_mut().insert(PeerConnectInfo {
            spiffe_id: Some(OPERATOR_ID.parse().unwrap()),
        });
        let mut stream = svc.watch_pod_events(request).await.unwrap().into_inner();

        // Matching event + non-matching event (unknown pod → no tenant → filtered).
        emitter.emit(PodEvent {
            pod_id: "db-replica-0".to_owned(),
            node_id: NODE_ID.to_owned(),
            event_type: "Started".to_owned(),
            reason: String::new(),
            message: String::new(),
            timestamp_unix: 0,
            count: 1,
        });
        emitter.emit(PodEvent {
            pod_id: "unknown-pod".to_owned(),
            node_id: NODE_ID.to_owned(),
            event_type: "Started".to_owned(),
            reason: String::new(),
            message: String::new(),
            timestamp_unix: 0,
            count: 1,
        });

        let first = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .expect("should receive an event")
            .expect("stream should yield")
            .expect("frame must be Ok");
        assert_eq!(first.pod_id, "db-replica-0");
    }
}
