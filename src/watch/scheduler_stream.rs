//! SchedulerService implementation — WatchSchedule stream for agents.
//!
//! Streams workload assignments to agents. Each WorkloadAssignment carries
//! workload_id, runtime, image, and role.
use super::broadcast::BroadcastHub;
use fleetos_core::proto::state::SchedulerService;
use fleetos_core::proto::state::{ScheduleUpdate, WatchRequest, WorkloadAssignment};
use fleetos_core::proto::workload::PodSpec;
use prost::Message;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

/// Internal representation of a workload assignment, serialized into
/// `ScheduleUpdateEvent.assignments_bytes` by the state machine.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WorkloadAssignmentRecord {
    pub workload_id: String,
    pub runtime: String,
    pub image: String,
    pub role: String,
    pub hostname: String,
    /// prost-encoded `PodSpec` (six trusted fields already overwritten) — CR-CTRL-4.
    pub pod_spec_bytes: Vec<u8>,
}

/// The SchedulerService gRPC implementation.
pub struct SchedulerServiceImpl {
    hub: Arc<BroadcastHub>,
    placements: fjall::Keyspace,
    workloads: fjall::Keyspace,
    versioned_state: crate::storage::version::VersionedState,
    data_trust_domain: String,
}

impl SchedulerServiceImpl {
    pub fn new(
        hub: Arc<BroadcastHub>,
        placements: fjall::Keyspace,
        workloads: fjall::Keyspace,
        versioned_state: crate::storage::version::VersionedState,
        data_trust_domain: String,
    ) -> Self {
        Self {
            hub,
            placements,
            workloads,
            versioned_state,
            data_trust_domain,
        }
    }
}

#[tonic::async_trait]
impl SchedulerService for SchedulerServiceImpl {
    type WatchScheduleStream =
        Pin<Box<dyn Stream<Item = Result<ScheduleUpdate, Status>> + Send + 'static>>;

    async fn watch_schedule(
        &self,
        _request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchScheduleStream>, Status> {
        // ORDERING (adjudication Q6): subscribe FIRST, then read committed
        // state, then yield frame one, then stream deltas. Deltas published
        // during the snapshot build buffer in `rx` and are drained after
        // frame one by the recv loop — nothing is dropped. Do not reorder.
        let mut rx = self.hub.subscribe_schedule();
        let assignments_bytes = super::snapshot::build_schedule_snapshot(
            &self.placements,
            &self.workloads,
            &self.data_trust_domain,
        );
        let frame_one = match deserialize_assignments(&assignments_bytes) {
            Ok(assignments) => ScheduleUpdate {
                version: self.versioned_state.current_version().get(),
                assignments,
            },
            Err(e) => {
                tracing::error!(error = %e, "failed to build initial schedule frame");
                return Err(Status::internal("failed to build initial schedule frame"));
            }
        };
        let stream = async_stream::stream! {
            yield Ok(frame_one);
            loop {
                match rx.recv().await {
                    Ok(update) => {
                        let assignments = match deserialize_assignments(&update.assignments_bytes) {
                            Ok(a) => a,
                            Err(e) => {
                                tracing::error!(error = %e, "failed to deserialize assignments");
                                continue;
                            }
                        };
                        yield Ok(ScheduleUpdate {
                            version: update.version.get(),
                            assignments,
                        });
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(lagged = n, "schedule subscriber lagged");
                        continue;
                    }
                }
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }
}

/// Deserialize workload assignments from internal postcard format to proto messages.
fn deserialize_assignments(bytes: &[u8]) -> Result<Vec<WorkloadAssignment>, super::WatchError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let records: Vec<WorkloadAssignmentRecord> =
        postcard::from_bytes(bytes).map_err(super::WatchError::Serialization)?;
    Ok(records
        .into_iter()
        .map(|r| {
            let pod_spec = if r.pod_spec_bytes.is_empty() {
                None
            } else {
                PodSpec::decode(r.pod_spec_bytes.as_slice()).ok()
            };
            WorkloadAssignment {
                workload_id: r.workload_id,
                runtime: r.runtime,
                image: r.image,
                role: r.role,
                pod_spec,
                hostname: r.hostname,
            }
        })
        .collect())
}
