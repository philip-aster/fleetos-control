//! SchedulerService implementation — WatchSchedule stream for agents.
//!
//! Streams workload assignments to agents. Each WorkloadAssignment carries
//! workload_id, runtime, image, and role.
use super::broadcast::BroadcastHub;
use fleetos_core::proto::state::SchedulerService;
use fleetos_core::proto::state::{ScheduleUpdate, WatchRequest, WorkloadAssignment};
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
}

/// The SchedulerService gRPC implementation.
pub struct SchedulerServiceImpl {
    hub: Arc<BroadcastHub>,
}

impl SchedulerServiceImpl {
    pub fn new(hub: Arc<BroadcastHub>) -> Self {
        Self { hub }
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
        let mut rx = self.hub.subscribe_schedule();
        let stream = async_stream::stream! {
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
                        let schedule_update = ScheduleUpdate {
                            version: update.version.get(),
                            assignments,
                        };
                        yield Ok(schedule_update);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
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
        .map(|r| WorkloadAssignment {
            workload_id: r.workload_id,
            runtime: r.runtime,
            image: r.image,
            role: r.role,
        })
        .collect())
}
