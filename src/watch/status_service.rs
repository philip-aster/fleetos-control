//! WorkloadStatusService implementation — agent status reporting (CR-4).
//!
//! Agents push liveness/readiness here so the pod controller has a death
//! signal other than missing placements (gap G-10).
use fleetos_core::proto::state::{StatusAck, WorkloadStatusReport, WorkloadStatusService};
use tonic::{Request, Response, Status};

pub struct WorkloadStatusServiceImpl;

impl WorkloadStatusServiceImpl {
    pub fn new() -> Self {
        Self
    }
}

#[tonic::async_trait]
impl WorkloadStatusService for WorkloadStatusServiceImpl {
    async fn report_workload_status(
        &self,
        request: Request<WorkloadStatusReport>,
    ) -> Result<Response<StatusAck>, Status> {
        let report = request.into_inner();
        // TODO: Wire to PodController state / Raft proposals in Step 16.
        // For now, accept the report to unblock agent compilation.
        tracing::debug!(
            pod_id = %report.pod_id,
            workload_id = %report.workload_id,
            ready = report.ready,
            live = report.live,
            "workload status received"
        );
        Ok(Response::new(StatusAck { accepted: true }))
    }
}
