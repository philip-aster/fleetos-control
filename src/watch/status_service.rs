//! WorkloadStatusService implementation — agent status reporting (CR-4 / G-10).
//!
//! Agents push liveness/readiness here. Reports are replicated through Raft
//! (upsert keyed by pod_id) so the leader's pod controller can use them for
//! death detection.
use crate::raft::FleetosRaftConfig;
use fleetos_core::proto::state::{StatusAck, WorkloadStatusReport, WorkloadStatusService};
use openraft::Raft;
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub struct WorkloadStatusServiceImpl {
    raft: Arc<Raft<FleetosRaftConfig>>,
}

impl WorkloadStatusServiceImpl {
    pub fn new(raft: Arc<Raft<FleetosRaftConfig>>) -> Self {
        Self { raft }
    }
}

#[tonic::async_trait]
impl WorkloadStatusService for WorkloadStatusServiceImpl {
    async fn report_workload_status(
        &self,
        request: Request<WorkloadStatusReport>,
    ) -> Result<Response<StatusAck>, Status> {
        let report = request.into_inner();

        if report.pod_id.is_empty() {
            return Err(Status::invalid_argument("pod_id cannot be empty"));
        }

        let record = crate::raft::records::WorkloadStatusRecord {
            pod_id: report.pod_id.clone(),
            workload_id: report.workload_id.clone(),
            tenant_id: report.tenant_id.clone(),
            ready: report.ready,
            live: report.live,
            observed_at_unix: report.observed_at_unix as i64,
        };

        self.raft
            .client_write(crate::raft::AuditedCommand::system(
                crate::raft::FleetosCommand::UpsertWorkloadStatus { record },
            ))
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::debug!(
            pod_id = %report.pod_id,
            ready = report.ready,
            live = report.live,
            "workload status recorded"
        );

        Ok(Response::new(StatusAck { accepted: true }))
    }
}
