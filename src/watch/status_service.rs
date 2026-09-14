// src/watch/status_service.rs
//! WorkloadStatusService implementation — agent status reporting (CR-4 / G-10).
//!
//! Agents push liveness/readiness here. Reports are replicated through Raft
//! (upsert keyed by pod_id) so the leader's pod controller can use them for
//! death detection.
//!
//! Agents also push high-frequency PodMetrics here (CR-CORE-9). Metrics are
//! leader-local, TTL'd, and capped — they are NOT replicated through Raft.
use crate::raft::FleetosRaftConfig;
use crate::watch::metrics_store::MetricsStore;
use fleetos_core::proto::state::{
    MetricsAck, PodMetrics, StatusAck, WorkloadStatusReport, WorkloadStatusService,
};
use openraft::Raft;
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub struct WorkloadStatusServiceImpl {
    raft: Arc<Raft<FleetosRaftConfig>>,
    metrics_store: Arc<MetricsStore>,
}

impl WorkloadStatusServiceImpl {
    pub fn new(raft: Arc<Raft<FleetosRaftConfig>>, metrics_store: Arc<MetricsStore>) -> Self {
        Self {
            raft,
            metrics_store,
        }
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
            started: report.started,
            policy_enforced: report.policy_enforced,
            restart_count: report.restart_count,
            observed_at_unix: report.observed_at_unix as i64,
            router_connected: report.router_connected,
            // Maintained by the state machine on upsert; leader-side default here.
            gate_violation_since_unix: 0,
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

    async fn report_pod_metrics(
        &self,
        request: Request<PodMetrics>,
    ) -> Result<Response<MetricsAck>, Status> {
        let metrics = request.into_inner();
        match self.metrics_store.report(metrics) {
            Ok(accepted) => Ok(Response::new(MetricsAck { accepted })),
            Err(e) => {
                tracing::warn!(error = %e, "pod metrics rejected");
                // Fail-closed: unknown pod_id or cap reached -> reject
                Err(Status::invalid_argument(e))
            }
        }
    }
}
