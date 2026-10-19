// src/watch/status_service.rs
//! WorkloadStatusService implementation — agent status reporting (CR-4 / G-10).
//!
//! Agents push liveness/readiness here. Reports are replicated through Raft
//! (upsert keyed by pod_id) so the leader's pod controller can use them for
//! death detection.
//!
//! Agents also push high-frequency PodMetrics here (CR-CORE-9). Metrics are
//! leader-local, TTL'd, and capped — they are NOT replicated through Raft.
//!
//! CORE-WI-6 (Ruling I): agents push a node-level heartbeat via
//! `ReportNodeStatus`. Liveness is NOT inferred from `ReportWorkloadStatus` —
//! zero-pod nodes would otherwise go silent and be evicted by the lease check.
use crate::raft::FleetosRaftConfig;
use crate::raft::records::NodeStatus;
use crate::tls::PeerConnectInfo;
use crate::watch::metrics_store::MetricsStore;
use fleetos_core::proto::state::{
    MetricsAck, NodeStatusReport, PodMetrics, StatusAck, WorkloadStatusReport,
    WorkloadStatusService,
};
use fleetos_core::spiffe::SpiffeId;
use openraft::Raft;
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub struct WorkloadStatusServiceImpl {
    raft: Arc<Raft<FleetosRaftConfig>>,
    metrics_store: Arc<MetricsStore>,
    /// Nodes keyspace for heartbeat validation (CORE-WI-6).
    nodes: fjall::Keyspace,
}

impl WorkloadStatusServiceImpl {
    pub fn new(
        raft: Arc<Raft<FleetosRaftConfig>>,
        metrics_store: Arc<MetricsStore>,
        nodes: fjall::Keyspace,
    ) -> Self {
        Self {
            raft,
            metrics_store,
            nodes,
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
                Err(Status::invalid_argument(e))
            }
        }
    }

    /// CORE-WI-6 (Ruling I): node-level liveness heartbeat.
    ///
    /// Fail-closed authz chain:
    /// 1. Unauthenticated → UNAUTHENTICATED
    /// 2. caller ≠ node_svid → PERMISSION_DENIED (never trust the claimed field)
    /// 3. Unknown node → NOT_FOUND
    /// 4. Evicted node → PERMISSION_DENIED
    ///
    /// The leader stamps `last_heartbeat` with its own receipt clock before
    /// proposing. The agent's `observed_at_unix` is diagnostic only — never
    /// used for lease math (anti-postdating rule).
    async fn report_node_status(
        &self,
        request: Request<NodeStatusReport>,
    ) -> Result<Response<StatusAck>, Status> {
        // CRITICAL: extract peer identity BEFORE into_inner() consumes the Request.
        let caller = request
            .extensions()
            .get::<PeerConnectInfo>()
            .and_then(|info| info.spiffe_id.clone())
            .ok_or_else(|| Status::unauthenticated("no authenticated peer identity"))?;

        let req = request.into_inner();

        // 1. Validate node_svid is a well-formed SPIFFE ID.
        if req.node_svid.is_empty() {
            return Err(Status::invalid_argument("node_svid cannot be empty"));
        }
        let node_spiffe: SpiffeId = req
            .node_svid
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid node_svid: {}", e)))?;

        // 2. Cross-check: authenticated identity MUST equal node_svid.
        if caller != node_spiffe {
            return Err(Status::permission_denied(
                "caller identity does not match node_svid",
            ));
        }

        // 3. Verify the node is registered and not evicted.
        let record_bytes = self
            .nodes
            .get(req.node_svid.as_bytes())
            .map_err(|e| Status::internal(format!("node lookup failed: {}", e)))?
            .ok_or_else(|| {
                Status::not_found(format!("node '{}' is not registered", req.node_svid))
            })?;
        let record: crate::raft::records::NodeRecord = postcard::from_bytes(&record_bytes)
            .map_err(|e| Status::internal(format!("corrupt node record: {}", e)))?;
        if record.status == NodeStatus::Evicted {
            return Err(Status::permission_denied(
                "node has been evicted; re-register to rejoin",
            ));
        }

        // 4. Stamp the receipt timestamp (leader's clock, not the agent's).
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        // 5. Propose via Raft.
        self.raft
            .client_write(crate::raft::AuditedCommand::system(
                crate::raft::FleetosCommand::NodeHeartbeat {
                    node_id: req.node_svid.clone(),
                    last_heartbeat: now,
                },
            ))
            .await
            .map_err(|e| Status::internal(format!("heartbeat proposal failed: {}", e)))?;

        tracing::debug!(
            node_id = %req.node_svid,
            agent_observed_at = req.observed_at_unix,
            "node heartbeat recorded"
        );
        Ok(Response::new(StatusAck { accepted: true }))
    }
}
