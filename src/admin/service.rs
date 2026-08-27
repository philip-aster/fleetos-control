//! AdminService gRPC implementation.
//!
//! This is the *only* API surface for `fleetctl-proxy`.
//! All methods require `ctrl`-kind SVID authorization.

use std::sync::Arc;

use crate::raft::FleetosRaftConfig;
use fleetos_core::proto::admin::AdminService;
use fleetos_core::proto::admin::ClusterStatus;
use fleetos_core::proto::admin::{
    CreateTenantRequest, CreateTenantResponse, DelegatedKeyRequest, DelegatedKeyResponse,
    DeleteSagRuleRequest, DeleteWorkloadRequest, GenerateJoinTokenRequest,
    GenerateJoinTokenResponse, GetClusterStatusRequest, ListNodesRequest, ListNodesResponse,
    NodeAck, NodeId, QuotaAck, QuotaRequest, QuotaResponse, SagRuleAck, ScaleWorkloadRequest,
    SecretAck, SecretAclChange, StoreSecretRequest, UpsertSagRuleRequest, WorkloadSpecAck,
};
use fleetos_core::proto::workload::{CronWorkload, WorkloadSpec};
use tonic::{Request, Response, Status};

use super::authz;
use crate::attestation::join_token::{JoinTokenStore, NodeKind};
use crate::controllers::cron_controller::CronController;
use crate::dummy_ip::allocator::DummyIpAllocator;
use crate::storage::StorageEngine;

/// The AdminService gRPC implementation.
pub struct AdminServiceImpl {
    storage: Arc<StorageEngine>,
    join_token_store: Arc<JoinTokenStore>,
    dummy_ip_allocator: Arc<DummyIpAllocator>,
    raft: Arc<openraft::Raft<FleetosRaftConfig>>,
}

impl AdminServiceImpl {
    pub fn new(
        storage: Arc<StorageEngine>,
        join_token_store: Arc<JoinTokenStore>,
        dummy_ip_allocator: Arc<DummyIpAllocator>,
        raft: Arc<openraft::Raft<FleetosRaftConfig>>,
    ) -> Self {
        Self {
            storage,
            join_token_store,
            dummy_ip_allocator,
            raft,
        }
    }

    /// Verify the caller is authorized (ctrl-kind SVID).
    ///
    /// This is defense-in-depth — the primary enforcement is at the mTLS layer
    /// (Admin trust bundle validation). But we check here too.
    fn verify_caller<T>(&self, request: &Request<T>) -> Result<(), Status> {
        // Extract the caller's SpiffeId from the connection info.
        // Tonic automatically makes `ConnectInfo` available in request extensions
        // when the stream implements `Connected`.
        let connect_info = request
            .extensions()
            .get::<crate::tls::PeerConnectInfo>()
            .ok_or_else(|| Status::unauthenticated("no peer certificate found"))?;
        let spiffe_id = connect_info
            .spiffe_id
            .as_ref()
            .ok_or_else(|| Status::unauthenticated("no peer certificate found"))?;

        authz::verify_admin_caller(spiffe_id)
            .map_err(|_| Status::permission_denied("caller SVID kind is not ctrl"))?;

        Ok(())
    }
}

#[tonic::async_trait]
impl AdminService for AdminServiceImpl {
    async fn create_tenant(
        &self,
        request: Request<CreateTenantRequest>,
    ) -> Result<Response<CreateTenantResponse>, Status> {
        self.verify_caller(&request)?;
        let req = request.into_inner();
        let tenant_id = req.tenant_id;
        if tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id cannot be empty"));
        }

        // Idempotency guard: check local state before proposing.
        let existing = self
            .storage
            .get_tenant(&tenant_id)
            .map_err(|e| Status::internal(format!("storage read failed: {}", e)))?;
        if existing.is_some() {
            return Err(Status::already_exists(format!(
                "tenant '{}' already exists",
                tenant_id
            )));
        }

        // Compute the dummy IP block allocation (read-only).
        let block = self
            .dummy_ip_allocator
            .compute_tenant_block_allocation(&tenant_id)
            .map_err(|e| Status::internal(format!("failed to allocate dummy IP block: {}", e)))?;

        // Propose AllocateTenantBlock
        self.raft
            .client_write(crate::raft::FleetosCommand::AllocateTenantBlock { record: block })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        // Propose CreateTenant
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let record = crate::raft::records::TenantRecord {
            tenant_id: tenant_id.clone(),
            created_at: now,
        };
        self.raft
            .client_write(crate::raft::FleetosCommand::CreateTenant { record })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(tenant_id = %tenant_id, "tenant created via raft");
        Ok(Response::new(CreateTenantResponse { success: true }))
    }

    /// Submit a workload definition.
    ///
    /// This triggers the workload controller to expand the WorkloadSpec
    /// into concrete PodSpecs per role/ordinal.
    ///
    /// CRITICAL: The six trusted fields (tenant_id, workload_id, role, image,
    /// ordinal, pod_id) are unconditionally overwritten during expansion.
    /// Caller-submitted values in the template are ignored.
    async fn submit_workload_spec(
        &self,
        request: Request<WorkloadSpec>,
    ) -> Result<Response<WorkloadSpecAck>, Status> {
        self.verify_caller(&request)?;
        let spec = request.into_inner();
        if spec.tenant_id.is_empty()
            || spec.workload_id.is_empty()
            || spec.image.is_empty()
            || spec.replicas.is_empty()
        {
            return Err(Status::invalid_argument("invalid workload spec"));
        }

        let record = crate::raft::records::WorkloadSpecRecord {
            tenant_id: spec.tenant_id.clone(),
            workload_id: spec.workload_id.clone(),
            spec_bytes: prost::Message::encode_to_vec(&spec),
        };
        self.raft
            .client_write(crate::raft::FleetosCommand::SubmitWorkloadSpec { record })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(tenant_id = %spec.tenant_id, workload_id = %spec.workload_id, "workload spec submitted via raft");
        Ok(Response::new(WorkloadSpecAck { accepted: true }))
    }

    /// List all fleetos-agent nodes and their status.
    ///
    /// Returns SPIFFE IDs of all registered nodes except evicted ones.
    async fn list_nodes(
        &self,
        request: Request<ListNodesRequest>,
    ) -> Result<Response<ListNodesResponse>, Status> {
        self.verify_caller(&request)?;

        let records = self
            .storage
            .list_node_records()
            .map_err(|e| Status::internal(format!("node registry query failed: {}", e)))?;

        let node_svids: Vec<String> = records
            .iter()
            .filter(|r| r.status != crate::raft::records::NodeStatus::Evicted)
            .map(|r| r.node_id.clone())
            .collect();

        Ok(Response::new(ListNodesResponse { node_svids }))
    }

    /// Get overall cluster health and capacity.
    ///
    /// Reports the current Raft term and the count of nodes in Active status.
    async fn get_cluster_status(
        &self,
        request: Request<GetClusterStatusRequest>,
    ) -> Result<Response<ClusterStatus>, Status> {
        self.verify_caller(&request)?;

        // Current Raft term from live metrics.
        let raft_term = self.raft.metrics().borrow().current_term;

        // Healthy = nodes in Active status (cordoned nodes are healthy but
        // not schedulable; evicted nodes are gone).
        let records = self
            .storage
            .list_node_records()
            .map_err(|e| Status::internal(format!("node registry query failed: {}", e)))?;
        let healthy_nodes = records
            .iter()
            .filter(|r| r.status == crate::raft::records::NodeStatus::Active)
            .count() as u32;

        Ok(Response::new(ClusterStatus {
            raft_term,
            healthy_nodes,
        }))
    }

    /// Mint a Join Token for bootstrapping new infrastructure.
    ///
    /// The token is cryptographically random, strictly single-use,
    /// and stored in the join_tokens keyspace.
    ///
    /// GenerateJoinToken routes to the correct trust domain root at
    /// issuance time based on requested node kind:
    /// - AGENT/ROUTER/GATEWAY → Data/Control domain
    /// - CONTROL → Data/Control domain (Raft peers are in Data/Control)
    /// - FLEETCTL_PROXY → Admin domain
    async fn generate_join_token(
        &self,
        request: Request<GenerateJoinTokenRequest>,
    ) -> Result<Response<GenerateJoinTokenResponse>, Status> {
        self.verify_caller(&request)?;
        let req = request.into_inner();
        let node_kind = match req.node_kind.as_str() {
            "agent" => NodeKind::Agent,
            "router" => NodeKind::Router,
            "gateway" => NodeKind::Gateway,
            "control" => NodeKind::Control,
            "fleetctl_proxy" => NodeKind::FleetctlProxy,
            other => {
                return Err(Status::invalid_argument(format!(
                    "invalid node_kind '{}'",
                    other
                )));
            }
        };

        let record = self
            .join_token_store
            .compute_token_record(node_kind)
            .map_err(|e| Status::internal(format!("failed to generate join token: {}", e)))?;
        let token_bytes = record.token.clone();

        self.raft
            .client_write(crate::raft::FleetosCommand::MintJoinToken { record })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(node_kind = %req.node_kind, "join token minted via raft");
        Ok(Response::new(GenerateJoinTokenResponse {
            token: token_bytes,
        }))
    }

    /// Submit a cron workload definition.
    ///
    /// This stores the CronWorkload and triggers the cron controller
    /// to evaluate its schedule.
    async fn submit_cron_workload(
        &self,
        request: Request<CronWorkload>,
    ) -> Result<Response<fleetos_core::proto::admin::CronWorkloadAck>, Status> {
        self.verify_caller(&request)?;
        let cron = request.into_inner();
        if cron.tenant_id.is_empty() || cron.cron_workload_id.is_empty() {
            return Err(Status::invalid_argument("invalid cron workload"));
        }
        if let Some(schedule) = &cron.schedule {
            CronController::validate_expression(&schedule.expression)
                .map_err(|e| Status::invalid_argument(format!("invalid cron expression: {}", e)))?;
        } else {
            return Err(Status::invalid_argument("schedule cannot be empty"));
        }
        if cron.workload_template.is_none() {
            return Err(Status::invalid_argument(
                "workload_template cannot be empty",
            ));
        }

        let spec_bytes = prost::Message::encode_to_vec(&cron);
        let record = crate::raft::records::CronWorkloadRecord {
            tenant_id: cron.tenant_id.clone(),
            cron_workload_id: cron.cron_workload_id.clone(),
            schedule_expression: cron
                .schedule
                .as_ref()
                .map(|s| s.expression.clone())
                .unwrap_or_default(),
            spec_bytes,
        };
        self.raft
            .client_write(crate::raft::FleetosCommand::SubmitCronWorkload { record })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(tenant_id = %cron.tenant_id, cron_workload_id = %cron.cron_workload_id, "cron workload submitted via raft");
        Ok(Response::new(fleetos_core::proto::admin::CronWorkloadAck {
            accepted: true,
        }))
    }

    // --- v0.1.5-rc.1 AdminService surface (stubs pending Step 16/20) ---

    async fn upsert_sag_rule(
        &self,
        request: Request<UpsertSagRuleRequest>,
    ) -> Result<Response<SagRuleAck>, Status> {
        self.verify_caller(&request)?;
        Err(Status::unimplemented("scheduled for Step 16/20"))
    }

    async fn delete_sag_rule(
        &self,
        request: Request<DeleteSagRuleRequest>,
    ) -> Result<Response<SagRuleAck>, Status> {
        self.verify_caller(&request)?;
        Err(Status::unimplemented("scheduled for Step 16/20"))
    }

    async fn store_secret(
        &self,
        request: Request<StoreSecretRequest>,
    ) -> Result<Response<SecretAck>, Status> {
        self.verify_caller(&request)?;
        Err(Status::unimplemented("scheduled for Step 16/20"))
    }

    async fn grant_secret_access(
        &self,
        request: Request<SecretAclChange>,
    ) -> Result<Response<SecretAck>, Status> {
        self.verify_caller(&request)?;
        Err(Status::unimplemented("scheduled for Step 16/20"))
    }

    async fn revoke_secret_access(
        &self,
        request: Request<SecretAclChange>,
    ) -> Result<Response<SecretAck>, Status> {
        self.verify_caller(&request)?;
        Err(Status::unimplemented("scheduled for Step 16/20"))
    }

    async fn request_delegated_key(
        &self,
        request: Request<DelegatedKeyRequest>,
    ) -> Result<Response<DelegatedKeyResponse>, Status> {
        self.verify_caller(&request)?;
        Err(Status::unimplemented("scheduled for Step 20"))
    }

    async fn delete_workload(
        &self,
        request: Request<DeleteWorkloadRequest>,
    ) -> Result<Response<WorkloadSpecAck>, Status> {
        self.verify_caller(&request)?;
        Err(Status::unimplemented("scheduled for Step 16"))
    }

    async fn scale_workload(
        &self,
        request: Request<ScaleWorkloadRequest>,
    ) -> Result<Response<WorkloadSpecAck>, Status> {
        self.verify_caller(&request)?;
        Err(Status::unimplemented("scheduled for Step 16"))
    }

    async fn cordon_node(&self, request: Request<NodeId>) -> Result<Response<NodeAck>, Status> {
        self.verify_caller(&request)?;
        Err(Status::unimplemented("scheduled for Step 16"))
    }

    async fn evict_node(&self, request: Request<NodeId>) -> Result<Response<NodeAck>, Status> {
        self.verify_caller(&request)?;
        Err(Status::unimplemented("scheduled for Step 16"))
    }

    async fn set_quota(
        &self,
        request: Request<QuotaRequest>,
    ) -> Result<Response<QuotaAck>, Status> {
        self.verify_caller(&request)?;
        Err(Status::unimplemented("scheduled for Step 16"))
    }

    async fn get_quota(
        &self,
        request: Request<QuotaRequest>,
    ) -> Result<Response<QuotaResponse>, Status> {
        self.verify_caller(&request)?;
        Err(Status::unimplemented("scheduled for Step 16"))
    }
}
