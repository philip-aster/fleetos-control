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
use crate::controllers::workload_controller::WorkloadController;
use crate::dummy_ip::allocator::DummyIpAllocator;
use crate::storage::StorageEngine;

/// The AdminService gRPC implementation.
pub struct AdminServiceImpl {
    storage: Arc<StorageEngine>,
    join_token_store: Arc<JoinTokenStore>,
    dummy_ip_allocator: Arc<DummyIpAllocator>,
    workload_controller: Arc<WorkloadController>,
    #[allow(dead_code)]
    cron_controller: Arc<CronController>,
    raft: Arc<openraft::Raft<FleetosRaftConfig>>,
}

impl AdminServiceImpl {
    pub fn new(
        storage: Arc<StorageEngine>,
        join_token_store: Arc<JoinTokenStore>,
        dummy_ip_allocator: Arc<DummyIpAllocator>,
        workload_controller: Arc<WorkloadController>,
        cron_controller: Arc<CronController>,
        raft: Arc<openraft::Raft<FleetosRaftConfig>>,
    ) -> Self {
        Self {
            storage,
            join_token_store,
            dummy_ip_allocator,
            workload_controller,
            cron_controller,
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
    /// Create a new tenant namespace.
    ///
    /// This allocates a dummy IP block for the tenant from the 240.0.0.0/4 space.
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

        // Check if tenant already exists.
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

        // Allocate a dummy IP block for this tenant.
        self.dummy_ip_allocator
            .allocate_tenant_block(&tenant_id)
            .map_err(|e| Status::internal(format!("failed to allocate dummy IP block: {}", e)))?;

        // Persist the tenant record.
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let record = crate::raft::records::TenantRecord {
            tenant_id: tenant_id.clone(),
            created_at: now,
        };
        self.storage
            .store_tenant(&record)
            .map_err(|e| Status::internal(format!("failed to store tenant: {}", e)))?;

        tracing::info!(tenant_id = %tenant_id, "tenant created");
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

        // Validate the WorkloadSpec.
        if spec.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id cannot be empty"));
        }
        if spec.workload_id.is_empty() {
            return Err(Status::invalid_argument("workload_id cannot be empty"));
        }
        if spec.image.is_empty() {
            return Err(Status::invalid_argument("image cannot be empty"));
        }
        if spec.replicas.is_empty() {
            return Err(Status::invalid_argument("replicas map cannot be empty"));
        }

        // Trigger the workload controller to expand and schedule.
        self.workload_controller
            .reconcile(&spec)
            .await
            .map_err(|e| Status::internal(format!("workload reconciliation failed: {}", e)))?;

        tracing::info!(
            tenant_id = %spec.tenant_id,
            workload_id = %spec.workload_id,
            "workload spec submitted"
        );

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

        // Parse the node kind from the request string.
        let node_kind = match req.node_kind.as_str() {
            "agent" => NodeKind::Agent,
            "router" => NodeKind::Router,
            "gateway" => NodeKind::Gateway,
            "control" => NodeKind::Control,
            "fleetctl_proxy" => NodeKind::FleetctlProxy,
            other => {
                return Err(Status::invalid_argument(format!(
                    "invalid node_kind '{}': expected agent, router, gateway, control, or fleetctl_proxy",
                    other
                )));
            }
        };

        // Generate a cryptographically random join token.
        let token = self
            .join_token_store
            .generate(node_kind)
            .map_err(|e| Status::internal(format!("failed to generate join token: {}", e)))?;

        tracing::info!(
            node_kind = %req.node_kind,
            "join token generated"
        );

        Ok(Response::new(GenerateJoinTokenResponse { token }))
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

        // Validate the CronWorkload.
        if cron.tenant_id.is_empty() {
            return Err(Status::invalid_argument("tenant_id cannot be empty"));
        }
        if cron.cron_workload_id.is_empty() {
            return Err(Status::invalid_argument("cron_workload_id cannot be empty"));
        }

        // Validate the cron expression.
        if let Some(schedule) = &cron.schedule {
            CronController::validate_expression(&schedule.expression)
                .map_err(|e| Status::invalid_argument(format!("invalid cron expression: {}", e)))?;
        } else {
            return Err(Status::invalid_argument("schedule cannot be empty"));
        }

        // Validate the workload template.
        if cron.workload_template.is_none() {
            return Err(Status::invalid_argument(
                "workload_template cannot be empty",
            ));
        }

        // Persist the CronWorkload to storage with cron: prefix.
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
        let serialized = postcard::to_allocvec(&record)
            .map_err(|e| Status::internal(format!("serialization failed: {}", e)))?;
        let key = format!("cron:{}:{}", record.tenant_id, record.cron_workload_id);
        self.storage
            .workloads
            .insert(key.as_bytes(), serialized.as_slice())
            .map_err(|e| Status::internal(format!("storage write failed: {}", e)))?;

        tracing::info!(
            tenant_id = %cron.tenant_id,
            cron_workload_id = %cron.cron_workload_id,
            "cron workload submitted"
        );

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
