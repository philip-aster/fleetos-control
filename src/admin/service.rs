//! AdminService gRPC implementation.
//!
//! This is the *only* API surface for `fleetctl-proxy`.
//! All methods require `ctrl`-kind SVID authorization.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use fleetos_core::proto::admin::AdminService;
use fleetos_core::proto::admin::ClusterStatus;
use fleetos_core::proto::admin::{
    CreateTenantRequest, CreateTenantResponse, GenerateJoinTokenRequest, GenerateJoinTokenResponse,
    GetClusterStatusRequest, ListNodesRequest, ListNodesResponse, WorkloadSpecAck,
};
use fleetos_core::proto::workload::{CronWorkload, WorkloadSpec};

use super::authz;
use crate::attestation::join_token::{JoinTokenStore, NodeKind};
use crate::controllers::cron_controller::CronController;
use crate::controllers::workload_controller::WorkloadController;
use crate::dummy_ip::allocator::DummyIpAllocator;
use crate::storage::StorageEngine;

/// The AdminService gRPC implementation.
pub struct AdminServiceImpl {
    #[allow(dead_code)]
    storage: Arc<StorageEngine>,
    join_token_store: Arc<JoinTokenStore>,
    dummy_ip_allocator: Arc<DummyIpAllocator>,
    workload_controller: Arc<WorkloadController>,
    #[allow(dead_code)]
    cron_controller: Arc<CronController>,
}

impl AdminServiceImpl {
    pub fn new(
        storage: Arc<StorageEngine>,
        join_token_store: Arc<JoinTokenStore>,
        dummy_ip_allocator: Arc<DummyIpAllocator>,
        workload_controller: Arc<WorkloadController>,
        cron_controller: Arc<CronController>,
    ) -> Self {
        Self {
            storage,
            join_token_store,
            dummy_ip_allocator,
            workload_controller,
            cron_controller,
        }
    }

    /// Verify the caller is authorized (ctrl-kind SVID).
    ///
    /// This is defense-in-depth — the primary enforcement is at the mTLS layer
    /// (Admin trust bundle validation). But we check here too.
    fn verify_caller<T>(&self, request: &Request<T>) -> Result<(), Status> {
        // Extract the caller's SpiffeId from the mTLS peer certificate.
        // The TLS layer attaches it to the request extensions.
        let caller_svid = request
            .extensions()
            .get::<fleetos_core::spiffe::SpiffeId>()
            .ok_or_else(|| Status::unauthenticated("no peer certificate found"))?;

        authz::verify_admin_caller(caller_svid)
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

        // TODO: Check if tenant already exists in storage.
        // let existing = self.storage.get_tenant(&tenant_id)?;
        // if existing.is_some() {
        //     return Err(Status::already_exists(format!(
        //         "tenant '{}' already exists", tenant_id
        //     )));
        // }

        // Allocate a dummy IP block for this tenant.
        // Default /16 block (65,536 addresses, up to 4,096 tenants).
        self.dummy_ip_allocator
            .allocate_tenant_block(&tenant_id)
            .map_err(|e| Status::internal(format!("failed to allocate dummy IP block: {}", e)))?;

        // TODO: Store the tenant record in storage.
        // self.storage.store_tenant(&tenant_id)?;

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
    /// v1: Returns node SVIDs only. Detailed status is a fast-follow.
    async fn list_nodes(
        &self,
        request: Request<ListNodesRequest>,
    ) -> Result<Response<ListNodesResponse>, Status> {
        self.verify_caller(&request)?;

        // TODO: Query the node registry from storage.
        // let nodes = self.storage.list_nodes()?;
        // let node_svids = nodes.iter().map(|n| n.svid.to_string()).collect();

        // Placeholder: return empty list until storage query is wired.
        let node_svids: Vec<String> = Vec::new();

        Ok(Response::new(ListNodesResponse { node_svids }))
    }

    /// Get overall cluster health and capacity.
    async fn get_cluster_status(
        &self,
        request: Request<GetClusterStatusRequest>,
    ) -> Result<Response<ClusterStatus>, Status> {
        self.verify_caller(&request)?;

        // TODO: Query Raft state for current term and healthy node count.
        // let raft_term = self.raft.current_term()?;
        // let healthy_nodes = self.storage.count_healthy_nodes()?;

        // Placeholder values until Raft state query is wired.
        let status = ClusterStatus {
            raft_term: 0,
            healthy_nodes: 0,
        };

        Ok(Response::new(status))
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

        // TODO: Store the CronWorkload in storage.
        // self.storage.store_cron_workload(&cron)?;

        // TODO: Notify the cron controller to re-evaluate schedules.
        // The cron controller's run_loop will pick up the new CronWorkload
        // on its next evaluation cycle.

        tracing::info!(
            tenant_id = %cron.tenant_id,
            cron_workload_id = %cron.cron_workload_id,
            "cron workload submitted"
        );

        Ok(Response::new(fleetos_core::proto::admin::CronWorkloadAck {
            accepted: true,
        }))
    }
}
