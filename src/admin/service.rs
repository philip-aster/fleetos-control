//! AdminService gRPC implementation.
//!
//! This is the *only* API surface for `fleetctl-proxy`.
//! All methods require `ctrl`-kind SVID authorization.

use crate::attestation::join_token::{JoinTokenStore, NodeKind};
use crate::controllers::cron_controller::CronController;
use crate::dummy_ip::allocator::DummyIpAllocator;
use crate::raft::FleetosRaftConfig;
use crate::storage::StorageEngine;
use fleetos_core::proto::admin::{
    AdminService, ClusterStatus, CreateTenantRequest, CreateTenantResponse, DelegatedKeyRequest,
    DelegatedKeyResponse, DeleteSagRuleRequest, DeleteWorkloadRequest, GenerateJoinTokenRequest,
    GenerateJoinTokenResponse, GetClusterStatusRequest, ListNodePoolsRequest,
    ListNodePoolsResponse, ListNodesRequest, ListNodesResponse, NodeAck, NodeId, NodePoolAck,
    NodePoolCreateRequest, NodePoolDeleteRequest, NodePoolInfo, QuotaAck, QuotaRequest,
    QuotaResponse, RegisterNodeEkRequest, RegisterNodeEkResponse, RevokeNodeEkRequest, SagRuleAck,
    ScaleWorkloadRequest, SecretAck, SecretAclChange, StoreSecretRequest, UpsertSagRuleRequest,
    WorkloadSpecAck,
};
use fleetos_core::proto::workload::{CronWorkload, WorkloadSpec};
use fleetos_core::spiffe::SpiffeId;
use rand::Rng;
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// The AdminService gRPC implementation.
pub struct AdminServiceImpl {
    storage: Arc<StorageEngine>,
    join_token_store: Arc<JoinTokenStore>,
    dummy_ip_allocator: Arc<DummyIpAllocator>,
    raft: Arc<openraft::Raft<FleetosRaftConfig>>,
    operators_config: crate::config::OperatorsConfig,
    node_ttl_secs: u64,
    secret_store: Arc<crate::secrets::SecretStore>,
    ca_data_control: Option<Arc<parking_lot::RwLock<crate::ca::trust_bundle::TrustBundle>>>,
    delegated_key_ttl_secs: u64,
    node_eks: fjall::Keyspace,
}

/// Admission hardening (G-12): identifiers must be DNS-label-shaped so they
/// remain safe as SPIFFE path segments, storage key prefixes, and dummy-IP
/// tenant keys. Rejects empty, oversized, and non-[a-z0-9-] values.
fn validate_identifier(value: &str, field: &str) -> Result<(), Status> {
    if value.is_empty() || value.len() > 63 {
        return Err(Status::invalid_argument(format!(
            "{} must be 1-63 characters",
            field
        )));
    }
    let valid = value
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !value.starts_with('-')
        && !value.ends_with('-');
    if !valid {
        return Err(Status::invalid_argument(format!(
            "{} must match [a-z0-9-] and not start/end with '-'",
            field
        )));
    }
    Ok(())
}

const MAX_REPLICAS_PER_ROLE: u32 = 1024;
const MAX_ROLES_PER_WORKLOAD: usize = 16;
const MAX_SPEC_BYTES: usize = 1024 * 1024;

impl AdminServiceImpl {
    pub fn new(
        storage: Arc<StorageEngine>,
        join_token_store: Arc<JoinTokenStore>,
        dummy_ip_allocator: Arc<DummyIpAllocator>,
        raft: Arc<openraft::Raft<FleetosRaftConfig>>,
        operators_config: crate::config::OperatorsConfig,
        node_ttl_secs: u64,
        secret_store: Arc<crate::secrets::SecretStore>,
        ca_data_control: Option<Arc<parking_lot::RwLock<crate::ca::trust_bundle::TrustBundle>>>,
        delegated_key_ttl_secs: u64,
        node_eks: fjall::Keyspace,
    ) -> Self {
        Self {
            storage,
            join_token_store,
            dummy_ip_allocator,
            raft,
            operators_config,
            node_ttl_secs,
            secret_store,
            ca_data_control,
            delegated_key_ttl_secs,
            node_eks,
        }
    }

    /// Verify the caller is authorized (ctrl or operator SVID).
    ///
    /// This is defense-in-depth — the primary enforcement is at the mTLS layer
    /// (Admin trust bundle validation). But we check here too.
    fn verify_caller<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let connect_info = request
            .extensions()
            .get::<crate::tls::PeerConnectInfo>()
            .ok_or_else(|| Status::unauthenticated("no peer certificate found"))?;
        let spiffe_id = connect_info
            .spiffe_id
            .as_ref()
            .ok_or_else(|| Status::unauthenticated("no peer certificate found"))?;

        match spiffe_id.kind {
            fleetos_core::spiffe::IdKind::Ctrl => Ok(()),
            fleetos_core::spiffe::IdKind::Operator => Ok(()),
            _ => Err(Status::permission_denied(
                "caller SVID kind is not ctrl or operator",
            )),
        }
    }

    /// G-3: generate a unique request ID for correlation.
    fn generate_request_id() -> String {
        let mut bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut bytes);
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Build the audit context for an admin request (G-2 / G-3).
    /// Must be called BEFORE `request.into_inner()` consumes the Request.
    fn build_audit_context<T>(
        &self,
        request: &Request<T>,
        target: &str,
    ) -> crate::raft::records::AuditContext {
        let actor = request
            .extensions()
            .get::<crate::tls::PeerConnectInfo>()
            .and_then(|ci| ci.spiffe_id.as_ref())
            .map(|id| id.to_string())
            .unwrap_or_else(|| "unknown".to_owned());
        crate::raft::records::AuditContext {
            request_id: Self::generate_request_id(),
            actor,
            target: target.to_owned(),
            timestamp_unix: time::OffsetDateTime::now_utc().unix_timestamp() as u64,
        }
    }

    /// Extract the caller's SPIFFE ID string from request extensions.
    fn caller_spiffe_id<T>(&self, request: &Request<T>) -> Result<String, Status> {
        let connect_info = request
            .extensions()
            .get::<crate::tls::PeerConnectInfo>()
            .ok_or_else(|| Status::unauthenticated("no peer certificate found"))?;
        let spiffe_id = connect_info
            .spiffe_id
            .as_ref()
            .ok_or_else(|| Status::unauthenticated("no peer certificate found"))?;
        Ok(spiffe_id.to_string())
    }

    /// CR-8 middleware: require cluster_admin scope.
    ///
    /// Ctrl-kind callers (fleetctl-proxy) have full access. Operator-kind
    /// callers must be a config-seeded bootstrap admin or hold an active,
    /// unexpired grant with cluster_admin=true.
    fn require_cluster_admin<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let caller = self.caller_spiffe_id(request)?;
        let connect_info = request
            .extensions()
            .get::<crate::tls::PeerConnectInfo>()
            .ok_or_else(|| Status::unauthenticated("no peer certificate found"))?;
        let kind = connect_info
            .spiffe_id
            .as_ref()
            .map(|s| s.kind)
            .ok_or_else(|| Status::unauthenticated("no peer certificate found"))?;

        if kind == fleetos_core::spiffe::IdKind::Ctrl {
            return Ok(());
        }
        if kind == fleetos_core::spiffe::IdKind::Operator {
            if self.operators_config.bootstrap_admins.contains(&caller) {
                return Ok(());
            }
            let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
            if self.has_active_grant(&caller, now, |g| g.cluster_admin)? {
                return Ok(());
            }
        }
        Err(Status::permission_denied("cluster_admin scope required"))
    }

    /// Scan all active (unexpired) grants for an operator.
    fn active_grants_for_operator(
        &self,
        operator_id: &str,
        now: u64,
    ) -> Result<Vec<crate::raft::records::OperatorAccessGrantRecord>, Status> {
        let mut grants = Vec::new();
        for guard in self.storage.operator_grants.prefix(Vec::<u8>::new()) {
            let value = guard
                .value()
                .map_err(|e| Status::internal(format!("storage error: {}", e)))?;
            if let Ok(record) = postcard::from_bytes::<
                crate::raft::records::OperatorAccessGrantRecord,
            >(value.as_ref())
            {
                if record.operator_id == operator_id && record.expires_at_unix > now {
                    grants.push(record);
                }
            }
        }
        Ok(grants)
    }

    /// Returns true if the caller is ctrl-kind (fleetctl-proxy), which has full access.
    fn caller_is_ctrl<T>(&self, request: &Request<T>) -> Result<bool, Status> {
        let connect_info = request
            .extensions()
            .get::<crate::tls::PeerConnectInfo>()
            .ok_or_else(|| Status::unauthenticated("no peer certificate found"))?;
        let kind = connect_info
            .spiffe_id
            .as_ref()
            .map(|s| s.kind)
            .ok_or_else(|| Status::unauthenticated("no peer certificate found"))?;
        Ok(kind == fleetos_core::spiffe::IdKind::Ctrl)
    }

    /// CR-8 middleware: require read access.
    ///
    /// Ctrl-kind callers have full access. Operator-kind callers need at least
    /// one active grant; read-only grants are sufficient for reads.
    fn require_read_access<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if self.caller_is_ctrl(request)? {
            return Ok(());
        }
        let caller = self.caller_spiffe_id(request)?;
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
        let grants = self.active_grants_for_operator(&caller, now)?;
        if grants.is_empty() {
            return Err(Status::permission_denied(
                "no active operator grant for read access",
            ));
        }
        Ok(())
    }

    /// CR-8 middleware: require write access to a specific tenant.
    ///
    /// Ctrl-kind callers have full access. Operator-kind callers need an
    /// active, non-read-only grant that is either cluster_admin or lists
    /// the target tenant.
    fn require_tenant_write<T>(&self, request: &Request<T>, tenant_id: &str) -> Result<(), Status> {
        if self.caller_is_ctrl(request)? {
            return Ok(());
        }
        let caller = self.caller_spiffe_id(request)?;
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
        let grants = self.active_grants_for_operator(&caller, now)?;
        let has_write = grants
            .iter()
            .any(|g| !g.read_only && (g.cluster_admin || g.tenants.iter().any(|t| t == tenant_id)));
        if !has_write {
            return Err(Status::permission_denied(format!(
                "no active write grant for tenant '{}'",
                tenant_id
            )));
        }
        Ok(())
    }

    /// Check whether adding a workload would exceed the tenant's quota.
    ///
    /// If no quota is set, resources are unlimited (default-open).
    /// Returns `Ok(())` if the workload fits, or a `Status::resource_exhausted`
    /// error if it would exceed the quota.
    fn check_tenant_quota(
        &self,
        tenant_id: &str,
        spec: &fleetos_core::proto::workload::WorkloadSpec,
    ) -> Result<(), Status> {
        let quota = self
            .storage
            .get_tenant_quota(tenant_id)
            .map_err(|e| Status::internal(format!("quota lookup failed: {}", e)))?;

        let Some(quota) = quota else {
            // No quota set — unlimited.
            return Ok(());
        };

        let (current_cpu, current_memory, current_workloads) = self
            .storage
            .compute_tenant_usage(tenant_id)
            .map_err(|e| Status::internal(format!("usage computation failed: {}", e)))?;

        // Compute the new workload's resource footprint.
        let cpu_per_pod = spec
            .pod_spec
            .as_ref()
            .and_then(|ps| ps.resources.as_ref())
            .map(|r| r.vcpus as u64 * 1000)
            .unwrap_or(0);
        let mem_per_pod = spec
            .pod_spec
            .as_ref()
            .and_then(|ps| ps.resources.as_ref())
            .map(|r| r.memory_mb as u64 * 1024 * 1024)
            .unwrap_or(0);
        let total_replicas: u64 = spec.replicas.values().map(|&c| c as u64).sum();

        let new_cpu = current_cpu + cpu_per_pod * total_replicas;
        let new_memory = current_memory + mem_per_pod * total_replicas;
        let new_workloads = current_workloads + 1;

        if new_workloads > quota.max_workloads as u32 {
            return Err(Status::resource_exhausted(format!(
                "tenant '{}' workload quota exceeded: {} of {} allowed",
                tenant_id, new_workloads, quota.max_workloads
            )));
        }
        if new_cpu > quota.max_cpu_millicores {
            return Err(Status::resource_exhausted(format!(
                "tenant '{}' CPU quota exceeded: {} of {} millicores allowed",
                tenant_id, new_cpu, quota.max_cpu_millicores
            )));
        }
        if new_memory > quota.max_memory_bytes {
            return Err(Status::resource_exhausted(format!(
                "tenant '{}' memory quota exceeded: {} of {} bytes allowed",
                tenant_id, new_memory, quota.max_memory_bytes
            )));
        }

        Ok(())
    }

    /// CR-8 middleware: require cluster_admin scope for MUTATING operations.
    ///
    /// Like `require_cluster_admin`, but also rejects read-only grants —
    /// a read-only cluster admin may list/inspect but not mutate.
    fn require_cluster_admin_write<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if self.caller_is_ctrl(request)? {
            return Ok(());
        }
        let caller = self.caller_spiffe_id(request)?;
        if self.operators_config.bootstrap_admins.contains(&caller) {
            return Ok(());
        }
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
        let grants = self.active_grants_for_operator(&caller, now)?;
        let has_access = grants.iter().any(|g| g.cluster_admin && !g.read_only);
        if !has_access {
            return Err(Status::permission_denied(
                "cluster_admin write scope required",
            ));
        }
        Ok(())
    }

    /// Scan operator grants for an active grant matching a predicate.
    fn has_active_grant(
        &self,
        operator_id: &str,
        now: u64,
        pred: impl Fn(&crate::raft::records::OperatorAccessGrantRecord) -> bool,
    ) -> Result<bool, Status> {
        for guard in self.storage.operator_grants.prefix(Vec::<u8>::new()) {
            let value = guard
                .value()
                .map_err(|e| Status::internal(format!("storage error: {}", e)))?;
            if let Ok(record) = postcard::from_bytes::<
                crate::raft::records::OperatorAccessGrantRecord,
            >(value.as_ref())
            {
                if record.operator_id == operator_id
                    && record.expires_at_unix > now
                    && pred(&record)
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

#[tonic::async_trait]
impl AdminService for AdminServiceImpl {
    async fn create_tenant(
        &self,
        request: Request<CreateTenantRequest>,
    ) -> Result<Response<CreateTenantResponse>, Status> {
        self.verify_caller(&request)?;
        self.require_cluster_admin_write(&request)?;

        // 1. Extract target BEFORE consuming the request
        let tenant_id = request.get_ref().tenant_id.clone();
        validate_identifier(&tenant_id, "tenant_id")?;
        let audit = self.build_audit_context(&request, &tenant_id);
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

        // 2. NOW consume the request
        let _req = request.into_inner();

        let block = self
            .dummy_ip_allocator
            .compute_tenant_block_allocation(&tenant_id)
            .map_err(|e| Status::internal(format!("failed to allocate dummy IP block: {}", e)))?;

        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::AllocateTenantBlock { record: block },
                audit: Some(audit.clone()),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let record = crate::raft::records::TenantRecord {
            tenant_id: tenant_id.clone(),
            created_at: now,
        };

        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::CreateTenant { record },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(tenant_id = %tenant_id, "tenant created via raft");
        Ok(Response::new(CreateTenantResponse { success: true }))
    }

    async fn submit_workload_spec(
        &self,
        request: Request<WorkloadSpec>,
    ) -> Result<Response<WorkloadSpecAck>, Status> {
        self.verify_caller(&request)?;

        let workload_id = request.get_ref().workload_id.clone();
        let tenant_id = request.get_ref().tenant_id.clone();
        self.require_tenant_write(&request, &tenant_id)?;
        let audit = self.build_audit_context(&request, &workload_id);
        let spec = request.into_inner();
        validate_identifier(&spec.tenant_id, "tenant_id")?;
        validate_identifier(&spec.workload_id, "workload_id")?;
        if spec.image.is_empty() {
            return Err(Status::invalid_argument("image cannot be empty"));
        }
        if spec.replicas.is_empty() {
            return Err(Status::invalid_argument("replicas map cannot be empty"));
        }
        if spec.replicas.len() > MAX_ROLES_PER_WORKLOAD {
            return Err(Status::invalid_argument(format!(
                "too many roles: max {} per workload",
                MAX_ROLES_PER_WORKLOAD
            )));
        }
        for (role, count) in &spec.replicas {
            validate_identifier(role, "role")?;
            if *count == 0 || *count > MAX_REPLICAS_PER_ROLE {
                return Err(Status::invalid_argument(format!(
                    "replica count for role '{}' must be 1-{}",
                    role, MAX_REPLICAS_PER_ROLE
                )));
            }
        }
        if prost::Message::encoded_len(&spec) > MAX_SPEC_BYTES {
            return Err(Status::invalid_argument("workload spec exceeds 1 MiB"));
        }

        // CR-7: enforce tenant quota before storing the workload.
        self.check_tenant_quota(&spec.tenant_id, &spec)?;

        let record = crate::raft::records::WorkloadSpecRecord {
            tenant_id: spec.tenant_id.clone(),
            workload_id: spec.workload_id.clone(),
            spec_bytes: prost::Message::encode_to_vec(&spec),
        };

        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::SubmitWorkloadSpec { record },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(tenant_id = %spec.tenant_id, workload_id = %spec.workload_id, "workload spec submitted via raft");
        Ok(Response::new(WorkloadSpecAck { accepted: true }))
    }

    async fn list_nodes(
        &self,
        request: Request<ListNodesRequest>,
    ) -> Result<Response<ListNodesResponse>, Status> {
        self.verify_caller(&request)?;
        self.require_read_access(&request)?;
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

    async fn get_cluster_status(
        &self,
        request: Request<GetClusterStatusRequest>,
    ) -> Result<Response<ClusterStatus>, Status> {
        self.verify_caller(&request)?;
        self.require_read_access(&request)?;
        let raft_term = self.raft.metrics().borrow().current_term;
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

    async fn generate_join_token(
        &self,
        request: Request<GenerateJoinTokenRequest>,
    ) -> Result<Response<GenerateJoinTokenResponse>, Status> {
        self.verify_caller(&request)?;
        self.require_cluster_admin_write(&request)?;

        let node_kind_str = request.get_ref().node_kind.clone();
        let audit = self.build_audit_context(&request, &node_kind_str);
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
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::MintJoinToken { record },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(node_kind = %req.node_kind, "join token minted via raft");
        Ok(Response::new(GenerateJoinTokenResponse {
            token: token_bytes,
        }))
    }

    async fn submit_cron_workload(
        &self,
        request: Request<CronWorkload>,
    ) -> Result<Response<fleetos_core::proto::admin::CronWorkloadAck>, Status> {
        self.verify_caller(&request)?;
        let cron_id = request.get_ref().cron_workload_id.clone();
        let tenant_id = request.get_ref().tenant_id.clone();
        self.require_tenant_write(&request, &tenant_id)?;
        let audit = self.build_audit_context(&request, &cron_id);
        let cron = request.into_inner();
        validate_identifier(&cron.tenant_id, "tenant_id")?;
        validate_identifier(&cron.cron_workload_id, "cron_workload_id")?;
        if let Some(schedule) = &cron.schedule {
            CronController::validate_expression(&schedule.expression)
                .map_err(|e| Status::invalid_argument(format!("invalid cron expression: {}", e)))?;
        } else {
            return Err(Status::invalid_argument("schedule cannot be empty"));
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
        // G-11: initial checkpoint at submission time so the cron controller
        // has a baseline and does not backfill from the epoch.
        let checkpoint = crate::raft::records::CronCheckpointRecord {
            tenant_id: cron.tenant_id.clone(),
            cron_workload_id: cron.cron_workload_id.clone(),
            last_triggered_at_unix: time::OffsetDateTime::now_utc().unix_timestamp(),
        };
        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::SubmitCronWorkload { record, checkpoint },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(tenant_id = %cron.tenant_id, cron_workload_id = %cron.cron_workload_id, "cron workload submitted via raft");
        Ok(Response::new(fleetos_core::proto::admin::CronWorkloadAck {
            accepted: true,
        }))
    }

    // --- v0.1.5-rc.1 AdminService surface (stubs pending Step 16/20) ---
    // (Keep your existing stubs exactly as they are)

    async fn upsert_sag_rule(
        &self,
        request: Request<UpsertSagRuleRequest>,
    ) -> Result<Response<SagRuleAck>, Status> {
        self.verify_caller(&request)?;
        self.require_cluster_admin_write(&request)?;

        // Extract the rule before consuming the request.
        let rule = request
            .get_ref()
            .rule
            .clone()
            .ok_or_else(|| Status::invalid_argument("rule is required"))?;

        let from = rule
            .from
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("rule.from is required"))?;
        let to = rule
            .to
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("rule.to is required"))?;

        // Cross-tenant rules are prohibited by the TenantCtx contract.
        if from.tenant != to.tenant {
            return Err(Status::invalid_argument(
                "from.tenant and to.tenant must match (cross-tenant rules are prohibited)",
            ));
        }

        // Validate identifiers.
        validate_identifier(&from.tenant, "from.tenant")?;
        validate_identifier(&from.service_name, "from.service_name")?;
        validate_identifier(&to.service_name, "to.service_name")?;

        // Validate ports (reject > 65535, don't truncate).
        let from_port = crate::policy::port_validation::validate_optional_port(from.port)
            .map_err(|e| Status::invalid_argument(format!("invalid from.port: {}", e)))?;
        let to_port = crate::policy::port_validation::validate_optional_port(to.port)
            .map_err(|e| Status::invalid_argument(format!("invalid to.port: {}", e)))?;

        // Parse roles (empty string = wildcard).
        let from_role = if from.role.is_empty() {
            None
        } else {
            Some(
                fleetos_core::spiffe::WorkloadRole::try_from(from.role.as_str())
                    .map_err(|e| Status::invalid_argument(format!("invalid from.role: {}", e)))?,
            )
        };
        let to_role = if to.role.is_empty() {
            None
        } else {
            Some(
                fleetos_core::spiffe::WorkloadRole::try_from(to.role.as_str())
                    .map_err(|e| Status::invalid_argument(format!("invalid to.role: {}", e)))?,
            )
        };

        // Compute the canonical rule_id from rule content.
        let action_str = match rule.action {
            0 => "ALLOW",
            1 => "DENY",
            other => {
                return Err(Status::invalid_argument(format!(
                    "invalid action value: {}",
                    other
                )));
            }
        };

        let rule_id = fleetos_core::policy::SagRuleId::of_rule(
            &from.tenant,
            &from.service_name,
            from_role.as_ref(),
            from_port,
            &to.service_name,
            to_role.as_ref(),
            to_port,
            action_str,
        )
        .to_hex();

        let audit = self.build_audit_context(&request, &rule_id);
        let _req = request.into_inner();

        // Encode the proto rule for storage (decoded as proto by policy_stream).
        let rule_bytes = prost::Message::encode_to_vec(&rule);

        let record = crate::raft::records::SagRuleRecord {
            rule_id: rule_id.clone(),
            rule_bytes,
        };

        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::UpsertSagRule { record },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(rule_id = %rule_id, "SAG rule upserted via raft");
        Ok(Response::new(SagRuleAck {
            accepted: true,
            rule_id,
        }))
    }

    async fn delete_sag_rule(
        &self,
        request: Request<DeleteSagRuleRequest>,
    ) -> Result<Response<SagRuleAck>, Status> {
        self.verify_caller(&request)?;
        self.require_cluster_admin_write(&request)?;

        let rule_id = request.get_ref().rule_id.clone();
        if rule_id.is_empty() {
            return Err(Status::invalid_argument("rule_id cannot be empty"));
        }

        let audit = self.build_audit_context(&request, &rule_id);
        let _req = request.into_inner();

        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::DeleteSagRule {
                    rule_id: rule_id.clone(),
                },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(rule_id = %rule_id, "SAG rule deleted via raft");
        Ok(Response::new(SagRuleAck {
            accepted: true,
            rule_id,
        }))
    }
    async fn store_secret(
        &self,
        request: Request<StoreSecretRequest>,
    ) -> Result<Response<SecretAck>, Status> {
        self.verify_caller(&request)?;
        let tenant_id = request.get_ref().tenant_id.clone();
        let key = request.get_ref().key.clone();
        self.require_tenant_write(&request, &tenant_id)?;
        let audit = self.build_audit_context(&request, &key);
        let req = request.into_inner();

        validate_identifier(&req.tenant_id, "tenant_id")?;
        if req.key.is_empty() {
            return Err(Status::invalid_argument("key cannot be empty"));
        }
        if req.value.is_empty() {
            return Err(Status::invalid_argument("value cannot be empty"));
        }
        if req.authorized_spiffe_ids.is_empty() {
            return Err(Status::invalid_argument(
                "at least one authorized_spiffe_id is required",
            ));
        }

        let mut authorized = Vec::new();
        for s in &req.authorized_spiffe_ids {
            let spiffe: SpiffeId = s.parse().map_err(|e| {
                Status::invalid_argument(format!("invalid authorized_spiffe_id '{}': {}", s, e))
            })?;
            authorized.push(spiffe);
        }

        // Leader-side: envelope encryption + ACL construction (non-deterministic).
        let (envelope_bytes, acl_bytes) = self
            .secret_store
            .prepare_secret(&req.key, &req.value, &authorized)
            .map_err(|e| Status::internal(format!("failed to prepare secret: {}", e)))?;

        let record = crate::raft::records::SecretRecord {
            key: req.key.clone(),
            envelope_bytes,
            acl_bytes,
        };

        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::StoreSecret {
                    record,
                    target_spiffe_id: authorized[0].to_string(),
                },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(tenant_id = %req.tenant_id, key = %req.key, "secret stored via raft");
        Ok(Response::new(SecretAck { accepted: true }))
    }

    async fn grant_secret_access(
        &self,
        request: Request<SecretAclChange>,
    ) -> Result<Response<SecretAck>, Status> {
        self.verify_caller(&request)?;
        let tenant_id = request.get_ref().tenant_id.clone();
        let key = request.get_ref().key.clone();
        self.require_tenant_write(&request, &tenant_id)?;
        let audit = self.build_audit_context(&request, &key);
        let req = request.into_inner();

        validate_identifier(&req.tenant_id, "tenant_id")?;
        if req.key.is_empty() {
            return Err(Status::invalid_argument("key cannot be empty"));
        }
        let _: SpiffeId = req
            .spiffe_id
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid spiffe_id: {}", e)))?;

        // Verify the secret exists before proposing the ACL change.
        let secret_key = format!("secret:{}", req.key);
        let exists = self
            .storage
            .secrets
            .get(secret_key.as_bytes())
            .map_err(|e| Status::internal(format!("storage read failed: {}", e)))?
            .is_some();
        if !exists {
            return Err(Status::not_found(format!("secret '{}' not found", req.key)));
        }

        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::GrantSecretAccess {
                    tenant_id: req.tenant_id.clone(),
                    key: req.key.clone(),
                    spiffe_id: req.spiffe_id.clone(),
                },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(key = %req.key, spiffe_id = %req.spiffe_id, "secret access granted via raft");
        Ok(Response::new(SecretAck { accepted: true }))
    }

    async fn revoke_secret_access(
        &self,
        request: Request<SecretAclChange>,
    ) -> Result<Response<SecretAck>, Status> {
        self.verify_caller(&request)?;
        let tenant_id = request.get_ref().tenant_id.clone();
        let key = request.get_ref().key.clone();
        self.require_tenant_write(&request, &tenant_id)?;
        let audit = self.build_audit_context(&request, &key);
        let req = request.into_inner();

        validate_identifier(&req.tenant_id, "tenant_id")?;
        if req.key.is_empty() {
            return Err(Status::invalid_argument("key cannot be empty"));
        }
        let _: SpiffeId = req
            .spiffe_id
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid spiffe_id: {}", e)))?;

        let secret_key = format!("secret:{}", req.key);
        let exists = self
            .storage
            .secrets
            .get(secret_key.as_bytes())
            .map_err(|e| Status::internal(format!("storage read failed: {}", e)))?
            .is_some();
        if !exists {
            return Err(Status::not_found(format!("secret '{}' not found", req.key)));
        }

        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::RevokeSecretAccess {
                    tenant_id: req.tenant_id.clone(),
                    key: req.key.clone(),
                    spiffe_id: req.spiffe_id.clone(),
                },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(key = %req.key, spiffe_id = %req.spiffe_id, "secret access revoked via raft");
        Ok(Response::new(SecretAck { accepted: true }))
    }
    async fn request_delegated_key(
        &self,
        request: Request<DelegatedKeyRequest>,
    ) -> Result<Response<DelegatedKeyResponse>, Status> {
        self.verify_caller(&request)?;

        let req = request.get_ref();
        let node_svid_str = req.node_svid.clone();
        let target_spiffe_str = req.target_spiffe_id.clone();

        // Authorization: caller must be the node itself, or a cluster admin.
        let caller = self.caller_spiffe_id(&request)?;
        let is_self = caller == node_svid_str;
        if !is_self {
            self.require_cluster_admin(&request)?;
        }

        let node_spiffe: SpiffeId = node_svid_str
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid node_svid: {}", e)))?;
        let target_spiffe: SpiffeId = target_spiffe_str
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid target_spiffe_id: {}", e)))?;

        // Bound the TTL to the configured maximum.
        let ttl = if req.requested_ttl_secs == 0
            || req.requested_ttl_secs > self.delegated_key_ttl_secs
        {
            self.delegated_key_ttl_secs
        } else {
            req.requested_ttl_secs
        };

        let ca_bundle = self
            .ca_data_control
            .as_ref()
            .ok_or_else(|| Status::unavailable("CA not available (join mode first boot)"))?;

        let placement_verifier =
            crate::ca::key_issuance::StoragePlacementVerifier::new(self.storage.placements.clone());

        let delegation_req = crate::ca::key_issuance::DelegationRequest {
            node_id: node_spiffe.clone(),
            target_svid_id: target_spiffe.clone(),
            target_ordinal: req.target_ordinal,
            ttl_secs: ttl,
        };

        // Issue the key (enforces placement verification + pathLen=0 constraint).
        let bundle = crate::ca::key_issuance::issue_delegated_key(
            &delegation_req,
            ca_bundle,
            &placement_verifier,
        )
        .map_err(|e| Status::internal(format!("failed to issue delegated key: {}", e)))?;

        // Record the delegation in Raft so it can be revoked on node eviction.
        let now = time::OffsetDateTime::now_utc();
        let issued_at = now.unix_timestamp();
        let expires_at = issued_at + ttl as i64;
        let refresh_at = issued_at + (ttl as f64 * 0.75) as i64;

        let record = crate::delegation::DelegationRecord {
            delegation_id: bundle.delegation_id.clone(),
            node_id: node_spiffe,
            target_svid_id: target_spiffe,
            target_ordinal: req.target_ordinal,
            issued_at,
            expires_at,
            refresh_at,
        };

        let audit = self.build_audit_context(&request, &bundle.delegation_id);

        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::IssueDelegation { record },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(
            node_id = %node_svid_str,
            target = %target_spiffe_str,
            delegation_id = %bundle.delegation_id,
            "delegated key issued via raft"
        );

        Ok(Response::new(DelegatedKeyResponse {
            delegation_id: bundle.delegation_id.into_bytes(),
            key_material: bundle.key_bytes,
            expires_at_unix: expires_at as u64,
        }))
    }
    async fn delete_workload(
        &self,
        request: Request<DeleteWorkloadRequest>,
    ) -> Result<Response<WorkloadSpecAck>, Status> {
        self.verify_caller(&request)?;
        let tenant_id = request.get_ref().tenant_id.clone();
        let workload_id = request.get_ref().workload_id.clone();
        self.require_tenant_write(&request, &tenant_id)?;
        let audit = self.build_audit_context(&request, &workload_id);
        let _req = request.into_inner();

        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::DeleteWorkload {
                    tenant_id: tenant_id.clone(),
                    workload_id: workload_id.clone(),
                },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(tenant_id = %tenant_id, workload_id = %workload_id, "workload deleted via raft");
        Ok(Response::new(WorkloadSpecAck { accepted: true }))
    }
    async fn scale_workload(
        &self,
        request: Request<ScaleWorkloadRequest>,
    ) -> Result<Response<WorkloadSpecAck>, Status> {
        self.verify_caller(&request)?;
        let tenant_id = request.get_ref().tenant_id.clone();
        let workload_id = request.get_ref().workload_id.clone();
        self.require_tenant_write(&request, &tenant_id)?;
        let audit = self.build_audit_context(&request, &workload_id);
        let req = request.into_inner();

        // Load the current stored spec record.
        let record_bytes = self
            .storage
            .get_workload_spec(&tenant_id, &workload_id)
            .map_err(|e| Status::internal(format!("storage read failed: {}", e)))?
            .ok_or_else(|| {
                Status::not_found(format!(
                    "workload '{}/{}' not found",
                    tenant_id, workload_id
                ))
            })?;
        let mut record: crate::raft::records::WorkloadSpecRecord =
            postcard::from_bytes(&record_bytes).map_err(|e| {
                Status::internal(format!("failed to decode workload record: {}", e))
            })?;

        // Apply the new replica counts to the embedded WorkloadSpec.
        let mut spec: fleetos_core::proto::workload::WorkloadSpec =
            prost::Message::decode(record.spec_bytes.as_slice())
                .map_err(|e| Status::internal(format!("failed to decode workload spec: {}", e)))?;
        spec.replicas = req.replicas.clone();
        // CR-7: re-check tenant quota after scaling.
        self.check_tenant_quota(&tenant_id, &spec)?;
        record.spec_bytes = prost::Message::encode_to_vec(&spec);

        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::ScaleWorkload { record },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(tenant_id = %tenant_id, workload_id = %workload_id, "workload scaled via raft");
        Ok(Response::new(WorkloadSpecAck { accepted: true }))
    }
    async fn cordon_node(&self, request: Request<NodeId>) -> Result<Response<NodeAck>, Status> {
        self.verify_caller(&request)?;
        self.require_cluster_admin_write(&request)?;
        let node_svid = request.get_ref().node_svid.clone();
        let audit = self.build_audit_context(&request, &node_svid);
        let _req = request.into_inner();

        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::SetNodeSchedulable {
                    node_id: node_svid.clone(),
                    schedulable: false,
                },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(node_id = %node_svid, "node cordoned via admin");
        Ok(Response::new(NodeAck { accepted: true }))
    }

    async fn evict_node(&self, request: Request<NodeId>) -> Result<Response<NodeAck>, Status> {
        self.verify_caller(&request)?;
        self.require_cluster_admin_write(&request)?;
        let node_svid = request.get_ref().node_svid.clone();
        let audit = self.build_audit_context(&request, &node_svid);
        let _req = request.into_inner();

        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let svid_expires_at_unix = now + self.node_ttl_secs as i64;

        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::EvictNode {
                    node_id: node_svid.clone(),
                    svid_expires_at_unix,
                },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(node_id = %node_svid, "node evicted via admin");
        Ok(Response::new(NodeAck { accepted: true }))
    }
    async fn set_quota(
        &self,
        request: Request<QuotaRequest>,
    ) -> Result<Response<QuotaAck>, Status> {
        self.verify_caller(&request)?;
        self.require_cluster_admin_write(&request)?;

        let req = request.get_ref();
        let quota = req
            .quota
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("quota is required"))?;

        validate_identifier(&quota.tenant_id, "tenant_id")?;

        // Build audit context BEFORE consuming the request.
        let audit = self.build_audit_context(&request, &quota.tenant_id);

        // Verify the tenant exists.
        let tenant_exists = self
            .storage
            .get_tenant(&quota.tenant_id)
            .map_err(|e| Status::internal(format!("tenant lookup failed: {}", e)))?
            .is_some();
        if !tenant_exists {
            return Err(Status::not_found(format!(
                "tenant '{}' not found",
                quota.tenant_id
            )));
        }

        // NOW consume the request.
        let req = request.into_inner();
        let quota = req.quota.unwrap();

        let record = crate::raft::records::TenantQuotaRecord {
            tenant_id: quota.tenant_id.clone(),
            max_cpu_millicores: quota.max_cpu_millicores,
            max_memory_bytes: quota.max_memory_bytes,
            max_workloads: quota.max_workloads,
        };

        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::SetTenantQuota { record },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(
            tenant_id = %quota.tenant_id,
            max_cpu = quota.max_cpu_millicores,
            max_memory = quota.max_memory_bytes,
            max_workloads = quota.max_workloads,
            "tenant quota set via raft"
        );

        Ok(Response::new(QuotaAck { accepted: true }))
    }

    async fn get_quota(
        &self,
        request: Request<QuotaRequest>,
    ) -> Result<Response<QuotaResponse>, Status> {
        self.verify_caller(&request)?;
        self.require_read_access(&request)?;

        let req = request.into_inner();
        let quota = req
            .quota
            .ok_or_else(|| Status::invalid_argument("quota is required"))?;

        validate_identifier(&quota.tenant_id, "tenant_id")?;

        let record = self
            .storage
            .get_tenant_quota(&quota.tenant_id)
            .map_err(|e| Status::internal(format!("quota lookup failed: {}", e)))?
            .ok_or_else(|| {
                Status::not_found(format!("no quota set for tenant '{}'", quota.tenant_id))
            })?;

        Ok(Response::new(QuotaResponse {
            quota: Some(fleetos_core::proto::admin::TenantQuota {
                tenant_id: record.tenant_id,
                max_cpu_millicores: record.max_cpu_millicores,
                max_memory_bytes: record.max_memory_bytes,
                max_workloads: record.max_workloads,
            }),
        }))
    }

    // --- CR-8: Operator JIT Access (Stubs for Step 25) ---
    async fn grant_operator_access(
        &self,
        request: Request<fleetos_core::proto::admin::GrantOperatorAccessRequest>,
    ) -> Result<Response<fleetos_core::proto::admin::OperatorAccessAck>, Status> {
        self.verify_caller(&request)?;
        self.require_cluster_admin_write(&request)?;
        let granted_by = self.caller_spiffe_id(&request)?;
        let audit = self.build_audit_context(&request, &request.get_ref().operator_id);

        let req = request.into_inner();

        // Validate operator_id is an operator-kind SPIFFE ID.
        let operator_spiffe: SpiffeId = req
            .operator_id
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid operator_id: {}", e)))?;
        if operator_spiffe.kind != fleetos_core::spiffe::IdKind::Operator {
            return Err(Status::invalid_argument(
                "operator_id must be an operator-kind SPIFFE ID",
            ));
        }

        // Enforce the pre-registered allow-list (empty = unrestricted).
        if !self.operators_config.allowed_operators.is_empty()
            && !self
                .operators_config
                .allowed_operators
                .contains(&req.operator_id)
        {
            return Err(Status::permission_denied(format!(
                "operator '{}' is not in the pre-registered allow-list",
                req.operator_id
            )));
        }

        // Leader-computed timestamps (determinism contract).
        let granted_at_unix = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
        let ttl = if req.ttl_secs == 0 {
            self.operators_config.grant_ttl_secs
        } else {
            req.ttl_secs
        };
        let expires_at_unix = granted_at_unix + ttl;

        let scope = req.scope.unwrap_or_default();
        let cluster_admin = scope.cluster_admin;
        let read_only = scope.read_only;
        let tenants = scope.tenants;

        // Content-derived grant id via the frozen 7-arg of_grant (CR-8 amendment).
        let tenant_refs: Vec<&str> = tenants.iter().map(|s| s.as_str()).collect();
        let grant_id = fleetos_core::OperatorGrantId::of_grant(
            &req.operator_id,
            &granted_by,
            granted_at_unix,
            expires_at_unix,
            cluster_admin,
            read_only,
            &tenant_refs,
        )
        .to_hex();

        let record = crate::raft::records::OperatorAccessGrantRecord {
            grant_id: grant_id.clone(),
            operator_id: req.operator_id.clone(),
            granted_by,
            granted_at_unix,
            expires_at_unix,
            cluster_admin,
            read_only,
            tenants,
        };

        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::GrantOperatorAccess { record },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(
            operator_id = %req.operator_id,
            grant_id = %grant_id,
            cluster_admin = cluster_admin,
            read_only = read_only,
            "operator access granted"
        );
        Ok(Response::new(
            fleetos_core::proto::admin::OperatorAccessAck {
                accepted: true,
                grant_id,
            },
        ))
    }

    async fn revoke_operator_access(
        &self,
        request: Request<fleetos_core::proto::admin::RevokeOperatorAccessRequest>,
    ) -> Result<Response<fleetos_core::proto::admin::OperatorAccessAck>, Status> {
        self.verify_caller(&request)?;
        self.require_cluster_admin_write(&request)?;
        let audit = self.build_audit_context(&request, &request.get_ref().grant_id);

        let req = request.into_inner();

        // Verify the grant exists before proposing revocation.
        let exists = self
            .storage
            .operator_grants
            .get(req.grant_id.as_bytes())
            .map_err(|e| Status::internal(format!("storage error: {}", e)))?
            .is_some();
        if !exists {
            return Err(Status::not_found(format!(
                "grant '{}' not found",
                req.grant_id
            )));
        }

        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::RevokeOperatorAccess {
                    grant_id: req.grant_id.clone(),
                },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(grant_id = %req.grant_id, "operator access revoked");
        Ok(Response::new(
            fleetos_core::proto::admin::OperatorAccessAck {
                accepted: true,
                grant_id: req.grant_id,
            },
        ))
    }

    async fn list_operator_access(
        &self,
        request: Request<fleetos_core::proto::admin::ListOperatorAccessRequest>,
    ) -> Result<Response<fleetos_core::proto::admin::ListOperatorAccessResponse>, Status> {
        self.verify_caller(&request)?;
        self.require_cluster_admin(&request)?;
        let _ = request.into_inner();

        let mut grants = Vec::new();
        for guard in self.storage.operator_grants.prefix(Vec::<u8>::new()) {
            let value = guard
                .value()
                .map_err(|e| Status::internal(format!("storage error: {}", e)))?;
            if let Ok(record) = postcard::from_bytes::<
                crate::raft::records::OperatorAccessGrantRecord,
            >(value.as_ref())
            {
                grants.push(fleetos_core::proto::admin::OperatorAccessGrant {
                    grant_id: record.grant_id,
                    operator_id: record.operator_id,
                    granted_by: record.granted_by,
                    granted_at_unix: record.granted_at_unix,
                    expires_at_unix: record.expires_at_unix,
                    scope: Some(fleetos_core::proto::admin::OperatorScope {
                        cluster_admin: record.cluster_admin,
                        tenants: record.tenants,
                        read_only: record.read_only,
                    }),
                });
            }
        }

        Ok(Response::new(
            fleetos_core::proto::admin::ListOperatorAccessResponse { grants },
        ))
    }

    // --- CR-9: Replicated Audit Log (Read Path) ---
    async fn list_audit_log(
        &self,
        request: Request<fleetos_core::proto::admin::ListAuditLogRequest>,
    ) -> Result<Response<fleetos_core::proto::admin::ListAuditLogResponse>, Status> {
        self.verify_caller(&request)?;
        self.require_cluster_admin(&request)?;
        let req = request.into_inner();
        let from_version = req.from_version;
        let max_entries = if req.max_entries == 0 {
            1000
        } else {
            req.max_entries as usize
        };

        let start_key = from_version.to_be_bytes().to_vec();
        let mut entries = Vec::new();

        for guard in self.storage.audit_log.range(start_key..) {
            if entries.len() >= max_entries {
                break;
            }
            let value = guard
                .value()
                .map_err(|e| Status::internal(format!("storage error: {}", e)))?;
            let record: crate::raft::records::AuditRecord = postcard::from_bytes(value.as_ref())
                .map_err(|e| Status::internal(format!("deserialization error: {}", e)))?;

            entries.push(fleetos_core::proto::admin::AuditEntry {
                version: record.version,
                request_id: record.request_id,
                actor: record.actor,
                action: record.action,
                target: record.target,
                timestamp_unix: record.timestamp_unix,
            });
        }

        Ok(Response::new(
            fleetos_core::proto::admin::ListAuditLogResponse { entries },
        ))
    }

    // --- CR-12: Node Pool Management (V-3 remediation) ---

    async fn create_node_pool(
        &self,
        request: Request<NodePoolCreateRequest>,
    ) -> Result<Response<NodePoolAck>, Status> {
        self.verify_caller(&request)?;
        self.require_cluster_admin_write(&request)?;

        // CRITICAL: Extract target and build audit context BEFORE consuming the request.
        let pool_id = request.get_ref().pool_id.clone();
        let audit = self.build_audit_context(&request, &pool_id);

        // NOW consume the request.
        let req = request.into_inner();

        // Validate pool_id.
        if req.pool_id.is_empty() {
            return Err(Status::invalid_argument("pool_id cannot be empty"));
        }
        validate_identifier(&req.pool_id, "pool_id")?;

        // Convert proto NodeKind to internal.
        let node_kind = crate::provisioning::node_kind_from_proto(req.node_kind)
            .map_err(|e| Status::invalid_argument(format!("invalid node_kind: {}", e)))?;

        // Idempotency guard: reject if pool already exists.
        let existing = self
            .storage
            .get_node_pool(&req.pool_id)
            .map_err(|e| Status::internal(format!("storage read failed: {}", e)))?;
        if existing.is_some() {
            return Err(Status::already_exists(format!(
                "node pool '{}' already exists",
                req.pool_id
            )));
        }

        // Build the record.
        let record = crate::provisioning::NodePoolRecord {
            pool_id: req.pool_id.clone(),
            node_kind,
            desired_count: req.desired_count,
            vcpus: req.vcpus,
            memory_mb: req.memory_mb,
            disk_gb: req.disk_gb,
            region_hint: req.region_hint.clone(),
        };

        // Propose through Raft.
        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::StoreNodePool { record },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(pool_id = %req.pool_id, "node pool created via raft");
        Ok(Response::new(NodePoolAck { accepted: true }))
    }

    async fn delete_node_pool(
        &self,
        request: Request<NodePoolDeleteRequest>,
    ) -> Result<Response<NodePoolAck>, Status> {
        self.verify_caller(&request)?;
        self.require_cluster_admin_write(&request)?;

        // CRITICAL: Extract target and build audit context BEFORE consuming the request.
        let pool_id = request.get_ref().pool_id.clone();
        let audit = self.build_audit_context(&request, &pool_id);

        // NOW consume the request.
        let req = request.into_inner();

        if req.pool_id.is_empty() {
            return Err(Status::invalid_argument("pool_id cannot be empty"));
        }

        // Existence check.
        let existing = self
            .storage
            .get_node_pool(&req.pool_id)
            .map_err(|e| Status::internal(format!("storage read failed: {}", e)))?;
        if existing.is_none() {
            return Err(Status::not_found(format!(
                "node pool '{}' not found",
                req.pool_id
            )));
        }

        // Propose through Raft.
        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::DeleteNodePool {
                    pool_id: req.pool_id.clone(),
                },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(pool_id = %req.pool_id, "node pool deleted via raft");
        Ok(Response::new(NodePoolAck { accepted: true }))
    }

    async fn list_node_pools(
        &self,
        request: Request<ListNodePoolsRequest>,
    ) -> Result<Response<ListNodePoolsResponse>, Status> {
        self.verify_caller(&request)?;
        self.require_read_access(&request)?;

        let _ = request.into_inner();

        let records = self
            .storage
            .list_node_pools()
            .map_err(|e| Status::internal(format!("storage read failed: {}", e)))?;

        let pools: Vec<NodePoolInfo> = records
            .into_iter()
            .map(|r| NodePoolInfo {
                pool_id: r.pool_id,
                node_kind: crate::provisioning::node_kind_to_proto(&r.node_kind),
                desired_count: r.desired_count,
                vcpus: r.vcpus,
                memory_mb: r.memory_mb,
                disk_gb: r.disk_gb,
                region_hint: r.region_hint,
            })
            .collect();

        Ok(Response::new(ListNodePoolsResponse { pools }))
    }

    async fn register_node_ek(
        &self,
        request: Request<RegisterNodeEkRequest>,
    ) -> Result<Response<RegisterNodeEkResponse>, Status> {
        self.verify_caller(&request)?;
        self.require_cluster_admin_write(&request)?;

        // FIX: Extract audit context BEFORE consuming the request
        let mut audit = self.build_audit_context(&request, "register_node_ek");

        // NOW consume the request
        let req = request.into_inner();

        // Validate: at least one of ek_cert_der or ek_pub must be present.
        if req.ek_cert_der.is_empty() && req.ek_pub.is_empty() {
            return Err(Status::invalid_argument(
                "either ek_cert_der or ek_pub must be provided",
            ));
        }
        // Step 8 (ATT-EKVAL): if a certificate is presented, validate its chain
        // against the configured manufacturer roots before anything else.
        if !req.ek_cert_der.is_empty() {
            crate::attestation::ek_cert::validate_ek_cert_chain(&req.ek_cert_der).map_err(|e| {
                Status::invalid_argument(format!("EK certificate chain validation failed: {}", e))
            })?;
        }
        // Compute EK fingerprint — fleetos-core owns the convention (CR-11).
        let fingerprint = if !req.ek_cert_der.is_empty() {
            fleetos_core::attestation::EkFingerprint::of_ek_cert(&req.ek_cert_der).map_err(|e| {
                Status::invalid_argument(format!("EK cert extraction failed: {}", e))
            })?
        } else {
            fleetos_core::attestation::EkFingerprint::of_ek_pub(&req.ek_pub)
        };
        // CR-11 convergence invariant: if both forms are provided, they must
        // fingerprint identically. One EK yields one fingerprint.
        if !req.ek_cert_der.is_empty() && !req.ek_pub.is_empty() {
            let fp_pub = fleetos_core::attestation::EkFingerprint::of_ek_pub(&req.ek_pub);
            if fingerprint != fp_pub {
                return Err(Status::invalid_argument(
                    "EK convergence check failed: cert and public key fingerprints differ",
                ));
            }
        }
        let fp_hex = fingerprint.to_hex();

        // Update the audit target now that we have the computed fingerprint
        audit.target = fp_hex.clone();

        // Idempotency guard: reject if already registered.
        let existing = self
            .node_eks
            .get(fp_hex.as_bytes())
            .map_err(|e| Status::internal(format!("EK lookup failed: {}", e)))?;
        if existing.is_some() {
            return Err(Status::already_exists(format!(
                "EK '{}' is already registered",
                fp_hex
            )));
        }

        // Compute TTL: 0 = use configured default (1 hour).
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let ttl = if req.ttl_secs == 0 {
            3600
        } else {
            req.ttl_secs as i64
        };

        let record = crate::raft::records::NodeEkRecord {
            ek_fingerprint: fp_hex.clone(),
            ek_pub: req.ek_pub.clone(),
            ek_cert_der: req.ek_cert_der.clone(),
            node_id: req.node_id.clone(),
            registered_at: now,
            expires_at: Some(now + ttl),
            state: crate::raft::records::EkRegistrationState::Pending,
        };

        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::RegisterNodeEk { record },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(ek_fingerprint = %fp_hex, "EK registered via raft");
        Ok(Response::new(RegisterNodeEkResponse {
            accepted: true,
            ek_fingerprint: fp_hex,
        }))
    }

    async fn revoke_node_ek(
        &self,
        request: Request<RevokeNodeEkRequest>,
    ) -> Result<Response<NodeAck>, Status> {
        self.verify_caller(&request)?;
        self.require_cluster_admin_write(&request)?;

        // FIX: Build audit context BEFORE consuming the request.
        // We use get_ref() to peek at the payload without taking ownership.
        let target_fp = request.get_ref().ek_fingerprint.clone();
        let audit = self.build_audit_context(&request, &target_fp);

        // NOW consume the request
        let req = request.into_inner();

        if req.ek_fingerprint.is_empty() {
            return Err(Status::invalid_argument("ek_fingerprint cannot be empty"));
        }

        // Verify the EK exists before proposing revocation.
        let exists = self
            .node_eks
            .get(req.ek_fingerprint.as_bytes())
            .map_err(|e| Status::internal(format!("EK lookup failed: {}", e)))?
            .is_some();
        if !exists {
            return Err(Status::not_found(format!(
                "EK '{}' not found",
                req.ek_fingerprint
            )));
        }

        self.raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::RevokeNodeEk {
                    ek_fingerprint: req.ek_fingerprint.clone(),
                },
                audit: Some(audit),
            })
            .await
            .map_err(|e| Status::internal(format!("raft proposal failed: {}", e)))?;

        tracing::info!(ek_fingerprint = %req.ek_fingerprint, "EK revoked via raft");
        Ok(Response::new(NodeAck { accepted: true }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_validation() {
        assert!(validate_identifier("tenant-1", "tenant_id").is_ok());
        assert!(validate_identifier("a", "x").is_ok());
        assert!(validate_identifier("db-replica-0", "x").is_ok());
        assert!(validate_identifier("", "x").is_err());
        assert!(validate_identifier("Tenant", "x").is_err());
        assert!(validate_identifier("-leading", "x").is_err());
        assert!(validate_identifier("trailing-", "x").is_err());
        assert!(validate_identifier("has space", "x").is_err());
        assert!(validate_identifier(&"a".repeat(64), "x").is_err());
    }
}
