//! AdminService gRPC implementation.
//!
//! This is the *only* API surface for `fleetctl-proxy`.
//! All methods require `ctrl`-kind SVID authorization.

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
use rand::Rng;
use std::sync::Arc;
use tonic::{Request, Response, Status};

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
    ) -> Self {
        Self {
            storage,
            join_token_store,
            dummy_ip_allocator,
            raft,
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
}

#[tonic::async_trait]
impl AdminService for AdminServiceImpl {
    async fn create_tenant(
        &self,
        request: Request<CreateTenantRequest>,
    ) -> Result<Response<CreateTenantResponse>, Status> {
        self.verify_caller(&request)?;

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

    // --- CR-8: Operator JIT Access (Stubs for Step 25) ---

    async fn grant_operator_access(
        &self,
        request: Request<fleetos_core::proto::admin::GrantOperatorAccessRequest>,
    ) -> Result<Response<fleetos_core::proto::admin::OperatorAccessAck>, Status> {
        self.verify_caller(&request)?;
        Err(Status::unimplemented("scheduled for Step 25"))
    }

    async fn revoke_operator_access(
        &self,
        request: Request<fleetos_core::proto::admin::RevokeOperatorAccessRequest>,
    ) -> Result<Response<fleetos_core::proto::admin::OperatorAccessAck>, Status> {
        self.verify_caller(&request)?;
        Err(Status::unimplemented("scheduled for Step 25"))
    }

    async fn list_operator_access(
        &self,
        request: Request<fleetos_core::proto::admin::ListOperatorAccessRequest>,
    ) -> Result<Response<fleetos_core::proto::admin::ListOperatorAccessResponse>, Status> {
        self.verify_caller(&request)?;
        Err(Status::unimplemented("scheduled for Step 25"))
    }

    // --- CR-9: Replicated Audit Log (Read Path) ---
    async fn list_audit_log(
        &self,
        request: Request<fleetos_core::proto::admin::ListAuditLogRequest>,
    ) -> Result<Response<fleetos_core::proto::admin::ListAuditLogResponse>, Status> {
        self.verify_caller(&request)?;

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
