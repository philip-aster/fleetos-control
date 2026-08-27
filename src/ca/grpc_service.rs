//! CaService gRPC implementation.
//!
//! Handles SVID issuance and trust bundle distribution:
//! 1. `SubmitCsr` — signs a CSR and returns the SVID certificate
//! 2. `GetTrustBundle` — returns the current trust bundle (root CA certs)
//!
//! Caller binding (Master finding M-3, fleetos-core CR-6 contract):
//! - Authenticated callers (mTLS) may sign only their own SPIFFE ID
//!   (self-renewal) or a workload SPIFFE ID they host (placement-verified).
//! - Unauthenticated callers (join flow, pre-SVID) may sign only when a
//!   single-use attestation grant — written by `submit_quote` on successful
//!   attestation — exists for exactly the CSR's SPIFFE ID.
//! Anything else is rejected fail-closed with PERMISSION_DENIED.
use super::SvidGrantRecord;
use super::key_issuance::{PlacementVerifier, StoragePlacementVerifier};
use super::rcgen_impl;
use super::trust_bundle::TrustBundle as InternalTrustBundle;
use fleetos_core::proto::identity::CaService;
use fleetos_core::proto::identity::{CsrRequest, SvidResponse, TrustBundle, TrustBundleRequest};
use fleetos_core::spiffe::{IdKind, SpiffeId};
use parking_lot::RwLock;
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// The CaService gRPC implementation.
pub struct CaServiceImpl {
    /// Data/Control trust domain CA.
    data_control: Arc<RwLock<InternalTrustBundle>>,
    /// SVID TTL configuration.
    svid_ttl_secs: u64,
    /// Keyspace for tracking SVID versions per SpiffeId.
    svids_keyspace: fjall::Keyspace,
    /// Single-use attestation grants keyed by SPIFFE ID (M-3, join path).
    svid_grants_keyspace: fjall::Keyspace,
    /// Placements for hosting verification (M-3, authenticated renewal path).
    placements_keyspace: fjall::Keyspace,
}

impl CaServiceImpl {
    pub fn new(
        data_control: Arc<RwLock<InternalTrustBundle>>,
        svid_ttl_secs: u64,
        svids_keyspace: fjall::Keyspace,
        svid_grants_keyspace: fjall::Keyspace,
        placements_keyspace: fjall::Keyspace,
    ) -> Self {
        Self {
            data_control,
            svid_ttl_secs,
            svids_keyspace,
            svid_grants_keyspace,
            placements_keyspace,
        }
    }

    /// M-3: bind CSR issuance to the caller's identity, fail-closed.
    fn authorize_issuance(
        &self,
        csr_spiffe_id: &str,
        caller: Option<&SpiffeId>,
    ) -> Result<(), Status> {
        match caller {
            Some(caller_id) => self.authorize_authenticated(csr_spiffe_id, caller_id),
            None => self.authorize_via_grant(csr_spiffe_id),
        }
    }

    /// Authenticated renewal: (a) self, or (b) a workload identity the
    /// caller's node actually hosts (placement-verified).
    fn authorize_authenticated(
        &self,
        csr_spiffe_id: &str,
        caller_id: &SpiffeId,
    ) -> Result<(), Status> {
        // (a) Self-renewal.
        if caller_id.to_string() == csr_spiffe_id {
            return Ok(());
        }
        // (b) Hosting node renewing a workload SVID it hosts.
        if caller_id.kind == IdKind::Node {
            let target: SpiffeId = csr_spiffe_id.parse().map_err(|e| {
                Status::invalid_argument(format!("CSR SPIFFE ID is malformed: {}", e))
            })?;
            let verifier = StoragePlacementVerifier::new(self.placements_keyspace.clone());
            return verifier
                .verify_placement(caller_id, &target, None)
                .map_err(|e| {
                    Status::permission_denied(format!(
                        "caller {} is not authorized to sign {}: {}",
                        caller_id, csr_spiffe_id, e
                    ))
                });
        }
        Err(Status::permission_denied(format!(
            "caller {} cannot sign a CSR for {}",
            caller_id, csr_spiffe_id
        )))
    }

    /// Unauthenticated join path: single-use attestation grant only.
    /// The grant is consumed before expiry validation — an expired grant
    /// must never be retryable.
    fn authorize_via_grant(&self, csr_spiffe_id: &str) -> Result<(), Status> {
        let grant_bytes = self
            .svid_grants_keyspace
            .get(csr_spiffe_id.as_bytes())
            .map_err(|e| Status::internal(format!("grant lookup failed: {}", e)))?
            .ok_or_else(|| {
                Status::permission_denied(
                    "unauthenticated CSR signing requires a valid attestation grant",
                )
            })?;
        self.svid_grants_keyspace
            .remove(csr_spiffe_id.as_bytes())
            .map_err(|e| Status::internal(format!("grant consumption failed: {}", e)))?;
        let grant: SvidGrantRecord = postcard::from_bytes(&grant_bytes)
            .map_err(|e| Status::internal(format!("corrupt attestation grant: {}", e)))?;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        if now > grant.expires_at {
            return Err(Status::permission_denied("attestation grant expired"));
        }
        tracing::info!(
            spiffe_id = %grant.spiffe_id,
            node_kind = grant.node_kind,
            "CSR authorized via attestation grant"
        );
        Ok(())
    }
}

#[tonic::async_trait]
impl CaService for CaServiceImpl {
    /// Sign a CSR and return the SVID certificate.
    ///
    /// The agent generates a keypair, creates a CSR with its SPIFFE ID as
    /// URI SAN, and submits it here. The CA signs the CSR and returns the
    /// certificate. The agent retains its own private key.
    async fn submit_csr(
        &self,
        request: Request<CsrRequest>,
    ) -> Result<Response<SvidResponse>, Status> {
        // CRITICAL: extract the peer identity BEFORE into_inner() consumes
        // the Request. None = unauthenticated connection (join flow on the
        // optional-auth Data/Control listener).
        let caller = request
            .extensions()
            .get::<crate::tls::PeerConnectInfo>()
            .and_then(|info| info.spiffe_id.clone());

        let req = request.into_inner();
        if req.csr_der.is_empty() {
            return Err(Status::invalid_argument("csr_der cannot be empty"));
        }

        // Extract the SpiffeId from the CSR for version tracking.
        let spiffe_id = rcgen_impl::extract_spiffe_id_from_csr(&req.csr_der)
            .map_err(|e| Status::invalid_argument(format!("CSR validation failed: {}", e)))?;

        // M-3 / CR-6: bind issuance to the caller, fail-closed.
        self.authorize_issuance(&spiffe_id, caller.as_ref())?;

        // Load the current SVID version for this SpiffeId, or start at 0.
        let current_version = match self
            .svids_keyspace
            .get(spiffe_id.as_bytes())
            .map_err(|e| Status::internal(format!("failed to read SVID record: {}", e)))?
        {
            Some(bytes) => {
                let record: crate::ca::SvidRecord = postcard::from_bytes(&bytes)
                    .map_err(|e| Status::internal(format!("failed to parse SVID record: {}", e)))?;
                record.svid_version
            }
            None => 0,
        };

        // Increment the version.
        let new_version = current_version + 1;

        // Persist the updated SVID record.
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let record = crate::ca::SvidRecord {
            spiffe_id: spiffe_id.clone(),
            svid_version: new_version,
            issued_at_unix: now,
        };
        let serialized = postcard::to_allocvec(&record)
            .map_err(|e| Status::internal(format!("failed to serialize SVID record: {}", e)))?;
        self.svids_keyspace
            .insert(spiffe_id.as_bytes(), serialized.as_slice())
            .map_err(|e| Status::internal(format!("failed to store SVID record: {}", e)))?;

        // Sign the CSR.
        let bundle = self.data_control.read();
        let cert_der = rcgen_impl::sign_csr(
            &req.csr_der,
            &bundle.current_key,
            &bundle.current_cert_der,
            self.svid_ttl_secs,
        )
        .map_err(|e| Status::internal(format!("CSR signing failed: {}", e)))?;

        tracing::info!(
            spiffe_id = %spiffe_id,
            cert_len = cert_der.len(),
            svid_version = new_version,
            "CSR signed and SVID issued"
        );

        Ok(Response::new(SvidResponse {
            cert_chain_der: cert_der,
            keypair_der: Vec::new(), // Client generates and keeps the keypair.
            svid_version: new_version,
        }))
    }

    /// Return the current trust bundle (root CA certificates).
    ///
    /// This is used by agents to validate SVIDs issued by this CA.
    /// Returns the Data/Control trust domain's root certificates.
    async fn get_trust_bundle(
        &self,
        _request: Request<TrustBundleRequest>,
    ) -> Result<Response<TrustBundle>, Status> {
        let bundle = self.data_control.read();

        // Collect root certificates (current + previous if mid-rotation).
        let mut roots_der = vec![bundle.current_cert_der.clone()];
        if let Some(ref previous) = bundle.previous {
            roots_der.push(previous.cert_der.clone());
        }

        Ok(Response::new(TrustBundle {
            trust_domain: bundle.trust_domain.clone(),
            roots_der,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::trust_bundle::TrustBundle;
    use crate::scheduler::{Placement, ResourceSpec};

    fn test_service(name: &str) -> (std::sync::Arc<fjall::Database>, CaServiceImpl) {
        let dir = std::env::temp_dir().join(format!(
            "fleetos-ca-authz-test-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let db = crate::storage::open_database(&dir).unwrap();
        let keyspaces = crate::storage::init_keyspaces(&db).unwrap();
        let bundle = TrustBundle::generate_root("fleet.example.internal").unwrap();
        let service = CaServiceImpl::new(
            Arc::new(RwLock::new(bundle)),
            3600,
            keyspaces.svids.clone(),
            keyspaces.svid_grants.clone(),
            keyspaces.placements.clone(),
        );
        (db, service)
    }

    fn write_grant(service: &CaServiceImpl, spiffe_id: &str, ttl_secs: i64) {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let grant = SvidGrantRecord {
            spiffe_id: spiffe_id.to_owned(),
            node_kind: 0,
            granted_at: now,
            expires_at: now + ttl_secs,
        };
        let bytes = postcard::to_allocvec(&grant).unwrap();
        service
            .svid_grants_keyspace
            .insert(spiffe_id.as_bytes(), bytes.as_slice())
            .unwrap();
    }

    #[test]
    fn unauthenticated_csr_without_grant_is_rejected() {
        let (_db, service) = test_service("no-grant");
        let result = service
            .authorize_issuance("spiffe://fleet.example.internal/ns/system/control/c1", None);
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn grant_authorizes_exactly_once() {
        let (_db, service) = test_service("grant-single-use");
        let id = "spiffe://fleet.example.internal/ns/system/control/c1";
        write_grant(&service, id, 300);
        assert!(service.authorize_issuance(id, None).is_ok());
        // Second attempt: the grant was consumed.
        assert_eq!(
            service.authorize_issuance(id, None).unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
    }

    #[test]
    fn expired_grant_is_rejected_and_still_consumed() {
        let (_db, service) = test_service("grant-expired");
        let id = "spiffe://fleet.example.internal/ns/system/control/c1";
        write_grant(&service, id, -1); // already expired
        assert_eq!(
            service.authorize_issuance(id, None).unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
        // Expired grants must still be consumed — no retry path.
        assert!(
            service
                .svid_grants_keyspace
                .get(id.as_bytes())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn self_renewal_is_allowed() {
        let (_db, service) = test_service("self-renewal");
        let caller: SpiffeId = "spiffe://fleet.example.internal/ns/system/node/agent-1"
            .parse()
            .unwrap();
        assert!(
            service
                .authorize_issuance(
                    "spiffe://fleet.example.internal/ns/system/node/agent-1",
                    Some(&caller)
                )
                .is_ok()
        );
    }

    #[test]
    fn foreign_identity_renewal_is_rejected() {
        let (_db, service) = test_service("foreign-renewal");
        let caller: SpiffeId = "spiffe://fleet.example.internal/ns/system/node/agent-1"
            .parse()
            .unwrap();
        // agent-1 hosts no placements → placement verification fails.
        let result = service.authorize_issuance(
            "spiffe://fleet.example.internal/ns/tenant-1/sa/db",
            Some(&caller),
        );
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn non_node_caller_cannot_sign_foreign_identity() {
        let (_db, service) = test_service("control-foreign");
        let caller: SpiffeId = "spiffe://fleet.example.internal/ns/system/control/c1"
            .parse()
            .unwrap();
        let result = service.authorize_issuance(
            "spiffe://fleet.example.internal/ns/tenant-1/sa/db",
            Some(&caller),
        );
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn hosting_node_can_renew_hosted_workload() {
        let (_db, service) = test_service("hosting-renewal");
        let node: SpiffeId = "spiffe://fleet.example.internal/ns/system/node/agent-1"
            .parse()
            .unwrap();
        // Placement: agent-1 hosts tenant-1/db ordinal 0.
        let placement = Placement {
            pod_id: "db-replica-0".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            service: "db".to_owned(),
            role: "replica".to_owned(),
            ordinal: 0,
            node_id: node.clone(),
            resources: ResourceSpec {
                cpu_millicores: 500,
                memory_bytes: 512 * 1024 * 1024,
            },
        };
        let serialized = postcard::to_allocvec(&placement).unwrap();
        service
            .placements_keyspace
            .insert(placement.pod_id.as_bytes(), serialized.as_slice())
            .unwrap();
        assert!(
            service
                .authorize_issuance(
                    "spiffe://fleet.example.internal/ns/tenant-1/sa/db",
                    Some(&node)
                )
                .is_ok()
        );
    }
}
