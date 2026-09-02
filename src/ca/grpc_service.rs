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
    /// Control node addresses for leader redirect (N-1).
    control_addresses: fjall::Keyspace,
    raft: Arc<openraft::Raft<crate::raft::FleetosRaftConfig>>,
}

impl CaServiceImpl {
    pub fn new(
        data_control: Arc<RwLock<InternalTrustBundle>>,
        svid_ttl_secs: u64,
        svids_keyspace: fjall::Keyspace,
        svid_grants_keyspace: fjall::Keyspace,
        placements_keyspace: fjall::Keyspace,
        control_addresses: fjall::Keyspace,
        raft: Arc<openraft::Raft<crate::raft::FleetosRaftConfig>>,
    ) -> Self {
        Self {
            data_control,
            svid_ttl_secs,
            svids_keyspace,
            svid_grants_keyspace,
            placements_keyspace,
            control_addresses,
            raft,
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

    /// Look up the Data/Control address of a control node by Raft node ID.
    fn leader_dc_address(&self, leader_id: u64) -> Result<Option<String>, Status> {
        match self
            .control_addresses
            .get(leader_id.to_be_bytes())
            .map_err(|e| Status::internal(format!("address lookup failed: {}", e)))?
        {
            Some(bytes) => {
                let rec: crate::raft::records::ControlNodeAddressRecord =
                    postcard::from_bytes(&bytes)
                        .map_err(|e| Status::internal(format!("corrupt address record: {}", e)))?;
                Ok(Some(rec.dc_addr))
            }
            None => Ok(None),
        }
    }

    /// Build a gRPC status that tells the client to retry against the leader.
    fn redirect_to_leader(leader_addr: &str) -> Status {
        let mut status = Status::unavailable("not the Raft leader; retry against the leader");
        if let Ok(v) = tonic::metadata::MetadataValue::try_from(leader_addr) {
            status.metadata_mut().insert("leader-dc-address", v);
        }
        status
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

        // V-4c: Route SVID version write through Raft (leader-only issuance).
        // The state machine writes the new version to the `svids` keyspace,
        // making it replicated state consistent across all nodes.
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let record = crate::ca::SvidRecord {
            spiffe_id: spiffe_id.clone(),
            svid_version: new_version,
            issued_at_unix: now,
        };
        match self
            .raft
            .client_write(crate::raft::AuditedCommand::system(
                crate::raft::FleetosCommand::UpsertSvidVersion { record },
            ))
            .await
        {
            Ok(_) => {}
            Err(openraft::error::RaftError::APIError(
                openraft::error::ClientWriteError::ForwardToLeader(fwd),
            )) => {
                let leader_id = fwd
                    .leader_id
                    .ok_or_else(|| Status::internal("forward response missing leader id"))?;
                let leader_addr = self
                    .leader_dc_address(leader_id)?
                    .ok_or_else(|| Status::internal("leader DC address not registered"))?;
                return Err(Self::redirect_to_leader(&leader_addr));
            }
            Err(e) => {
                return Err(Status::internal(format!(
                    "SVID version write failed: {}",
                    e
                )));
            }
        }

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

    async fn test_service(name: &str) -> (std::sync::Arc<fjall::Database>, CaServiceImpl) {
        let dir = std::env::temp_dir().join(format!(
            "fleetos-ca-authz-test-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let db = crate::storage::open_database(&dir).unwrap();
        let keyspaces = crate::storage::init_keyspaces(&db).unwrap();
        let bundle = TrustBundle::generate_root("fleet.example.internal").unwrap();

        // Spin up a single-node Raft for tests
        let versioned_state =
            crate::storage::version::VersionedState::new(keyspaces.version.clone());
        let broadcast_hub = crate::watch::broadcast::BroadcastHub::new();
        let raft_config = openraft::Config {
            heartbeat_interval: 50,
            election_timeout_min: 150,
            election_timeout_max: 300,
            ..Default::default()
        };
        let raft_config = Arc::new(raft_config.validate().unwrap());
        let log_storage = crate::raft::store::FjallLogStorage::new(
            db.clone(),
            keyspaces.raft_log.clone(),
            keyspaces.raft_log_meta.clone(),
        );
        let state_machine = crate::raft::state_machine::FjallStateMachine::new(
            db.clone(),
            keyspaces.clone(),
            versioned_state,
            broadcast_hub,
            "test.example.internal".to_owned(),
        );

        struct NoOpNetworkFactory;
        impl openraft::network::RaftNetworkFactory<crate::raft::FleetosRaftConfig> for NoOpNetworkFactory {
            type Network = NoOpNetwork;
            async fn new_client(
                &mut self,
                _target: u64,
                _node: &openraft::BasicNode,
            ) -> Self::Network {
                NoOpNetwork
            }
        }
        struct NoOpNetwork;
        impl openraft::network::RaftNetwork<crate::raft::FleetosRaftConfig> for NoOpNetwork {
            async fn append_entries(
                &mut self,
                _req: openraft::raft::AppendEntriesRequest<crate::raft::FleetosRaftConfig>,
                _option: openraft::network::RPCOption,
            ) -> Result<
                openraft::raft::AppendEntriesResponse<u64>,
                openraft::error::RPCError<
                    u64,
                    openraft::BasicNode,
                    openraft::error::RaftError<u64>,
                >,
            > {
                Err(openraft::error::RPCError::Network(
                    openraft::error::NetworkError::new(&std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "test",
                    )),
                ))
            }
            async fn vote(
                &mut self,
                _req: openraft::raft::VoteRequest<u64>,
                _option: openraft::network::RPCOption,
            ) -> Result<
                openraft::raft::VoteResponse<u64>,
                openraft::error::RPCError<
                    u64,
                    openraft::BasicNode,
                    openraft::error::RaftError<u64>,
                >,
            > {
                Err(openraft::error::RPCError::Network(
                    openraft::error::NetworkError::new(&std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "test",
                    )),
                ))
            }
            async fn install_snapshot(
                &mut self,
                _req: openraft::raft::InstallSnapshotRequest<crate::raft::FleetosRaftConfig>,
                _option: openraft::network::RPCOption,
            ) -> Result<
                openraft::raft::InstallSnapshotResponse<u64>,
                openraft::error::RPCError<
                    u64,
                    openraft::BasicNode,
                    openraft::error::RaftError<u64, openraft::error::InstallSnapshotError>,
                >,
            > {
                Err(openraft::error::RPCError::Network(
                    openraft::error::NetworkError::new(&std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "test",
                    )),
                ))
            }
        }

        let raft = openraft::Raft::new(
            1,
            raft_config,
            NoOpNetworkFactory,
            log_storage,
            state_machine,
        )
        .await
        .unwrap();
        let raft = Arc::new(raft);

        // Bootstrap single node
        let mut members = std::collections::BTreeMap::new();
        members.insert(
            1,
            openraft::BasicNode {
                addr: String::new(),
            },
        );
        raft.initialize(members).await.unwrap();

        let service = CaServiceImpl::new(
            Arc::new(RwLock::new(bundle)),
            3600,
            keyspaces.svids.clone(),
            keyspaces.svid_grants.clone(),
            keyspaces.placements.clone(),
            keyspaces.control_addresses.clone(),
            raft,
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

    #[tokio::test]
    async fn unauthenticated_csr_without_grant_is_rejected() {
        let (_db, service) = test_service("no-grant").await;
        let result = service
            .authorize_issuance("spiffe://fleet.example.internal/ns/system/control/c1", None);
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn grant_authorizes_exactly_once() {
        let (_db, service) = test_service("grant-single-use").await;
        let id = "spiffe://fleet.example.internal/ns/system/control/c1";
        write_grant(&service, id, 300);
        assert!(service.authorize_issuance(id, None).is_ok());
        assert_eq!(
            service.authorize_issuance(id, None).unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
    }

    #[tokio::test]
    async fn expired_grant_is_rejected_and_still_consumed() {
        let (_db, service) = test_service("grant-expired").await;
        let id = "spiffe://fleet.example.internal/ns/system/control/c1";
        write_grant(&service, id, -1);
        assert_eq!(
            service.authorize_issuance(id, None).unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
        assert!(
            service
                .svid_grants_keyspace
                .get(id.as_bytes())
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn self_renewal_is_allowed() {
        let (_db, service) = test_service("self-renewal").await;
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

    #[tokio::test]
    async fn foreign_identity_renewal_is_rejected() {
        let (_db, service) = test_service("foreign-renewal").await;
        let caller: SpiffeId = "spiffe://fleet.example.internal/ns/system/node/agent-1"
            .parse()
            .unwrap();
        let result = service.authorize_issuance(
            "spiffe://fleet.example.internal/ns/tenant-1/sa/db",
            Some(&caller),
        );
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn non_node_caller_cannot_sign_foreign_identity() {
        let (_db, service) = test_service("control-foreign").await;
        let caller: SpiffeId = "spiffe://fleet.example.internal/ns/system/control/c1"
            .parse()
            .unwrap();
        let result = service.authorize_issuance(
            "spiffe://fleet.example.internal/ns/tenant-1/sa/db",
            Some(&caller),
        );
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn hosting_node_can_renew_hosted_workload() {
        let (_db, service) = test_service("hosting-renewal").await;
        let node: SpiffeId = "spiffe://fleet.example.internal/ns/system/node/agent-1"
            .parse()
            .unwrap();
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
