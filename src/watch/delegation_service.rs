//! DelegationService implementation — node-callable delegated key acquisition (CR-16).
//!
//! Unary Data/Control service. Agents request degraded-mode delegated signing
//! keys over their own mTLS identity. Authorization is fail-closed and enforced
//! server-side: the authenticated caller MUST be the node named in the request.
//!
//! `AdminService.RequestDelegatedKey` remains the cluster-admin/operator
//! override path; both entry points issue through
//! `ca::key_issuance::issue_delegated_key` + `StoragePlacementVerifier` so
//! placement verification and the pathLen=0 constraint cannot diverge.
//!
//! Agent-side redirect-and-retry on leader redirect is an agent-directive
//! obligation; we only log the redirect here.
use crate::ca::key_issuance::StoragePlacementVerifier;
use crate::ca::trust_bundle::TrustBundle;
use crate::raft::FleetosRaftConfig;
use crate::tls::PeerConnectInfo;
use fleetos_core::proto::state::{DelegatedKeyRequest, DelegatedKeyResponse, DelegationService};
use fleetos_core::spiffe::{IdKind, SpiffeId};
use openraft::Raft;
use parking_lot::RwLock;
use rand::Rng;
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// The DelegationService gRPC implementation.
pub struct DelegationServiceImpl {
    raft: Arc<Raft<FleetosRaftConfig>>,
    /// Data/Control CA. `None` on a join-mode first boot until the CA has
    /// been replicated; every call then fails `UNAVAILABLE`.
    ca_data_control: Option<Arc<RwLock<TrustBundle>>>,
    /// Placements keyspace for hosting verification.
    placements: fjall::Keyspace,
    /// Configured maximum delegated-key TTL (seconds).
    delegated_key_ttl_secs: u64,
    /// Fraction of TTL at which refresh becomes due (0.0–1.0).
    svid_refresh_fraction: f64,
    /// Control node addresses for leader redirect (N-1).
    control_addresses: fjall::Keyspace,
}

impl DelegationServiceImpl {
    pub fn new(
        raft: Arc<Raft<FleetosRaftConfig>>,
        ca_data_control: Option<Arc<RwLock<TrustBundle>>>,
        placements: fjall::Keyspace,
        delegated_key_ttl_secs: u64,
        svid_refresh_fraction: f64,
        control_addresses: fjall::Keyspace,
    ) -> Self {
        Self {
            raft,
            ca_data_control,
            placements,
            delegated_key_ttl_secs,
            svid_refresh_fraction,
            control_addresses,
        }
    }

    /// G-3: generate a unique request ID for correlation.
    fn generate_request_id() -> String {
        let mut bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut bytes);
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
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

    /// Build a gRPC status that tells the caller to retry against the leader.
    fn redirect_to_leader(leader_addr: &str) -> Status {
        let mut status = Status::unavailable("not the Raft leader; retry against the leader");
        if let Ok(v) = tonic::metadata::MetadataValue::try_from(leader_addr) {
            status.metadata_mut().insert("leader-dc-address", v);
        }
        status
    }
}

#[tonic::async_trait]
impl DelegationService for DelegationServiceImpl {
    async fn request_delegated_key(
        &self,
        request: Request<DelegatedKeyRequest>,
    ) -> Result<Response<DelegatedKeyResponse>, Status> {
        // Fail-closed authz chain. PeerConnectInfo MUST be extracted before
        // into_inner() consumes the Request. The DC listener runs OPTIONAL
        // client auth (pre-SVID join flow), so unauthenticated reachability
        // is structural — reject it before any other logic runs.
        let caller = request
            .extensions()
            .get::<PeerConnectInfo>()
            .and_then(|info| info.spiffe_id.clone())
            .ok_or_else(|| Status::unauthenticated("no authenticated peer identity"))?;

        let req = request.into_inner();

        // 1. Kind gate: only node identities acquire delegated signing keys.
        if caller.kind != IdKind::Node {
            return Err(Status::permission_denied(
                "delegated keys are only issued to node identities",
            ));
        }

        // 2. Caller binding: the authenticated identity MUST equal the
        //    requested node_svid. Never fall back to the claimed field.
        let node_svid: SpiffeId = req
            .node_svid
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid node_svid: {}", e)))?;
        if caller != node_svid {
            return Err(Status::permission_denied(
                "caller identity does not match node_svid",
            ));
        }

        // 3. CA availability (join-mode first boot: CA not yet replicated).
        let ca_bundle = self.ca_data_control.as_ref().ok_or_else(|| {
            Status::unavailable("CA not yet replicated; delegated keys unavailable until catch-up")
        })?;

        let target_svid: SpiffeId = req
            .target_spiffe_id
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid target_spiffe_id: {}", e)))?;

        // TTL cap: 0 or above the configured maximum → capped. Identical
        // arithmetic to the admin path.
        let ttl = if req.requested_ttl_secs == 0
            || req.requested_ttl_secs > self.delegated_key_ttl_secs
        {
            self.delegated_key_ttl_secs
        } else {
            req.requested_ttl_secs
        };

        // Single issuance path: placement verification + pathLen=0 constraint
        // enforced identically to the admin override.
        let verifier = StoragePlacementVerifier::new(self.placements.clone());
        let delegation_req = crate::ca::key_issuance::DelegationRequest {
            node_id: caller.clone(),
            target_svid_id: target_svid.clone(),
            target_ordinal: req.target_ordinal,
            ttl_secs: ttl,
        };
        let bundle =
            crate::ca::key_issuance::issue_delegated_key(&delegation_req, ca_bundle, &verifier)
                .map_err(|e| match e {
                    crate::ca::CaError::PlacementVerification { .. } => {
                        Status::permission_denied(format!("placement verification failed: {}", e))
                    }
                    other => Status::internal(format!("delegated key issuance failed: {}", other)),
                })?;

        let now = time::OffsetDateTime::now_utc();
        let issued_at = now.unix_timestamp();
        let expires_at = issued_at + ttl as i64;
        let refresh_at = issued_at + (ttl as f64 * self.svid_refresh_fraction) as i64;

        let record = crate::delegation::DelegationRecord {
            delegation_id: bundle.delegation_id.clone(),
            node_id: caller.clone(),
            target_svid_id: target_svid.clone(),
            target_ordinal: req.target_ordinal,
            issued_at,
            expires_at,
            refresh_at,
        };

        // G-2/G-3: replicate with an audit context naming the node actor.
        let audit = crate::raft::records::AuditContext {
            request_id: Self::generate_request_id(),
            actor: caller.to_string(),
            target: target_svid.to_string(),
            timestamp_unix: now.unix_timestamp() as u64,
        };
        match self
            .raft
            .client_write(crate::raft::AuditedCommand {
                cmd: crate::raft::FleetosCommand::IssueDelegation { record },
                audit: Some(audit),
            })
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
                tracing::info!(
                    node_id = %caller,
                    leader = %leader_addr,
                    "delegation request redirected to leader (agent retries)"
                );
                return Err(Self::redirect_to_leader(&leader_addr));
            }
            Err(e) => {
                return Err(Status::internal(format!(
                    "delegation replication failed: {}",
                    e
                )));
            }
        }

        tracing::info!(
            node_id = %caller,
            target = %target_svid,
            delegation_id = %bundle.delegation_id,
            ttl_secs = ttl,
            "delegated signing key issued via node-callable path"
        );

        Ok(Response::new(DelegatedKeyResponse {
            delegation_id: bundle.delegation_id.into_bytes(),
            key_material: bundle.key_bytes,
            expires_at_unix: expires_at as u64,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::{Placement, ResourceSpec};

    const NODE_ID: &str = "spiffe://fleet.example.internal/ns/system/node/agent-1";
    const OTHER_NODE_ID: &str = "spiffe://fleet.example.internal/ns/system/node/agent-2";
    const CONTROL_ID: &str = "spiffe://fleet.example.internal/ns/system/control/control-1";
    const TARGET_ID: &str = "spiffe://fleet.example.internal/ns/tenant-1/sa/db";
    const TTL_CAP: u64 = 14400;

    // --- No-op Raft network (mode gate fires before any network use) ---
    struct NoOpNetworkFactory;
    impl openraft::network::RaftNetworkFactory<crate::raft::FleetosRaftConfig> for NoOpNetworkFactory {
        type Network = NoOpNetwork;
        async fn new_client(&mut self, _target: u64, _node: &openraft::BasicNode) -> Self::Network {
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
            openraft::error::RPCError<u64, openraft::BasicNode, openraft::error::RaftError<u64>>,
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
            openraft::error::RPCError<u64, openraft::BasicNode, openraft::error::RaftError<u64>>,
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

    /// Single-node raft + keyspaces + seeded placement + fresh CA.
    async fn setup(
        name: &str,
    ) -> (
        Arc<Raft<crate::raft::FleetosRaftConfig>>,
        crate::storage::Keyspaces,
        Arc<RwLock<TrustBundle>>,
    ) {
        let dir = std::env::temp_dir().join(format!(
            "fleetos-delegation-svc-test-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let db = crate::storage::open_database(&dir).unwrap();
        let keyspaces = crate::storage::init_keyspaces(&db).unwrap();
        let versioned_state =
            crate::storage::version::VersionedState::new(keyspaces.version.clone());
        let broadcast_hub = crate::watch::broadcast::BroadcastHub::new();
        let raft_config = Arc::new(
            openraft::Config {
                heartbeat_interval: 50,
                election_timeout_min: 150,
                election_timeout_max: 300,
                ..Default::default()
            }
            .validate()
            .unwrap(),
        );
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
            "fleet.example.internal".to_owned(),
        );
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
        let mut members = std::collections::BTreeMap::new();
        members.insert(
            1,
            openraft::BasicNode {
                addr: String::new(),
            },
        );
        raft.initialize(members).await.unwrap();

        // Seed a placement: agent-1 hosts tenant-1/db ordinal 0.
        let placement = Placement {
            pod_id: "db-replica-0".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            service: "db".to_owned(),
            role: "replica".to_owned(),
            ordinal: 0,
            node_id: NODE_ID.parse().unwrap(),
            resources: ResourceSpec {
                cpu_millicores: 500,
                memory_bytes: 512 * 1024 * 1024,
            },
        };
        let serialized = postcard::to_allocvec(&placement).unwrap();
        keyspaces
            .placements
            .insert(placement.pod_id.as_bytes(), serialized.as_slice())
            .unwrap();

        let bundle = TrustBundle::generate_root("fleet.example.internal").unwrap();
        (raft, keyspaces, Arc::new(RwLock::new(bundle)))
    }

    fn service(
        raft: Arc<Raft<crate::raft::FleetosRaftConfig>>,
        keyspaces: &crate::storage::Keyspaces,
        ca: Option<Arc<RwLock<TrustBundle>>>,
    ) -> DelegationServiceImpl {
        DelegationServiceImpl::new(
            raft,
            ca,
            keyspaces.placements.clone(),
            TTL_CAP,
            0.75,
            keyspaces.control_addresses.clone(),
        )
    }

    fn request_as(caller: &str, req: DelegatedKeyRequest) -> Request<DelegatedKeyRequest> {
        let mut request = Request::new(req);
        request.extensions_mut().insert(PeerConnectInfo {
            spiffe_id: Some(caller.parse().unwrap()),
        });
        request
    }

    fn standard_request(ttl: u64) -> DelegatedKeyRequest {
        DelegatedKeyRequest {
            node_svid: NODE_ID.to_owned(),
            target_spiffe_id: TARGET_ID.to_owned(),
            target_ordinal: Some(0),
            requested_ttl_secs: ttl,
        }
    }

    // (a) node caller == node_svid → issued, replicated, audited.
    #[tokio::test]
    async fn node_caller_matching_node_svid_is_issued() {
        let (raft, keyspaces, ca) = setup("issued").await;
        let svc = service(raft, &keyspaces, Some(ca));
        let before = time::OffsetDateTime::now_utc().unix_timestamp();
        let resp = svc
            .request_delegated_key(request_as(NODE_ID, standard_request(3600)))
            .await
            .expect("issuance should succeed");
        let inner = resp.into_inner();
        assert!(!inner.delegation_id.is_empty());
        assert!(!inner.key_material.is_empty());
        let after = time::OffsetDateTime::now_utc().unix_timestamp();
        assert!(inner.expires_at_unix >= (before + 3600) as u64);
        assert!(inner.expires_at_unix <= (after + 3600) as u64);

        // IssueDelegation must replicate, and the audit trail must carry
        // the node actor (G-2/G-3).
        let mut delegation_found = false;
        let mut audit_found = false;
        for _ in 0..100 {
            if !delegation_found {
                for guard in keyspaces.active_delegations.prefix(Vec::<u8>::new()) {
                    if guard.value().is_ok() {
                        delegation_found = true;
                        break;
                    }
                }
            }
            if !audit_found {
                for guard in keyspaces.audit_log.prefix(Vec::<u8>::new()) {
                    if let Ok(value) = guard.value() {
                        if let Ok(rec) = postcard::from_bytes::<crate::raft::records::AuditRecord>(
                            value.as_ref(),
                        ) {
                            if rec.actor == NODE_ID && rec.action == "IssueDelegation" {
                                audit_found = true;
                                break;
                            }
                        }
                    }
                }
            }
            if delegation_found && audit_found {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            delegation_found,
            "IssueDelegation must replicate into active_delegations"
        );
        assert!(audit_found, "audit trail must carry the node actor");
    }

    // (b) caller ≠ node_svid → PERMISSION_DENIED.
    #[tokio::test]
    async fn caller_mismatch_is_rejected() {
        let (raft, keyspaces, ca) = setup("mismatch").await;
        let svc = service(raft, &keyspaces, Some(ca));
        let err = svc
            .request_delegated_key(request_as(OTHER_NODE_ID, standard_request(3600)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    // (c) non-node kind → PERMISSION_DENIED.
    #[tokio::test]
    async fn non_node_kind_is_rejected() {
        let (raft, keyspaces, ca) = setup("kind").await;
        let svc = service(raft, &keyspaces, Some(ca));
        // CONTROL-kind caller asking for its own id as node_svid: the kind
        // gate fires before the binding check.
        let mut req = standard_request(3600);
        req.node_svid = CONTROL_ID.to_owned();
        let err = svc
            .request_delegated_key(request_as(CONTROL_ID, req))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    // (d) unauthenticated → UNAUTHENTICATED (missing PeerConnectInfo AND
    // PeerConnectInfo with spiffe_id: None).
    #[tokio::test]
    async fn unauthenticated_is_rejected() {
        let (raft, keyspaces, ca) = setup("unauth").await;
        let svc = service(raft, &keyspaces, Some(ca));
        let err = svc
            .request_delegated_key(Request::new(standard_request(3600)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);

        let mut request = Request::new(standard_request(3600));
        request
            .extensions_mut()
            .insert(PeerConnectInfo { spiffe_id: None });
        let err = svc.request_delegated_key(request).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    // (e) TTL capped: 0 → cap, above cap → cap.
    #[tokio::test]
    async fn ttl_is_capped_to_configured_maximum() {
        let (raft, keyspaces, ca) = setup("ttl-cap").await;
        let svc = service(raft, &keyspaces, Some(ca));
        for ttl in [0u64, TTL_CAP + 9999] {
            let before = time::OffsetDateTime::now_utc().unix_timestamp();
            let resp = svc
                .request_delegated_key(request_as(NODE_ID, standard_request(ttl)))
                .await
                .expect("issuance should succeed");
            let after = time::OffsetDateTime::now_utc().unix_timestamp();
            let expires = resp.into_inner().expires_at_unix;
            assert!(
                expires >= (before + TTL_CAP as i64) as u64
                    && expires <= (after + TTL_CAP as i64) as u64,
                "requested ttl {} must be capped to {}",
                ttl,
                TTL_CAP
            );
        }
    }

    // (f) unplaced target → PERMISSION_DENIED.
    #[tokio::test]
    async fn unplaced_target_is_rejected() {
        let (raft, keyspaces, ca) = setup("unplaced").await;
        let svc = service(raft, &keyspaces, Some(ca));
        let mut req = standard_request(3600);
        req.target_spiffe_id = "spiffe://fleet.example.internal/ns/tenant-1/sa/web".to_owned();
        let err = svc
            .request_delegated_key(request_as(NODE_ID, req))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    // (i, bonus wiring check) CA unavailable → UNAVAILABLE.
    #[tokio::test]
    async fn ca_unavailable_returns_unavailable() {
        let (raft, keyspaces, _ca) = setup("no-ca").await;
        let svc = service(raft, &keyspaces, None);
        let err = svc
            .request_delegated_key(request_as(NODE_ID, standard_request(3600)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }
}
