//! AttestationService gRPC implementation.

use super::join_token::JoinTokenStore;
use super::nonce::NonceManager;
use super::pcr_policy::PcrPolicyStore;
use fleetos_core::proto::identity::{
    ActivationChallenge, ActivationProof, ActivationRequest, AttestationQuote, AttestationService,
    AttestedIdentity, NonceRequest, NonceResponse, SvidResponse,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// Node-local pending activation state for secure attestation (CR-10).
/// Keyed by server_nonce. NOT replicated — transient, per-connection.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PendingActivationRecord {
    ek_fingerprint: String,
    ak_pub: Vec<u8>,
    server_nonce: Vec<u8>,
    secret: Vec<u8>,
    created_at: i64,
    expires_at: i64,
}

/// The AttestationService gRPC implementation.
pub struct AttestationServiceImpl {
    nonce_manager: Arc<NonceManager>,
    join_token_store: Arc<JoinTokenStore>,
    pcr_store: Arc<PcrPolicyStore>,
    /// Keyspace mapping issued nonce -> claimed SPIFFE ID from RequestNonce.
    /// Persisted to fjall so claims survive control-plane restarts.
    nonce_claims_keyspace: fjall::Keyspace,
    /// Single-use CSR issuance grants keyed by attested SPIFFE ID (M-3).
    svid_grants_keyspace: fjall::Keyspace,
    raft: Arc<openraft::Raft<crate::raft::FleetosRaftConfig>>,
    control_addresses: fjall::Keyspace,
    node_eks: fjall::Keyspace,
    pending_activations: fjall::Keyspace,
    data_control: Arc<parking_lot::RwLock<crate::ca::trust_bundle::TrustBundle>>,
    svid_ttl_secs: u64,
    attestation_mode: crate::config::AttestationMode,
}

impl AttestationServiceImpl {
    pub fn new(
        nonce_manager: Arc<NonceManager>,
        join_token_store: Arc<JoinTokenStore>,
        pcr_store: Arc<PcrPolicyStore>,
        nonce_claims_keyspace: fjall::Keyspace,
        svid_grants_keyspace: fjall::Keyspace,
        raft: Arc<openraft::Raft<crate::raft::FleetosRaftConfig>>,
        control_addresses: fjall::Keyspace,
        node_eks: fjall::Keyspace,
        pending_activations: fjall::Keyspace,
        data_control: Arc<parking_lot::RwLock<crate::ca::trust_bundle::TrustBundle>>,
        svid_ttl_secs: u64,
        attestation_mode: crate::config::AttestationMode,
    ) -> Self {
        Self {
            nonce_manager,
            join_token_store,
            pcr_store,
            nonce_claims_keyspace,
            svid_grants_keyspace,
            raft,
            control_addresses,
            node_eks,
            pending_activations,
            data_control,
            svid_ttl_secs,
            attestation_mode,
        }
    }

    /// Load the claimed SpiffeId persisted for a nonce by RequestNonce.
    fn lookup_nonce_claim(&self, nonce: &[u8]) -> Result<String, Status> {
        let claimed_bytes = self
            .nonce_claims_keyspace
            .get(nonce)
            .map_err(|e| Status::internal(format!("nonce claim lookup failed: {}", e)))?
            .ok_or_else(|| Status::permission_denied("no claimed identity for this nonce"))?;
        String::from_utf8(claimed_bytes.to_vec())
            .map_err(|_| Status::internal("corrupt nonce claim".to_owned()))
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

    /// Build a gRPC status that tells the join client to retry against the leader.
    fn redirect_to_leader(leader_addr: &str) -> Status {
        let mut status = Status::unavailable("not the Raft leader; retry against the leader");
        if let Ok(v) = tonic::metadata::MetadataValue::try_from(leader_addr) {
            status.metadata_mut().insert("leader-dc-address", v);
        }
        status
    }
}

#[tonic::async_trait]
impl AttestationService for AttestationServiceImpl {
    async fn request_nonce(
        &self,
        request: Request<NonceRequest>,
    ) -> Result<Response<NonceResponse>, Status> {
        if self.attestation_mode == crate::config::AttestationMode::Secure {
            return Err(Status::permission_denied(
                "insecure (join-token) attestation is disabled in secure mode",
            ));
        }
        let req = request.into_inner();
        if req.claimed_spiffe_id.is_empty() {
            return Err(Status::invalid_argument(
                "claimed_spiffe_id cannot be empty",
            ));
        }

        let nonce = self.nonce_manager.generate_nonce().map_err(|e| match e {
            super::AttestationError::RateLimited(msg) => Status::resource_exhausted(msg),
            other => Status::internal(format!("nonce generation failed: {}", other)),
        })?;

        // Persist the claim for this nonce: nonce -> claimed SPIFFE ID.
        self.nonce_claims_keyspace
            .insert(nonce.as_slice(), req.claimed_spiffe_id.as_bytes())
            .map_err(|e| Status::internal(format!("failed to persist nonce claim: {}", e)))?;

        tracing::info!(
            claimed_spiffe_id = %req.claimed_spiffe_id,
            "attestation nonce issued"
        );

        Ok(Response::new(NonceResponse { nonce }))
    }

    async fn submit_quote(
        &self,
        request: Request<AttestationQuote>,
    ) -> Result<Response<AttestedIdentity>, Status> {
        if self.attestation_mode == crate::config::AttestationMode::Secure {
            return Err(Status::permission_denied(
                "insecure (join-token) attestation is disabled in secure mode",
            ));
        }

        let quote = request.into_inner();

        if quote.join_token.is_empty() {
            return Err(Status::invalid_argument(
                "join_token is required for initial attestation",
            ));
        }

        let token_bytes = quote.join_token.as_bytes().to_vec();
        // Read-only validation; removal happens in the Raft state machine.
        let token_record = self
            .join_token_store
            .validate_only(&token_bytes)
            .map_err(|e| {
                Status::permission_denied(format!("join token validation failed: {}", e))
            })?;

        let (extracted_nonce, claimed_spiffe_id) = match quote.quote_type {
            0 => {
                let tpm_quote: super::tpm::TpmQuote = postcard::from_bytes(&quote.raw_quote)
                    .map_err(|e| {
                        Status::invalid_argument(format!("failed to parse TPM quote: {}", e))
                    })?;

                let nonce_valid = self
                    .nonce_manager
                    .validate_and_consume(&tpm_quote.nonce)
                    .map_err(|e| Status::internal(format!("nonce validation failed: {}", e)))?;
                if !nonce_valid {
                    return Err(Status::permission_denied(
                        "attestation nonce is invalid or already consumed",
                    ));
                }

                let claimed = self.lookup_nonce_claim(&tpm_quote.nonce)?;

                if let Some(expected_pcrs) = self
                    .pcr_store
                    .get_expected_pcrs(&claimed)
                    .map_err(|e| Status::internal(format!("PCR policy lookup failed: {}", e)))?
                {
                    super::tpm::verify_tpm_quote(&tpm_quote, &tpm_quote.nonce, &expected_pcrs)
                        .map_err(|e| {
                            Status::permission_denied(format!(
                                "TPM quote verification failed: {}",
                                e
                            ))
                        })?;
                } else {
                    super::tpm::verify_tpm_quote(&tpm_quote, &tpm_quote.nonce, &[]).map_err(
                        |e| {
                            Status::permission_denied(format!(
                                "TPM quote verification failed: {}",
                                e
                            ))
                        },
                    )?;
                }

                (tpm_quote.nonce, claimed)
            }
            1 => {
                let se_attestation: super::apple_se::AppleSeAttestation =
                    postcard::from_bytes(&quote.raw_quote).map_err(|e| {
                        Status::invalid_argument(format!(
                            "failed to parse Apple SE attestation: {}",
                            e
                        ))
                    })?;

                let nonce_valid = self
                    .nonce_manager
                    .validate_and_consume(&se_attestation.nonce)
                    .map_err(|e| Status::internal(format!("nonce validation failed: {}", e)))?;
                if !nonce_valid {
                    return Err(Status::permission_denied(
                        "attestation nonce is invalid or already consumed",
                    ));
                }

                let claimed = self.lookup_nonce_claim(&se_attestation.nonce)?;

                super::apple_se::verify_apple_se_attestation(
                    &se_attestation,
                    &se_attestation.nonce,
                )
                .map_err(|e| {
                    Status::permission_denied(format!("Apple SE attestation failed: {}", e))
                })?;

                (se_attestation.nonce, claimed)
            }
            other => {
                return Err(Status::invalid_argument(format!(
                    "unsupported quote_type: {}",
                    other
                )));
            }
        };
        // M-2(b): bind the claimed SPIFFE ID kind to the join token's node_kind.
        // A join token minted for one node kind may only attest an identity of the
        // matching kind. Secure mode supersedes this via EK binding (node_eks
        // registry); this is defense-in-depth for the insecure/testing path.
        let claimed_spiffe: fleetos_core::spiffe::SpiffeId =
            claimed_spiffe_id.parse().map_err(|e| {
                Status::invalid_argument(format!("claimed SPIFFE ID is malformed: {}", e))
            })?;
        let expected_kind = match token_record.node_kind {
            crate::attestation::join_token::NodeKind::Agent => fleetos_core::spiffe::IdKind::Node,
            crate::attestation::join_token::NodeKind::Router => {
                fleetos_core::spiffe::IdKind::Router
            }
            crate::attestation::join_token::NodeKind::Gateway => {
                fleetos_core::spiffe::IdKind::Gateway
            }
            crate::attestation::join_token::NodeKind::Control => {
                fleetos_core::spiffe::IdKind::Control
            }
            crate::attestation::join_token::NodeKind::FleetctlProxy => {
                fleetos_core::spiffe::IdKind::Ctrl
            }
        };
        if claimed_spiffe.kind != expected_kind {
            return Err(Status::permission_denied(format!(
                "claimed SPIFFE ID kind '{:?}' does not match join token node_kind '{:?}'",
                claimed_spiffe.kind, token_record.node_kind
            )));
        }

        // Consume the join token through Raft (cluster-wide single use, V-2).
        match self
            .raft
            .client_write(crate::raft::AuditedCommand::system(
                crate::raft::FleetosCommand::ConsumeJoinToken { token: token_bytes },
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
            Err(e) => return Err(Status::internal(format!("token consumption failed: {}", e))),
        }

        // Clean up the nonce claim after successful verification.
        self.nonce_claims_keyspace
            .remove(&extracted_nonce)
            .map_err(|e| Status::internal(format!("nonce claim cleanup failed: {}", e)))?;

        let now = time::OffsetDateTime::now_utc();

        // M-3: mint the single-use CSR issuance grant bound to this attested
        // identity. This grant is the ONLY path to SubmitCsr without mTLS;
        // SubmitCsr consumes it. Note: grants are node-local — the join flow
        // pins RequestNonce/SubmitQuote/SubmitCsr to one channel/target, so
        // all three RPCs hit this node.
        let grant = crate::ca::SvidGrantRecord {
            spiffe_id: claimed_spiffe_id.clone(),
            node_kind: token_record.node_kind as u8,
            granted_at: now.unix_timestamp(),
            expires_at: now.unix_timestamp() + crate::ca::SVID_GRANT_TTL_SECS,
        };
        let grant_bytes = postcard::to_allocvec(&grant)
            .map_err(|e| Status::internal(format!("grant serialization failed: {}", e)))?;
        self.svid_grants_keyspace
            .insert(claimed_spiffe_id.as_bytes(), grant_bytes.as_slice())
            .map_err(|e| Status::internal(format!("failed to persist CSR grant: {}", e)))?;

        tracing::info!(
            claimed_spiffe_id = %claimed_spiffe_id,
            node_kind = ?token_record.node_kind,
            quote_type = quote.quote_type,
            "attestation quote verified"
        );

        Ok(Response::new(AttestedIdentity {
            claimed_spiffe_id,
            quote_type: quote.quote_type,
            pcr_digest: Vec::new(),
            verified_at_unix: now.unix_timestamp(),
        }))
    }

    async fn request_activation(
        &self,
        request: Request<ActivationRequest>,
    ) -> Result<Response<ActivationChallenge>, Status> {
        if self.attestation_mode == crate::config::AttestationMode::Insecure {
            return Err(Status::permission_denied(
                "secure (credential-activation) attestation is disabled in insecure mode",
            ));
        }

        let req = request.into_inner();

        // Validate input.
        if req.ak_pub.is_empty() {
            return Err(Status::invalid_argument("ak_pub cannot be empty"));
        }
        if req.ek_cert_der.is_empty() && req.ek_pub.is_empty() {
            return Err(Status::invalid_argument(
                "either ek_cert_der or ek_pub must be provided",
            ));
        }

        // Compute EK fingerprint — fleetos-core owns the convention (CR-11).
        let fingerprint = if !req.ek_cert_der.is_empty() {
            fleetos_core::attestation::EkFingerprint::of_ek_cert(&req.ek_cert_der).map_err(|e| {
                Status::invalid_argument(format!("EK cert extraction failed: {}", e))
            })?
        } else {
            fleetos_core::attestation::EkFingerprint::of_ek_pub(&req.ek_pub)
        };
        let fp_hex = fingerprint.to_hex();

        // Look up EK registration — fail closed.
        let ek_bytes = self
            .node_eks
            .get(fp_hex.as_bytes())
            .map_err(|e| Status::internal(format!("EK lookup failed: {}", e)))?
            .ok_or_else(|| Status::permission_denied("EK not registered"))?;

        let ek_record: crate::raft::records::NodeEkRecord = postcard::from_bytes(&ek_bytes)
            .map_err(|e| Status::internal(format!("corrupt EK record: {}", e)))?;

        // Check state.
        if ek_record.state == crate::raft::records::EkRegistrationState::Revoked {
            return Err(Status::permission_denied(
                "EK registration has been revoked",
            ));
        }

        // Check TTL expiry.
        if let Some(expires_at) = ek_record.expires_at {
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            if now > expires_at {
                return Err(Status::permission_denied("EK registration has expired"));
            }
        }

        // TPM2_MakeCredential requires tss-esapi + TPM hardware.
        // CR-10 security gate: the activation path is NOT production-enabled
        // until TPM signature verification lands in attestation/tpm.rs.
        // TODO: Generate server nonce + secret S, store PendingActivationRecord,
        //       call TPM2_MakeCredential(ek_pub, ak_pub, S), return the blob.
        Err(Status::unimplemented(
            "TPM2_MakeCredential requires tss-esapi integration (not yet implemented). \
             Secure attestation is not production-enabled until TPM verification lands.",
        ))
    }

    async fn submit_activation_proof(
        &self,
        request: Request<ActivationProof>,
    ) -> Result<Response<SvidResponse>, Status> {
        if self.attestation_mode == crate::config::AttestationMode::Insecure {
            return Err(Status::permission_denied(
                "secure (credential-activation) attestation is disabled in insecure mode",
            ));
        }

        let req = request.into_inner();

        if req.hmac.is_empty() {
            return Err(Status::invalid_argument("hmac cannot be empty"));
        }
        if req.csr_der.is_empty() {
            return Err(Status::invalid_argument("csr_der cannot be empty"));
        }

        // Find the matching pending activation by trying HMAC verification
        // against each stored record. The number of pending activations is
        // small (bounded by the nonce cap).
        let mut matched: Option<PendingActivationRecord> = None;
        let mut matched_nonce: Option<Vec<u8>> = None;
        for guard in self.pending_activations.prefix(Vec::<u8>::new()) {
            // FIX: use into_inner() to get both key and value without moving guard twice
            let (key, value) = match guard.into_inner() {
                Ok(kv) => kv,
                Err(e) => {
                    tracing::warn!(error = %e, "pending activation read failed");
                    continue;
                }
            };
            if let Ok(record) = postcard::from_bytes::<PendingActivationRecord>(value.as_ref()) {
                // Check expiry.
                let now = time::OffsetDateTime::now_utc().unix_timestamp();
                if now > record.expires_at {
                    continue;
                }
                // Verify HMAC(key=S, payload=server_nonce) using BLAKE3 keyed hash.
                let expected = blake3::keyed_hash(
                    record
                        .secret
                        .as_slice()
                        .try_into()
                        .map_err(|_| Status::internal("invalid secret length"))?,
                    &record.server_nonce,
                );
                if expected.as_bytes() == req.hmac.as_slice() {
                    matched = Some(record);
                    matched_nonce = Some(key.to_vec());
                    break;
                }
            }
        }

        let record = matched.ok_or_else(|| {
            Status::permission_denied("no matching pending activation for this HMAC proof")
        })?;

        // Consume the pending activation (single-use).
        if let Some(nonce_key) = matched_nonce {
            let _ = self.pending_activations.remove(nonce_key.as_slice());
        }

        // Verify PCR quote — structural placeholder.
        // TODO: Implement real TPM quote signature verification using tss-esapi.
        // Until then, this is a structural check only (nonce binding + non-empty).
        if req.quote.is_empty() {
            return Err(Status::invalid_argument("quote cannot be empty"));
        }
        if req.quote_signature.is_empty() {
            return Err(Status::invalid_argument("quote_signature cannot be empty"));
        }

        // Extract SPIFFE ID from the CSR.
        // Extract SPIFFE ID from the CSR.
        let spiffe_id = crate::ca::rcgen_impl::extract_spiffe_id_from_csr(&req.csr_der)
            .map_err(|e| Status::invalid_argument(format!("CSR validation failed: {}", e)))?;

        // Sign the CSR using the Data/Control CA.
        // FIX: Scope the read lock so the RwLockReadGuard is dropped BEFORE the .await
        let cert_der = {
            let bundle = self.data_control.read();
            crate::ca::rcgen_impl::sign_csr(
                &req.csr_der,
                &bundle.current_key,
                &bundle.current_cert_der,
                self.svid_ttl_secs,
            )
            .map_err(|e| Status::internal(format!("CSR signing failed: {}", e)))?
        }; // bundle dropped here

        // Propose ActivateNodeEk via Raft (Pending → Joined).
        match self
            .raft
            .client_write(crate::raft::AuditedCommand::system(
                crate::raft::FleetosCommand::ActivateNodeEk {
                    ek_fingerprint: record.ek_fingerprint.clone(),
                    node_id: spiffe_id.clone(),
                },
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
            Err(e) => return Err(Status::internal(format!("node activation failed: {}", e))),
        }

        tracing::info!(
            ek_fingerprint = %record.ek_fingerprint,
            spiffe_id = %spiffe_id,
            "secure attestation complete, node activated"
        );

        Ok(Response::new(SvidResponse {
            cert_chain_der: cert_der,
            keypair_der: Vec::new(), // Node holds its own private key (CR-10).
            svid_version: 1,
        }))
    }
}
