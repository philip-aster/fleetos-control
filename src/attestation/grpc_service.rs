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
    data_control: Option<Arc<parking_lot::RwLock<crate::ca::trust_bundle::TrustBundle>>>,
    svid_ttl_secs: u64,
    attestation_mode: crate::config::AttestationMode,
    #[cfg_attr(not(feature = "tpm"), allow(dead_code))]
    tpm_config: crate::config::TpmConfig,
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
        data_control: Option<Arc<parking_lot::RwLock<crate::ca::trust_bundle::TrustBundle>>>,
        svid_ttl_secs: u64,
        attestation_mode: crate::config::AttestationMode,
        tpm_config: crate::config::TpmConfig,
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
            tpm_config,
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
            agent_x25519_pubkey: quote.agent_x25519_pubkey.clone(),
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
        // fail closed if the CA hasn't been replicated yet (first join boot).
        if self.data_control.is_none() {
            return Err(Status::unavailable(
                "CA not yet replicated; secure attestation unavailable until catch-up",
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

        if req.ek_cert_der.is_empty() && req.ek_pub.is_empty() {
            return Err(Status::invalid_argument(
                "either ek_cert_der or ek_pub must be provided",
            ));
        }
        // Step 8 (ATT-EKVAL): validate the EK certificate chain if present.
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

        // Generate the server nonce and a fresh 32-byte secret S.
        let server_nonce = self
            .nonce_manager
            .generate_nonce()
            .map_err(|e| Status::internal(format!("nonce generation failed: {}", e)))?;

        let mut secret = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut secret);

        // Record the pending activation (node-local, transient).
        let now = time::OffsetDateTime::now_utc();
        let record = PendingActivationRecord {
            ek_fingerprint: fp_hex.clone(),
            ak_pub: req.ak_pub.clone(),
            server_nonce: server_nonce.clone(),
            secret: secret.to_vec(),
            created_at: now.unix_timestamp(),
            expires_at: now.unix_timestamp() + 300, // 5 minute TTL
        };

        let record_bytes = postcard::to_allocvec(&record)
            .map_err(|e| Status::internal(format!("record serialization failed: {}", e)))?;
        self.pending_activations
            .insert(server_nonce.as_slice(), record_bytes.as_slice())
            .map_err(|e| Status::internal(format!("failed to persist activation: {}", e)))?;

        // Resolve the EK public key in SPKI DER form for the TPM.
        // Prefer the raw SPKI if provided; otherwise extract it from the EK certificate.
        let ek_spki_der: Vec<u8> = if !req.ek_pub.is_empty() {
            req.ek_pub.clone()
        } else {
            extract_spki_from_cert(&req.ek_cert_der)
                .map_err(|e| Status::internal(format!("EK SPKI extraction failed: {}", e)))?
        };

        // TPM2_MakeCredential (Step 10). Feature-gated.
        #[cfg(not(feature = "tpm"))]
        {
            let _ = ek_spki_der; // suppress unused variable warning when tpm is disabled
            return Err(Status::unimplemented(
                "TPM2_MakeCredential requires the `tpm` feature (tss-esapi).",
            ));
        }

        #[cfg(feature = "tpm")]
        {
            let (credential_blob, enc_secret) = crate::attestation::tpm::make_credential(
                &self.tpm_config,
                &ek_spki_der,
                &req.ak_pub,
                &secret,
            )
            .map_err(|e| Status::internal(format!("TPM2_MakeCredential failed: {}", e)))?;

            tracing::info!(
                ek_fingerprint = %fp_hex,
                "activation challenge issued (TPM2_MakeCredential)"
            );

            Ok(Response::new(ActivationChallenge {
                credential_blob,
                secret: enc_secret,
                server_nonce,
            }))
        }
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
        // NEW: extract the CA guard early, returning UNAVAILABLE if missing.
        let bundle_guard = self.data_control.as_ref().ok_or_else(|| {
            Status::unavailable(
                "CA not yet replicated; secure attestation unavailable until catch-up",
            )
        })?;
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
        let cert_der = {
            let bundle = bundle_guard.read();
            crate::ca::rcgen_impl::sign_csr(
                &req.csr_der,
                &bundle.current_key,
                &bundle.current_cert_der,
                self.svid_ttl_secs,
            )
            .map_err(|e| Status::internal(format!("CSR signing failed: {}", e)))?
        };

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

/// Extract the SubjectPublicKeyInfo DER from an X.509 certificate.
/// Used to feed the EK public key to TPM2_MakeCredential.
/// Uses `x509-cert` to guarantee byte-for-byte convergence with
/// `fleetos_core::attestation::EkFingerprint::of_ek_cert`.
fn extract_spki_from_cert(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    use x509_cert::Certificate;
    use x509_cert::der::{Decode, Encode};

    let cert = Certificate::from_der(cert_der).map_err(|e| format!("cert parse failed: {}", e))?;

    cert.tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| format!("SPKI re-encode failed: {}", e))
}

#[cfg(test)]
mod mode_enforcement_tests {
    use super::*;
    use crate::config::AttestationMode;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tonic::Code;

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

    /// Build a real AttestationServiceImpl backed by a single-node Raft, in the given mode.
    async fn service_with_mode(name: &str, mode: AttestationMode) -> AttestationServiceImpl {
        let dir = std::env::temp_dir().join(format!(
            "fleetos-attest-mode-{}-{}",
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
            "test.example.internal".to_owned(),
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
        let mut members = BTreeMap::new();
        members.insert(
            1,
            openraft::BasicNode {
                addr: String::new(),
            },
        );
        raft.initialize(members).await.unwrap();

        let bundle =
            crate::ca::trust_bundle::TrustBundle::generate_root("test.example.internal").unwrap();

        AttestationServiceImpl::new(
            Arc::new(crate::attestation::nonce::NonceManager::new(
                keyspaces.nonces.clone(),
            )),
            Arc::new(crate::attestation::join_token::JoinTokenStore::new(
                keyspaces.join_tokens.clone(),
            )),
            Arc::new(crate::attestation::pcr_policy::PcrPolicyStore::new(
                keyspaces.pcr_policies.clone(),
            )),
            keyspaces.nonce_claims.clone(),
            keyspaces.svid_grants.clone(),
            raft,
            keyspaces.control_addresses.clone(),
            keyspaces.node_eks.clone(),
            keyspaces.pending_activations.clone(),
            Some(Arc::new(parking_lot::RwLock::new(bundle))),
            3600,
            mode,
            crate::config::TpmConfig::default(),
        )
    }

    fn is_mode_gate(err: &tonic::Status) -> bool {
        err.code() == Code::PermissionDenied && err.message().contains("disabled in")
    }

    // --- secure mode: insecure flow rejected, secure flow passes the gate ---

    #[tokio::test]
    async fn secure_mode_rejects_request_nonce() {
        let svc = service_with_mode("sec-nonce", AttestationMode::Secure).await;
        let err = svc
            .request_nonce(Request::new(NonceRequest {
                claimed_spiffe_id: "spiffe://test.example.internal/ns/system/node/n1".into(),
            }))
            .await
            .unwrap_err();
        assert!(
            is_mode_gate(&err),
            "expected mode-gate reject, got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn secure_mode_rejects_submit_quote() {
        let svc = service_with_mode("sec-quote", AttestationMode::Secure).await;
        let err = svc
            .submit_quote(Request::new(AttestationQuote::default()))
            .await
            .unwrap_err();
        assert!(
            is_mode_gate(&err),
            "expected mode-gate reject, got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn secure_mode_passes_request_activation_gate() {
        let svc = service_with_mode("sec-act", AttestationMode::Secure).await;
        // Empty ak_pub fails validation (InvalidArgument), proving it got PAST the mode gate.
        let err = svc
            .request_activation(Request::new(ActivationRequest::default()))
            .await
            .unwrap_err();
        assert!(
            !is_mode_gate(&err),
            "must not be a mode-gate reject, got {:?}",
            err
        );
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn secure_mode_passes_submit_activation_proof_gate() {
        let svc = service_with_mode("sec-proof", AttestationMode::Secure).await;
        // Empty hmac fails validation (InvalidArgument), proving it got PAST the mode gate.
        let err = svc
            .submit_activation_proof(Request::new(ActivationProof::default()))
            .await
            .unwrap_err();
        assert!(
            !is_mode_gate(&err),
            "must not be a mode-gate reject, got {:?}",
            err
        );
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    // --- insecure mode: insecure flow allowed, secure flow rejected (current code) ---

    #[tokio::test]
    async fn insecure_mode_allows_request_nonce() {
        let svc = service_with_mode("ins-nonce", AttestationMode::Insecure).await;
        let resp = svc
            .request_nonce(Request::new(NonceRequest {
                claimed_spiffe_id: "spiffe://test.example.internal/ns/system/node/n1".into(),
            }))
            .await;
        assert!(
            resp.is_ok(),
            "insecure mode must serve RequestNonce, got {:?}",
            resp.err()
        );
    }

    #[tokio::test]
    async fn insecure_mode_passes_submit_quote_gate() {
        let svc = service_with_mode("ins-quote", AttestationMode::Insecure).await;
        // Empty join_token fails validation (InvalidArgument), proving it got PAST the mode gate.
        let err = svc
            .submit_quote(Request::new(AttestationQuote::default()))
            .await
            .unwrap_err();
        assert!(
            !is_mode_gate(&err),
            "must not be a mode-gate reject, got {:?}",
            err
        );
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    // DECISION-DEPENDENT: matches current code (reject). Flip to "passes gate"
    // if we adopt the handover's "insecure allows both."
    #[tokio::test]
    async fn insecure_mode_rejects_request_activation() {
        let svc = service_with_mode("ins-act", AttestationMode::Insecure).await;
        let err = svc
            .request_activation(Request::new(ActivationRequest::default()))
            .await
            .unwrap_err();
        assert!(
            is_mode_gate(&err),
            "expected mode-gate reject, got {:?}",
            err
        );
    }

    // DECISION-DEPENDENT: matches current code (reject).
    #[tokio::test]
    async fn insecure_mode_rejects_submit_activation_proof() {
        let svc = service_with_mode("ins-proof", AttestationMode::Insecure).await;
        let err = svc
            .submit_activation_proof(Request::new(ActivationProof::default()))
            .await
            .unwrap_err();
        assert!(
            is_mode_gate(&err),
            "expected mode-gate reject, got {:?}",
            err
        );
    }

    // --- config surface ---

    #[test]
    fn attestation_mode_deserializes_both_variants() {
        // `toml::from_str` requires a full TOML document (key = value), not a
        // bare value. Deserialize through AttestationConfig — the actual
        // config path that carries the `mode` field.
        let insecure: crate::config::AttestationConfig =
            toml::from_str("mode = \"insecure\"").unwrap();
        assert_eq!(insecure.mode, AttestationMode::Insecure);

        let secure: crate::config::AttestationConfig = toml::from_str("mode = \"secure\"").unwrap();
        assert_eq!(secure.mode, AttestationMode::Secure);
    }

    #[test]
    fn attestation_mode_defaults_to_insecure_when_omitted() {
        // Fail-safe default: an omitted [attestation].mode must not silently
        // enable the secure path, and must not panic.
        let cfg: crate::config::AttestationConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.mode, AttestationMode::Insecure);
    }
}
