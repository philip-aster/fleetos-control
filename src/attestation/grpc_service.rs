//! AttestationService gRPC implementation.

use super::join_token::JoinTokenStore;
use super::nonce::NonceManager;
use super::pcr_policy::PcrPolicyStore;
use fleetos_core::proto::identity::AttestationService;
use fleetos_core::proto::identity::{
    AttestationQuote, AttestedIdentity, NonceRequest, NonceResponse,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};

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
    ) -> Self {
        Self {
            nonce_manager,
            join_token_store,
            pcr_store,
            nonce_claims_keyspace,
            svid_grants_keyspace,
            raft,
            control_addresses,
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
}
