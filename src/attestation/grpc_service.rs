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
}

impl AttestationServiceImpl {
    pub fn new(
        nonce_manager: Arc<NonceManager>,
        join_token_store: Arc<JoinTokenStore>,
        pcr_store: Arc<PcrPolicyStore>,
        nonce_claims_keyspace: fjall::Keyspace,
    ) -> Self {
        Self {
            nonce_manager,
            join_token_store,
            pcr_store,
            nonce_claims_keyspace,
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

        let nonce = self
            .nonce_manager
            .generate_nonce()
            .map_err(|e| Status::internal(format!("nonce generation failed: {}", e)))?;

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
        let token_record = self
            .join_token_store
            .validate_and_consume(&token_bytes)
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

        // Clean up the nonce claim after successful verification.
        self.nonce_claims_keyspace
            .remove(&extracted_nonce)
            .map_err(|e| Status::internal(format!("nonce claim cleanup failed: {}", e)))?;

        let now = time::OffsetDateTime::now_utc();
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
