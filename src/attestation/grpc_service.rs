//! AttestationService gRPC implementation.
//!
//! Handles the attestation flow for nodes joining the cluster:
//! 1. `RequestNonce` — issues a fresh nonce for the attestation challenge
//! 2. `SubmitQuote` — verifies the hardware quote and join token, returns attested identity
//!
//! This service runs on the Data/Control listener (unauthenticated initially —
//! the node doesn't have an SVID yet, that's the whole point of attestation).
use super::join_token::JoinTokenStore;
use super::nonce::NonceManager;
use super::pcr_policy::PcrPolicyStore;
use fleetos_core::proto::identity::AttestationService;
use fleetos_core::proto::identity::{
    AttestationQuote, AttestedIdentity, NonceRequest, NonceResponse,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// The AttestationService gRPC implementation.
pub struct AttestationServiceImpl {
    nonce_manager: Arc<NonceManager>,
    join_token_store: Arc<JoinTokenStore>,
    #[allow(dead_code)]
    pcr_store: Arc<PcrPolicyStore>,
    /// Maps nonce → claimed_spiffe_id for correlating RequestNonce with SubmitQuote.
    /// TODO: Wire to persistent storage for multi-node consistency.
    nonce_claims: Arc<RwLock<HashMap<Vec<u8>, String>>>,
}

impl AttestationServiceImpl {
    pub fn new(
        nonce_manager: Arc<NonceManager>,
        join_token_store: Arc<JoinTokenStore>,
        pcr_store: Arc<PcrPolicyStore>,
    ) -> Self {
        Self {
            nonce_manager,
            join_token_store,
            pcr_store,
            nonce_claims: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[tonic::async_trait]
impl AttestationService for AttestationServiceImpl {
    /// Issue a fresh nonce for an attestation challenge.
    ///
    /// Every attestation attempt requires a nonce we generated.
    /// A captured quote from a previous join is worthless without the matching nonce.
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

        // Generate a fresh cryptographically-random nonce.
        let nonce = self
            .nonce_manager
            .generate()
            .map_err(|e| Status::internal(format!("nonce generation failed: {}", e)))?;

        // Store the nonce → claimed_spiffe_id association for SubmitQuote correlation.
        self.nonce_claims
            .write()
            .insert(nonce.clone(), req.claimed_spiffe_id.clone());

        tracing::info!(
            claimed_spiffe_id = %req.claimed_spiffe_id,
            "attestation nonce issued"
        );

        Ok(Response::new(NonceResponse { nonce }))
    }

    /// Verify a hardware attestation quote and join token.
    ///
    /// Flow:
    /// 1. Validate and consume the join token (strict single-use)
    /// 2. Deserialize the raw quote based on quote_type
    /// 3. Extract the nonce from the quote and validate against NonceManager
    /// 4. Correlate the nonce with the claimed SpiffeId from RequestNonce
    /// 5. Verify the quote signature and PCR values
    /// 6. Return the attested identity with the verified claimed SpiffeId
    async fn submit_quote(
        &self,
        request: Request<AttestationQuote>,
    ) -> Result<Response<AttestedIdentity>, Status> {
        let quote = request.into_inner();

        // Validate join token is present.
        if quote.join_token.is_empty() {
            return Err(Status::invalid_argument(
                "join_token is required for initial attestation",
            ));
        }

        // Validate and consume the join token (strict single-use).
        let token_bytes = quote.join_token.as_bytes().to_vec();
        let token_record = self
            .join_token_store
            .validate_and_consume(&token_bytes)
            .map_err(|e| {
                Status::permission_denied(format!("join token validation failed: {}", e))
            })?;

        // Deserialize the raw quote based on quote_type and extract the nonce.
        // The raw_quote is a postcard-serialized TpmQuote or AppleSeAttestation.
        let (extracted_nonce, claimed_spiffe_id) = match quote.quote_type {
            // TPM2 quote
            0 => {
                let tpm_quote: super::tpm::TpmQuote = postcard::from_bytes(&quote.raw_quote)
                    .map_err(|e| {
                        Status::invalid_argument(format!("failed to parse TPM quote: {}", e))
                    })?;

                // Validate the nonce against the NonceManager (single-use).
                let nonce_valid = self
                    .nonce_manager
                    .validate_and_consume(&tpm_quote.nonce)
                    .map_err(|e| Status::internal(format!("nonce validation failed: {}", e)))?;
                if !nonce_valid {
                    return Err(Status::permission_denied(
                        "attestation nonce is invalid or already consumed",
                    ));
                }

                // Look up the claimed SpiffeId associated with this nonce.
                let claimed = self
                    .nonce_claims
                    .read()
                    .get(&tpm_quote.nonce)
                    .cloned()
                    .ok_or_else(|| {
                        Status::permission_denied("no claimed identity for this nonce")
                    })?;

                // Verify PCR values against the expected policy for this node.
                // The node_id is derived from the claimed SpiffeId for PCR policy lookup.
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
                    // No PCR policy configured — verify with empty expected set.
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
            // Apple Secure Enclave quote
            1 => {
                let se_attestation: super::apple_se::AppleSeAttestation =
                    postcard::from_bytes(&quote.raw_quote).map_err(|e| {
                        Status::invalid_argument(format!(
                            "failed to parse Apple SE attestation: {}",
                            e
                        ))
                    })?;

                // Validate the nonce against the NonceManager (single-use).
                let nonce_valid = self
                    .nonce_manager
                    .validate_and_consume(&se_attestation.nonce)
                    .map_err(|e| Status::internal(format!("nonce validation failed: {}", e)))?;
                if !nonce_valid {
                    return Err(Status::permission_denied(
                        "attestation nonce is invalid or already consumed",
                    ));
                }

                // Look up the claimed SpiffeId associated with this nonce.
                let claimed = self
                    .nonce_claims
                    .read()
                    .get(&se_attestation.nonce)
                    .cloned()
                    .ok_or_else(|| {
                        Status::permission_denied("no claimed identity for this nonce")
                    })?;

                // Verify the Apple SE attestation.
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
        self.nonce_claims.write().remove(&extracted_nonce);

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
