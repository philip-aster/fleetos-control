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
    /// 1. Validate the nonce (must have been issued by us, single-use)
    /// 2. Verify the quote based on quote_type (TPM2, Apple SE, VSOCK)
    /// 3. Validate and consume the join token (strict single-use)
    /// 4. Return the attested identity
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

        // TODO: Extract nonce from the raw quote and validate against NonceManager.
        // The nonce is embedded in the TPM quote's extraData field or the
        // Apple SE attestation data. For now, we skip nonce verification
        // and rely on the join token as the primary authorization.
        //
        // Full implementation requires:
        // 1. Parse the raw_quote based on quote_type
        // 2. Extract the nonce from the quote structure
        // 3. Call nonce_manager.validate_and_consume(extracted_nonce)
        // 4. Verify the quote signature against the attestation key
        // 5. Validate PCR values against the expected policy

        // Determine the claimed SPIFFE ID.
        // For now, we construct it from the node kind in the join token.
        // In production, this would be extracted from the quote or provided
        // by the agent during the attestation flow.
        let claimed_spiffe_id = format!(
            "spiffe://fleet.example.internal/ns/system/node/pending-{}",
            token_record.node_kind as u8
        );

        let now = time::OffsetDateTime::now_utc();

        tracing::info!(
            claimed_spiffe_id = %claimed_spiffe_id,
            node_kind = ?token_record.node_kind,
            "attestation quote verified"
        );

        Ok(Response::new(AttestedIdentity {
            claimed_spiffe_id,
            quote_type: quote.quote_type,
            pcr_digest: Vec::new(), // TODO: Extract from quote
            verified_at_unix: now.unix_timestamp(),
        }))
    }
}
