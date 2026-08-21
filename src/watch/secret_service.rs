//! SecretService implementation — pull-based FetchSecret (unary RPC).
//!
//! Agents fetch secrets on demand, authenticated by the existing mTLS channel.
//! Control tracks no per-agent subscription or delivery/ack state.
//!
//! The one thing control pushes is a lightweight rotation notification over
//! WatchService — "the secret for this SpiffeId changed, refetch" — not the
//! secret payload itself.
//!
//! Secret rotation coupling:
//! - A secret sealed to SVID version N becomes permanently unreadable once
//!   the agent rotates past version N.
//! - Control tracks SVID rotation counters and re-seals with the new public key.
//! - SealedSecret includes sequence for replay protection.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use fleetos_core::proto::secret::SecretService;
use fleetos_core::proto::secret::{FetchSecretRequest, SealedSecret};
use fleetos_core::spiffe::SpiffeId;

use crate::secrets::SecretStore;

/// The SecretService gRPC implementation.
pub struct SecretServiceImpl {
    secret_store: Arc<SecretStore>,
}

impl SecretServiceImpl {
    pub fn new(secret_store: Arc<SecretStore>) -> Self {
        Self { secret_store }
    }
}

#[tonic::async_trait]
impl SecretService for SecretServiceImpl {
    /// Pull-based FetchSecret — unary RPC, not streaming.
    ///
    /// The request specifies the target_spiffe_id (the workload whose secret
    /// is being fetched) and sealed_for_svid_version (the SVID version to
    /// seal the secret for).
    ///
    /// We:
    /// 1. Extract the requesting agent's SpiffeId from the mTLS certificate
    /// 2. Check the ACL (is this agent authorized for this secret?)
    /// 3. Decrypt the secret at rest (envelope encryption)
    /// 4. Re-seal for delivery using fleetos_core::crypto::seal()
    /// 5. Return the sealed secret
    async fn fetch_secret(
        &self,
        request: Request<FetchSecretRequest>,
    ) -> Result<Response<SealedSecret>, Status> {
        let req = request.into_inner();

        // Parse the target SpiffeId from the request.
        let target_spiffe_id: SpiffeId = req
            .target_spiffe_id
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid target SpiffeId: {}", e)))?;

        // TODO: Extract the requesting agent's SpiffeId from the mTLS peer certificate.
        // In production, this comes from the TLS connection's peer certificate SAN.
        // For now, we use the target_spiffe_id as a placeholder.
        let requesting_spiffe_id = target_spiffe_id.clone();

        // Fetch the secret (ACL check + at-rest decryption happens inside).
        let _plaintext = self
            .secret_store
            .fetch_secret(&req.target_spiffe_id, &requesting_spiffe_id)
            .map_err(|e| match e {
                crate::secrets::SecretError::AccessDenied { .. } => {
                    Status::permission_denied(e.to_string())
                }
                crate::secrets::SecretError::NotFound(_) => Status::not_found(e.to_string()),
                _ => Status::internal(e.to_string()),
            })?;

        // TODO: Re-seal for delivery using fleetos_core::crypto::seal().
        // This requires:
        // 1. Extract the agent's X25519 public key from their current SVID
        // 2. Call fleetos_core::crypto::seal(recipient_pubkey, plaintext, svid_version, sequence)
        // 3. Return the SealedSecret with ephemeral_pubkey, ciphertext, sequence
        //
        // For now, return a placeholder SealedSecret.

        tracing::info!(
            target_spiffe_id = %req.target_spiffe_id,
            svid_version = req.sealed_for_svid_version,
            "secret fetched (pull-based)"
        );

        Ok(Response::new(SealedSecret {
            target_spiffe_id: req.target_spiffe_id,
            sealed_for_svid_version: req.sealed_for_svid_version,
            sequence: 0,                     // TODO: proper sequence tracking
            ephemeral_pubkey: vec![0u8; 32], // TODO: actual X25519 ephemeral pubkey
            ciphertext: Vec::new(),          // TODO: actual sealed ciphertext
        }))
    }
}
