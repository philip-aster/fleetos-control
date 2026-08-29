//! SecretService implementation — pull-based FetchSecret (unary RPC).
//!
//! Agents fetch secrets on demand, authenticated by the existing mTLS channel.
//! Control tracks no per-agent subscription or delivery/ack state.
//!
//! Secret rotation coupling:
//! - A secret sealed to SVID version N becomes permanently unreadable once
//!   the agent rotates past version N.
//! - Control tracks SVID rotation counters and re-seals with the new public key.
//! - SealedSecret includes sequence for replay protection.
use crate::secrets::SecretStore;
use fleetos_core::crypto::{RecipientX25519Pubkey, SecretSequence, seal};
use fleetos_core::proto::secret::SecretService;
use fleetos_core::proto::secret::{FetchSecretRequest, SealedSecret};
use fleetos_core::spiffe::SpiffeId;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// The SecretService gRPC implementation.
pub struct SecretServiceImpl {
    secret_store: Arc<SecretStore>,
    svids_keyspace: fjall::Keyspace, // NEW
    sequence_tracker: Arc<RwLock<HashMap<(String, u64), u64>>>,
}

impl SecretServiceImpl {
    pub fn new(secret_store: Arc<SecretStore>, svids_keyspace: fjall::Keyspace) -> Self {
        Self {
            secret_store,
            svids_keyspace,
            sequence_tracker: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Allocate the next sequence number for a given recipient + SVID version.
    fn next_sequence(&self, spiffe_id: &str, svid_version: u64) -> u64 {
        let mut tracker = self.sequence_tracker.write();
        let key = (spiffe_id.to_owned(), svid_version);
        let seq = tracker.entry(key).or_insert(0);
        *seq += 1;
        *seq
    }

    /// S-10: look up the requester's current tracked SVID version.
    fn lookup_svid_version(&self, spiffe_id: &SpiffeId) -> Result<u64, Status> {
        let key = spiffe_id.to_string();
        let bytes = self
            .svids_keyspace
            .get(key.as_bytes())
            .map_err(|e| Status::internal(format!("storage error: {}", e)))?
            .ok_or_else(|| Status::not_found(format!("no SVID record for {}", spiffe_id)))?;
        let record: crate::ca::SvidRecord = postcard::from_bytes(&bytes)
            .map_err(|e| Status::internal(format!("failed to parse SVID record: {}", e)))?;
        Ok(record.svid_version)
    }
}

#[tonic::async_trait]
impl SecretService for SecretServiceImpl {
    /// Pull-based FetchSecret — unary RPC, not streaming.
    async fn fetch_secret(
        &self,
        request: Request<FetchSecretRequest>,
    ) -> Result<Response<SealedSecret>, Status> {
        // CRITICAL: Extract peer identity from extensions BEFORE into_inner(),
        // which consumes the Request.
        // CRITICAL: Extract peer identity from extensions BEFORE into_inner(),
        // which consumes the Request.
        let connect_info = request
            .extensions()
            .get::<crate::tls::PeerConnectInfo>()
            .cloned()
            .ok_or_else(|| Status::unauthenticated("no peer identity found"))?;
        let requesting_spiffe_id = connect_info
            .spiffe_id
            .ok_or_else(|| Status::unauthenticated("no peer identity found"))?;

        let req = request.into_inner();

        // Parse the target SpiffeId from the request.
        let _target_spiffe_id: SpiffeId = req
            .target_spiffe_id
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid target SpiffeId: {}", e)))?;

        // S-10: enforce SVID version binding. The requester's current SVID version
        // must match the version the secret is sealed for; otherwise the delivery
        // is stale (the agent rotated past it) and must be rejected.
        let requester_version = self.lookup_svid_version(&requesting_spiffe_id)?;
        if requester_version != req.sealed_for_svid_version {
            return Err(Status::permission_denied(format!(
                "SVID version mismatch: secret sealed for version {}, requester has version {}",
                req.sealed_for_svid_version, requester_version
            )));
        }

        // Fetch the secret (ACL check + at-rest decryption happens inside).
        let plaintext = self
            .secret_store
            .fetch_secret(&req.target_spiffe_id, &requesting_spiffe_id)
            .map_err(|e| match e {
                crate::secrets::SecretError::AccessDenied { .. } => {
                    Status::permission_denied(e.to_string())
                }
                crate::secrets::SecretError::NotFound(_) => Status::not_found(e.to_string()),
                _ => Status::internal(e.to_string()),
            })?;

        // Extract the agent's X25519 public key from their current SVID.
        let recipient_pubkey = self
            .lookup_x25519_pubkey(&requesting_spiffe_id)
            .map_err(|e| Status::internal(format!("failed to get recipient pubkey: {}", e)))?;

        // Allocate the next sequence number for replay protection.
        let sequence = self.next_sequence(&req.target_spiffe_id, req.sealed_for_svid_version);

        // Seal for delivery using fleetos_core::crypto::seal().
        let sealed = seal(
            &recipient_pubkey,
            &plaintext,
            req.sealed_for_svid_version,
            SecretSequence(sequence),
        )
        .map_err(|e| Status::internal(format!("sealing failed: {}", e)))?;

        tracing::info!(
            target_spiffe_id = %req.target_spiffe_id,
            svid_version = req.sealed_for_svid_version,
            sequence = sequence,
            "secret fetched and sealed for delivery"
        );

        Ok(Response::new(SealedSecret {
            target_spiffe_id: req.target_spiffe_id,
            sealed_for_svid_version: sealed.sealed_for_svid_version,
            sequence: sealed.sequence.0,
            ephemeral_pubkey: sealed.ephemeral_pubkey.to_vec(),
            ciphertext: sealed.ciphertext,
        }))
    }
}

impl SecretServiceImpl {
    /// Look up the X25519 public key for a given SpiffeId.
    ///
    /// The agent registers its X25519 pubkey during the attestation/join flow.
    /// This is stored in the svids keyspace keyed by the agent's SpiffeId string.
    fn lookup_x25519_pubkey(&self, spiffe_id: &SpiffeId) -> Result<RecipientX25519Pubkey, String> {
        let key = spiffe_id.to_string();
        let bytes = self
            .svids_keyspace
            .get(key.as_bytes())
            .map_err(|e| format!("storage error: {}", e))?
            .ok_or_else(|| format!("X25519 pubkey not registered for {}", spiffe_id))?;

        if bytes.len() != 32 {
            return Err(format!(
                "invalid X25519 pubkey length: expected 32, got {}",
                bytes.len()
            ));
        }

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(bytes.as_ref());
        Ok(RecipientX25519Pubkey(pubkey))
    }
}
