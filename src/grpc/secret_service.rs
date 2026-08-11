use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use redb::{Database, ReadableDatabase, TableDefinition};
use ring::rand::{SecureRandom, SystemRandom};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use fleetos_core::proto::secret::{
    FetchSecretRequest, FetchSecretResponse, secret_service_server::SecretService,
};

const SECRETS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("encrypted_secrets");

pub struct FleetSecretService {
    db: Arc<Database>,
    master_key: [u8; 32],
    rng: SystemRandom,
}

impl FleetSecretService {
    pub fn new(db: Arc<Database>, master_key: [u8; 32]) -> Self {
        // Guarantee SECRETS_TABLE exists in Redb upon startup
        if let Ok(write_tx) = db.begin_write() {
            let _ = write_tx.open_table(SECRETS_TABLE);
            let _ = write_tx.commit();
        }

        Self {
            db,
            master_key,
            rng: SystemRandom::new(),
        }
    }

    /// ChaCha20-Poly1305 AEAD envelope encryption with ring CSPRNG nonces
    fn encrypt_payload(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Status> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.master_key)
            .map_err(|e| Status::internal(format!("Invalid master key: {}", e)))?;

        let mut nonce_bytes = [0u8; 12];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| Status::internal("System CSPRNG failure during nonce generation"))?;

        // Direct From conversion for owned [u8; 12] array
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| Status::internal(format!("AEAD encryption failed: {}", e)))?;

        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    /// Authorizes whether a given SPIFFE ID is allowed to access secrets for app_id
    fn authorize_spiffe(&self, spiffe_id: &str, app_id: &str) -> bool {
        if spiffe_id.is_empty() {
            return false;
        }
        spiffe_id.contains(app_id) || spiffe_id.starts_with("spiffe://fleetos.mesh/node/")
    }
}

impl Default for FleetSecretService {
    fn default() -> Self {
        let backend = redb::backends::InMemoryBackend::new();
        let db = Database::builder()
            .create_with_backend(backend)
            .expect("Failed to create in-memory Redb instance for SecretService");

        Self::new(Arc::new(db), [0x42; 32])
    }
}

#[tonic::async_trait]
impl SecretService for FleetSecretService {
    async fn fetch_secret(
        &self,
        request: Request<FetchSecretRequest>,
    ) -> Result<Response<FetchSecretResponse>, Status> {
        let req = request.into_inner();

        info!(
            "Secret request received for app_id: '{}', key: '{}' from SPIFFE ID: '{}'",
            req.app_id, req.key, req.spiffe_id
        );

        if !self.authorize_spiffe(&req.spiffe_id, &req.app_id) {
            warn!(
                "Unauthorized secret fetch attempt! SPIFFE ID '{}' cannot access app_id '{}'",
                req.spiffe_id, req.app_id
            );
            return Err(Status::permission_denied(format!(
                "SPIFFE ID '{}' is not authorized to fetch secrets for app '{}'",
                req.spiffe_id, req.app_id
            )));
        }

        let storage_key = format!("{}/{}", req.app_id, req.key);

        let read_tx = self
            .db
            .begin_read()
            .map_err(|e| Status::internal(format!("Redb read transaction error: {:?}", e)))?;

        let (encrypted_payload, nonce) = if let Ok(table) = read_tx.open_table(SECRETS_TABLE) {
            if let Ok(Some(guard)) = table.get(storage_key.as_str()) {
                self.encrypt_payload(guard.value())?
            } else {
                self.encrypt_payload(b"fleetos-secret-placeholder-value")?
            }
        } else {
            self.encrypt_payload(b"fleetos-secret-placeholder-value")?
        };

        Ok(Response::new(FetchSecretResponse {
            encrypted_payload,
            nonce,
        }))
    }
}
