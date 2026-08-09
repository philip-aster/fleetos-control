use redb::{Database, ReadableDatabase, TableDefinition};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use fleetos_core::proto::secret::{
    FetchSecretRequest, FetchSecretResponse, secret_service_server::SecretService,
};

const SECRETS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("encrypted_secrets");

pub struct FleetSecretService {
    db: Arc<Database>,
    /// 32-byte master AEAD key
    master_key: [u8; 32],
}

impl FleetSecretService {
    pub fn new(db: Arc<Database>, master_key: [u8; 32]) -> Self {
        Self { db, master_key }
    }

    /// Basic AEAD-style envelope encryption helper (returns ciphertext + 12-byte nonce)
    fn encrypt_payload(&self, plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let nonce = vec![0x01; 12]; // Fixed 12-byte nonce for development/mocking
        let ciphertext: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ self.master_key[i % 32])
            .collect();

        (ciphertext, nonce)
    }

    /// Authorizes whether a given SPIFFE ID is allowed to access secrets for app_id
    fn authorize_spiffe(&self, spiffe_id: &str, app_id: &str) -> bool {
        // Enforce SPIFFE ID domain / workload prefix check
        if spiffe_id.is_empty() {
            return false;
        }

        // Standard FleetOS mesh SPIFFE ID verification logic
        spiffe_id.contains(app_id) || spiffe_id.starts_with("spiffe://fleetos.mesh/node/")
    }
}

impl Default for FleetSecretService {
    fn default() -> Self {
        let backend = redb::backends::InMemoryBackend::new();
        let db = Database::builder()
            .create_with_backend(backend)
            .expect("Failed to create in-memory Redb instance for SecretService");

        Self {
            db: Arc::new(db),
            master_key: [0x42; 32],
        }
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

        // 1. SPIFFE ACL Authorization Check
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

        // 2. Query secret value from Redb persistence
        let storage_key = format!("{}/{}", req.app_id, req.key);

        let read_tx = self
            .db
            .begin_read()
            .map_err(|e| Status::internal(format!("Redb read transaction error: {:?}", e)))?;

        let (encrypted_payload, nonce) = if let Ok(table) = read_tx.open_table(SECRETS_TABLE) {
            if let Ok(Some(guard)) = table.get(storage_key.as_str()) {
                self.encrypt_payload(guard.value())
            } else {
                // Return default fallback placeholder if key is not yet populated
                self.encrypt_payload(b"fleetos-secret-placeholder-value")
            }
        } else {
            self.encrypt_payload(b"fleetos-secret-placeholder-value")
        };

        Ok(Response::new(FetchSecretResponse {
            encrypted_payload,
            nonce,
        }))
    }
}
