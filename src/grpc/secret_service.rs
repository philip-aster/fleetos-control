use fleetos_core::proto::secret::{
    FetchSecretRequest, FetchSecretResponse, secret_service_server::SecretService,
};
use tonic::{Request, Response, Status};
use tracing::info;

#[derive(Default)]
pub struct FleetSecretService;

impl FleetSecretService {
    pub fn new() -> Self {
        Self
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

        // Placeholder for AEAD envelope decryption and SPIFFE ACL check
        Ok(Response::new(FetchSecretResponse {
            encrypted_payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            nonce: vec![0x01; 12],
        }))
    }
}
