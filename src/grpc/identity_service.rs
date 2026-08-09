use crate::storage::models::PodRole;
use fleetos_core::SpiffeId;
use fleetos_core::attestor::HardwareAttestor;
use fleetos_core::attestor::mock::MockHardwareAttestor;
use fleetos_core::proto::identity::{
    AttestNodeRequest, AttestNodeResponse, MintWorkloadRequest, MintWorkloadResponse,
    identity_service_server::IdentityService,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};
use tracing::{info, warn};

pub struct FleetIdentityService {
    mock_attestor: MockHardwareAttestor,
}

impl Default for FleetIdentityService {
    fn default() -> Self {
        Self::new()
    }
}

impl FleetIdentityService {
    pub fn new() -> Self {
        Self {
            mock_attestor: MockHardwareAttestor::new(),
        }
    }

    /// Verifies if a given SPIFFE ID matches the expected PodRole constraints
    pub fn authorize_role(&self, spiffe_id: &str, role: &PodRole) -> Result<(), Status> {
        if let Some(ref required_spiffe) = role.spiffe_id {
            if spiffe_id != required_spiffe {
                warn!(
                    "Role authorization failed: Expected SPIFFE ID '{}', got '{}'",
                    required_spiffe, spiffe_id
                );
                return Err(Status::permission_denied(format!(
                    "Unauthorized: SPIFFE ID '{}' does not match role requirements for '{}'",
                    spiffe_id, role.role_name
                )));
            }
        }

        info!(
            "SPIFFE ID '{}' successfully authorized for role '{}'",
            spiffe_id, role.role_name
        );
        Ok(())
    }
}

#[tonic::async_trait]
impl IdentityService for FleetIdentityService {
    async fn attest_node(
        &self,
        request: Request<AttestNodeRequest>,
    ) -> Result<Response<AttestNodeResponse>, Status> {
        let req = request.into_inner();
        info!(
            "Received node attestation request with join token: {}",
            req.join_token
        );

        // Map proto PCR entries to fleetos_core attestation payload
        let payload = fleetos_core::attestor::AttestationPayload {
            public_identity_key: req.public_identity_key.clone(),
            signature_quote: req.signature_quote,
            pcr_values: req
                .pcr_values
                .into_iter()
                .map(|p| fleetos_core::attestor::PcrEntry {
                    pcr_index: p.index,
                    digest: p.digest,
                })
                .collect(),
        };

        let nonce = b"fleetos-attestation-nonce";
        let valid = self
            .mock_attestor
            .verify_quote(&payload, nonce)
            .await
            .map_err(|e| Status::internal(format!("Attestation verification failed: {}", e)))?;

        if !valid {
            return Err(Status::unauthenticated(
                "Invalid hardware attestation quote",
            ));
        }

        let node_hash = if req.public_identity_key.len() >= 4 {
            hex::encode(&req.public_identity_key[..4])
        } else {
            "default".to_string()
        };

        let spiffe_id = format!("spiffe://fleetos.mesh/node/node-{}", node_hash);
        info!(
            "Node successfully attested! Assigned SPIFFE ID: {}",
            spiffe_id
        );

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expires_at_unix = now + (24 * 3600);

        Ok(Response::new(AttestNodeResponse {
            spiffe_id,
            svid_certificate_pem: vec![0x30; 64], // DER/PEM X.509 SVID cert
            private_key_pem: vec![0x30; 32],      // Private key
            expires_at_unix,
        }))
    }

    async fn mint_workload_svid(
        &self,
        request: Request<MintWorkloadRequest>,
    ) -> Result<Response<MintWorkloadResponse>, Status> {
        let req = request.into_inner();

        info!(
            "Minting workload X.509 SVID for service: {}, role: {}",
            req.service_name, req.role_name
        );

        let spiffe_id =
            SpiffeId::new_workload("fleetos.mesh", "default", &req.service_name, &req.role_name)
                .to_uri();

        let expires_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Status::internal(e.to_string()))?
            .as_secs()
            + (24 * 3600);

        Ok(Response::new(MintWorkloadResponse {
            spiffe_id,
            svid_certificate_pem: vec![0x30; 64], // DER/PEM X.509 SVID cert
            expires_at_unix,
        }))
    }
}
