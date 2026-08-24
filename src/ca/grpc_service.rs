//! CaService gRPC implementation.
//!
//! Handles SVID issuance and trust bundle distribution:
//! 1. `SubmitCsr` — signs a CSR and returns the SVID certificate
//! 2. `GetTrustBundle` — returns the current trust bundle (root CA certs)
//!
//! This service runs on the Data/Control listener. The caller must already
//! have a valid SVID (authenticated via mTLS) to call SubmitCsr.
//! GetTrustBundle may be called during initial join (pre-SVID).
use super::rcgen_impl;
use super::trust_bundle::TrustBundle as InternalTrustBundle;
use fleetos_core::proto::identity::CaService;
use fleetos_core::proto::identity::{CsrRequest, SvidResponse, TrustBundle, TrustBundleRequest};
use parking_lot::RwLock;
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// The CaService gRPC implementation.
pub struct CaServiceImpl {
    /// Data/Control trust domain CA.
    data_control: Arc<RwLock<InternalTrustBundle>>,
    /// SVID TTL configuration.
    svid_ttl_secs: u64,
}

impl CaServiceImpl {
    pub fn new(data_control: Arc<RwLock<InternalTrustBundle>>, svid_ttl_secs: u64) -> Self {
        Self {
            data_control,
            svid_ttl_secs,
        }
    }
}

#[tonic::async_trait]
impl CaService for CaServiceImpl {
    /// Sign a CSR and return the SVID certificate.
    ///
    /// The agent generates a keypair, creates a CSR with its SPIFFE ID as
    /// URI SAN, and submits it here. The CA signs the CSR and returns the
    /// certificate. The agent retains its own private key.
    async fn submit_csr(
        &self,
        request: Request<CsrRequest>,
    ) -> Result<Response<SvidResponse>, Status> {
        let req = request.into_inner();

        if req.csr_der.is_empty() {
            return Err(Status::invalid_argument("csr_der cannot be empty"));
        }

        // Sign the CSR with the Data/Control CA.
        let bundle = self.data_control.read();
        let cert_der = rcgen_impl::sign_csr(
            &req.csr_der,
            &bundle.current_key,
            &bundle.current_params,
            self.svid_ttl_secs,
        )
        .map_err(|e| Status::internal(format!("CSR signing failed: {}", e)))?;

        tracing::info!(cert_len = cert_der.len(), "SVID issued via CSR signing");

        Ok(Response::new(SvidResponse {
            cert_chain_der: cert_der,
            // Empty for CSR-based signing — the agent retains its own private key.
            keypair_der: Vec::new(),
            // TODO: Implement SVID version tracking for rotation.
            svid_version: 1,
        }))
    }

    /// Return the current trust bundle (root CA certificates).
    ///
    /// This is used by agents to validate SVIDs issued by this CA.
    /// Returns the Data/Control trust domain's root certificates.
    async fn get_trust_bundle(
        &self,
        _request: Request<TrustBundleRequest>,
    ) -> Result<Response<TrustBundle>, Status> {
        let bundle = self.data_control.read();

        // Collect root certificates (current + previous if mid-rotation).
        let mut roots_der = vec![bundle.current_cert_der.clone()];
        if let Some(ref previous) = bundle.previous {
            roots_der.push(previous.cert_der.clone());
        }

        Ok(Response::new(TrustBundle {
            trust_domain: bundle.trust_domain.clone(),
            roots_der,
        }))
    }
}
