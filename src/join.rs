//! Join mode client.
//!
//! Two responsibilities:
//! 1. `join_cluster` — attest to an existing control node over plaintext gRPC
//!    (the joiner has no SVID yet), and come away with a signed SVID plus the
//!    cluster trust bundle.
//! 2. `request_membership` — ask the cluster to add us as a learner (blocking
//!    until we catch up) and promote us to voter, via the internal
//!    `RaftTransport.RequestJoin` RPC. Follows leader redirects automatically.
use crate::raft::{JoinRequestPayload, JoinResponsePayload, RaftRpc, RaftTransportClient};
use fleetos_core::proto::fleetos::attestation_service_client::AttestationServiceClient;
use fleetos_core::proto::fleetos::ca_service_client::CaServiceClient;
use fleetos_core::proto::identity::{
    AttestationQuote, CsrRequest, NonceRequest, TrustBundleRequest,
};
use std::time::Duration;

/// Errors from the join flow.
#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("connection failed: {0}")]
    Connection(String),
    #[error("attestation failed: {0}")]
    Attestation(String),
    #[error("CSR generation failed: {0}")]
    Csr(String),
    #[error("SVID issuance failed: {0}")]
    Svid(String),
    #[error("trust bundle retrieval failed: {0}")]
    TrustBundle(String),
    #[error("membership request failed: {0}")]
    Membership(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),
}

/// Result of a successful join attestation.
pub struct JoinResult {
    /// DER-encoded SVID certificate.
    pub svid_cert_der: Vec<u8>,
    /// DER-encoded PKCS#8 private key for the SVID.
    pub svid_key_der: Vec<u8>,
    /// PEM-encoded trust bundle (root CA certs) for mTLS.
    pub trust_bundle_pem: String,
    /// The SPIFFE ID assigned to this node.
    pub claimed_spiffe_id: String,
}

fn channel_addr(addr: &str) -> String {
    if addr.starts_with("http") {
        addr.to_owned()
    } else {
        format!("http://{}", addr)
    }
}

/// Execute the full join flow against an existing control node.
pub async fn join_cluster(
    join_target: &str,
    join_token: &str,
    node_name: &str,
    trust_domain: &str,
) -> Result<JoinResult, JoinError> {
    tracing::info!(
        join_target = %join_target,
        node_name = %node_name,
        "beginning join flow"
    );

    // 1. Connect to join_target via plaintext gRPC (no mTLS yet — we have no SVID).
    let channel = tonic::transport::Channel::from_shared(channel_addr(join_target))
        .map_err(|e| JoinError::Connection(e.to_string()))?
        .connect()
        .await
        .map_err(|e| JoinError::Connection(e.to_string()))?;

    // 2. RequestNonce — fresh attestation challenge.
    let mut attestation_client = AttestationServiceClient::new(channel.clone());
    let claimed_spiffe_id = format!("spiffe://{}/ns/system/control/{}", trust_domain, node_name);
    let nonce = attestation_client
        .request_nonce(NonceRequest {
            claimed_spiffe_id: claimed_spiffe_id.clone(),
        })
        .await
        .map_err(|e| JoinError::Attestation(e.to_string()))?
        .into_inner()
        .nonce;

    tracing::debug!(nonce_len = nonce.len(), "attestation nonce received");

    // 3. SubmitQuote — join token + quote. Full hardware-quote verification
    //    is Step 7; the server currently authorizes on the single-use token.
    let quote = AttestationQuote {
        join_token: join_token.to_owned(),
        quote_type: 0, // TPM
        raw_quote: nonce,
        ..Default::default()
    };
    let attested_identity = attestation_client
        .submit_quote(quote)
        .await
        .map_err(|e| JoinError::Attestation(e.to_string()))?
        .into_inner();

    tracing::info!(
        claimed_spiffe_id = %attested_identity.claimed_spiffe_id,
        "attestation successful"
    );

    // 4. Generate keypair + CSR with the attested SPIFFE ID.
    let csr_params = crate::ca::rcgen_impl::SvidParams {
        spiffe_id: attested_identity.claimed_spiffe_id.clone(),
        kind: crate::ca::rcgen_impl::SvidKind::Control,
        role: None,
        ordinal: None,
        degraded: false,
        ttl_secs: 3600,
    };
    let csr_bundle =
        crate::ca::rcgen_impl::build_csr(&csr_params).map_err(|e| JoinError::Csr(e.to_string()))?;

    // 5. SubmitCsr — get the signed SVID.
    let mut ca_client = CaServiceClient::new(channel.clone());
    let svid_response = ca_client
        .submit_csr(CsrRequest {
            csr_der: csr_bundle.csr_der.clone(),
        })
        .await
        .map_err(|e| JoinError::Svid(e.to_string()))?
        .into_inner();

    tracing::info!(cert_len = svid_response.cert_chain_der.len(), "SVID issued");

    // 6. GetTrustBundle — root certs for mTLS validation.
    let trust_bundle_response = ca_client
        .get_trust_bundle(TrustBundleRequest {})
        .await
        .map_err(|e| JoinError::TrustBundle(e.to_string()))?
        .into_inner();

    let mut trust_bundle_pem = String::new();
    for root_der in &trust_bundle_response.roots_der {
        let pem = der_to_pem(root_der, "CERTIFICATE").map_err(JoinError::TrustBundle)?;
        trust_bundle_pem.push_str(&pem);
    }

    tracing::info!(
        trust_domain = %trust_bundle_response.trust_domain,
        roots_count = trust_bundle_response.roots_der.len(),
        "trust bundle retrieved"
    );

    Ok(JoinResult {
        svid_cert_der: svid_response.cert_chain_der,
        svid_key_der: csr_bundle.private_key.to_vec(),
        trust_bundle_pem,
        claimed_spiffe_id: attested_identity.claimed_spiffe_id,
    })
}

/// Request cluster membership: add as learner (blocking until caught up),
/// then promote to voter. Follows leader redirects. Retries forever —
/// this only runs on a first join boot and must eventually succeed or
/// keep trying.
pub async fn request_membership(
    join_raft_target: &str,
    node_id: u64,
    our_raft_addr: &str,
) -> Result<(), JoinError> {
    let mut target = join_raft_target.to_owned();
    let payload = postcard::to_allocvec(&JoinRequestPayload {
        node_id,
        address: our_raft_addr.to_owned(),
    })?;

    loop {
        match RaftTransportClient::connect(channel_addr(&target)).await {
            Ok(mut client) => {
                let rpc = RaftRpc {
                    sender_id: node_id,
                    target_id: 0,
                    payload: payload.clone(),
                };
                match client.request_join(rpc).await {
                    Ok(resp) => {
                        let join_resp: JoinResponsePayload =
                            postcard::from_bytes(&resp.into_inner().payload)?;
                        if join_resp.success {
                            tracing::info!(node_id, "membership request accepted");
                            return Ok(());
                        }
                        match join_resp.leader_address {
                            Some(addr) if addr != target => {
                                tracing::info!(leader = %addr, "redirecting join request to leader");
                                target = addr;
                                continue;
                            }
                            _ => {
                                tracing::warn!("join request rejected, retrying");
                            }
                        }
                    }
                    Err(e) => {
                        // Long-running RPC (blocking add_learner + snapshot transfer)
                        // can fail mid-way; safe to retry — add_learner is idempotent.
                        tracing::warn!(error = %e, "join request RPC failed, retrying");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, target = %target, "cannot reach cluster, retrying");
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Convert DER bytes to PEM format.
fn der_to_pem(der: &[u8], label: &str) -> Result<String, String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let b64 = STANDARD.encode(der);
    let mut pem = String::new();
    pem.push_str(&format!("-----BEGIN {}-----\n", label));
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).map_err(|e| e.to_string())?);
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    Ok(pem)
}
