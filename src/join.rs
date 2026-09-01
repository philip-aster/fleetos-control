//! Join mode client.
//!
//! Two responsibilities:
//! 1. `join_cluster` — attest to an existing control node over plaintext gRPC
//!    (the joiner has no SVID yet), and come away with a signed SVID plus the
//!    cluster trust bundle.
//! 2. `request_membership` — ask the cluster to add us as a learner (blocking
//!    until we catch up) and promote us to voter, via the internal
//!    `RaftTransport.RequestJoin` RPC. Follows leader redirects automatically.
use crate::raft::{JoinRequestPayload, JoinResponsePayload, RaftRpc};
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
    #[error("redirect to leader: {0}")]
    Redirect(String),
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

/// Extract a leader redirect address from a gRPC status, if present.
fn leader_redirect(status: &tonic::Status) -> Option<String> {
    if status.code() != tonic::Code::Unavailable {
        return None;
    }
    status
        .metadata()
        .get("leader-dc-address")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned())
}

/// Execute the full join flow against an existing control node.
///
/// Follows leader redirects: if `submit_quote` lands on a follower, the
/// follower returns the leader's Data/Control address and we restart the
/// attestation against the leader (V-2 leader-directed attestation).
pub async fn join_cluster(
    join_target: &str,
    join_token: &str,
    node_name: &str,
    trust_domain: &str,
    join_trust_bundle_pem: &str,
) -> Result<JoinResult, JoinError> {
    tracing::info!(
        join_target = %join_target,
        node_name = %node_name,
        "beginning join flow"
    );

    let mut target = channel_addr(join_target);
    loop {
        // Attestation leg: server-trust TLS (trust the DC root bundle,
        // no client cert — the joiner is pre-SVID).
        let tls_config = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(tonic::transport::Certificate::from_pem(
                join_trust_bundle_pem,
            ))
            .domain_name(trust_domain);
        let channel = tonic::transport::Channel::from_shared(target.clone())
            .map_err(|e| JoinError::Connection(e.to_string()))?
            .tls_config(tls_config)
            .map_err(|e| JoinError::Connection(e.to_string()))?
            .connect()
            .await
            .map_err(|e| JoinError::Connection(e.to_string()))?;

        let mut attestation_client = AttestationServiceClient::new(channel.clone());
        let claimed_spiffe_id =
            format!("spiffe://{}/ns/system/control/{}", trust_domain, node_name);

        // 2. RequestNonce — fresh attestation challenge.
        let nonce = match attestation_client
            .request_nonce(NonceRequest {
                claimed_spiffe_id: claimed_spiffe_id.clone(),
            })
            .await
        {
            Ok(r) => r.into_inner().nonce,
            Err(status) => {
                if let Some(leader) = leader_redirect(&status) {
                    tracing::info!(leader = %leader, "redirecting attestation to leader");
                    target = channel_addr(&leader);
                    continue;
                }
                return Err(JoinError::Attestation(status.to_string()));
            }
        };
        tracing::debug!(nonce_len = nonce.len(), "attestation nonce received");

        // 3. SubmitQuote — construct a TPM quote bound to the nonce.
        //
        // SECURITY (Master findings M-2/S-11): the quote below is a STRUCTURAL
        // PLACEHOLDER — zeroed quote/signature bytes. The server-side verifiers
        // (attestation/tpm.rs, attestation/apple_se.rs) currently check structure
        // and nonce binding only, not cryptographic signatures. Until real quote
        // generation (client) and signature verification (server) land,
        // control-plane join is gated by JOIN-TOKEN POSSESSION ALONE. Treat join
        // tokens as high-value secrets: they are single-use and TTL-bounded
        // (default 1h), but a leaked token yields a voter.
        let tpm_quote = crate::attestation::tpm::TpmQuote {
            quote_bytes: vec![0u8; 32],         // Placeholder TPM quote structure
            signature: vec![0u8; 64],           // Placeholder signature
            nonce: nonce.clone(),               // Bound to the issued nonce
            pcr_selection: Vec::new(),          // No PCR values for control-plane join
            attestation_key_pub: vec![0u8; 32], // Placeholder attestation key
        };
        let raw_quote = postcard::to_allocvec(&tpm_quote)
            .map_err(|e| JoinError::Attestation(format!("quote serialization failed: {}", e)))?;
        let quote = AttestationQuote {
            join_token: join_token.to_owned(),
            quote_type: 0, // TPM
            raw_quote,
            ..Default::default()
        };

        let attested_identity = match attestation_client.submit_quote(quote).await {
            Ok(r) => r.into_inner(),
            Err(status) => {
                if let Some(leader) = leader_redirect(&status) {
                    tracing::info!(leader = %leader, "redirecting attestation to leader");
                    target = channel_addr(&leader);
                    continue; // restart attestation against the leader
                }
                return Err(JoinError::Attestation(status.to_string()));
            }
        };
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
        let csr_bundle = crate::ca::rcgen_impl::build_csr(&csr_params)
            .map_err(|e| JoinError::Csr(e.to_string()))?;

        // 5. SubmitCsr — get the signed SVID (same channel = leader).
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

        return Ok(JoinResult {
            svid_cert_der: svid_response.cert_chain_der,
            svid_key_der: csr_bundle.private_key.to_vec(),
            trust_bundle_pem,
            claimed_spiffe_id: attested_identity.claimed_spiffe_id,
        });
    }
}

/// Request cluster membership: add as learner (blocking until caught up),
/// then promote to voter. Follows leader redirects. Retries forever —
/// this only runs on a first join boot and must eventually succeed or
/// keep trying.
pub async fn request_membership(
    join_raft_target: &str,
    node_id: u64,
    our_raft_addr: &str,
    our_dc_addr: &str,
    svid_cert_der: &[u8],
    svid_key_der: &[u8],
    trust_bundle_pem: &str,
    trust_domain: &str,
) -> Result<(), JoinError> {
    let mut target = join_raft_target.to_owned();
    let payload = postcard::to_allocvec(&JoinRequestPayload {
        node_id,
        address: our_raft_addr.to_owned(),
        dc_address: our_dc_addr.to_owned(),
    })?;

    // Membership leg: full mTLS with the SVID from the attestation leg.
    let cert_pem = der_to_pem(svid_cert_der, "CERTIFICATE").map_err(JoinError::Membership)?;
    let key_pem = der_to_pem(svid_key_der, "PRIVATE KEY").map_err(JoinError::Membership)?;
    let identity = tonic::transport::Identity::from_pem(cert_pem, key_pem);

    loop {
        let tls_config = tonic::transport::ClientTlsConfig::new()
            .identity(identity.clone())
            .ca_certificate(tonic::transport::Certificate::from_pem(trust_bundle_pem))
            .domain_name(trust_domain);
        match crate::raft::connect_raft_client_tls(channel_addr(&target), tls_config).await {
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
                // Long-running RPC (blocking add_learner + snapshot transfer)
                // can fail mid-way; safe to retry — add_learner is idempotent.
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
