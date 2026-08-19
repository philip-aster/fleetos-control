//! Delegated SVID signing — the final signing step for `sign_svid_delegated`.
//!
//! When the control plane is unavailable, a node uses its `DelegatedSigningKey`
//! to renew workload SVIDs locally. The security checks (delegation-key
//! expiration, node ID scope match, validity-window bounding) execute in
//! `fleetos-core` — this module provides only the raw signing logic.

use super::CaError;

/// Sign an SVID using a delegated signing key.
///
/// This is called by `fleetos-core::ca::sign_svid_delegated` after it has
/// verified:
/// - The delegation key has not expired
/// - The requested SVID's node_id matches the delegation's node_id scope
/// - The requested SVID's identity matches the delegation's target
/// - The validity window is within the delegation's validity window
///
/// This function performs only the cryptographic signing step.
pub fn sign_with_delegated_key(
    csr_der: &[u8],
    delegated_key_der: &[u8],
    delegated_cert_der: &[u8],
) -> Result<Vec<u8>, CaError> {
    // Parse the CSR.
    // Parse the delegated key (private key for signing).
    // Parse the delegated certificate (to extract issuer info for the new cert).
    // Sign the CSR with the delegated key.
    // Return the signed certificate DER.

    // TODO: Implement using rcgen or ring.
    // The flow:
    // 1. Parse CSR from csr_der
    // 2. Parse private key from delegated_key_der
    // 3. Build a new certificate from the CSR, signed by the delegated key
    // 4. Set the issuer to the delegated certificate's subject
    // 5. Copy extensions from CSR to the new certificate
    // 6. Add the degraded-mode OID extension (set to true)
    // 7. Return the DER-encoded signed certificate

    tracing::debug!(
        csr_len = csr_der.len(),
        key_len = delegated_key_der.len(),
        cert_len = delegated_cert_der.len(),
        "delegated signing (placeholder)"
    );

    Err(CaError::Signing(
        "delegated signing not yet implemented".to_owned(),
    ))
}
