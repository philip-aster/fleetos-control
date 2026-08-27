//! Apple Secure Enclave attestation verification.
//!
//! Verifies attestation from `fleetctl` on macOS workstations.
//! `AttestedIdentity` output shape is identical to TPM — `fleetctl-proxy`
//! does not need backend-specific handling.
//!
//! Requires `security-framework` crate (macOS only).
//! Feature-gated: only compiled on `target_os = "macos"` with `apple-se` feature.

//! SECURITY (Master findings M-2/S-11): until the verification TODO below is
//! implemented, attestation checks are STRUCTURAL ONLY — nonce binding plus
//! non-empty fields. Control-plane join is currently gated by join-token
//! possession alone.
use super::AttestationError;

/// An Apple Secure Enclave attestation submission.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AppleSeAttestation {
    /// The attestation data from the Secure Enclave.
    pub attestation_data: Vec<u8>,

    /// The nonce that was bound into this attestation.
    pub nonce: Vec<u8>,

    /// The device's public key (for verification).
    pub device_public_key: Vec<u8>,

    /// Optional: DCOS (Device Check OS) attestation token.
    pub dcos_token: Option<Vec<u8>>,
}

/// Verify an Apple Secure Enclave attestation.
///
/// This implements the `QuoteVerifier` trait from `fleetos-core::attestation`
/// for the Apple SE backend.
///
/// Verification steps:
/// 1. Verify the nonce matches the one we issued
/// 2. Verify the attestation signature using the device public key
/// 3. Optionally validate DCOS token for additional device integrity
pub fn verify_apple_se_attestation(
    attestation: &AppleSeAttestation,
    expected_nonce: &[u8],
) -> Result<(), AttestationError> {
    // Step 1: Verify nonce matches.
    if attestation.nonce != expected_nonce {
        return Err(AttestationError::Nonce(
            "attestation nonce does not match issued nonce".to_owned(),
        ));
    }

    // Step 2: Verify attestation signature.
    // TODO: Implement actual Apple SE verification using security-framework.
    // This requires:
    // 1. Parse the attestation data
    // 2. Verify the signature using device_public_key
    // 3. Confirm the attestation's nonce field matches our issued nonce
    //
    // For now, this is a placeholder that validates structure only.
    if attestation.attestation_data.is_empty() {
        return Err(AttestationError::QuoteVerification(
            "empty attestation data".to_owned(),
        ));
    }
    if attestation.device_public_key.is_empty() {
        return Err(AttestationError::QuoteVerification(
            "empty device public key".to_owned(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_mismatch_rejected() {
        let attestation = AppleSeAttestation {
            attestation_data: vec![1, 2, 3],
            nonce: vec![0xAA; 32],
            device_public_key: vec![4, 5, 6],
            dcos_token: None,
        };

        let result = verify_apple_se_attestation(&attestation, &[0xBB; 32]);
        assert!(matches!(result, Err(AttestationError::Nonce(_))));
    }

    #[test]
    fn valid_attestation_passes() {
        let attestation = AppleSeAttestation {
            attestation_data: vec![1, 2, 3],
            nonce: vec![0xAA; 32],
            device_public_key: vec![4, 5, 6],
            dcos_token: None,
        };

        let result = verify_apple_se_attestation(&attestation, &[0xAA; 32]);
        assert!(result.is_ok());
    }
}
