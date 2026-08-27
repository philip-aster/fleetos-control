//! TPM 2.0 quote verification.
//!
//! Verifies TPM quotes from `fleetos-agent`, `fleetos-router`, `fleetos-gateway`.
//! PCR policy is stored per-node in fjall. PCR policy covers firmware +
//! bootloader + kernel measurements. Operators configure expected PCR values per fleet.
//!
//! Requires `tss-esapi` crate (wraps system `tpm2-tss`).
//! Compiling with `tpm` feature on Linux requires TPM2 TSS dev headers:
//!   sudo apt install tpm2-tss-dev

//! SECURITY (Master findings M-2/S-11): until the signature-verification TODO
//! below is implemented, quote verification is STRUCTURAL ONLY — nonce binding
//! plus non-empty quote/signature bytes. Combined with `join.rs`'s placeholder
//! quote, control-plane join is currently gated by join-token possession alone.

use super::AttestationError;

/// A TPM quote submitted by a node for attestation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TpmQuote {
    /// The raw TPM quote bytes (TPMS_ATTEST structure).
    pub quote_bytes: Vec<u8>,

    /// The signature over the quote (from the TPM's Attestation Key).
    pub signature: Vec<u8>,

    /// The nonce that was bound into this quote.
    pub nonce: Vec<u8>,

    /// PCR values included in the quote (PCR selections + digest).
    pub pcr_selection: Vec<PcrValue>,

    /// The public key of the Attestation Key (for signature verification).
    pub attestation_key_pub: Vec<u8>,
}

/// A single PCR register value.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PcrValue {
    /// PCR index (0-23).
    pub index: u8,

    /// The hash algorithm used (SHA-256 = 0x000B).
    pub hash_algorithm: u16,

    /// The PCR digest value.
    pub digest: Vec<u8>,
}

/// Verify a TPM quote against the expected PCR policy.
///
/// This implements the `QuoteVerifier` trait from `fleetos-core::attestation`.
///
/// Verification steps:
/// 1. Verify the nonce matches the one we issued
/// 2. Verify the signature over the quote using the Attestation Key
/// 3. Verify PCR values match the expected policy for this node
pub fn verify_tpm_quote(
    quote: &TpmQuote,
    expected_nonce: &[u8],
    expected_pcrs: &[PcrValue],
) -> Result<(), AttestationError> {
    // Step 1: Verify nonce matches.
    if quote.nonce != expected_nonce {
        return Err(AttestationError::Nonce(
            "quote nonce does not match issued nonce".to_owned(),
        ));
    }

    // Step 2: Verify signature over the quote.
    // TODO: Implement actual TPM signature verification using tss-esapi.
    // This requires:
    // 1. Parse the TPMS_ATTEST structure from quote_bytes
    // 2. Verify the signature using attestation_key_pub
    // 3. Confirm the quote's extraData matches our nonce
    //
    // For now, this is a placeholder that validates structure only.
    if quote.quote_bytes.is_empty() {
        return Err(AttestationError::QuoteVerification(
            "empty quote bytes".to_owned(),
        ));
    }
    if quote.signature.is_empty() {
        return Err(AttestationError::QuoteVerification(
            "empty signature".to_owned(),
        ));
    }

    // Step 3: Verify PCR values match expected policy.
    verify_pcr_values(&quote.pcr_selection, expected_pcrs)?;

    Ok(())
}

/// Verify that submitted PCR values match the expected policy.
fn verify_pcr_values(
    submitted: &[PcrValue],
    expected: &[PcrValue],
) -> Result<(), AttestationError> {
    for expected_pcr in expected {
        let submitted_pcr = submitted
            .iter()
            .find(|p| p.index == expected_pcr.index)
            .ok_or_else(|| {
                AttestationError::PcrMismatch(format!(
                    "PCR {} not present in quote",
                    expected_pcr.index
                ))
            })?;

        if submitted_pcr.digest != expected_pcr.digest {
            return Err(AttestationError::PcrMismatch(format!(
                "PCR {} digest mismatch",
                expected_pcr.index
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_mismatch_rejected() {
        let quote = TpmQuote {
            quote_bytes: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            nonce: vec![0xAA; 32],
            pcr_selection: vec![],
            attestation_key_pub: vec![7, 8, 9],
        };

        let result = verify_tpm_quote(&quote, &[0xBB; 32], &[]);
        assert!(matches!(result, Err(AttestationError::Nonce(_))));
    }

    #[test]
    fn pcr_mismatch_rejected() {
        let quote = TpmQuote {
            quote_bytes: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            nonce: vec![0xAA; 32],
            pcr_selection: vec![PcrValue {
                index: 0,
                hash_algorithm: 0x000B,
                digest: vec![0x11; 32],
            }],
            attestation_key_pub: vec![7, 8, 9],
        };

        let expected = vec![PcrValue {
            index: 0,
            hash_algorithm: 0x000B,
            digest: vec![0x22; 32], // Different digest
        }];

        let result = verify_tpm_quote(&quote, &[0xAA; 32], &expected);
        assert!(matches!(result, Err(AttestationError::PcrMismatch(_))));
    }

    #[test]
    fn valid_quote_passes() {
        let pcr = PcrValue {
            index: 0,
            hash_algorithm: 0x000B,
            digest: vec![0x11; 32],
        };

        let quote = TpmQuote {
            quote_bytes: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            nonce: vec![0xAA; 32],
            pcr_selection: vec![pcr.clone()],
            attestation_key_pub: vec![7, 8, 9],
        };

        let result = verify_tpm_quote(&quote, &[0xAA; 32], &[pcr]);
        assert!(result.is_ok());
    }
}
