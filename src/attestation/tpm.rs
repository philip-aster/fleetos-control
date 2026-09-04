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

// ============================================================================
// Step 10 / ATT-TSS: TPM2_MakeCredential (hardware default, swtpm fallback).
// Option C: backend selected by `[tpm] backend` in control config.
// ============================================================================

/// Errors from TSS operations.
#[derive(Debug, thiserror::Error)]
pub enum TssError {
    #[error("tss-esapi error: {0}")]
    Esapi(String),
    #[error("invalid EK public key: {0}")]
    InvalidEk(String),
    #[error("invalid AK public key: {0}")]
    InvalidAk(String),
}

/// Build the TCTI configuration from the `[tpm]` config block.
///
/// - `device`: hardware TPM via the kernel resource manager (default).
/// - `swtpm` / `mssim`: TCP socket to a software TPM.
#[cfg(feature = "tpm")]
fn build_tcti_name_conf(
    config: &crate::config::TpmConfig,
) -> Result<tss_esapi::TctiNameConf, TssError> {
    use crate::config::TpmBackend;
    use std::str::FromStr;

    // tss-esapi 7.x implements FromStr for TctiNameConf, which is much safer
    // than guessing the exact struct variants for Swtpm/Mssim/Device.
    let tcti_str = match config.backend {
        TpmBackend::Device => format!("device:{}", config.device_path),
        TpmBackend::Swtpm => format!("swtpm:host={},port={}", config.host, config.port),
        TpmBackend::Mssim => format!("mssim:host={},port={}", config.host, config.port),
    };
    tss_esapi::TctiNameConf::from_str(&tcti_str)
        .map_err(|e| TssError::Esapi(format!("TCTI parse failed: {}", e)))
}

#[cfg(feature = "tpm")]
fn create_context(config: &crate::config::TpmConfig) -> Result<tss_esapi::Context, TssError> {
    let tcti = build_tcti_name_conf(config)?;
    // Context::new is the constructor in 7.x (Context::create is a TPM command)
    tss_esapi::Context::new(tcti).map_err(|e| TssError::Esapi(e.to_string()))
}

/// TPM2_MakeCredential: encrypt `secret` to the EK public key, binding it to
/// the AK's name. Returns `(credential_blob, encrypted_secret)` — the two
/// fields of `ActivationChallenge`.
///
/// `ek_spki_der` is the EK public key in SPKI DER (RFC 5280). `ak_pub` is the
/// marshaled TPMT_PUBLIC of the ephemeral AK from `ActivationRequest`.
#[cfg(feature = "tpm")]
pub fn make_credential(
    config: &crate::config::TpmConfig,
    ek_spki_der: &[u8],
    ak_pub: &[u8],
    secret: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), TssError> {
    use tss_esapi::interface_types::resource_handles::Hierarchy;
    use tss_esapi::structures::{Digest, Name};

    let mut context = create_context(config)?;

    // Convert the EK SPKI DER into a TPM Public structure.
    let ek_public = spki_to_tpm_public(ek_spki_der)?;
    // Convert the marshaled AK TPMT_PUBLIC into a TPM Public structure.
    let ak_public = unmarshal_ak_public(ak_pub)?;

    let ek_sensitive = empty_sensitive_for(&ek_public)?;
    let ek_handle = context
        .load_external(ek_sensitive, ek_public, Hierarchy::Endorsement)
        .map_err(|e| TssError::Esapi(format!("load EK failed: {}", e)))?;

    let ak_sensitive = empty_sensitive_for(&ak_public)?;
    let ak_handle = context
        .load_external(ak_sensitive, ak_public, Hierarchy::Null)
        .map_err(|e| TssError::Esapi(format!("load AK failed: {}", e)))?;

    let ak_name: Name = context
        .tr_get_name(ak_handle.into())
        .map_err(|e| TssError::Esapi(format!("get AK name failed: {}", e)))?;

    let credential = Digest::try_from(secret.to_vec())
        .map_err(|e| TssError::Esapi(format!("digest failed: {}", e)))?;
    let (id_object, enc_secret) = context
        .make_credential(ek_handle, credential, ak_name)
        .map_err(|e| TssError::Esapi(format!("make_credential failed: {}", e)))?;

    Ok((id_object.value().to_vec(), enc_secret.value().to_vec()))
}

/// Convert an EK public key in SPKI DER (RFC 5280) to a tss-esapi `Public`.
///
/// Supports RSA EKs (the common case). Parses the SubjectPublicKeyInfo and
/// extracts the RSA modulus/exponent to build `Public::Rsa`.
#[cfg(feature = "tpm")]
fn spki_to_tpm_public(spki_der: &[u8]) -> Result<tss_esapi::structures::Public, TssError> {
    use spki::SubjectPublicKeyInfoRef;
    use spki::der::Decode;
    use tss_esapi::attributes::ObjectAttributes;
    use tss_esapi::interface_types::algorithm::HashingAlgorithm;
    use tss_esapi::interface_types::key_bits::RsaKeyBits;
    use tss_esapi::structures::{
        Public, PublicKeyRsa, PublicRsaParameters, RsaExponent, RsaScheme,
        SymmetricDefinitionObject,
    };

    const RSA_OID: spki::ObjectIdentifier =
        spki::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TssError::InvalidEk(format!("SPKI parse failed: {}", e)))?;

    if spki.algorithm.oid != RSA_OID {
        return Err(TssError::InvalidEk(
            "only RSA EKs are supported for MakeCredential".to_owned(),
        ));
    }

    let (modulus, exponent) = parse_rsa_public_key(spki.subject_public_key.raw_bytes())?;

    let key_bits = match modulus.len() * 8 {
        2048 => RsaKeyBits::Rsa2048,
        3072 => RsaKeyBits::Rsa3072,
        other => {
            return Err(TssError::InvalidEk(format!(
                "unsupported RSA EK size: {}",
                other
            )));
        }
    };

    let object_attributes = ObjectAttributes::builder()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_admin_with_policy(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .map_err(|e| TssError::InvalidEk(format!("object attributes: {}", e)))?;

    Ok(Public::Rsa {
        object_attributes,
        name_hashing_algorithm: HashingAlgorithm::Sha256, // renamed from name_alg
        auth_policy: Default::default(),
        parameters: PublicRsaParameters::new(
            SymmetricDefinitionObject::Null,
            RsaScheme::Null,
            key_bits,
            RsaExponent::try_from(exponent)
                .map_err(|e| TssError::InvalidEk(format!("exponent: {}", e)))?,
        ),
        unique: PublicKeyRsa::try_from(modulus) // renamed from PublicRsa
            .map_err(|e| TssError::InvalidEk(format!("modulus: {}", e)))?,
    })
}

/// Unmarshal the AK public key (TPM2B_PUBLIC bytes) into a tss-esapi `Public`.
#[cfg(feature = "tpm")]
fn unmarshal_ak_public(ak_pub: &[u8]) -> Result<tss_esapi::structures::Public, TssError> {
    use tss_esapi::tss2_esys::{TPM2B_PUBLIC, Tss2_MU_TPM2B_PUBLIC_Unmarshal};

    let mut dest: TPM2B_PUBLIC = unsafe { std::mem::zeroed() };
    let mut offset: u64 = 0;
    let rc = unsafe {
        Tss2_MU_TPM2B_PUBLIC_Unmarshal(ak_pub.as_ptr(), ak_pub.len() as u64, &mut offset, &mut dest)
    };
    if rc != 0 {
        return Err(TssError::InvalidAk(format!(
            "TPM2B_PUBLIC unmarshal failed, rc={:#x}",
            rc
        )));
    }
    tss_esapi::structures::Public::try_from(dest).map_err(|e| {
        TssError::InvalidAk(format!("TPM2B_PUBLIC -> Public conversion failed: {}", e))
    })
}

/// Parse a DER RSAPublicKey (SEQUENCE { modulus INTEGER, exponent INTEGER })
/// into (modulus bytes, exponent u32).
#[cfg(feature = "tpm")]
fn parse_rsa_public_key(der: &[u8]) -> Result<(Vec<u8>, u32), TssError> {
    // Manual DER parsing to avoid `der` crate trait-bound issues with SequenceRef
    if der.is_empty() || der[0] != 0x30 {
        return Err(TssError::InvalidEk("expected SEQUENCE".into()));
    }
    let (_seq_len, mut offset) = parse_der_length(&der[1..])?;
    offset += 1;

    if der.len() <= offset || der[offset] != 0x02 {
        return Err(TssError::InvalidEk("expected INTEGER for modulus".into()));
    }
    let (mod_len, mod_len_bytes) = parse_der_length(&der[offset + 1..])?;
    offset += 1 + mod_len_bytes;
    let mut modulus = der[offset..offset + mod_len].to_vec();
    if modulus.len() > 1 && modulus[0] == 0 {
        modulus.remove(0); // Strip leading sign byte
    }
    offset += mod_len;

    if der.len() <= offset || der[offset] != 0x02 {
        return Err(TssError::InvalidEk("expected INTEGER for exponent".into()));
    }
    let (exp_len, exp_len_bytes) = parse_der_length(&der[offset + 1..])?;
    offset += 1 + exp_len_bytes;
    let exp_bytes = &der[offset..offset + exp_len];
    let mut exponent: u32 = 0;
    for &b in exp_bytes {
        exponent = (exponent << 8) | b as u32;
    }
    if exponent == 65537 {
        exponent = 0; // TPM uses 0 to represent the default exponent (65537)
    }
    Ok((modulus, exponent))
}

/// Build a structurally-valid but empty `Sensitive` for a public-only
/// `load_external`. tss-esapi 7.7 has no null sensitive variant, so we
/// supply zeroed inner key material matching the public key type.
#[cfg(feature = "tpm")]
fn empty_sensitive_for(
    public: &tss_esapi::structures::Public,
) -> Result<tss_esapi::structures::Sensitive, TssError> {
    use tss_esapi::structures::{Public, Sensitive};
    match public {
        Public::Rsa { .. } => Ok(Sensitive::Rsa {
            auth_value: Default::default(),
            seed_value: Default::default(),
            sensitive: Default::default(), // PrivateKeyRsa (empty)
        }),
        Public::Ecc { .. } => Ok(Sensitive::Ecc {
            auth_value: Default::default(),
            seed_value: Default::default(),
            sensitive: Default::default(), // EccParameter (empty)
        }),
        _ => Err(TssError::InvalidEk(
            "unsupported EK/AK key type for load_external".to_owned(),
        )),
    }
}

#[cfg(feature = "tpm")]
fn parse_der_length(bytes: &[u8]) -> Result<(usize, usize), TssError> {
    if bytes.is_empty() {
        return Err(TssError::InvalidEk("unexpected end of DER".into()));
    }
    let b = bytes[0];
    if b < 0x80 {
        Ok((b as usize, 1))
    } else {
        let n = (b & 0x7f) as usize;
        if n == 0 || n > 4 || bytes.len() < 1 + n {
            return Err(TssError::InvalidEk("invalid DER length".into()));
        }
        let mut len = 0usize;
        for i in 1..=n {
            len = (len << 8) | bytes[i] as usize;
        }
        Ok((len, 1 + n))
    }
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
