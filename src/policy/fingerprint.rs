use fleetos_core::WorkloadRole;
use fleetos_core::hash::IdentityFingerprint;
use fleetos_core::spiffe::SpiffeId;

use super::PolicyError;

/// Compute the 16-byte BLAKE3 fingerprint for a (SpiffeId, role) pair.
///
/// Returns raw `[u8; 16]` bytes extracted from `IdentityFingerprint.0`.
/// This is the ONLY fingerprint function in this crate.
pub fn compute_fingerprint(
    id: &SpiffeId,
    role: Option<&WorkloadRole>,
) -> Result<[u8; 16], PolicyError> {
    let fingerprint = IdentityFingerprint::of(id, role);
    Ok(fingerprint.0)
}

pub fn compute_rule_fingerprints(
    src_id: &SpiffeId,
    src_role: Option<&WorkloadRole>,
    dst_id: &SpiffeId,
    dst_role: Option<&WorkloadRole>,
) -> Result<([u8; 16], [u8; 16]), PolicyError> {
    let src = compute_fingerprint(src_id, src_role)?;
    let dst = compute_fingerprint(dst_id, dst_role)?;
    Ok((src, dst))
}
