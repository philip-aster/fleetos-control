//! Admin API authorization — SVID kind enforcement.
//!
//! **Critical security boundary:** AdminService is ONLY callable by SVID kind `ctrl`
//! (fleetctl-proxy's identity). This is enforced at the mTLS layer, not the
//! application layer.
//!
//! The enforcement mechanism:
//! 1. The Admin gRPC listener uses the Admin-domain trust bundle for TLS validation.
//! 2. After TLS handshake, we extract the peer's SVID from the certificate.
//! 3. We verify the SVID's `kind` is `ctrl` before dispatching to any handler.
//!
//! A valid `sa`, `node`, `router`, `gateway`, or `control` SVID hitting this
//! endpoint is rejected — even if the certificate chain is valid. The trust
//! domain separation means these SVIDs are signed by the Data/Control root,
//! which the Admin listener doesn't trust at all. But as defense-in-depth,
//! we also check the kind at the application layer.

use fleetos_core::spiffe::{IdKind, SpiffeId};

use super::AdminError;

/// Verify that the calling SVID is authorized to access AdminService.
///
/// This is the application-layer defense-in-depth check. The primary
/// enforcement is at the mTLS layer (Admin trust bundle validation),
/// but we check here too in case of misconfiguration.
///
/// Only `ctrl`-kind SVIDs (fleetctl-proxy) are authorized.
pub fn verify_admin_caller(caller_svid: &SpiffeId) -> Result<(), AdminError> {
    match caller_svid.kind {
        IdKind::Ctrl => Ok(()),
        _ => Err(AdminError::Unauthorized),
    }
}

/// Extract the caller's SpiffeId from a tonic request's mTLS peer certificate.
///
/// In production, the SVID is extracted from the TLS connection's peer
/// certificate SAN (Subject Alternative Name). The mTLS layer has already
/// verified the certificate chain against the Admin trust bundle.
///
/// This function extracts the SpiffeId from the certificate's URI SAN.
pub fn extract_caller_svid(_request: &tonic::Request<()>) -> Result<SpiffeId, AdminError> {
    // In tonic, the peer certificate is available via the transport's
    // TLS info. We extract the SpiffeId from the certificate's URI SAN.
    //
    // The exact mechanism depends on how the TLS layer exposes the peer cert.
    // For now, we use tonic's metadata extension if available.
    //
    // TODO: Wire this to the actual TLS peer certificate extraction.
    // The mTLS layer (tls/mtls.rs) should attach the verified SpiffeId
    // to the request extensions during the handshake.

    // Placeholder: extract from request extensions
    // In production, this would be:
    // let spiffe_id = request.extensions().get::<SpiffeId>()
    //     .ok_or(AdminError::Unauthorized)?;
    // verify_admin_caller(spiffe_id)?;
    // Ok(spiffe_id.clone())

    // For now, return an error indicating the TLS layer needs to be wired
    Err(AdminError::Unauthorized)
}

/// Verify admin caller from a SpiffeId string (for testing or when the
/// TLS layer provides the SVID as a string).
pub fn verify_admin_caller_from_str(caller_svid_str: &str) -> Result<SpiffeId, AdminError> {
    let spiffe_id: SpiffeId = caller_svid_str
        .parse()
        .map_err(|_| AdminError::Unauthorized)?;

    verify_admin_caller(&spiffe_id)?;
    Ok(spiffe_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctrl_kind_is_authorized() {
        let ctrl_svid = SpiffeId::new(
            "admin.example.internal",
            "system",
            IdKind::Ctrl,
            "fleetctl-proxy",
        );
        assert!(verify_admin_caller(&ctrl_svid).is_ok());
    }

    #[test]
    fn sa_kind_is_rejected() {
        let sa_svid = SpiffeId::new(
            "data.example.internal",
            "my-tenant",
            IdKind::Sa,
            "my-service",
        );
        assert!(matches!(
            verify_admin_caller(&sa_svid),
            Err(AdminError::Unauthorized)
        ));
    }

    #[test]
    fn node_kind_is_rejected() {
        let node_svid = SpiffeId::new("data.example.internal", "system", IdKind::Node, "agent-1");
        assert!(matches!(
            verify_admin_caller(&node_svid),
            Err(AdminError::Unauthorized)
        ));
    }

    #[test]
    fn control_kind_is_rejected() {
        // IdKind::Control is fleetos-control's own Raft-peer identity.
        // It should NOT be authorized for AdminService — that's for
        // fleetctl-proxy (IdKind::Ctrl) only.
        let control_svid = SpiffeId::new(
            "data.example.internal",
            "system",
            IdKind::Control,
            "control-1",
        );
        assert!(matches!(
            verify_admin_caller(&control_svid),
            Err(AdminError::Unauthorized)
        ));
    }
}
