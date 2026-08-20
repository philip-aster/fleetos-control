//! Dual trust domain enforcement.
//!
//! Each trust domain has its own CA root, its own trust bundle, and its own
//! set of permitted identity kinds. Routing is structural — the listener
//! determines which trust domain applies.
//!
//! Path convention for cluster-level identities:
//!   spiffe://<trust-domain>/ns/system/<kind>/<name>
//! e.g.: spiffe://fleet.example.internal/ns/system/control/control-1

use crate::config::ControlConfig;

use super::TlsError;

/// Which trust domain a connection belongs to, determined structurally
/// by which listener it arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDomainRole {
    /// Data/Control overlay: agent, router, gateway, control (Raft peers).
    DataControl,
    /// Admin overlay: fleetctl-proxy only.
    Admin,
}

/// Trust domain configuration extracted from the control config.
#[derive(Debug, Clone)]
pub struct TrustDomainConfig {
    /// The trust domain string for Data/Control overlay.
    pub data_control: String,
    /// The trust domain string for Admin overlay.
    pub admin: String,
}

impl TrustDomainConfig {
    pub fn from_config(config: &ControlConfig) -> Self {
        Self {
            data_control: config.trust_domains.data_control.clone(),
            admin: config.trust_domains.admin.clone(),
        }
    }

    /// Get the expected trust domain for a given listener role.
    pub fn expected_domain(&self, role: TrustDomainRole) -> &str {
        match role {
            TrustDomainRole::DataControl => &self.data_control,
            TrustDomainRole::Admin => &self.admin,
        }
    }
}

/// Validate that a SPIFFE ID belongs to the expected trust domain
/// and has an acceptable identity kind for the given listener.
///
/// This is called during TLS handshake (certificate verification),
/// NOT at application layer. Enforcement at mTLS layer is mandatory.
pub fn validate_peer_identity(
    spiffe_id: &str,
    role: TrustDomainRole,
    config: &TrustDomainConfig,
) -> Result<(), TlsError> {
    let expected_domain = config.expected_domain(role);

    // Parse the trust domain from the SPIFFE ID.
    // Format: spiffe://<trust-domain>/<path...>
    let trust_domain = extract_trust_domain(spiffe_id).ok_or_else(|| {
        TlsError::SpiffeParse(format!("cannot extract trust domain from: {}", spiffe_id))
    })?;

    // Verify trust domain matches.
    if trust_domain != expected_domain {
        return Err(TlsError::TrustDomainMismatch {
            expected: expected_domain.to_owned(),
            actual: trust_domain.to_owned(),
        });
    }

    // Extract identity kind from the SPIFFE path.
    let kind = extract_identity_kind(spiffe_id);

    match role {
        TrustDomainRole::DataControl => {
            // Accept: node, sa (workload), router, gateway, control
            match kind {
                Some("node") | Some("sa") | Some("router") | Some("gateway") | Some("control") => {
                    Ok(())
                }
                Some(other) => Err(TlsError::IdentityKindMismatch {
                    expected: "node/sa/router/gateway/control".to_owned(),
                    actual: other.to_owned(),
                }),
                None => Err(TlsError::SpiffeParse(
                    "cannot extract identity kind from SPIFFE ID".to_owned(),
                )),
            }
        }
        TrustDomainRole::Admin => {
            // Accept ONLY: ctrl (fleetctl-proxy's identity kind).
            // A valid `sa` or `node` SVID hitting this endpoint must be rejected
            // at the TLS/mTLS layer, not just at the application layer.
            match kind {
                Some("ctrl") => Ok(()),
                Some(other) => Err(TlsError::IdentityKindMismatch {
                    expected: "ctrl".to_owned(),
                    actual: other.to_owned(),
                }),
                None => Err(TlsError::SpiffeParse(
                    "cannot extract identity kind from SPIFFE ID".to_owned(),
                )),
            }
        }
    }
}

/// Extract the trust domain from a SPIFFE ID.
///
/// SPIFFE ID format: `spiffe://<trust-domain>/<path>`
/// Returns the trust domain portion.
fn extract_trust_domain(spiffe_id: &str) -> Option<&str> {
    let stripped = spiffe_id.strip_prefix("spiffe://")?;
    // Trust domain is everything up to the first '/'
    stripped.split('/').next()
}

/// Extract the identity kind from a SPIFFE ID path.
///
/// Path convention for cluster-level identities:
///   spiffe://<td>/ns/system/<kind>/<name>
/// For workloads:
///   spiffe://<td>/ns/<tenant>/sa/<service>
///
/// Returns the kind component (e.g., "node", "sa", "ctrl", "control", "router", "gateway").
fn extract_identity_kind(spiffe_id: &str) -> Option<&str> {
    let stripped = spiffe_id.strip_prefix("spiffe://")?;
    let path = stripped.find('/').map(|i| &stripped[i + 1..])?;

    let segments: Vec<&str> = path.split('/').collect();

    // Expected formats:
    //   ns/system/<kind>/<name>  → segments = ["ns", "system", "<kind>", "<name>"]
    //   ns/<tenant>/sa/<service> → segments = ["ns", "<tenant>", "sa", "<service>"]
    if segments.len() >= 4 && segments[0] == "ns" {
        if segments[1] == "system" {
            // Cluster-level: kind is segments[2]
            Some(segments[2])
        } else {
            // Tenant-scoped workload: kind is "sa" (segments[2])
            Some(segments[2])
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> TrustDomainConfig {
        TrustDomainConfig {
            data_control: "fleet.example.internal".to_owned(),
            admin: "fleet-admin.example.internal".to_owned(),
        }
    }

    #[test]
    fn data_control_accepts_node_kind() {
        let config = test_config();
        let result = validate_peer_identity(
            "spiffe://fleet.example.internal/ns/system/node/agent-1",
            TrustDomainRole::DataControl,
            &config,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn data_control_accepts_control_kind() {
        let config = test_config();
        let result = validate_peer_identity(
            "spiffe://fleet.example.internal/ns/system/control/control-1",
            TrustDomainRole::DataControl,
            &config,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn data_control_accepts_workload_sa() {
        let config = test_config();
        let result = validate_peer_identity(
            "spiffe://fleet.example.internal/ns/my-tenant/sa/my-service",
            TrustDomainRole::DataControl,
            &config,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn data_control_rejects_ctrl_kind() {
        let config = test_config();
        let result = validate_peer_identity(
            "spiffe://fleet-admin.example.internal/ns/system/ctrl/fleetctl-proxy",
            TrustDomainRole::DataControl,
            &config,
        );
        assert!(result.is_err());
    }

    #[test]
    fn admin_accepts_only_ctrl() {
        let config = test_config();
        let result = validate_peer_identity(
            "spiffe://fleet-admin.example.internal/ns/system/ctrl/fleetctl-proxy",
            TrustDomainRole::Admin,
            &config,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn admin_rejects_node_kind() {
        let config = test_config();
        let result = validate_peer_identity(
            "spiffe://fleet-admin.example.internal/ns/system/node/agent-1",
            TrustDomainRole::Admin,
            &config,
        );
        assert!(matches!(result, Err(TlsError::IdentityKindMismatch { .. })));
    }

    #[test]
    fn admin_rejects_wrong_trust_domain() {
        let config = test_config();
        // Data/Control domain trying to hit Admin listener
        let result = validate_peer_identity(
            "spiffe://fleet.example.internal/ns/system/ctrl/fleetctl-proxy",
            TrustDomainRole::Admin,
            &config,
        );
        assert!(matches!(result, Err(TlsError::TrustDomainMismatch { .. })));
    }

    #[test]
    fn extract_trust_domain_works() {
        assert_eq!(
            extract_trust_domain("spiffe://fleet.example.internal/ns/system/node/agent-1"),
            Some("fleet.example.internal")
        );
    }

    #[test]
    fn extract_identity_kind_system() {
        assert_eq!(
            extract_identity_kind("spiffe://fleet.example.internal/ns/system/control/control-1"),
            Some("control")
        );
    }

    #[test]
    fn extract_identity_kind_tenant() {
        assert_eq!(
            extract_identity_kind("spiffe://fleet.example.internal/ns/my-tenant/sa/my-service"),
            Some("sa")
        );
    }
}
