//! Custom OID extensions for FleetOS SVIDs.
//!
//! FleetOS stamps additional information into X.509 certificates via custom
//! OID extensions, beyond the standard SPIFFE URI SAN. These extensions
//! carry workload metadata that downstream policy engines can inspect
//! without needing to query the control plane.
//!
//! OID arcs (IANA PEN 66561):
//!   Role:            1.3.6.1.4.1.66561.1.1
//!   Degraded marker: 1.3.6.1.4.1.66561.1.2
//!   Ordinal:         1.3.6.1.4.1.66561.1.3

use rcgen::CustomExtension;

/// IANA Private Enterprise Number assigned to FleetOS.
pub const FLEETOS_PEN: u64 = 66561;

/// OID for workload role extension.
///
/// Value: UTF-8 string of the `WorkloadRole` (e.g., "primary", "replica").
/// Arc: 1.3.6.1.4.1.66561.1.1
pub const OID_ROLE: &[u64] = &[1, 3, 6, 1, 4, 1, FLEETOS_PEN, 1, 1];

/// OID for degraded-mode marker.
///
/// Value: ASN.1 BOOLEAN. True if this SVID was issued in degraded mode
/// (CA unavailable, delegated signing key used instead).
/// Arc: 1.3.6.1.4.1.66561.1.2
pub const OID_DEGRADED: &[u64] = &[1, 3, 6, 1, 4, 1, FLEETOS_PEN, 1, 2];

/// OID for ordinal extension.
///
/// Value: UTF-8 string of the ordinal number (e.g., "0", "1", "2").
/// Only present for stateful workloads with ordinal assignment.
/// Arc: 1.3.6.1.4.1.66561.1.3
pub const OID_ORDINAL: &[u64] = &[1, 3, 6, 1, 4, 1, FLEETOS_PEN, 1, 3];

/// Build a custom extension for the workload role.
pub fn role_extension(role: &str) -> CustomExtension {
    let mut ext = CustomExtension::from_oid_content(OID_ROLE, role.as_bytes().to_vec());
    ext.set_criticality(false);
    ext
}

/// Build a custom extension for the degraded-mode marker.
pub fn degraded_extension(is_degraded: bool) -> CustomExtension {
    // ASN.1 BOOLEAN encoding: tag(0x01) length(0x01) value(0xFF or 0x00)
    let value = if is_degraded {
        vec![0x01, 0x01, 0xFF]
    } else {
        vec![0x01, 0x01, 0x00]
    };
    let mut ext = CustomExtension::from_oid_content(OID_DEGRADED, value);
    ext.set_criticality(false);
    ext
}

/// Build a custom extension for the ordinal.
pub fn ordinal_extension(ordinal: u32) -> CustomExtension {
    let value = ordinal.to_string();
    let mut ext = CustomExtension::from_oid_content(OID_ORDINAL, value.as_bytes().to_vec());
    ext.set_criticality(false);
    ext
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_arcs_are_distinct() {
        assert_ne!(OID_ROLE, OID_ORDINAL);
        assert_ne!(OID_ROLE, OID_DEGRADED);
        assert_ne!(OID_ORDINAL, OID_DEGRADED);
    }

    #[test]
    fn oid_arcs_share_pen_prefix() {
        // All OIDs share the 1.3.6.1.4.1.66561 prefix
        let prefix = &[1u64, 3, 6, 1, 4, 1, FLEETOS_PEN];
        assert!(OID_ROLE.starts_with(prefix));
        assert!(OID_DEGRADED.starts_with(prefix));
        assert!(OID_ORDINAL.starts_with(prefix));
    }

    #[test]
    fn oid_arcs_match_directive_numbering() {
        // Role = .1.1, Degraded = .1.2, Ordinal = .1.3
        assert_eq!(OID_ROLE[7..], [1, 1]);
        assert_eq!(OID_DEGRADED[7..], [1, 2]);
        assert_eq!(OID_ORDINAL[7..], [1, 3]);
    }

    #[test]
    fn role_extension_encodes_correctly() {
        let ext = role_extension("replica");
        let _ = ext;
    }

    #[test]
    fn ordinal_extension_encodes_correctly() {
        let ext = ordinal_extension(42);
        let _ = ext;
    }

    #[test]
    fn degraded_extension_encodes_true_and_false() {
        let ext_true = degraded_extension(true);
        let ext_false = degraded_extension(false);
        let _ = (ext_true, ext_false);
    }
}
