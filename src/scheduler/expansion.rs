//! Deterministic PodSpec expansion (CR-CTRL-4).
//!
//! Reconstructs the full `PodSpec` from a replicated `WorkloadSpec`,
//! unconditionally overwriting the six trusted fields. Pure and deterministic:
//! safe to call from the Raft state machine on EVERY replica (bit-for-bit
//! identical output) and from the WorkloadController. Both call sites use this
//! single helper — no second copy of the expansion logic.

use fleetos_core::proto::workload::{PodSpec, WorkloadSpec};

/// Overwrite the six trusted fields; everything else is preserved from the template.
pub fn expand_pod_spec(
    workload_spec: &WorkloadSpec,
    pod_id: &str,
    tenant_id: &str,
    workload_id: &str,
    role: &str,
    ordinal: u32,
) -> PodSpec {
    let mut pod_spec = workload_spec.pod_spec.clone().unwrap_or_default();
    // Unconditionally overwrite the six trusted fields.
    pod_spec.tenant_id = tenant_id.to_string();
    pod_spec.workload_id = workload_id.to_string();
    pod_spec.role = role.to_string();
    pod_spec.image = workload_spec.image.clone();
    pod_spec.ordinal = Some(ordinal);
    pod_spec.pod_id = Some(pod_id.to_string());
    pod_spec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_fields_are_overwritten() {
        let spec = WorkloadSpec {
            tenant_id: "tenant-A".to_owned(),
            workload_id: "web".to_owned(),
            image: "legit:v1".to_owned(),
            pod_spec: Some(PodSpec {
                tenant_id: "tenant-B".to_owned(),     // SPOOFED
                workload_id: "malicious".to_owned(),  // SPOOFED
                role: "admin".to_owned(),             // SPOOFED
                image: "malicious:latest".to_owned(), // SPOOFED
                ordinal: Some(99),                    // SPOOFED
                pod_id: Some("spoofed".to_owned()),   // SPOOFED
                ..Default::default()
            }),
            ..Default::default()
        };
        let out = expand_pod_spec(&spec, "web-primary-0", "tenant-A", "web", "primary", 0);
        assert_eq!(out.tenant_id, "tenant-A");
        assert_eq!(out.workload_id, "web");
        assert_eq!(out.role, "primary");
        assert_eq!(out.image, "legit:v1");
        assert_eq!(out.ordinal, Some(0));
        assert_eq!(out.pod_id.as_deref(), Some("web-primary-0"));
    }
}
