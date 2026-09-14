//! Shared snapshot builders (CR-CTRL-1).
//!
//! The state machine's publish path AND the watch services' initial frame both
//! call these builders, so the frame and the deltas can never diverge
//! (single-canonical-builder principle). All reads are over committed state.

use fjall::Keyspace;
use prost::Message;

use crate::delegation::DelegationRecord;
use crate::raft::records::{RevokedSvidRecord, WorkloadSpecRecord};
use crate::scheduler::Placement;
use crate::watch::router_assignment::RouteEntryRecord;
use crate::watch::scheduler_stream::WorkloadAssignmentRecord;

/// Snapshot of SAG rules + revocation sets (for `SagUpdate`).
pub struct SagSnapshot {
    /// Length-prefixed proto `SagRule` buffer (decode with `policy_service::decode_rules`).
    pub rules_bytes: Vec<u8>,
    pub revoked_delegation_ids: Vec<Vec<u8>>,
    pub revoked_spiffe_ids: Vec<String>,
}

/// Read all SAG rules and revocation sets into a snapshot.
pub fn build_sag_snapshot(
    sag_rules: &Keyspace,
    revoked_delegations: &Keyspace,
    revoked_svids: &Keyspace,
) -> SagSnapshot {
    let mut rules_bytes = Vec::new();
    for guard in sag_rules.prefix(Vec::<u8>::new()) {
        let Ok(value) = guard.value() else { continue };
        let rule_bytes = value.as_ref();
        rules_bytes.extend_from_slice(&(rule_bytes.len() as u32).to_le_bytes());
        rules_bytes.extend_from_slice(rule_bytes);
    }

    let mut revoked_delegation_ids: Vec<Vec<u8>> = Vec::new();
    for guard in revoked_delegations.prefix(Vec::<u8>::new()) {
        let Ok(value) = guard.value() else { continue };
        if let Ok(record) = postcard::from_bytes::<DelegationRecord>(value.as_ref()) {
            revoked_delegation_ids.push(record.delegation_id.into_bytes());
        }
    }

    let mut revoked_spiffe_ids: Vec<String> = Vec::new();
    for guard in revoked_svids.prefix(Vec::<u8>::new()) {
        let Ok(value) = guard.value() else { continue };
        if let Ok(record) = postcard::from_bytes::<RevokedSvidRecord>(value.as_ref()) {
            revoked_spiffe_ids.push(record.spiffe_id);
        }
    }

    SagSnapshot {
        rules_bytes,
        revoked_delegation_ids,
        revoked_spiffe_ids,
    }
}

/// Build the postcard-encoded `Vec<WorkloadAssignmentRecord>` for a
/// `ScheduleUpdate`, expanding the full `PodSpec` per placement (CR-CTRL-4).
pub fn build_schedule_snapshot(
    placements: &Keyspace,
    workloads: &Keyspace,
    data_trust_domain: &str,
) -> Vec<u8> {
    let mut records: Vec<WorkloadAssignmentRecord> = Vec::new();
    for guard in placements.prefix(Vec::<u8>::new()) {
        let Ok(value) = guard.value() else { continue };
        let Ok(placement) = postcard::from_bytes::<Placement>(value.as_ref()) else {
            continue;
        };
        // Compute canonical hostname (Directive A.1)
        let hostname = fleetos_core::naming::dummy_ip_hostname(
            &placement.service,
            &placement.role,
            &placement.tenant_id,
            data_trust_domain,
        )
        .unwrap_or_default();

        let spec = lookup_workload_spec(workloads, &placement.tenant_id, &placement.service);
        let (runtime, image, pod_spec_bytes) = match spec {
            Some(spec) => {
                let runtime = spec
                    .pod_spec
                    .as_ref()
                    .map(|p| p.runtime.clone())
                    .unwrap_or_default();
                let image = spec.image.clone();
                let pod_spec = crate::scheduler::expansion::expand_pod_spec(
                    &spec,
                    &placement.pod_id,
                    &placement.tenant_id,
                    &placement.service,
                    &placement.role,
                    placement.ordinal,
                );
                (runtime, image, pod_spec.encode_to_vec())
            }
            None => (String::new(), String::new(), Vec::new()),
        };
        records.push(WorkloadAssignmentRecord {
            workload_id: placement.service.clone(),
            runtime,
            image,
            role: placement.role.clone(),
            hostname,
            pod_spec_bytes,
        });
    }
    postcard::to_allocvec(&records).unwrap_or_default()
}

/// Build the postcard-encoded `Vec<RouteEntryRecord>` for a `RouteUpdate`.
pub fn build_routes_snapshot(
    placements: &Keyspace,
    dummy_ips: &Keyspace,
    data_trust_domain: &str,
) -> Vec<u8> {
    let mut records: Vec<RouteEntryRecord> = Vec::new();
    for guard in placements.prefix(Vec::<u8>::new()) {
        let Ok(value) = guard.value() else { continue };
        let Ok(placement) = postcard::from_bytes::<Placement>(value.as_ref()) else {
            continue;
        };
        let service_key = format!(
            "service:{}:{}:{}",
            placement.tenant_id, placement.service, placement.role
        );
        let dummy_ip = match dummy_ips.get(service_key.as_bytes()) {
            Ok(Some(bytes)) => {
                postcard::from_bytes::<crate::dummy_ip::allocator::ServiceAddress>(bytes.as_ref())
                    .map(|sa| sa.address)
                    .unwrap_or(0)
            }
            _ => 0,
        };
        let destination_svid = format!(
            "spiffe://{}/ns/{}/sa/{}",
            data_trust_domain, placement.tenant_id, placement.service
        );
        records.push(RouteEntryRecord {
            destination_svid,
            destination_role: placement.role.clone(),
            target_agent_svid: placement.node_id.to_string(),
            dummy_ip,
        });
    }
    postcard::to_allocvec(&records).unwrap_or_default()
}

fn lookup_workload_spec(
    workloads: &Keyspace,
    tenant_id: &str,
    workload_id: &str,
) -> Option<fleetos_core::proto::workload::WorkloadSpec> {
    let key = format!("{}:{}", tenant_id, workload_id);
    let value = workloads.get(key.as_bytes()).ok().flatten()?;
    let record: WorkloadSpecRecord = postcard::from_bytes(value.as_ref()).ok()?;
    fleetos_core::proto::workload::WorkloadSpec::decode(record.spec_bytes.as_slice()).ok()
}
