use super::ControllerError;
use crate::raft::records::NodeTaint;
use crate::raft::{AuditedCommand, FleetosCommand, FleetosRaftConfig};
use crate::scheduler::Placement;
use crate::scheduler::ordinal::OrdinalAssignment;
use crate::watch::pod_event_store::PodEventEmitter;
use fleetos_core::proto::fleetos::Toleration;
use fleetos_core::proto::state::PodEvent;
use fleetos_core::proto::workload::WorkloadSpec;
use fleetos_core::spiffe::SpiffeId;
use openraft::Raft;
use prost::Message;
use std::sync::Arc;
use time::OffsetDateTime;

pub struct NodeController {
    raft: Arc<Raft<FleetosRaftConfig>>,
    node_ttl_secs: u64,
    /// CR-CTRL-9: replicated operator taints, keyed by node_id.
    node_taints: fjall::Keyspace,
    placements: fjall::Keyspace,
    workloads: fjall::Keyspace,
    pod_event_emitter: Arc<PodEventEmitter>,
}

impl NodeController {
    pub fn new(
        raft: Arc<Raft<FleetosRaftConfig>>,
        node_ttl_secs: u64,
        node_taints: fjall::Keyspace,
        placements: fjall::Keyspace,
        workloads: fjall::Keyspace,
        pod_event_emitter: Arc<PodEventEmitter>,
    ) -> Self {
        Self {
            raft,
            node_ttl_secs,
            node_taints,
            placements,
            workloads,
            pod_event_emitter,
        }
    }

    /// Evict a node: propose `EvictNode`; the state machine marks it evicted,
    /// revokes ALL its delegations, removes its placements, and records its
    /// own SVID as revoked — atomically. Then prune expired revoked SVIDs.
    pub async fn evict_node(&self, node_id: &SpiffeId) -> Result<(), ControllerError> {
        let node_id_str = node_id.to_string();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let svid_expires_at_unix = now + self.node_ttl_secs as i64;
        tracing::warn!(node_id = %node_id_str, "evicting node");
        self.raft
            .client_write(AuditedCommand::system(FleetosCommand::EvictNode {
                node_id: node_id_str,
                svid_expires_at_unix,
            }))
            .await
            .map_err(|e| ControllerError::Raft(e.to_string()))?;
        self.raft
            .client_write(AuditedCommand::system(
                FleetosCommand::PruneExpiredRevokedSvids { cutoff_unix: now },
            ))
            .await
            .map_err(|e| ControllerError::Raft(e.to_string()))?;
        Ok(())
    }

    pub async fn handle_heartbeat(&self, node_id: &SpiffeId) -> Result<(), ControllerError> {
        tracing::debug!(node_id = %node_id, "heartbeat received");
        Ok(())
    }

    /// CR-CTRL-9: enforce NoExecute taints against placed pods.
    ///
    /// For every node carrying NoExecute taints, evict pods that do not
    /// tolerate them (immediately) or whose `toleration_seconds` grace has
    /// elapsed. Eviction = RemovePlacement + freed ordinal slot + `Evicting`
    /// pod event; the victim is re-scheduled elsewhere on a later cycle.
    pub async fn enforce_no_execute_taints(&self) -> Result<(), ControllerError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        for guard in self.node_taints.prefix(Vec::<u8>::new()) {
            let (key, value) = guard
                .into_inner()
                .map_err(|e| ControllerError::Storage(crate::storage::StorageError::Storage(e)))?;
            let node_id_str = String::from_utf8_lossy(key.as_ref()).to_string();
            let Ok(node_taints) = postcard::from_bytes::<Vec<NodeTaint>>(value.as_ref()) else {
                continue;
            };
            if !node_taints
                .iter()
                .any(|t| t.effect == crate::scheduler::taints::EFFECT_NO_EXECUTE)
            {
                continue;
            }
            let Ok(node_spiffe) = node_id_str.parse::<SpiffeId>() else {
                continue;
            };
            // Collect this node's placements.
            let mut node_placements: Vec<Placement> = Vec::new();
            for g in self.placements.prefix(Vec::<u8>::new()) {
                let Ok(v) = g.value() else { continue };
                if let Ok(p) = postcard::from_bytes::<Placement>(v.as_ref()) {
                    if p.node_id == node_spiffe {
                        node_placements.push(p);
                    }
                }
            }
            if node_placements.is_empty() {
                continue;
            }
            let evictions = crate::scheduler::taints::plan_no_execute_evictions(
                now,
                &node_taints,
                &node_placements,
                &|p: &Placement| self.lookup_tolerations(&p.tenant_id, &p.service),
            );
            for pod_id in evictions {
                let Some(p) = node_placements.iter().find(|p| p.pod_id == pod_id) else {
                    continue;
                };
                tracing::warn!(pod_id = %pod_id, node = %node_id_str, "evicting pod for NoExecute taint");
                self.pod_event_emitter.emit(PodEvent {
                    pod_id: pod_id.clone(),
                    node_id: node_id_str.clone(),
                    event_type: "Evicting".to_owned(),
                    reason: "NoExecuteTaint".to_owned(),
                    message: String::new(),
                    timestamp_unix: 0,
                    count: 1,
                });
                self.raft
                    .client_write(AuditedCommand::system(FleetosCommand::RemovePlacement {
                        pod_id: pod_id.clone(),
                    }))
                    .await
                    .map_err(|e| ControllerError::Raft(e.to_string()))?;
                let freed = OrdinalAssignment {
                    tenant_id: p.tenant_id.clone(),
                    service: p.service.clone(),
                    role: p.role.clone(),
                    ordinal: p.ordinal,
                    current_pod_id: None,
                    current_node_id: None,
                };
                self.raft
                    .client_write(AuditedCommand::system(
                        FleetosCommand::RecordOrdinalAssignment { record: freed },
                    ))
                    .await
                    .map_err(|e| ControllerError::Raft(e.to_string()))?;
            }
        }
        Ok(())
    }

    /// Tolerations come from the workload's PodSpec template (all pods of a
    /// workload share them). Missing/corrupt records fail safe: no tolerations.
    fn lookup_tolerations(&self, tenant_id: &str, service: &str) -> Vec<Toleration> {
        let key = format!("{}:{}", tenant_id, service);
        let Some(bytes) = self.workloads.get(key.as_bytes()).ok().flatten() else {
            return Vec::new();
        };
        let Ok(record) = postcard::from_bytes::<crate::raft::records::WorkloadSpecRecord>(&bytes)
        else {
            return Vec::new();
        };
        let Ok(spec) = WorkloadSpec::decode(record.spec_bytes.as_slice()) else {
            return Vec::new();
        };
        spec.pod_spec.map(|p| p.tolerations).unwrap_or_default()
    }
}
