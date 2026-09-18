//! CR-CTRL-11: Vertical Pod Autoscaler (VPA).
//!
//! Leader-gated controller that consumes PodMetrics from the leader-local
//! `MetricsStore` (CR-CORE-9), computes recommended resource footprints
//! against the workload's `VerticalAutoscalingPolicy`, and either replicates
//! a recommendation (OFF mode) or proposes `ResizeWorkload` + pod replacement
//! (RECREATE mode) through Raft.
//!
//! Each dimension is sized by its own metric — no max-across step (that's
//! HPA's). A target of `0` disables that dimension.
//!
//! Guards:
//! - HPA conflict: if HPA is active on CPU, VPA must not act on CPU.
//!   Same for memory. Enforced at admission AND runtime.
//! - CR-CTRL-6: every pod replacement routes through DisruptionGuard
//!   under `DisruptionTarget::VerticalResize`.
//! - CR-7: footprint increases pre-check tenant quota.
//! - Deadband: no action while BOTH dimensions within ±deadband%.
//! - Stabilization window: shrinks only; grows are immediate.
//! - MIN_WINDOWS: pods with fewer than 3 metric windows are excluded.
use super::ControllerError;
use crate::disruption::{DisruptionGuard, DisruptionTarget};
use crate::raft::records::{AuditContext, VpaRecommendationRecord, WorkloadSpecRecord};
use crate::raft::{AuditedCommand, FleetosCommand, FleetosRaftConfig};
use crate::scheduler::Placement;
use crate::scheduler::ordinal::OrdinalAssignment;
use crate::storage::StorageEngine;
use crate::watch::metrics_store::MetricsStore;
use crate::watch::pod_event_store::PodEventEmitter;
use fleetos_core::proto::state::PodEvent;
use fleetos_core::proto::workload::{VerticalAutoscalingPolicy, WorkloadSpec};
use fleetos_core::spiffe::WorkloadRole;
use fleetos_core::tenant::TenantId;
use openraft::Raft;
use prost::Message;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Minimum metric windows per pod before it counts toward utilization.
/// Reuses the HPA constant for consistency.
const MIN_WINDOWS: usize = 3;

/// Default deadband percentage when policy specifies 0.
const DEFAULT_DEADBAND_PERCENT: u32 = 10;

pub struct VpaController {
    storage: Arc<StorageEngine>,
    metrics: Arc<MetricsStore>,
    raft: Arc<Raft<FleetosRaftConfig>>,
    guard: Arc<dyn DisruptionGuard>,
    pod_event_emitter: Arc<PodEventEmitter>,
    /// (tenant_id, workload_id) → unix time at which sustained shrink
    /// pressure was first observed. Leader-local wall-clock state.
    shrink_since: Mutex<HashMap<(String, String), i64>>,
}

impl VpaController {
    pub fn new(
        storage: Arc<StorageEngine>,
        metrics: Arc<MetricsStore>,
        raft: Arc<Raft<FleetosRaftConfig>>,
        guard: Arc<dyn DisruptionGuard>,
        pod_event_emitter: Arc<PodEventEmitter>,
    ) -> Self {
        Self {
            storage,
            metrics,
            raft,
            guard,
            pod_event_emitter,
            shrink_since: Mutex::new(HashMap::new()),
        }
    }

    /// One evaluation pass over all workloads (production entry point).
    pub async fn evaluate(&self) -> Result<(), ControllerError> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        self.evaluate_at(now).await
    }

    /// Evaluation pass at an explicit unix time (testable core).
    pub async fn evaluate_at(&self, now: i64) -> Result<(), ControllerError> {
        let workloads = self
            .storage
            .list_workloads()
            .map_err(ControllerError::Storage)?;
        let placements = self
            .storage
            .list_placements()
            .map_err(ControllerError::Storage)?;
        for record in &workloads {
            if let Err(e) = self.evaluate_workload(record, &placements, now).await {
                tracing::warn!(
                    tenant = %record.tenant_id,
                    workload = %record.workload_id,
                    error = %e,
                    "VPA evaluation failed for workload"
                );
            }
        }
        Ok(())
    }

    /// Evaluate one workload. Returns true if a mutation was proposed.
    async fn evaluate_workload(
        &self,
        record: &WorkloadSpecRecord,
        placements: &[Placement],
        now: i64,
    ) -> Result<bool, ControllerError> {
        let spec: WorkloadSpec = match WorkloadSpec::decode(record.spec_bytes.as_slice()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    tenant = %record.tenant_id,
                    workload = %record.workload_id,
                    error = %e,
                    "VPA: undecodable workload spec; skipping"
                );
                return Ok(false);
            }
        };

        let Some(policy) = spec.vertical_autoscaling.as_ref() else {
            return Ok(false);
        };
        if !policy.enabled {
            return Ok(false);
        }

        // Validate: at least one target must be active.
        let cpu_active = policy.target_cpu_utilization_percent > 0;
        let mem_active = policy.target_memory_utilization_percent > 0;
        if !cpu_active && !mem_active {
            tracing::warn!(
                tenant = %spec.tenant_id,
                workload = %spec.workload_id,
                "VPA policy has no active targets; skipping"
            );
            return Ok(false);
        }

        // Runtime HPA conflict check.
        if let Some(hpa) = spec.autoscaling.as_ref() {
            if hpa.enabled {
                if cpu_active && hpa.target_cpu_millicores > 0 {
                    tracing::warn!(
                        tenant = %spec.tenant_id,
                        workload = %spec.workload_id,
                        "VPA CPU conflicts with HPA CPU; VPA skipping CPU dimension"
                    );
                    // Disable CPU dimension at runtime.
                    return self
                        .evaluate_with_dimensions(
                            record, &spec, policy, placements, now, false, mem_active,
                        )
                        .await;
                }
                if mem_active && hpa.target_memory_bytes > 0 {
                    tracing::warn!(
                        tenant = %spec.tenant_id,
                        workload = %spec.workload_id,
                        "VPA memory conflicts with HPA memory; VPA skipping memory dimension"
                    );
                    return self
                        .evaluate_with_dimensions(
                            record, &spec, policy, placements, now, cpu_active, false,
                        )
                        .await;
                }
            }
        }

        self.evaluate_with_dimensions(
            record, &spec, policy, placements, now, cpu_active, mem_active,
        )
        .await
    }

    /// Core evaluation with explicit dimension flags.
    async fn evaluate_with_dimensions(
        &self,
        record: &WorkloadSpecRecord,
        spec: &WorkloadSpec,
        policy: &VerticalAutoscalingPolicy,
        placements: &[Placement],
        now: i64,
        cpu_active: bool,
        mem_active: bool,
    ) -> Result<bool, ControllerError> {
        if !cpu_active && !mem_active {
            return Ok(false);
        }

        // Get current footprint from the spec template.
        let current_resources = spec.pod_spec.as_ref().and_then(|ps| ps.resources.as_ref());
        let (current_vcpus, current_memory_mb) = match current_resources {
            Some(r) => (r.vcpus, r.memory_mb),
            None => {
                tracing::warn!(
                    tenant = %spec.tenant_id,
                    workload = %spec.workload_id,
                    "VPA: workload has no resource requirements; skipping"
                );
                return Ok(false);
            }
        };

        // Get placed pods for this workload.
        let pod_ids: Vec<&str> = placements
            .iter()
            .filter(|p| p.tenant_id == spec.tenant_id && p.service == spec.workload_id)
            .map(|p| p.pod_id.as_str())
            .collect();
        if pod_ids.is_empty() {
            return Ok(false);
        }

        // Qualifying pods: at least MIN_WINDOWS metric windows each.
        let mut qualifying: Vec<Vec<fleetos_core::proto::state::PodMetrics>> = Vec::new();
        for pod_id in &pod_ids {
            if let Some(windows) = self.metrics.get_windows(pod_id) {
                if windows.len() >= MIN_WINDOWS {
                    qualifying.push(windows);
                }
            }
        }
        if qualifying.is_empty() {
            return Ok(false);
        }

        // Compute per-dimension recommendations.
        let deadband = if policy.deadband_percent == 0 {
            DEFAULT_DEADBAND_PERCENT
        } else {
            policy.deadband_percent
        };

        let mut new_vcpus = current_vcpus;
        let mut new_memory_mb = current_memory_mb;
        let mut any_change = false;

        // CPU dimension.
        if cpu_active {
            let avg_cpu_millicores: u64 = qualifying
                .iter()
                .map(|ws| {
                    let sum: u64 = ws.iter().map(|w| w.cpu_millicores as u64).sum();
                    sum / ws.len() as u64
                })
                .sum::<u64>()
                / qualifying.len() as u64;

            // recommended_millicores = avg × 100 / target_pct
            let recommended_millicores =
                (avg_cpu_millicores * 100) / policy.target_cpu_utilization_percent as u64;
            // Convert to whole vCPUs (round up).
            let recommended_vcpus = ((recommended_millicores + 999) / 1000) as u32;
            // Clamp to bounds.
            let clamped = recommended_vcpus.clamp(policy.min_vcpus.max(1), policy.max_vcpus.max(1));

            // Deadband check for this dimension.
            if !within_deadband(current_vcpus, clamped, deadband) {
                new_vcpus = clamped;
                any_change = true;
            }
        }

        // Memory dimension.
        if mem_active {
            let avg_memory_bytes: u64 = qualifying
                .iter()
                .map(|ws| {
                    let sum: u64 = ws.iter().map(|w| w.memory_bytes).sum();
                    sum / ws.len() as u64
                })
                .sum::<u64>()
                / qualifying.len() as u64;

            // recommended_bytes = avg × 100 / target_pct
            let recommended_bytes =
                (avg_memory_bytes * 100) / policy.target_memory_utilization_percent as u64;
            // Convert to MB (round up).
            let recommended_mb = ((recommended_bytes + 1024 * 1024 - 1) / (1024 * 1024)) as u32;
            // Clamp to bounds (convert bounds to MB for comparison).
            let min_mb = ((policy.min_memory_bytes + 1024 * 1024 - 1) / (1024 * 1024)) as u32;
            let max_mb = ((policy.max_memory_bytes + 1024 * 1024 - 1) / (1024 * 1024)) as u32;
            let clamped = recommended_mb.clamp(min_mb.max(1), max_mb.max(1));

            if !within_deadband(current_memory_mb, clamped, deadband) {
                new_memory_mb = clamped;
                any_change = true;
            }
        }

        if !any_change {
            // Steady: clear any pending shrink marker.
            let key = (spec.tenant_id.clone(), spec.workload_id.clone());
            self.shrink_since.lock().unwrap().remove(&key);
            return Ok(false);
        }

        // Determine mode string.
        let mode_str = match policy.mode {
            0 => "OFF",
            1 => "RECREATE",
            _ => "OFF",
        };

        // Propose recommendation (both modes).
        let recommendation = VpaRecommendationRecord {
            tenant_id: spec.tenant_id.clone(),
            workload_id: spec.workload_id.clone(),
            recommended_vcpus: new_vcpus,
            recommended_memory_mb: new_memory_mb,
            current_vcpus,
            current_memory_mb,
            computed_at_unix: now,
            mode: mode_str.to_owned(),
        };

        // Check if recommendation changed (avoid redundant Raft writes).
        let existing = self
            .storage
            .get_vpa_recommendation(&spec.tenant_id, &spec.workload_id)
            .map_err(ControllerError::Storage)?;
        let rec_changed = match &existing {
            Some(e) => e.recommended_vcpus != new_vcpus || e.recommended_memory_mb != new_memory_mb,
            None => true,
        };

        if rec_changed {
            let audit = AuditContext {
                request_id: String::new(),
                actor: "system:vpa-controller".to_owned(),
                target: format!("{}:{}", spec.tenant_id, spec.workload_id),
                timestamp_unix: now as u64,
            };
            self.raft
                .client_write(AuditedCommand {
                    cmd: FleetosCommand::UpsertVpaRecommendation {
                        record: recommendation,
                    },
                    audit: Some(audit),
                })
                .await
                .map_err(|e| ControllerError::Raft(e.to_string()))?;
        }

        // OFF mode: recommendation only, no footprint change.
        if policy.mode == 0 {
            return Ok(rec_changed);
        }

        // RECREATE mode: apply the footprint change.
        let is_shrink = new_vcpus < current_vcpus || new_memory_mb < current_memory_mb;

        // Stabilization window for shrinks.
        if is_shrink {
            let window = policy.stabilization_window_seconds as i64;
            let key = (spec.tenant_id.clone(), spec.workload_id.clone());
            let since = {
                let mut m = self.shrink_since.lock().unwrap();
                *m.entry(key.clone()).or_insert(now)
            };
            if now - since < window {
                return Ok(false);
            }
        } else {
            // Grow: clear shrink marker.
            let key = (spec.tenant_id.clone(), spec.workload_id.clone());
            self.shrink_since.lock().unwrap().remove(&key);
        }

        // CR-7: pre-check tenant quota for grows.
        if new_vcpus > current_vcpus || new_memory_mb > current_memory_mb {
            if let Err(e) = self.check_quota_for_grow(&spec, new_vcpus, new_memory_mb) {
                tracing::warn!(
                    tenant = %spec.tenant_id,
                    workload = %spec.workload_id,
                    error = %e,
                    "VPA grow rejected by quota"
                );
                return Ok(false);
            }
        }

        // Check DisruptionGuard for one pod before proposing ResizeWorkload.
        let stale_pods = self.find_stale_pods(&spec, placements, new_vcpus, new_memory_mb);
        if stale_pods.is_empty() {
            return Ok(false);
        }

        // Guard check for the first stale pod.
        let first_pod = &stale_pods[0];
        let allowed = self.check_guard_for_pod(&spec, first_pod)?;
        if !allowed {
            tracing::info!(
                tenant = %spec.tenant_id,
                workload = %spec.workload_id,
                pod = %first_pod.pod_id,
                "VPA resize blocked by disruption guard"
            );
            return Ok(false);
        }

        // Emit Resizing event.
        self.pod_event_emitter.emit(PodEvent {
            pod_id: first_pod.pod_id.clone(),
            node_id: first_pod.node_id.to_string(),
            event_type: "Resizing".to_owned(),
            reason: "VerticalResize".to_owned(),
            message: format!(
                "vcpus {}→{}, memory {}→{} MB",
                current_vcpus, new_vcpus, current_memory_mb, new_memory_mb
            ),
            timestamp_unix: 0,
            count: 1,
        });

        // Propose ResizeWorkload (updates spec template).
        let mut new_spec = spec.clone();
        if let Some(ps) = new_spec.pod_spec.as_mut() {
            if let Some(res) = ps.resources.as_mut() {
                res.vcpus = new_vcpus;
                res.memory_mb = new_memory_mb;
            }
        }
        let new_record = WorkloadSpecRecord {
            tenant_id: record.tenant_id.clone(),
            workload_id: record.workload_id.clone(),
            spec_bytes: new_spec.encode_to_vec(),
            last_applied_bytes: vec![],
        };
        let audit = AuditContext {
            request_id: String::new(),
            actor: "system:vpa-controller".to_owned(),
            target: format!("{}:{}", record.tenant_id, record.workload_id),
            timestamp_unix: now as u64,
        };
        self.raft
            .client_write(AuditedCommand {
                cmd: FleetosCommand::ResizeWorkload { record: new_record },
                audit: Some(audit),
            })
            .await
            .map_err(|e| ControllerError::Raft(e.to_string()))?;

        // Remove the first stale pod: free ordinal slot + remove placement.
        self.remove_stale_pod(first_pod).await?;

        tracing::info!(
            tenant = %spec.tenant_id,
            workload = %spec.workload_id,
            pod = %first_pod.pod_id,
            new_vcpus = new_vcpus,
            new_memory_mb = new_memory_mb,
            "VPA resized workload (RECREATE)"
        );

        Ok(true)
    }

    /// Find pods whose placement resources don't match the new template.
    fn find_stale_pods(
        &self,
        spec: &WorkloadSpec,
        placements: &[Placement],
        new_vcpus: u32,
        new_memory_mb: u32,
    ) -> Vec<Placement> {
        let template_cpu_millicores = new_vcpus as u64 * 1000;
        let template_memory_bytes = new_memory_mb as u64 * 1024 * 1024;

        placements
            .iter()
            .filter(|p| {
                p.tenant_id == spec.tenant_id
                    && p.service == spec.workload_id
                    && (p.resources.cpu_millicores != template_cpu_millicores
                        || p.resources.memory_bytes != template_memory_bytes)
            })
            .cloned()
            .collect()
    }

    /// Check DisruptionGuard for a single pod replacement.
    fn check_guard_for_pod(
        &self,
        spec: &WorkloadSpec,
        pod: &Placement,
    ) -> Result<bool, ControllerError> {
        let result = (|| {
            let tenant = TenantId::new(spec.tenant_id.clone()).ok()?;
            let role_typed = WorkloadRole::try_from(pod.role.as_str()).ok()?;
            self.guard
                .allow_disruption(
                    &tenant,
                    &spec.workload_id,
                    &role_typed,
                    1,
                    DisruptionTarget::VerticalResize,
                )
                .ok()
        })();
        Ok(result.is_some())
    }

    /// Remove a stale pod: free ordinal slot + remove placement.
    async fn remove_stale_pod(&self, pod: &Placement) -> Result<(), ControllerError> {
        // Free the ordinal slot.
        let freed = OrdinalAssignment {
            tenant_id: pod.tenant_id.clone(),
            service: pod.service.clone(),
            role: pod.role.clone(),
            ordinal: pod.ordinal,
            current_pod_id: None,
            current_node_id: None,
        };
        self.raft
            .client_write(AuditedCommand::system(
                FleetosCommand::RecordOrdinalAssignment { record: freed },
            ))
            .await
            .map_err(|e| ControllerError::Raft(e.to_string()))?;

        // Remove the placement.
        self.raft
            .client_write(AuditedCommand::system(FleetosCommand::RemovePlacement {
                pod_id: pod.pod_id.clone(),
            }))
            .await
            .map_err(|e| ControllerError::Raft(e.to_string()))?;

        // Emit Resized event.
        self.pod_event_emitter.emit(PodEvent {
            pod_id: pod.pod_id.clone(),
            node_id: pod.node_id.to_string(),
            event_type: "Resized".to_owned(),
            reason: "VerticalResize".to_owned(),
            message: String::new(),
            timestamp_unix: 0,
            count: 1,
        });

        Ok(())
    }

    /// CR-7: pre-check tenant quota for a footprint increase.
    fn check_quota_for_grow(
        &self,
        spec: &WorkloadSpec,
        new_vcpus: u32,
        new_memory_mb: u32,
    ) -> Result<(), ControllerError> {
        let quota = self
            .storage
            .get_tenant_quota(&spec.tenant_id)
            .map_err(ControllerError::Storage)?;
        let Some(quota) = quota else {
            return Ok(()); // No quota = unlimited.
        };

        let (current_cpu, current_memory, _workloads) = self
            .storage
            .compute_tenant_usage(&spec.tenant_id)
            .map_err(ControllerError::Storage)?;

        // Compute the delta for this workload.
        let total_replicas: u64 = spec.replicas.values().map(|&c| c as u64).sum();
        let old_cpu_per_pod = spec
            .pod_spec
            .as_ref()
            .and_then(|ps| ps.resources.as_ref())
            .map(|r| r.vcpus as u64 * 1000)
            .unwrap_or(0);
        let new_cpu_per_pod = new_vcpus as u64 * 1000;
        let old_mem_per_pod = spec
            .pod_spec
            .as_ref()
            .and_then(|ps| ps.resources.as_ref())
            .map(|r| r.memory_mb as u64 * 1024 * 1024)
            .unwrap_or(0);
        let new_mem_per_pod = new_memory_mb as u64 * 1024 * 1024;

        let new_total_cpu =
            current_cpu - (old_cpu_per_pod * total_replicas) + (new_cpu_per_pod * total_replicas);
        let new_total_memory = current_memory - (old_mem_per_pod * total_replicas)
            + (new_mem_per_pod * total_replicas);

        if new_total_cpu > quota.max_cpu_millicores {
            return Err(ControllerError::Raft(format!(
                "tenant '{}' CPU quota exceeded: {} > {}",
                spec.tenant_id, new_total_cpu, quota.max_cpu_millicores
            )));
        }
        if new_total_memory > quota.max_memory_bytes {
            return Err(ControllerError::Raft(format!(
                "tenant '{}' memory quota exceeded: {} > {}",
                spec.tenant_id, new_total_memory, quota.max_memory_bytes
            )));
        }
        Ok(())
    }
}

/// True if `recommended` is within ±`deadband_pct`% of `current`.
fn within_deadband(current: u32, recommended: u32, deadband_pct: u32) -> bool {
    if current == 0 {
        return false;
    }
    let diff = if recommended > current {
        (recommended - current) as u64
    } else {
        (current - recommended) as u64
    };
    diff * 100 <= (current as u64) * (deadband_pct as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadband_truth_table() {
        assert!(within_deadband(10, 10, 10)); // no change
        assert!(within_deadband(10, 11, 10)); // +10%
        assert!(within_deadband(10, 9, 10)); // -10%
        assert!(!within_deadband(10, 12, 10)); // +20%
        assert!(!within_deadband(10, 8, 10)); // -20%
        assert!(!within_deadband(0, 1, 10)); // degenerate current
    }

    #[test]
    fn vcpu_recommendation_math() {
        // avg=500m, target=70% → recommended = 500×100/70 = 714m → ceil(714/1000) = 1 vCPU
        let avg_cpu: u64 = 500;
        let target_pct: u64 = 70;
        let recommended_millicores = (avg_cpu * 100) / target_pct;
        let recommended_vcpus = ((recommended_millicores + 999) / 1000) as u32;
        assert_eq!(recommended_vcpus, 1);

        // avg=1500m, target=70% → 2142m → 3 vCPU
        let avg_cpu: u64 = 1500;
        let recommended_millicores = (avg_cpu * 100) / target_pct;
        let recommended_vcpus = ((recommended_millicores + 999) / 1000) as u32;
        assert_eq!(recommended_vcpus, 3);
    }

    #[test]
    fn memory_recommendation_math() {
        // avg=512MB, target=80% → 640MB
        let avg_bytes: u64 = 512 * 1024 * 1024;
        let target_pct: u64 = 80;
        let recommended_bytes = (avg_bytes * 100) / target_pct;
        let recommended_mb = ((recommended_bytes + 1024 * 1024 - 1) / (1024 * 1024)) as u32;
        assert_eq!(recommended_mb, 640);
    }
}
