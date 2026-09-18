//! CR-CTRL-8: Metrics-based pod autoscaler (HPA).
//!
//! Leader-gated controller that consumes PodMetrics from the leader-local
//! `MetricsStore` (CR-CORE-9 ingestion), computes desired replicas against
//! the workload's `AutoscalingPolicy`, and proposes `ScaleWorkload` through
//! Raft. The policy is declarative and read-only here; an absent policy or
//! `enabled == false` is a hard stop (fail-closed).
//!
//! Multi-metric (CR-CORE-9 addendum): the active targets are CPU
//! (`target_cpu_millicores`), memory (`target_memory_bytes`), and net RX/TX
//! (`target_net_*_bytes_per_sec`). A zero target means "do not autoscale on
//! this metric."
//!
//! Semantics (all deterministic given the same inputs):
//! - Utilization: for each active metric, the average of per-pod rolling
//!   averages over the workload's placed pods; desired per metric is
//!   ceil(current_total * avg / target) clamped to [min_replicas,
//!   max_replicas]; the final desired is the MAX across active metrics
//!   (standard K8s multi-metric semantics). Pods with fewer than
//!   `MIN_WINDOWS` metric windows are excluded; workloads with no
//!   qualifying pods are skipped (no reaction to noise).
//! - `min_replicas` is floored at 1: HPA never scales a workload to zero
//!   and never resurrects a stopped one (K8s parity — scale-from-zero is
//!   out of scope).
//! - Anti-thrash deadband: no action while the desired total is within
//!   ±10% of the current total.
//! - Scale-up executes immediately. Scale-down executes only after
//!   `stabilization_window_seconds` of sustained low utilization AND with
//!   `DisruptionGuard` consent (CR-CTRL-6 seam).
//! - The desired total is distributed across roles proportionally to the
//!   current replica ratios (largest remainder; ties broken by ascending
//!   role name).
//!
//! Net-metric unit contract (settled): the controller compares reported
//! `net_rx_bytes` / `net_tx_bytes` verbatim against
//! `target_net_*_bytes_per_sec`; fleetos-agent MUST normalize net counters
//! to per-second rates at the CR-CORE-9 ingestion boundary before reporting.
//! fleetos-agent builds against this implementation — the contract flows
//! control → agent.
//!
//! Known limitation: tenant quotas are enforced at the AdminService
//! boundary, not in the state machine; HPA is bounded by the operator-set
//! `max_replicas` instead.
use super::ControllerError;
use crate::disruption::{DisruptionGuard, DisruptionTarget};
use crate::raft::records::{AuditContext, WorkloadSpecRecord};
use crate::raft::{AuditedCommand, FleetosCommand, FleetosRaftConfig};
use crate::scheduler::Placement;
use crate::storage::StorageEngine;
use crate::watch::metrics_store::MetricsStore;
use fleetos_core::proto::state::PodMetrics;
use fleetos_core::proto::workload::WorkloadSpec;
use fleetos_core::spiffe::WorkloadRole;
use fleetos_core::tenant::TenantId;
use openraft::Raft;
use prost::Message;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

/// Minimum metric windows per pod before it counts toward utilization.
pub const MIN_WINDOWS: usize = 3;

/// Deadband: no action while |desired - current| is within this percentage
/// of current (anti-thrash).
const DEADBAND_PERCENT: u64 = 10;

/// Rolling average of one metric across a pod's metric windows.
fn pod_average_of(windows: &[PodMetrics], metric: impl Fn(&PodMetrics) -> u64) -> u64 {
    if windows.is_empty() {
        return 0;
    }
    let sum: u64 = windows.iter().map(metric).sum();
    sum / windows.len() as u64
}

/// Rolling average CPU millicores across a pod's metric windows.
pub fn pod_average_cpu(windows: &[PodMetrics]) -> u64 {
    pod_average_of(windows, |w| w.cpu_millicores as u64)
}

/// Rolling average memory bytes across a pod's metric windows.
pub fn pod_average_memory(windows: &[PodMetrics]) -> u64 {
    pod_average_of(windows, |w| w.memory_bytes)
}

/// Rolling average net RX bytes across a pod's metric windows.
pub fn pod_average_net_rx(windows: &[PodMetrics]) -> u64 {
    pod_average_of(windows, |w| w.net_rx_bytes)
}

/// Rolling average net TX bytes across a pod's metric windows.
pub fn pod_average_net_tx(windows: &[PodMetrics]) -> u64 {
    pod_average_of(windows, |w| w.net_tx_bytes)
}

/// One autoscaling signal: observed average utilization and the policy
/// target for a single metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricSignal {
    /// Average utilization across qualifying pods.
    pub avg: u64,
    /// Policy target for this metric. Zero means the metric is inactive.
    pub target: u64,
}

/// Desired total replicas from a single active metric:
/// `ceil(current_total * avg / target)`, clamped to `[min, max]`.
///
/// Returns `None` when the metric is inactive (`target == 0`) or the input
/// is degenerate (`current_total == 0`).
pub fn compute_desired_for_metric(
    current_total: u32,
    avg: u64,
    target: u64,
    min: u32,
    max: u32,
) -> Option<u32> {
    if current_total == 0 || target == 0 {
        return None;
    }
    // ceil(current * avg / target) in integer math (u128: cannot overflow).
    let raw = ((current_total as u128) * (avg as u128) + (target as u128) - 1) / (target as u128);
    let raw = raw.min(u32::MAX as u128) as u32;
    Some(raw.clamp(min, max))
}

/// Multi-metric HPA semantics (K8s parity): compute desired per active
/// metric and take the MAX across metrics. Returns `None` when no active
/// metric yields a desired count (no active targets or a stopped workload);
/// callers treat that as "no reaction".
pub fn compute_desired_total(
    current_total: u32,
    signals: &[MetricSignal],
    min: u32,
    max: u32,
) -> Option<u32> {
    let mut best: Option<u32> = None;
    for signal in signals {
        if let Some(desired) =
            compute_desired_for_metric(current_total, signal.avg, signal.target, min, max)
        {
            best = Some(best.map_or(desired, |cur| cur.max(desired)));
        }
    }
    best
}

/// True when `desired_total` is within ±`DEADBAND_PERCENT`% of `current_total`.
pub fn within_deadband(current_total: u32, desired_total: u32) -> bool {
    if current_total == 0 {
        return false;
    }
    let diff = if desired_total > current_total {
        (desired_total - current_total) as u64
    } else {
        (current_total - desired_total) as u64
    };
    // diff / current <= DEADBAND_PERCENT%  ⇔  diff * 100 <= current * P
    diff * 100 <= (current_total as u64) * DEADBAND_PERCENT
}

/// Distribute `desired_total` across roles proportionally to `current`
/// (largest-remainder method; ties broken by ascending role name).
/// Deterministic. The result always sums to exactly `desired_total`.
pub fn distribute_replicas(
    current: &BTreeMap<String, u32>,
    desired_total: u32,
) -> BTreeMap<String, u32> {
    let mut out: BTreeMap<String, u32> = current.keys().map(|k| (k.clone(), 0)).collect();
    let current_total: u64 = current.values().map(|&v| v as u64).sum();
    if current_total == 0 || desired_total == 0 {
        return out;
    }
    let desired = desired_total as u64;
    // (role, base allocation, remainder numerator)
    let mut parts: Vec<(String, u64, u64)> = Vec::with_capacity(current.len());
    let mut allocated: u64 = 0;
    for (role, &count) in current.iter() {
        let numerator = desired * (count as u64);
        let base = numerator / current_total;
        let remainder = numerator % current_total;
        allocated += base;
        parts.push((role.clone(), base, remainder));
    }
    // Hand out the shortfall one replica at a time, largest remainder first,
    // ties broken by ascending role name (deterministic).
    let mut order: Vec<usize> = (0..parts.len()).collect();
    order.sort_by(|&a, &b| {
        parts[b]
            .2
            .cmp(&parts[a].2)
            .then_with(|| parts[a].0.cmp(&parts[b].0))
    });
    let mut shortfall = desired.saturating_sub(allocated);
    for idx in order {
        if shortfall == 0 {
            break;
        }
        parts[idx].1 += 1;
        shortfall -= 1;
    }
    for (role, base, _) in parts {
        out.insert(role, base as u32);
    }
    out
}

pub struct HpaController {
    storage: Arc<StorageEngine>,
    metrics: Arc<MetricsStore>,
    raft: Arc<Raft<FleetosRaftConfig>>,
    guard: Arc<dyn DisruptionGuard>,
    /// (tenant_id, workload_id) → unix time at which sustained scale-down
    /// pressure was first observed. Leader-local wall-clock state: resets on
    /// leadership change (conservative — the new leader re-observes).
    scale_down_since: Mutex<HashMap<(String, String), i64>>,
}

impl HpaController {
    pub fn new(
        storage: Arc<StorageEngine>,
        metrics: Arc<MetricsStore>,
        raft: Arc<Raft<FleetosRaftConfig>>,
        guard: Arc<dyn DisruptionGuard>,
    ) -> Self {
        Self {
            storage,
            metrics,
            raft,
            guard,
            scale_down_since: Mutex::new(HashMap::new()),
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
                    "HPA evaluation failed for workload"
                );
            }
        }
        Ok(())
    }

    /// Evaluate one workload. Returns true if a ScaleWorkload was proposed.
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
                    "HPA: undecodable workload spec; skipping"
                );
                return Ok(false);
            }
        };
        let Some(policy) = spec.autoscaling.as_ref() else {
            return Ok(false);
        };
        if !policy.enabled {
            return Ok(false);
        }
        // Multi-metric validity: at least one target must be active.
        let no_active_target = policy.target_cpu_millicores == 0
            && policy.target_memory_bytes == 0
            && policy.target_net_rx_bytes_per_sec == 0
            && policy.target_net_tx_bytes_per_sec == 0;
        if no_active_target || policy.max_replicas == 0 {
            tracing::warn!(
                tenant = %spec.tenant_id,
                workload = %spec.workload_id,
                "HPA policy invalid (no active metric targets or zero max); autoscaling disabled for workload"
            );
            return Ok(false);
        }
        let min = policy.min_replicas.max(1);
        let max = policy.max_replicas;
        if min > max {
            tracing::warn!(
                tenant = %spec.tenant_id,
                workload = %spec.workload_id,
                min,
                max,
                "HPA policy invalid (min > max); autoscaling disabled for workload"
            );
            return Ok(false);
        }

        // Pods currently placed for this workload.
        let pod_ids: Vec<&str> = placements
            .iter()
            .filter(|p| p.tenant_id == spec.tenant_id && p.service == spec.workload_id)
            .map(|p| p.pod_id.as_str())
            .collect();
        if pod_ids.is_empty() {
            return Ok(false);
        }

        // Qualifying pods: at least MIN_WINDOWS metric windows each, so
        // fresh/restarted pods cannot skew the signal.
        let mut qualifying: Vec<Vec<PodMetrics>> = Vec::new();
        for pod_id in &pod_ids {
            if let Some(windows) = self.metrics.get_windows(pod_id) {
                if windows.len() >= MIN_WINDOWS {
                    qualifying.push(windows);
                }
            }
        }
        if qualifying.is_empty() {
            return Ok(false); // insufficient data — no reaction to noise
        }

        let current: BTreeMap<String, u32> =
            spec.replicas.iter().map(|(k, v)| (k.clone(), *v)).collect();
        let current_total: u32 = current.values().sum();
        if current_total == 0 {
            return Ok(false); // stopped workload: HPA never resurrects
        }

        // One signal per active metric: average of per-pod rolling averages
        // against the policy target. Net targets are compared verbatim —
        // the agent reports per-second units (see module doc).
        let metric_defs: [(u64, fn(&[PodMetrics]) -> u64); 4] = [
            (policy.target_cpu_millicores as u64, pod_average_cpu),
            (policy.target_memory_bytes, pod_average_memory),
            (policy.target_net_rx_bytes_per_sec, pod_average_net_rx),
            (policy.target_net_tx_bytes_per_sec, pod_average_net_tx),
        ];
        let mut signals: Vec<MetricSignal> = Vec::new();
        for (target, average_fn) in metric_defs {
            if target == 0 {
                continue; // zero target: metric inactive
            }
            let sum: u64 = qualifying.iter().map(|w| average_fn(w)).sum();
            let avg = sum / qualifying.len() as u64;
            signals.push(MetricSignal { avg, target });
        }

        // K8s multi-metric semantics: max across active metrics.
        let Some(desired_total) = compute_desired_total(current_total, &signals, min, max) else {
            return Ok(false); // fail-closed: no usable signal
        };

        let key = (spec.tenant_id.clone(), spec.workload_id.clone());
        if within_deadband(current_total, desired_total) {
            // Steady (or recovered): clear any pending scale-down marker.
            self.scale_down_since.lock().unwrap().remove(&key);
            return Ok(false);
        }

        if desired_total < current_total {
            // Scale-down: sustained low utilization for the full window.
            let window = policy.stabilization_window_seconds as i64;
            let since = {
                let mut m = self.scale_down_since.lock().unwrap();
                *m.entry(key.clone()).or_insert(now)
            };
            if now - since < window {
                return Ok(false);
            }
            let new_replicas = distribute_replicas(&current, desired_total);
            // CR-CTRL-6 seam: every role being scaled down must be allowed.
            for (role, &to) in new_replicas.iter() {
                let from = current.get(role).copied().unwrap_or(0);
                if to < from {
                    let count = from - to;
                    // Fail-closed: if tenant/role can't be typed, block.
                    let allowed = (|| {
                        let tenant = TenantId::new(spec.tenant_id.clone()).ok()?;
                        let role_typed = WorkloadRole::try_from(role.as_str()).ok()?;
                        self.guard
                            .allow_disruption(
                                &tenant,
                                &spec.workload_id,
                                &role_typed,
                                count,
                                DisruptionTarget::ScaleDown,
                            )
                            .ok()
                    })()
                    .is_some();
                    if !allowed {
                        tracing::info!(
                            tenant = %spec.tenant_id,
                            workload = %spec.workload_id,
                            role = %role,
                            "HPA scale-down blocked by disruption guard"
                        );
                        return Ok(false);
                    }
                }
            }
            self.propose_scale(record, &spec, &new_replicas).await?;
            self.scale_down_since.lock().unwrap().remove(&key);
            return Ok(true);
        }

        // Scale-up: immediate (no cooldown).
        self.scale_down_since.lock().unwrap().remove(&key);
        let new_replicas = distribute_replicas(&current, desired_total);
        self.propose_scale(record, &spec, &new_replicas).await?;
        Ok(true)
    }

    /// Propose the scaled spec through Raft (existing ScaleWorkload command —
    /// the state machine updates the stored spec and prunes excess placements).
    async fn propose_scale(
        &self,
        record: &WorkloadSpecRecord,
        spec: &WorkloadSpec,
        new_replicas: &BTreeMap<String, u32>,
    ) -> Result<(), ControllerError> {
        let mut new_spec = spec.clone();
        new_spec.replicas = new_replicas.iter().map(|(k, v)| (k.clone(), *v)).collect();
        let new_record = WorkloadSpecRecord {
            tenant_id: record.tenant_id.clone(),
            workload_id: record.workload_id.clone(),
            spec_bytes: new_spec.encode_to_vec(),
            last_applied_bytes: vec![],
        };
        let audit = AuditContext {
            request_id: String::new(),
            actor: "system:hpa-controller".to_owned(),
            target: format!("{}:{}", record.tenant_id, record.workload_id),
            timestamp_unix: time::OffsetDateTime::now_utc().unix_timestamp() as u64,
        };
        self.raft
            .client_write(AuditedCommand {
                cmd: FleetosCommand::ScaleWorkload { record: new_record },
                audit: Some(audit),
            })
            .await
            .map_err(|e| ControllerError::Raft(e.to_string()))?;
        tracing::info!(
            tenant = %record.tenant_id,
            workload = %record.workload_id,
            replicas = ?new_replicas,
            "HPA scaled workload"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::ResourceSpec;
    use fleetos_core::proto::fleetos::AutoscalingPolicy;
    use std::time::Duration;

    const NODE_ID: &str = "spiffe://fleet.example.internal/ns/system/node/agent-1";

    // ---------- pure decision logic ----------

    fn windows_of(cpu: u32, count: usize) -> Vec<PodMetrics> {
        (0..count)
            .map(|i| PodMetrics {
                pod_id: "p".to_owned(),
                cpu_millicores: cpu,
                memory_bytes: 0,
                net_tx_bytes: 0,
                net_rx_bytes: 0,
                window_unix: 1_000 + i as u64,
            })
            .collect()
    }

    fn signal(avg: u64, target: u64) -> MetricSignal {
        MetricSignal { avg, target }
    }

    #[test]
    fn pod_average_cpu_is_the_mean() {
        let mut ws = windows_of(100, 3);
        ws.push(PodMetrics {
            cpu_millicores: 300,
            ..ws[0].clone()
        });
        assert_eq!(pod_average_cpu(&ws), 150);
        assert_eq!(pod_average_cpu(&[]), 0);
    }

    #[test]
    fn pod_average_memory_and_net_are_means() {
        let ws: Vec<PodMetrics> = (0..3)
            .map(|i| PodMetrics {
                pod_id: "p".to_owned(),
                cpu_millicores: 0,
                memory_bytes: 100 * (i as u64 + 1), // 100, 200, 300
                net_tx_bytes: 10 * (i as u64 + 1),  // 10, 20, 30
                net_rx_bytes: 1_000 * (i as u64 + 1), // 1000, 2000, 3000
                window_unix: 1_000 + i as u64,
            })
            .collect();
        assert_eq!(pod_average_memory(&ws), 200);
        assert_eq!(pod_average_net_tx(&ws), 20);
        assert_eq!(pod_average_net_rx(&ws), 2_000);
        assert_eq!(pod_average_memory(&[]), 0);
        assert_eq!(pod_average_net_rx(&[]), 0);
        assert_eq!(pod_average_net_tx(&[]), 0);
    }

    #[test]
    fn desired_total_scales_with_utilization() {
        // 2 pods at 2x target → 4.
        assert_eq!(
            compute_desired_total(2, &[signal(1_000, 500)], 1, 10),
            Some(4)
        );
        // ceil: 3 pods at 501/500 → ceil(3.006) = 4.
        assert_eq!(
            compute_desired_total(3, &[signal(501, 500)], 1, 10),
            Some(4)
        );
        // idle → min.
        assert_eq!(compute_desired_total(5, &[signal(0, 500)], 2, 10), Some(2));
    }

    #[test]
    fn desired_total_clamps_to_bounds() {
        assert_eq!(
            compute_desired_total(2, &[signal(10_000, 500)], 1, 5),
            Some(5)
        ); // max
        assert_eq!(compute_desired_total(5, &[signal(1, 500)], 3, 10), Some(3)); // min
    }

    #[test]
    fn desired_total_guards_degenerate_inputs() {
        // Stopped workload → no decision.
        assert_eq!(compute_desired_total(0, &[signal(1_000, 500)], 1, 10), None);
        // No active metrics → no decision.
        assert_eq!(compute_desired_total(3, &[], 1, 10), None);
        // Zero target is inactive even when red-hot.
        assert_eq!(
            compute_desired_total(3, &[signal(u64::MAX, 0)], 1, 10),
            None
        );
    }

    #[test]
    fn max_across_metrics_wins() {
        // CPU says ceil(2 * 300/500) = 2; memory says 2 * 2048/512 = 8.
        let signals = [signal(300, 500), signal(2_048, 512)];
        assert_eq!(compute_desired_total(2, &signals, 1, 10), Some(8));
        // Order-independent.
        assert_eq!(
            compute_desired_total(2, &[signal(2_048, 512), signal(300, 500)], 1, 10),
            Some(8)
        );
    }

    #[test]
    fn inactive_metric_never_contributes() {
        // Hot-but-inactive (target 0) must not move the desired count.
        let signals = [signal(300, 500), signal(u64::MAX, 0)];
        assert_eq!(compute_desired_total(2, &signals, 1, 10), Some(2));
    }

    #[test]
    fn per_metric_clamp_then_max() {
        // Metric A wants 100 → clamps to max 5. Metric B wants 2.
        let signals = [signal(25_000, 500), signal(500, 500)];
        assert_eq!(compute_desired_total(2, &signals, 1, 5), Some(5));
        // Both below min → min.
        let signals = [signal(1, 500), signal(1, 512)];
        assert_eq!(compute_desired_total(3, &signals, 3, 10), Some(3));
    }

    #[test]
    fn deadband_truth_table() {
        assert!(within_deadband(10, 10)); // no change
        assert!(within_deadband(10, 11)); // +10%
        assert!(within_deadband(10, 9)); // -10%
        assert!(!within_deadband(10, 12)); // +20%
        assert!(!within_deadband(10, 8)); // -20%
        assert!(!within_deadband(1, 2)); // +100%
        assert!(!within_deadband(0, 1)); // degenerate current
    }

    #[test]
    fn distribute_replicas_single_role() {
        let current: BTreeMap<String, u32> = [("primary".to_owned(), 2)].into_iter().collect();
        let out = distribute_replicas(&current, 5);
        assert_eq!(out["primary"], 5);
    }

    #[test]
    fn distribute_replicas_proportional_with_remainder() {
        // {primary: 1, replica: 2}, desired 4:
        // bases primary=1 (rem 1), replica=2 (rem 2); shortfall 1 goes to
        // replica (largest remainder) → {primary: 1, replica: 3}.
        let current: BTreeMap<String, u32> = [("primary".to_owned(), 1), ("replica".to_owned(), 2)]
            .into_iter()
            .collect();
        let out = distribute_replicas(&current, 4);
        assert_eq!(out["primary"], 1);
        assert_eq!(out["replica"], 3);
    }

    #[test]
    fn distribute_replicas_tiebreak_by_role_name() {
        let current: BTreeMap<String, u32> = [("a".to_owned(), 1), ("b".to_owned(), 1)]
            .into_iter()
            .collect();
        let out = distribute_replicas(&current, 3);
        assert_eq!(out["a"], 2); // equal remainders → "a" wins
        assert_eq!(out["b"], 1);
    }

    #[test]
    fn distribute_replicas_sum_is_exact() {
        let current: BTreeMap<String, u32> = [
            ("a".to_owned(), 3),
            ("b".to_owned(), 5),
            ("c".to_owned(), 7),
        ]
        .into_iter()
        .collect();
        for desired in 0..=20u32 {
            let out = distribute_replicas(&current, desired);
            assert_eq!(out.values().sum::<u32>(), desired, "desired={desired}");
        }
    }

    // ---------- Raft-backed integration tests ----------

    struct NoOpNetworkFactory;
    impl openraft::network::RaftNetworkFactory<crate::raft::FleetosRaftConfig> for NoOpNetworkFactory {
        type Network = NoOpNetwork;
        async fn new_client(&mut self, _target: u64, _node: &openraft::BasicNode) -> Self::Network {
            NoOpNetwork
        }
    }

    struct NoOpNetwork;
    impl openraft::network::RaftNetwork<crate::raft::FleetosRaftConfig> for NoOpNetwork {
        async fn append_entries(
            &mut self,
            _req: openraft::raft::AppendEntriesRequest<crate::raft::FleetosRaftConfig>,
            _option: openraft::network::RPCOption,
        ) -> Result<
            openraft::raft::AppendEntriesResponse<u64>,
            openraft::error::RPCError<u64, openraft::BasicNode, openraft::error::RaftError<u64>>,
        > {
            Err(openraft::error::RPCError::Network(
                openraft::error::NetworkError::new(&std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "test",
                )),
            ))
        }
        async fn vote(
            &mut self,
            _req: openraft::raft::VoteRequest<u64>,
            _option: openraft::network::RPCOption,
        ) -> Result<
            openraft::raft::VoteResponse<u64>,
            openraft::error::RPCError<u64, openraft::BasicNode, openraft::error::RaftError<u64>>,
        > {
            Err(openraft::error::RPCError::Network(
                openraft::error::NetworkError::new(&std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "test",
                )),
            ))
        }
        async fn install_snapshot(
            &mut self,
            _req: openraft::raft::InstallSnapshotRequest<crate::raft::FleetosRaftConfig>,
            _option: openraft::network::RPCOption,
        ) -> Result<
            openraft::raft::InstallSnapshotResponse<u64>,
            openraft::error::RPCError<
                u64,
                openraft::BasicNode,
                openraft::error::RaftError<u64, openraft::error::InstallSnapshotError>,
            >,
        > {
            Err(openraft::error::RPCError::Network(
                openraft::error::NetworkError::new(&std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "test",
                )),
            ))
        }
    }

    async fn setup(
        name: &str,
    ) -> (
        Arc<Raft<crate::raft::FleetosRaftConfig>>,
        crate::storage::Keyspaces,
        Arc<StorageEngine>,
        Arc<MetricsStore>,
    ) {
        let dir =
            std::env::temp_dir().join(format!("fleetos-hpa-test-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        let db = crate::storage::open_database(&dir).unwrap();
        let keyspaces = crate::storage::init_keyspaces(&db).unwrap();
        let versioned_state =
            crate::storage::version::VersionedState::new(keyspaces.version.clone());
        let broadcast_hub = crate::watch::broadcast::BroadcastHub::new();
        let raft_config = Arc::new(
            openraft::Config {
                heartbeat_interval: 50,
                election_timeout_min: 150,
                election_timeout_max: 300,
                ..Default::default()
            }
            .validate()
            .unwrap(),
        );
        let log_storage = crate::raft::store::FjallLogStorage::new(
            db.clone(),
            keyspaces.raft_log.clone(),
            keyspaces.raft_log_meta.clone(),
        );
        let state_machine = crate::raft::state_machine::FjallStateMachine::new(
            db.clone(),
            keyspaces.clone(),
            versioned_state,
            broadcast_hub,
            "test.example.internal".to_owned(),
        );
        let raft = openraft::Raft::new(
            1,
            raft_config,
            NoOpNetworkFactory,
            log_storage,
            state_machine,
        )
        .await
        .unwrap();
        let raft = Arc::new(raft);
        let mut members = std::collections::BTreeMap::new();
        members.insert(
            1,
            openraft::BasicNode {
                addr: String::new(),
            },
        );
        raft.initialize(members).await.unwrap();
        // Wait for leadership — fail explicitly if it never happens.
        let mut became_leader = false;
        for _ in 0..150 {
            if raft.metrics().borrow().state == openraft::ServerState::Leader {
                became_leader = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            became_leader,
            "single-node raft did not elect itself leader within 3s"
        );
        let storage = Arc::new(StorageEngine::new(
            keyspaces.version.clone(),
            keyspaces.raft_log.clone(),
            keyspaces.raft_log_meta.clone(),
            keyspaces.raft_state.clone(),
            keyspaces.raft_snapshot.clone(),
            keyspaces.nodes.clone(),
            keyspaces.svids.clone(),
            keyspaces.placements.clone(),
            keyspaces.tenants.clone(),
            keyspaces.ordinals.clone(),
            keyspaces.workloads.clone(),
            keyspaces.router_assignments.clone(),
            keyspaces.active_delegations.clone(),
            keyspaces.revoked_delegations.clone(),
            keyspaces.join_tokens.clone(),
            keyspaces.pcr_policies.clone(),
            keyspaces.dummy_ips.clone(),
            keyspaces.secrets.clone(),
            keyspaces.sag_rules.clone(),
            keyspaces.node_pools.clone(),
            keyspaces.audit_log.clone(),
            keyspaces.operator_grants.clone(),
            keyspaces.workload_status.clone(),
            keyspaces.tenant_quotas.clone(),
            keyspaces.vpa_recommendations.clone(),
        ));
        let metrics = MetricsStore::new(keyspaces.placements.clone());
        (raft, keyspaces, storage, metrics)
    }

    fn policy(target: u32, min: u32, max: u32, stab: u32) -> AutoscalingPolicy {
        AutoscalingPolicy {
            enabled: true,
            target_cpu_millicores: target,
            target_memory_bytes: 0,
            target_net_rx_bytes_per_sec: 0,
            target_net_tx_bytes_per_sec: 0,
            min_replicas: min,
            max_replicas: max,
            stabilization_window_seconds: stab,
        }
    }

    fn mem_policy(target_bytes: u64, min: u32, max: u32, stab: u32) -> AutoscalingPolicy {
        AutoscalingPolicy {
            enabled: true,
            target_cpu_millicores: 0, // CPU inactive: memory is the sole driver
            target_memory_bytes: target_bytes,
            target_net_rx_bytes_per_sec: 0,
            target_net_tx_bytes_per_sec: 0,
            min_replicas: min,
            max_replicas: max,
            stabilization_window_seconds: stab,
        }
    }

    /// Raft-bound await with a hard timeout: these tests must fail fast with a
    /// clear message — never hang — if a propose/commit ever stalls.
    async fn raft_timeout<F, T>(label: &str, fut: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        tokio::time::timeout(Duration::from_secs(30), fut)
            .await
            .unwrap_or_else(|_| panic!("{label} timed out after 30s — raft propose/commit stalled"))
    }

    async fn eval(hpa: &HpaController, now: i64) {
        raft_timeout("evaluate_at", hpa.evaluate_at(now))
            .await
            .unwrap();
    }

    /// Seed the workload spec + placements DIRECTLY into fjall, bypassing
    /// Raft. Every Raft commit fsyncs twice (log append + state-machine
    /// apply), and the SUT in these tests is the HPA decision path — not the
    /// placement pipeline. Direct seeding keeps each test at ≤2 Raft commits
    /// (initialize + the single ScaleWorkload under test).
    fn seed_direct(keyspaces: &crate::storage::Keyspaces, spec: &WorkloadSpec, pods: &[&str]) {
        let spec_record = WorkloadSpecRecord {
            tenant_id: spec.tenant_id.clone(),
            workload_id: spec.workload_id.clone(),
            spec_bytes: prost::Message::encode_to_vec(spec),
            last_applied_bytes: vec![],
        };
        let key = format!("{}:{}", spec.tenant_id, spec.workload_id);
        let value = postcard::to_allocvec(&spec_record).unwrap();
        keyspaces
            .workloads
            .insert(key.as_bytes(), value.as_slice())
            .unwrap();
        for (i, pod_id) in pods.iter().enumerate() {
            let placement = Placement {
                pod_id: (*pod_id).to_owned(),
                tenant_id: "t1".to_owned(),
                service: spec.workload_id.clone(),
                role: "primary".to_owned(),
                ordinal: i as u32,
                node_id: NODE_ID.parse().unwrap(),
                resources: ResourceSpec {
                    cpu_millicores: 500,
                    memory_bytes: 512 * 1024 * 1024,
                },
            };
            let value = postcard::to_allocvec(&placement).unwrap();
            keyspaces
                .placements
                .insert(pod_id.as_bytes(), value.as_slice())
                .unwrap();
        }
    }

    fn spec_with(replicas: u32, pol: AutoscalingPolicy) -> WorkloadSpec {
        WorkloadSpec {
            tenant_id: "t1".to_owned(),
            workload_id: "web".to_owned(),
            image: "web:v1".to_owned(),
            replicas: [("primary".to_owned(), replicas)].into_iter().collect(),
            autoscaling: Some(pol),
            ..Default::default()
        }
    }

    fn report(metrics: &MetricsStore, pod_id: &str, cpu: u32, count: usize) {
        for i in 0..count {
            metrics
                .report(PodMetrics {
                    pod_id: pod_id.to_owned(),
                    cpu_millicores: cpu,
                    memory_bytes: 0,
                    net_tx_bytes: 0,
                    net_rx_bytes: 0,
                    window_unix: 1_000 + i as u64,
                })
                .unwrap();
        }
    }

    fn report_memory(metrics: &MetricsStore, pod_id: &str, mem: u64, count: usize) {
        for i in 0..count {
            metrics
                .report(PodMetrics {
                    pod_id: pod_id.to_owned(),
                    cpu_millicores: 0,
                    memory_bytes: mem,
                    net_tx_bytes: 0,
                    net_rx_bytes: 0,
                    window_unix: 1_000 + i as u64,
                })
                .unwrap();
        }
    }

    async fn current_total(storage: &StorageEngine) -> u32 {
        let records = storage.list_workloads().unwrap();
        let rec = records.iter().find(|r| r.workload_id == "web").unwrap();
        let spec: WorkloadSpec = prost::Message::decode(rec.spec_bytes.as_slice()).unwrap();
        spec.replicas.values().sum()
    }

    async fn wait_for_total(storage: &StorageEngine, expected: u32) -> bool {
        for _ in 0..100 {
            if current_total(storage).await == expected {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    // CR verification: sustained high utilization → replica increase.
    #[tokio::test]
    async fn sustained_high_utilization_scales_up() {
        let (raft, keyspaces, storage, metrics) = setup("scale-up").await;
        let spec = spec_with(1, policy(500, 1, 5, 300));
        seed_direct(&keyspaces, &spec, &["web-primary-0"]);
        report(&metrics, "web-primary-0", 1_000, 5); // 2x target
        let hpa = HpaController::new(
            storage.clone(),
            metrics,
            raft.clone(),
            Arc::new(crate::disruption::NoopDisruptionGuard),
        );
        eval(&hpa, 10_000).await;
        assert!(wait_for_total(&storage, 2).await, "HPA must scale 1 → 2");
    }

    // CR-CORE-9 addendum: a memory-only policy drives scale-up through the
    // exact same Raft path.
    #[tokio::test]
    async fn sustained_high_memory_scales_up() {
        let (raft, keyspaces, storage, metrics) = setup("scale-up-memory").await;
        let spec = spec_with(1, mem_policy(512 * 1024 * 1024, 1, 5, 300));
        seed_direct(&keyspaces, &spec, &["web-primary-0"]);
        report_memory(&metrics, "web-primary-0", 1024 * 1024 * 1024, 5); // 2x target
        let hpa = HpaController::new(
            storage.clone(),
            metrics,
            raft.clone(),
            Arc::new(crate::disruption::NoopDisruptionGuard),
        );
        eval(&hpa, 10_000).await;
        assert!(
            wait_for_total(&storage, 2).await,
            "HPA must scale 1 → 2 on memory pressure"
        );
    }

    #[tokio::test]
    async fn disabled_policy_is_a_hard_stop() {
        let (raft, keyspaces, storage, metrics) = setup("disabled").await;
        let mut spec = spec_with(1, policy(500, 1, 5, 300));
        spec.autoscaling.as_mut().unwrap().enabled = false;
        seed_direct(&keyspaces, &spec, &["web-primary-0"]);
        report(&metrics, "web-primary-0", 10_000, 5);
        let hpa = HpaController::new(
            storage.clone(),
            metrics,
            raft.clone(),
            Arc::new(crate::disruption::NoopDisruptionGuard),
        );
        eval(&hpa, 10_000).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(current_total(&storage).await, 1);
    }

    #[tokio::test]
    async fn no_active_targets_is_a_hard_stop() {
        let (raft, keyspaces, storage, metrics) = setup("no-targets").await;
        let spec = spec_with(1, mem_policy(0, 1, 5, 300)); // all targets zero
        seed_direct(&keyspaces, &spec, &["web-primary-0"]);
        report(&metrics, "web-primary-0", 10_000, 5);
        let hpa = HpaController::new(
            storage.clone(),
            metrics,
            raft.clone(),
            Arc::new(crate::disruption::NoopDisruptionGuard),
        );
        eval(&hpa, 10_000).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(current_total(&storage).await, 1);
    }

    #[tokio::test]
    async fn insufficient_windows_does_not_react() {
        let (raft, keyspaces, storage, metrics) = setup("min-windows").await;
        let spec = spec_with(1, policy(500, 1, 5, 300));
        seed_direct(&keyspaces, &spec, &["web-primary-0"]);
        report(&metrics, "web-primary-0", 10_000, MIN_WINDOWS - 1);
        let hpa = HpaController::new(
            storage.clone(),
            metrics,
            raft.clone(),
            Arc::new(crate::disruption::NoopDisruptionGuard),
        );
        eval(&hpa, 10_000).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(current_total(&storage).await, 1);
    }

    #[tokio::test]
    async fn deadband_suppresses_small_fluctuations() {
        let (raft, keyspaces, storage, metrics) = setup("deadband").await;
        let pods: Vec<String> = (0..10).map(|i| format!("web-primary-{i}")).collect();
        let pod_refs: Vec<&str> = pods.iter().map(|s| s.as_str()).collect();
        let spec = spec_with(10, policy(500, 1, 20, 300));
        seed_direct(&keyspaces, &spec, &pod_refs);
        for pod in &pods {
            report(&metrics, pod, 525, 5);
        }
        let hpa = HpaController::new(
            storage.clone(),
            metrics,
            raft.clone(),
            Arc::new(crate::disruption::NoopDisruptionGuard),
        );
        eval(&hpa, 10_000).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let total = current_total(&storage).await;
        let _ = raft.shutdown().await;
        assert_eq!(total, 10, "±10% must be a no-op");
    }

    // CR verification: cooldown → no thrash. Scale-down waits the full
    // stabilization window, then lands exactly once.
    #[tokio::test]
    async fn scale_down_waits_for_stabilization_window() {
        let (raft, keyspaces, storage, metrics) = setup("stabilization").await;
        let pods: Vec<String> = (0..3).map(|i| format!("web-primary-{i}")).collect();
        let pod_refs: Vec<&str> = pods.iter().map(|s| s.as_str()).collect();
        let spec = spec_with(3, policy(500, 1, 5, 300));
        seed_direct(&keyspaces, &spec, &pod_refs);
        for pod in &pods {
            report(&metrics, pod, 100, 5); // avg 100 → desired 1
        }
        let hpa = HpaController::new(
            storage.clone(),
            metrics,
            raft.clone(),
            Arc::new(crate::disruption::NoopDisruptionGuard),
        );
        // t0: first observation — window starts, no action.
        eval(&hpa, 10_000).await;
        assert_eq!(current_total(&storage).await, 3);
        // t0 + 299: still inside the window — no action (no thrash).
        eval(&hpa, 10_299).await;
        assert_eq!(current_total(&storage).await, 3);
        // t0 + 300: sustained low utilization confirmed — scale down.
        eval(&hpa, 10_300).await;
        assert!(
            wait_for_total(&storage, 1).await,
            "scale-down must land after the window"
        );
    }

    #[tokio::test]
    async fn denying_guard_blocks_scale_down() {
        struct DenyGuard;
        impl DisruptionGuard for DenyGuard {
            fn allow_disruption(
                &self,
                _: &TenantId,
                _: &str,
                _: &WorkloadRole,
                _: u32,
                _: DisruptionTarget,
            ) -> Result<(), crate::disruption::DisruptionDenied> {
                Err(crate::disruption::DisruptionDenied {
                    min_available: 0,
                    current_healthy: 0,
                    requested: 0,
                    forced: false,
                })
            }
        }
        let (raft, keyspaces, storage, metrics) = setup("deny-guard").await;
        let pods: Vec<String> = (0..3).map(|i| format!("web-primary-{i}")).collect();
        let pod_refs: Vec<&str> = pods.iter().map(|s| s.as_str()).collect();
        // Zero stabilization window: the guard is the only remaining gate.
        let spec = spec_with(3, policy(500, 1, 5, 0));
        seed_direct(&keyspaces, &spec, &pod_refs);
        for pod in &pods {
            report(&metrics, pod, 100, 5);
        }
        let hpa = HpaController::new(storage.clone(), metrics, raft.clone(), Arc::new(DenyGuard));
        eval(&hpa, 10_000).await;
        eval(&hpa, 20_000).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            current_total(&storage).await,
            3,
            "guard must block scale-down"
        );
    }
}
