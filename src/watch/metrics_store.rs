// src/watch/metrics_store.rs
//! Leader-local PodMetrics store (CR-CORE-9).
//!
//! High-frequency telemetry is NOT replicated through Raft. It lives only on
//! the leader, is bounded by a hard cap, sweeps on a 1-hour TTL, and rejects
//! metrics for pods we never placed (fail-closed against spoofing).
use dashmap::DashMap;
use fleetos_core::proto::state::PodMetrics;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_PODS: usize = 16384;
const MAX_WINDOWS_PER_POD: usize = 10;
const TTL_SECONDS: u64 = 3600;

#[derive(Debug, Clone)]
pub struct PodMetricsRecord {
    pub windows: VecDeque<PodMetrics>,
    pub last_updated_unix: u64,
}

pub struct MetricsStore {
    pods: DashMap<String, PodMetricsRecord>,
    placements: fjall::Keyspace,
}

impl MetricsStore {
    pub fn new(placements: fjall::Keyspace) -> Arc<Self> {
        Arc::new(Self {
            pods: DashMap::new(),
            placements,
        })
    }

    pub fn report(&self, metrics: PodMetrics) -> Result<bool, String> {
        if metrics.pod_id.is_empty() {
            return Err("pod_id cannot be empty".to_string());
        }
        // Fail-closed: reject metrics for pods we never placed.
        match self.placements.get(metrics.pod_id.as_bytes()) {
            Ok(Some(_)) => {}
            Ok(None) => return Err(format!("unknown pod_id: {}", metrics.pod_id)),
            Err(e) => return Err(format!("storage error: {}", e)),
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Capacity check BEFORE taking any lock. (Calling self.pods.len()
        // while a DashMap entry/shard lock is held deadlocks: len() locks
        // every shard, including the one we hold. No borrow may be live
        // across it.)
        let pod_id = metrics.pod_id.clone();
        if !self.pods.contains_key(&pod_id) && self.pods.len() >= MAX_PODS {
            return Err("metrics store cap reached".to_string());
        }
        // Existing pod: update under a short-lived shard write lock.
        if let Some(mut record) = self.pods.get_mut(&pod_id) {
            // Dedup: reject windows older than or equal to the newest stored window.
            if let Some(newest) = record.windows.back() {
                if metrics.window_unix <= newest.window_unix {
                    return Ok(false);
                }
            }
            record.windows.push_back(metrics);
            if record.windows.len() > MAX_WINDOWS_PER_POD {
                record.windows.pop_front();
            }
            record.last_updated_unix = now;
            return Ok(true);
        }
        // New pod: insert. (Benign TOCTOU with a concurrent inserter of the
        // same pod_id; the loser overwrites with identical initial state.)
        let mut windows = VecDeque::with_capacity(MAX_WINDOWS_PER_POD);
        windows.push_back(metrics);
        self.pods.insert(
            pod_id,
            PodMetricsRecord {
                windows,
                last_updated_unix: now,
            },
        );
        Ok(true)
    }

    pub fn sweep_expired(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(TTL_SECONDS);
        self.pods
            .retain(|_, record| record.last_updated_unix > cutoff);
    }

    pub fn get_windows(&self, pod_id: &str) -> Option<Vec<PodMetrics>> {
        self.pods
            .get(pod_id)
            .map(|r| r.windows.iter().cloned().collect())
    }
}
