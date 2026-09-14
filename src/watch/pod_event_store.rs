//! Leader-local pod event store (CR-CORE-8 / CR-CTRL-7).
//!
//! Pod lifecycle events are high-churn operator telemetry. They are NEVER
//! replicated through Raft — they live only on the current leader, TTL'd and
//! capped. On failover the new leader's store starts empty; acceptable for
//! `describe`-style visibility.
//!
//! Canonical `event_type` vocabulary (enforced fail-closed at the report
//! boundary): Pulled, Created, Started, ProbeFailed, BackOff, OOMKilled,
//! Evicting, GracePeriodExpired, FailedScheduling.
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use dashmap::DashMap;
use fleetos_core::proto::state::PodEvent;

use super::broadcast::BroadcastHub;

/// Maximum stored events across all pods.
const MAX_EVENTS: usize = 10_000;
/// Maximum distinct events retained per pod.
const MAX_EVENTS_PER_POD: usize = 100;
/// Events older than this are swept.
const TTL_SECS: u64 = 3600;

/// Canonical event vocabulary. Unknown types are rejected fail-closed.
pub const EVENT_TYPES: &[&str] = &[
    "Pulled",
    "Created",
    "Started",
    "ProbeFailed",
    "BackOff",
    "OOMKilled",
    "Evicting",
    "GracePeriodExpired",
    "FailedScheduling",
];

pub fn is_valid_event_type(event_type: &str) -> bool {
    EVENT_TYPES.contains(&event_type)
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct PodEventStore {
    /// pod_id -> chronological deque of (coalesced) events.
    pods: DashMap<String, VecDeque<PodEvent>>,
    /// Total stored events (self-healed by `sweep_expired`).
    total: AtomicUsize,
}

impl PodEventStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            pods: DashMap::new(),
            total: AtomicUsize::new(0),
        })
    }

    /// Insert one event, coalescing identical `(pod_id, event_type, reason)`.
    pub fn insert(&self, event: PodEvent) {
        let pod_id = event.pod_id.clone();
        let mut entry = self
            .pods
            .entry(pod_id.clone())
            .or_insert_with(VecDeque::new);
        let deque = entry.value_mut();

        // Coalesce: identical type+reason increments count (K8s-style).
        if let Some(existing) = deque
            .iter_mut()
            .find(|e| e.event_type == event.event_type && e.reason == event.reason)
        {
            existing.count = existing.count.saturating_add(event.count.max(1));
            existing.timestamp_unix = existing.timestamp_unix.max(event.timestamp_unix);
            if !event.message.is_empty() {
                event.message.clone_into(&mut existing.message);
            }
            return;
        }

        deque.push_back(event);
        self.total.fetch_add(1, Ordering::Relaxed);

        // Per-pod cap: drop oldest.
        while deque.len() > MAX_EVENTS_PER_POD {
            deque.pop_front();
            self.total.fetch_sub(1, Ordering::Relaxed);
        }
        drop(entry);

        // Global cap: evict oldest events until under the cap.
        if self.total.load(Ordering::Relaxed) > MAX_EVENTS {
            self.evict_to_cap();
        }
    }

    fn evict_to_cap(&self) {
        loop {
            if self.total.load(Ordering::Relaxed) <= MAX_EVENTS {
                return;
            }
            // Find the pod holding the oldest front event.
            let mut oldest: Option<(String, u64)> = None;
            for entry in self.pods.iter() {
                if let Some(front) = entry.value().front() {
                    let better = match &oldest {
                        None => true,
                        Some((_, ts)) => front.timestamp_unix < *ts,
                    };
                    if better {
                        oldest = Some((entry.key().clone(), front.timestamp_unix));
                    }
                }
            }
            let Some((pod_id, _)) = oldest else {
                self.resync_total();
                return;
            };
            let removed = match self.pods.get_mut(&pod_id) {
                Some(mut deque) => {
                    let removed = deque.pop_front().is_some();
                    let empty = deque.is_empty();
                    drop(deque);
                    if empty {
                        self.pods.remove(&pod_id);
                    }
                    removed
                }
                None => false,
            };
            if removed {
                self.total.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    /// Remove events older than the TTL and self-heal the counter.
    pub fn sweep_expired(&self) {
        let cutoff = now_unix().saturating_sub(TTL_SECS);
        let mut empty_pods = Vec::new();
        for mut entry in self.pods.iter_mut() {
            entry.retain(|e| e.timestamp_unix >= cutoff);
            if entry.is_empty() {
                empty_pods.push(entry.key().clone());
            }
        }
        for pod_id in empty_pods {
            self.pods.remove(&pod_id);
        }
        self.resync_total();
    }

    fn resync_total(&self) {
        let actual: usize = self.pods.iter().map(|e| e.value().len()).sum();
        self.total.store(actual, Ordering::Relaxed);
    }

    pub fn len(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(test)]
    pub fn events_for_pod(&self, pod_id: &str) -> Vec<PodEvent> {
        self.pods
            .get(pod_id)
            .map(|d| d.iter().cloned().collect())
            .unwrap_or_default()
    }
}

/// Emits pod events into both the leader-local store and the watch fan-out.
///
/// Used by the `ReportPodEvents` RPC path (agent batches) and by control
/// itself (`FailedScheduling` from the workload controller).
pub struct PodEventEmitter {
    store: Arc<PodEventStore>,
    hub: Arc<BroadcastHub>,
}

impl PodEventEmitter {
    pub fn new(store: Arc<PodEventStore>, hub: Arc<BroadcastHub>) -> Self {
        Self { store, hub }
    }

    /// Emit a single event. Unknown vocabulary is dropped with a warning —
    /// control-generated events use the constants above, so a drop here is a
    /// bug we want visible.
    pub fn emit(&self, mut event: PodEvent) {
        if !is_valid_event_type(&event.event_type) {
            tracing::warn!(event_type = %event.event_type, "dropping pod event with unknown type");
            return;
        }
        if event.count == 0 {
            event.count = 1;
        }
        if event.timestamp_unix == 0 {
            event.timestamp_unix = now_unix();
        }
        self.store.insert(event.clone());
        self.hub.publish_pod_event(event);
    }

    /// Emit a pre-validated batch (agent report path validates first).
    pub fn emit_batch(&self, events: Vec<PodEvent>) {
        for event in events {
            self.store.insert(event.clone());
            self.hub.publish_pod_event(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(pod: &str, event_type: &str, reason: &str, ts: u64) -> PodEvent {
        PodEvent {
            pod_id: pod.to_owned(),
            node_id: String::new(),
            event_type: event_type.to_owned(),
            reason: reason.to_owned(),
            message: String::new(),
            timestamp_unix: ts,
            count: 1,
        }
    }

    #[test]
    fn vocabulary_validation() {
        assert!(is_valid_event_type("Started"));
        assert!(is_valid_event_type("FailedScheduling"));
        assert!(!is_valid_event_type("Exploded"));
        assert!(!is_valid_event_type(""));
    }

    #[test]
    fn coalescing_increments_count() {
        let store = PodEventStore::new();
        store.insert(make_event("pod-1", "BackOff", "CrashLoop", 100));
        store.insert(make_event("pod-1", "BackOff", "CrashLoop", 200));
        let events = store.events_for_pod("pod-1");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].count, 2);
        assert_eq!(events[0].timestamp_unix, 200);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn distinct_reasons_are_not_coalesced() {
        let store = PodEventStore::new();
        store.insert(make_event("pod-1", "ProbeFailed", "liveness", 100));
        store.insert(make_event("pod-1", "ProbeFailed", "readiness", 100));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn sweep_removes_expired_and_heals_counter() {
        let store = PodEventStore::new();
        let now = now_unix();
        store.insert(make_event(
            "pod-old",
            "Started",
            "",
            now.saturating_sub(TTL_SECS + 10),
        ));
        store.insert(make_event("pod-new", "Started", "", now));
        store.sweep_expired();
        assert!(store.events_for_pod("pod-old").is_empty());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn per_pod_cap_drops_oldest() {
        let store = PodEventStore::new();
        for i in 0..(MAX_EVENTS_PER_POD + 10) {
            // Distinct reason per event so nothing coalesces.
            store.insert(make_event(
                "pod-1",
                "Started",
                &format!("r{}", i),
                i as u64 + 1,
            ));
        }
        let events = store.events_for_pod("pod-1");
        assert_eq!(events.len(), MAX_EVENTS_PER_POD);
        // Oldest 10 dropped: first surviving reason is r10.
        assert_eq!(events[0].reason, "r10");
        assert_eq!(store.len(), MAX_EVENTS_PER_POD);
    }

    #[test]
    fn global_cap_evicts_oldest() {
        let store = PodEventStore::new();
        // 150 pods x 100 distinct events = 15,000 > MAX_EVENTS.
        for i in 0..15_000usize {
            store.insert(make_event(
                &format!("pod-{}", i % 150),
                "Started",
                &format!("r{}", i),
                i as u64 + 1,
            ));
        }
        assert!(store.len() <= MAX_EVENTS);
    }
}
