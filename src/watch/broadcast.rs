//! Shared broadcast channel infrastructure.
//!
//! The Raft state machine publishes events after applying log entries.
//! gRPC handlers subscribe to these channels and stream events to clients.

use std::sync::Arc;

use tokio::sync::broadcast;

use fleetos_core::MonotonicVersion;

/// Capacity for broadcast channels.
const CHANNEL_CAPACITY: usize = 4096;

/// Events broadcast over the unified WatchService stream.
///
/// Per the proto, WatchEvent currently only carries SecretRotationNotification.
/// TrustBundle rotations and cluster membership changes are handled separately
/// (they may be added to WatchEvent in a future proto revision, or delivered
/// via dedicated streams).
#[derive(Debug, Clone)]
pub enum WatchEvent {
    /// Secret rotation notification — "the secret for this SpiffeId changed, refetch."
    /// This is NOT the secret payload itself — agents pull via SecretService.
    SecretRotationNotification {
        /// The SpiffeId whose secret was rotated.
        spiffe_id: String,
        /// Version of this rotation.
        version: MonotonicVersion,
    },
}

/// Events broadcast over the PolicyService stream (WatchSag).
///
/// Carries the full set of SAG rules (not compiled eBPF structs — agents
/// compile locally) plus the full revoked delegation IDs set.
#[derive(Debug, Clone)]
pub struct SagUpdateEvent {
    /// The MonotonicVersion of this SAG update.
    pub version: MonotonicVersion,

    /// Serialized SAG rules (postcard-encoded Vec<SagRule> from fleetos-core).
    /// We store serialized bytes here to avoid depending on the exact generated
    /// proto type in the broadcast channel — the gRPC handler deserializes
    /// into proto types at the stream boundary.
    pub rules_bytes: Vec<u8>,

    /// Full set of currently-revoked delegation IDs (serialized DelegationId bytes).
    pub revoked_delegation_ids: Vec<Vec<u8>>,

    /// SPIFFE IDs of revoked node SVIDs
    pub revoked_spiffe_ids: Vec<String>,
}

/// Events broadcast over the SchedulerService stream (WatchSchedule).
#[derive(Debug, Clone)]
pub struct ScheduleUpdateEvent {
    /// The MonotonicVersion.
    pub version: MonotonicVersion,

    /// Serialized WorkloadAssignments.
    pub assignments_bytes: Vec<u8>,
}

/// Events broadcast over the RouterAssignmentService stream (WatchRoutes).
#[derive(Debug, Clone)]
pub struct RouteUpdateEvent {
    /// The MonotonicVersion.
    pub version: MonotonicVersion,

    /// Serialized RouteEntries.
    pub routes_bytes: Vec<u8>,
}

/// The central broadcast hub.
pub struct BroadcastHub {
    watch_tx: broadcast::Sender<WatchEvent>,
    sag_tx: broadcast::Sender<SagUpdateEvent>,
    schedule_tx: broadcast::Sender<ScheduleUpdateEvent>,
    route_tx: broadcast::Sender<RouteUpdateEvent>,
}

impl BroadcastHub {
    pub fn new() -> Arc<Self> {
        let (watch_tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        let (sag_tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        let (schedule_tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        let (route_tx, _) = broadcast::channel(CHANNEL_CAPACITY);

        Arc::new(Self {
            watch_tx,
            sag_tx,
            schedule_tx,
            route_tx,
        })
    }

    // --- Publish methods ---

    pub fn publish_watch_event(&self, event: WatchEvent) {
        let _ = self.watch_tx.send(event);
    }

    pub fn publish_sag_update(&self, update: SagUpdateEvent) {
        let _ = self.sag_tx.send(update);
    }

    pub fn publish_schedule_update(&self, update: ScheduleUpdateEvent) {
        let _ = self.schedule_tx.send(update);
    }

    pub fn publish_route_update(&self, update: RouteUpdateEvent) {
        let _ = self.route_tx.send(update);
    }

    // --- Subscribe methods ---

    pub fn subscribe_watch(&self) -> broadcast::Receiver<WatchEvent> {
        self.watch_tx.subscribe()
    }

    pub fn subscribe_sag(&self) -> broadcast::Receiver<SagUpdateEvent> {
        self.sag_tx.subscribe()
    }

    pub fn subscribe_schedule(&self) -> broadcast::Receiver<ScheduleUpdateEvent> {
        self.schedule_tx.subscribe()
    }

    pub fn subscribe_routes(&self) -> broadcast::Receiver<RouteUpdateEvent> {
        self.route_tx.subscribe()
    }
}
