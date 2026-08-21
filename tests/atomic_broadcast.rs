//! Hard invariant: no partial updates visible to readers.

use fleetos_control::watch::broadcast::{BroadcastHub, WatchEvent};
use fleetos_core::MonotonicVersion;

#[tokio::test]
async fn broadcast_hub_delivers_events() {
    let hub = BroadcastHub::new();
    let mut rx = hub.subscribe_watch();

    let event = WatchEvent::SecretRotationNotification {
        spiffe_id: "spiffe://test/ns/tenant/sa/db".to_owned(),
        version: MonotonicVersion::new(42),
    };

    // Publish the event
    hub.publish_watch_event(event.clone());

    // Receive it
    let received = rx.recv().await.unwrap();

    // Fix: Removed the unreachable `_ => panic!` arm since WatchEvent
    // currently only has one variant.
    match received {
        WatchEvent::SecretRotationNotification { spiffe_id, version } => {
            assert_eq!(spiffe_id, "spiffe://test/ns/tenant/sa/db");
            assert_eq!(version.get(), 42);
        }
    }
}
