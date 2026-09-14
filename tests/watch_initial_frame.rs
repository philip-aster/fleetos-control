//! CR-CTRL-1 (Ruling B): on subscribe in a quiet cluster, the agent receives
//! a full-state frame matching committed state — no policy vacuum on restart.
use fleetos_control::storage::version::VersionedState;
use fleetos_control::storage::{init_keyspaces, open_database};
use fleetos_control::watch::broadcast::BroadcastHub;
use fleetos_control::watch::policy_service::PolicyServiceImpl;
use fleetos_core::proto::fleetos::policy_service_server::PolicyService;
use fleetos_core::proto::state::{PeerSelector, SagRule, WatchRequest};
use prost::Message;
use tempfile::tempdir;
use tokio_stream::StreamExt;
use tonic::Request;

#[tokio::test]
async fn watch_sag_emits_initial_frame_matching_committed_state() {
    let dir = tempdir().unwrap();
    let db = open_database(dir.path()).unwrap();
    let ks = init_keyspaces(&db).unwrap();
    let versioned = VersionedState::new(ks.version.clone());
    let hub = BroadcastHub::new();

    // Seed one committed SAG rule directly (quiet cluster — no mutations after).
    // The sag_rules keyspace stores prost-encoded SagRule bytes — the exact
    // format the state machine writes via UpsertSagRule (AdminService path).
    // build_sag_snapshot -> decode_rules must be able to round-trip it.
    let rule = SagRule {
        id: "rule-1".to_owned(),
        from: Some(PeerSelector {
            tenant: "tenant-a".to_owned(),
            service_name: "web".to_owned(),
            role: "frontend".to_owned(),
            port: Some(8080),
        }),
        to: Some(PeerSelector {
            tenant: "tenant-a".to_owned(),
            service_name: "db".to_owned(),
            role: "primary".to_owned(),
            port: Some(5432),
        }),
        action: 0, // ALLOW
    };
    let rule_bytes = rule.encode_to_vec();
    ks.sag_rules
        .insert(b"rule-1", rule_bytes.as_slice())
        .unwrap();

    let svc = PolicyServiceImpl::new(
        hub,
        ks.sag_rules.clone(),
        versioned.clone(),
        ks.revoked_delegations.clone(),
        ks.revoked_svids.clone(),
    );

    let resp = svc
        .watch_sag(Request::new(WatchRequest {
            last_known_version: 0,
        }))
        .await
        .expect("watch_sag must open");
    let mut stream = resp.into_inner();

    // Frame one must arrive immediately (no mutation needed) and carry the rule.
    let first = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("initial frame must not wait for a mutation")
        .expect("stream must yield")
        .expect("frame must be Ok");

    assert_eq!(
        first.rules.len(),
        1,
        "initial frame must carry the committed rule"
    );
    assert_eq!(first.version, versioned.current_version().get());
}
