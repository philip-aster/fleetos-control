use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::time::{Duration, timeout};
use tokio_stream::StreamExt;

use fleetos_control::controllers::PodController;
use fleetos_control::grpc::{FleetSecretService, FleetStateService};
use fleetos_control::raft::{FleetRaft, Network, RedbStore};
use fleetos_control::scheduler::{FleetScheduler, NodeInfo};
use fleetos_control::secrets::{AclEvaluator, Action, CryptoEngine, SecretKey, SecretStore};
use fleetos_control::storage::KeyBuilder;

use fleetos_core::proto::state::WatchRequest;
use fleetos_core::{
    CloudHypervisorConfig, ContainerSpec, PodRole, PodSpec, QosClass, ResourceRequirements,
    RestartPolicy, RuntimeEngine, VolumeMount, VolumeSpec, VolumeType,
};
use openraft::Config as RaftConfig;
use redb::Database;

#[tokio::test]
async fn test_e2e_control_plane_workflow() -> Result<(), Box<dyn std::error::Error>> {
    // -------------------------------------------------------------------------
    // 1. Setup ephemeral environment and Redb database
    // -------------------------------------------------------------------------
    let temp_dir = tempdir()?;
    let db_path = temp_dir.path().join("test_control.redb");
    let db = Arc::new(Database::create(&db_path)?);

    // -------------------------------------------------------------------------
    // 2. Bootstrap Raft consensus engine (Node ID = 1)
    // -------------------------------------------------------------------------
    let (log_store, state_machine) = RedbStore::new(db.clone())?;
    let raft_config = Arc::new(RaftConfig::default().validate()?);
    let network = Network::new();

    let raft: FleetRaft =
        openraft::Raft::new(1, raft_config, network, log_store, state_machine).await?;

    let mut nodes = std::collections::BTreeMap::new();
    nodes.insert(1, openraft::BasicNode::new("127.0.0.1:9091"));
    let _ = raft.initialize(nodes).await;

    // -------------------------------------------------------------------------
    // 3. Initialize Control Services, Scheduler, and Controllers
    // -------------------------------------------------------------------------
    let state_service = Arc::new(FleetStateService::new(raft.clone(), db.clone()));
    let master_key = [0x77; 32];
    let _secret_service = FleetSecretService::new(db.clone(), master_key);

    let scheduler = Arc::new(FleetScheduler::new(state_service.clone()));
    let _pod_controller = PodController::new(state_service.clone(), scheduler.clone());

    // -------------------------------------------------------------------------
    // 4. Register a Node in cluster state
    // -------------------------------------------------------------------------
    let node_1_info = NodeInfo {
        node_id: "node-alpha".to_string(),
        spiffe_id: "spiffe://fleetos.mesh/ns/default/sa/node-alpha".to_string(),
        total_vcpus: 16,
        available_vcpus: 12,
        total_memory_mb: 32768,
        available_memory_mb: 24576,
        supports_hypervisor: true,
        supports_containerd: true,
    };

    let node_bytes = serde_json::to_vec(&node_1_info)?;
    let node_key = KeyBuilder::node_info("node-alpha");
    state_service.put_bytes(&node_key, &node_bytes).await?;

    // -------------------------------------------------------------------------
    // 5. Test State Watching Service
    // -------------------------------------------------------------------------
    let watch_req = tonic::Request::new(WatchRequest {
        node_id: "agent-watcher".to_string(),
        spiffe_id: "spiffe://fleetos.mesh/agent".to_string(),
        key_prefix: b"/pods/assigned/".to_vec(),
        start_revision: 0,
    });

    use fleetos_core::proto::state::state_service_server::StateService;
    let mut watch_stream = state_service.watch(watch_req).await?.into_inner();

    // -------------------------------------------------------------------------
    // 6. Submit Pending Pod & Schedule
    // -------------------------------------------------------------------------
    let pod_id = "pod-web-101";
    let pending_pod = PodSpec {
        id: pod_id.to_string(),
        name: "web-frontend".to_string(),
        namespace: "default".to_string(),
        role: PodRole {
            role_name: "api-server".to_string(),
            spiffe_id: Some("spiffe://fleetos.mesh/ns/default/sa/api-server".to_string()),
            capabilities: vec!["NET_BIND_SERVICE".to_string()],
            run_as_user: Some(1000),
            run_as_group: Some(1000),
        },
        qos: QosClass::Burstable,
        labels: HashMap::from([("app".to_string(), "web".to_string())]),
        annotations: HashMap::from([("fleetos.mesh/secure".to_string(), "true".to_string())]),
        containers: vec![ContainerSpec {
            name: "nginx".to_string(),
            image: "docker.io/library/nginx:alpine".to_string(),
            command: vec!["nginx".to_string()],
            args: vec!["-g".to_string(), "daemon off;".to_string()],
            env: HashMap::from([("ENV".to_string(), "production".to_string())]),
            volume_mounts: vec![VolumeMount {
                name: "web-logs".to_string(),
                mount_path: "/var/log/nginx".to_string(),
                read_only: false,
            }],
            resources: ResourceRequirements {
                cpu_shares: Some(1024),
                memory_limit_mb: Some(2048),
            },
        }],
        volumes: vec![VolumeSpec {
            name: "web-logs".to_string(),
            volume_type: VolumeType::HostPath {
                host_path: "/var/log/fleetos/web".to_string(),
            },
        }],
        restart_policy: RestartPolicy::Always,
        runtime: RuntimeEngine::CloudHypervisor(CloudHypervisorConfig {
            vcpus: 2,
            memory_mb: 2048,
            kernel_path: "/var/lib/fleetos/vmlinux".to_string(),
            initrd_path: None,
            cmdline: "console=ttyS0 console=hvc0 root=/dev/vda rw quiet".to_string(),
            enable_sev: false,
            enable_sgx: false,
            vsock_cid: None,
        }),
    };

    let pending_key = KeyBuilder::pod_pending(pod_id);
    let pod_bytes = serde_json::to_vec(&pending_pod)?;

    // Write pending pod
    state_service.put_bytes(&pending_key, &pod_bytes).await?;

    // Schedule through FleetScheduler
    let (assigned_node_id, revision) = scheduler
        .schedule_pod(
            pending_pod.clone(),
            &HashMap::from([("node-alpha".to_string(), node_1_info.clone())]),
        )
        .await?;

    assert_eq!(assigned_node_id, "node-alpha");
    assert!(revision > 0);

    // Write assigned pod state to trigger watch stream event
    let assigned_key = KeyBuilder::pod_assigned(&assigned_node_id, pod_id);
    state_service.put_bytes(&assigned_key, &pod_bytes).await?;

    // Cleanup pending key
    state_service.delete_key(&pending_key).await?;

    // -------------------------------------------------------------------------
    // 7. Verify Watch Event Arrival
    // -------------------------------------------------------------------------
    let watch_event = timeout(Duration::from_secs(3), watch_stream.next())
        .await?
        .expect("Watch stream closed unexpectedly")
        .expect("Watch stream error");

    let event_key = String::from_utf8_lossy(&watch_event.key);
    assert!(
        event_key.starts_with("/pods/assigned/node-alpha/"),
        "Watch event key should match assigned prefix, got: {}",
        event_key
    );

    // -------------------------------------------------------------------------
    // 8. Test Secrets Store, Encryption, and ACLs
    // -------------------------------------------------------------------------
    let key = SecretKey::generate();
    let crypto = CryptoEngine::new(key);
    let mut acl = AclEvaluator::new();

    acl.add_rule("production/db/*", &[Action::Read, Action::Write]);

    let secret_store = SecretStore::new(crypto, acl);
    let secret_path = "production/db/credentials";
    let secret_data = b"postgres://admin:super_secure_pass@10.0.0.5:5432/fleet_db";

    secret_store.set_secret(secret_path, secret_data)?;
    let decrypted_secret = secret_store.get_secret(secret_path)?;
    assert_eq!(decrypted_secret, secret_data);

    let unauthorized_read = secret_store.get_secret("staging/db/credentials");
    assert!(unauthorized_read.is_err());

    println!("✅ E2E Integration Test Passed Successfully!");
    Ok(())
}
