//! E14: join-flow integration over the REAL transport.
//!
//! Proves the production snapshot-install path end to end over the wire:
//!
//!     rustls mTLS (ALPN h2, DNS-SAN client auth) → tonic gRPC
//!     → RaftTransportServerImpl::install_snapshot → Raft::install_snapshot
//!     → FjallStateMachine::install_snapshot → keyspaces atomically restored
//!
//! Design:
//! - RECEIVER: fresh (uninitialized) Raft node behind a real tokio-rustls +
//!   tonic listener (ALPN h2 set explicitly, as required when bypassing
//!   tonic's tls_config).
//! - DONOR: single-node cluster; applies CreateTenant, waits for async
//!   state-machine apply, then builds a snapshot with FjallSnapshotBuilder
//!   (the same proven path as snapshot_round_trip).
//! - The test wraps the snapshot in an InstallSnapshotRequest under the
//!   donor's real committed vote and ships it through a real mTLS tonic
//!   channel to the receiver's RaftTransport service — the exact wire
//!   format the production `full_snapshot` sender produces (the Step-1
//!   cleanup made InstallSnapshotRequest the single wire format).
//!
//! Why the test sends the RPC directly instead of calling
//! `TonicRaftNetwork::full_snapshot`: openraft 0.9.x's `RPCOption` has only
//! private fields and no Default impl, so RaftNetwork trait methods cannot
//! be invoked from outside the openraft crate (and openraft's internal
//! snapshot trigger/purge chain is not reliably controllable from tests).
//! The request built here is byte-identical to what `full_snapshot`
//! produces, and the TLS channel setup mirrors `TonicRaftNetwork::get_client`.
//!
//! Known blockers handled here:
//! - ALPN: hand-built ServerConfig carries `h2`.
//! - DNS SAN: control SVIDs (SvidKind::Control) carry the trust domain as a
//!   DNS SAN; the client verifies against domain_name(TRUST_DOMAIN).
//! - openraft async apply: client_write returns on commit; we poll donor
//!   state before snapshotting.
//! - openraft::Snapshot has no .data field: payload is read from the boxed
//!   cursor.

use fleetos_control::ca::rcgen_impl::{self, SvidKind, SvidParams};
use fleetos_control::ca::trust_bundle::TrustBundle;
use fleetos_control::raft::network::{RaftClientTls, TonicRaftNetworkFactory};
use fleetos_control::raft::raft_proto::raft_transport_client::RaftTransportClient;
use fleetos_control::raft::raft_proto::raft_transport_server::RaftTransportServer;
use fleetos_control::raft::records::TenantRecord;
use fleetos_control::raft::snapshot::FjallSnapshotBuilder;
use fleetos_control::raft::state_machine::FjallStateMachine;
use fleetos_control::raft::store::FjallLogStorage;
use fleetos_control::raft::{AuditedCommand, FleetosCommand, FleetosRaftConfig, RaftRpc};
use fleetos_control::storage::version::VersionedState;
use fleetos_control::tls::mtls::{self, MtlsConfig};
use fleetos_control::tls::trust_domains::TrustDomainRole;
use fleetos_control::watch::broadcast::BroadcastHub;
use openraft::network::RaftNetworkFactory;
use openraft::raft::{InstallSnapshotRequest, InstallSnapshotResponse};
use openraft::{BasicNode, Config, Raft, ServerState, Vote};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::sync::Arc;
use tempfile::tempdir;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, Server};

const TRUST_DOMAIN: &str = "fleet.e14.test.internal";
const DONOR_ID: u64 = 1;
const RECEIVER_ID: u64 = 2;

// ---------------------------------------------------------------------------
// TLS material
// ---------------------------------------------------------------------------

fn install_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

fn make_ca() -> TrustBundle {
    TrustBundle::generate_root(TRUST_DOMAIN).unwrap()
}

/// Control-kind SVIDs carry the trust domain as a DNS SAN, which the raft
/// client needs for hostname verification (domain_name = TRUST_DOMAIN).
fn make_control_svid(ca: &TrustBundle, name: &str) -> rcgen_impl::SignedSvid {
    let params = SvidParams {
        spiffe_id: format!("spiffe://{}/ns/system/control/{}", TRUST_DOMAIN, name),
        kind: SvidKind::Control,
        role: None,
        ordinal: None,
        degraded: false,
        ttl_secs: 3600,
    };
    rcgen_impl::sign_svid(&params, &ca.current_key, &ca.current_cert_der).unwrap()
}

fn raft_client_tls(svid: &rcgen_impl::SignedSvid, ca: &TrustBundle) -> RaftClientTls {
    RaftClientTls {
        cert_der: svid.cert_der.clone(),
        key_der: svid.private_key_der.to_vec(),
        trust_bundle_pem: ca.trust_bundle_pem(),
        domain: TRUST_DOMAIN.to_owned(),
    }
}

fn mtls_config(svid: &rcgen_impl::SignedSvid, ca: &TrustBundle) -> MtlsConfig {
    MtlsConfig {
        cert_chain: vec![rustls::pki_types::CertificateDer::from(
            svid.cert_der.clone(),
        )],
        private_key: rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(svid.private_key_der.to_vec()),
        ),
        trust_bundle_pem: ca.trust_bundle_pem(),
        role: TrustDomainRole::DataControl,
    }
}

/// PEM encoding identical to the private helper in `src/raft/network.rs`.
fn der_to_pem(der: &[u8], label: &str) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}

/// Build a tonic RaftTransport client with the exact TLS setup used by
/// `TonicRaftNetwork::get_client`: client identity + CA bundle +
/// domain_name = trust domain (verified against the server's DNS SAN).
async fn connect_raft_client(
    address: &str,
    svid: &rcgen_impl::SignedSvid,
    ca: &TrustBundle,
) -> RaftTransportClient<Channel> {
    let cert_pem = der_to_pem(&svid.cert_der, "CERTIFICATE");
    let key_pem = der_to_pem(&svid.private_key_der, "PRIVATE KEY");
    let identity = Identity::from_pem(cert_pem, key_pem);
    let ca_cert = Certificate::from_pem(&ca.trust_bundle_pem());
    let tls_config = ClientTlsConfig::new()
        .identity(identity)
        .ca_certificate(ca_cert)
        .domain_name(TRUST_DOMAIN.to_owned());
    let channel = Channel::from_shared(format!("https://{}", address))
        .expect("valid endpoint URI")
        .tls_config(tls_config)
        .expect("valid TLS config")
        .connect()
        .await
        .expect("TLS connection to receiver must succeed (ALPN h2 + mTLS)");
    RaftTransportClient::new(channel)
}

// ---------------------------------------------------------------------------
// Raft node over the real network factory
// ---------------------------------------------------------------------------

struct TestNode {
    raft: Arc<Raft<FleetosRaftConfig>>,
    db: Arc<fjall::Database>,
    keyspaces: fleetos_control::storage::Keyspaces,
    _dir: tempfile::TempDir,
}

async fn create_node<F>(node_id: u64, factory: F, config: Config, initialize: bool) -> TestNode
where
    F: RaftNetworkFactory<FleetosRaftConfig>,
{
    let dir = tempdir().unwrap();
    let db = fleetos_control::storage::open_database(dir.path()).unwrap();
    let keyspaces = fleetos_control::storage::init_keyspaces(&db).unwrap();
    let versioned_state = VersionedState::new(keyspaces.version.clone());
    let broadcast_hub = BroadcastHub::new();

    let raft_config = Arc::new(config.validate().unwrap());

    let log_storage = FjallLogStorage::new(
        db.clone(),
        keyspaces.raft_log.clone(),
        keyspaces.raft_log_meta.clone(),
    );
    let state_machine = FjallStateMachine::new(
        db.clone(),
        keyspaces.clone(),
        versioned_state,
        broadcast_hub,
        TRUST_DOMAIN.to_owned(),
    );

    let raft = Raft::new(node_id, raft_config, factory, log_storage, state_machine)
        .await
        .unwrap();
    let raft = Arc::new(raft);

    if initialize {
        let mut members = BTreeMap::new();
        members.insert(
            node_id,
            BasicNode {
                addr: String::new(),
            },
        );
        raft.initialize(members).await.unwrap();
    }

    TestNode {
        raft,
        db,
        keyspaces,
        _dir: dir,
    }
}

// ---------------------------------------------------------------------------
// Real TLS listener (mirrors main.rs: tokio-rustls + serve_with_incoming)
// ---------------------------------------------------------------------------

/// TLS stream annotated for tonic's `serve_with_incoming`.
struct TlsConn {
    inner: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    peer_addr: std::net::SocketAddr,
}

impl tokio::io::AsyncRead for TlsConn {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TlsConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl tonic::transport::server::Connected for TlsConn {
    type ConnectInfo = std::net::SocketAddr;
    fn connect_info(&self) -> Self::ConnectInfo {
        self.peer_addr
    }
}

/// Spawn a real tonic RaftTransport server over tokio-rustls mTLS.
///
/// Sets ALPN `h2` explicitly — mandatory when bypassing tonic's tls_config.
async fn spawn_raft_server(
    raft: Arc<Raft<FleetosRaftConfig>>,
    mtls: &MtlsConfig,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    tokio::sync::watch::Sender<bool>,
) {
    let mut server_config = mtls::build_server_config(mtls).unwrap();
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let transport = fleetos_control::raft::server::RaftTransportServerImpl::new(raft);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    let handle = tokio::spawn(async move {
        let incoming = async_stream::stream! {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let acceptor = acceptor.clone();
                        yield async move {
                            let tls = acceptor
                                .accept(stream)
                                .await
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                            Ok::<TlsConn, std::io::Error>(TlsConn {
                                inner: tls,
                                peer_addr,
                            })
                        }
                        .await;
                    }
                    Err(e) => {
                        eprintln!("raft test listener accept failed: {}", e);
                    }
                }
            }
        };

        let shutdown_fut = async move {
            loop {
                if *shutdown_rx.borrow() {
                    return;
                }
                if shutdown_rx.changed().await.is_err() {
                    return;
                }
            }
        };

        let _ = Server::builder()
            .add_service(RaftTransportServer::new(transport))
            .serve_with_incoming_shutdown(incoming, shutdown_fut)
            .await;
    });

    (addr, handle, shutdown_tx)
}

// ---------------------------------------------------------------------------
// Polling helpers
// ---------------------------------------------------------------------------

async fn wait_for_leader(raft: &Raft<FleetosRaftConfig>) {
    for _ in 0..200 {
        if raft.metrics().borrow().state == ServerState::Leader {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("node did not become leader in time");
}

async fn wait_for_tenant(keyspaces: &fleetos_control::storage::Keyspaces, tenant_id: &str) {
    for _ in 0..200 {
        if keyspaces
            .tenants
            .get(tenant_id.as_bytes())
            .unwrap()
            .is_some()
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("tenant '{}' never appeared", tenant_id);
}

async fn propose_tenant(donor: &TestNode, tenant_id: &str, base: u32) {
    donor
        .raft
        .client_write(AuditedCommand::system(FleetosCommand::CreateTenant {
            record: TenantRecord {
                tenant_id: tenant_id.to_owned(),
                created_at: 1_700_000_000,
            },
            block: fleetos_control::dummy_ip::allocator::TenantBlock {
                tenant_id: tenant_id.to_owned(),
                base,
                prefix: 16,
                next_offset: 0,
            },
        }))
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn snapshot_transfer_over_real_tls_transport() {
    install_crypto_provider();

    let ca = make_ca();
    let donor_svid = make_control_svid(&ca, "donor");
    let receiver_svid = make_control_svid(&ca, "receiver");

    // --- Receiver: real mTLS raft listener, fresh uninitialized Raft ---
    let receiver_factory =
        TonicRaftNetworkFactory::new(HashMap::new(), raft_client_tls(&receiver_svid, &ca));
    let receiver_config = Config {
        heartbeat_interval: 100,
        election_timeout_min: 300,
        election_timeout_max: 600,
        ..Default::default()
    };
    let receiver = create_node(RECEIVER_ID, receiver_factory, receiver_config, false).await;

    let (receiver_addr, _server_handle, shutdown_tx) =
        spawn_raft_server(receiver.raft.clone(), &mtls_config(&receiver_svid, &ca)).await;
    let receiver_addr_str = receiver_addr.to_string();

    // --- Donor: single-node cluster over the real transport factory ---
    let mut peers = HashMap::new();
    peers.insert(RECEIVER_ID, receiver_addr_str.clone());
    let donor_factory = TonicRaftNetworkFactory::new(peers, raft_client_tls(&donor_svid, &ca));
    let donor_config = Config {
        heartbeat_interval: 100,
        election_timeout_min: 300,
        election_timeout_max: 600,
        ..Default::default()
    };
    let donor = create_node(DONOR_ID, donor_factory, donor_config, true).await;

    wait_for_leader(&donor.raft).await;

    // Apply one command on the donor.
    propose_tenant(&donor, "tenant-e14", 0xF000_0000).await;

    // openraft applies asynchronously after commit: wait for the donor's
    // state machine before snapshotting.
    wait_for_tenant(&donor.keyspaces, "tenant-e14").await;

    // --- Build the snapshot on the donor (proven path, snapshot_round_trip) ---
    let mut builder = FjallSnapshotBuilder::new(donor.db.clone(), donor.keyspaces.clone());
    let snapshot = openraft::RaftSnapshotBuilder::build_snapshot(&mut builder)
        .await
        .unwrap();

    // The donor's real committed vote, as persisted by its log storage
    // (FjallLogStorage::save_vote writes it to raft_log_meta under "vote").
    let vote_bytes = donor
        .keyspaces
        .raft_log_meta
        .get("vote")
        .unwrap()
        .expect("donor raft_log_meta must carry the vote");
    let vote: Vote<u64> = postcard::from_bytes(&vote_bytes).unwrap();

    // Extract the payload from the boxed cursor — Snapshot has no .data field.
    let mut cursor = snapshot.snapshot;
    cursor.set_position(0);
    let mut data = Vec::new();
    cursor.read_to_end(&mut data).unwrap();

    // --- Ship it over a real mTLS tonic channel ---
    let req = InstallSnapshotRequest::<FleetosRaftConfig> {
        vote,
        meta: snapshot.meta,
        offset: 0,
        data,
        done: true,
    };
    let payload = postcard::to_allocvec(&req).unwrap();
    let rpc = RaftRpc {
        sender_id: DONOR_ID,
        target_id: RECEIVER_ID,
        payload,
    };

    let mut client = connect_raft_client(&receiver_addr_str, &donor_svid, &ca).await;
    let response = client
        .install_snapshot(rpc)
        .await
        .expect("install_snapshot over real TLS must succeed");

    // Envelope round-trip (E13): response payload is InstallSnapshotResponse.
    let resp: InstallSnapshotResponse<u64> =
        postcard::from_bytes(&response.into_inner().payload).unwrap();
    assert_eq!(
        resp.vote, vote,
        "receiver must adopt the leader's committed vote"
    );

    // --- Assert the receiver absorbed the snapshot state ---
    wait_for_tenant(&receiver.keyspaces, "tenant-e14").await;

    let bytes = receiver
        .keyspaces
        .tenants
        .get("tenant-e14".as_bytes())
        .unwrap()
        .expect("tenant must exist on receiver after snapshot install");
    let record: TenantRecord = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(record.tenant_id, "tenant-e14");
    assert_eq!(record.created_at, 1_700_000_000);

    // Atomicity (E12c): the dummy-IP block rides with the tenant.
    let block = receiver
        .keyspaces
        .dummy_ips
        .get("tenant:tenant-e14".as_bytes())
        .unwrap();
    assert!(
        block.is_some(),
        "tenant dummy-IP block must be present after snapshot install"
    );

    let _ = shutdown_tx.send(true);
}
