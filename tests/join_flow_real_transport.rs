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

// ---------------------------------------------------------------------------
// R-3: secure join over the REAL transport — attestation → membership
// ---------------------------------------------------------------------------

use fleetos_control::attestation::grpc_service::{AttestationServiceImpl, PendingActivationRecord};
use fleetos_control::attestation::join_token::JoinTokenStore;
use fleetos_control::attestation::nonce::NonceManager;
use fleetos_control::attestation::pcr_policy::{PcrPolicy, PcrPolicyStore};
use fleetos_control::ca::grpc_service::CaServiceImpl;
use fleetos_core::proto::fleetos::attestation_service_client::AttestationServiceClient;
use fleetos_core::proto::fleetos::attestation_service_server::AttestationServiceServer;
use fleetos_core::proto::fleetos::ca_service_client::CaServiceClient;
use fleetos_core::proto::fleetos::ca_service_server::CaServiceServer;
use fleetos_core::proto::identity::{
    ActivationProof, AttestationQuote, CsrRequest, TrustBundleRequest,
};

const SECURE_TRUST_DOMAIN: &str = "fleet.r3.test.internal";
const SECURE_DONOR_ID: u64 = 1;
const SECURE_JOINER_ID: u64 = 2;

fn secure_control_svid(ca: &TrustBundle, name: &str) -> rcgen_impl::SignedSvid {
    let params = SvidParams {
        spiffe_id: format!(
            "spiffe://{}/ns/system/control/{}",
            SECURE_TRUST_DOMAIN, name
        ),
        kind: SvidKind::Control,
        role: None,
        ordinal: None,
        degraded: false,
        ttl_secs: 3600,
    };
    rcgen_impl::sign_svid(&params, &ca.current_key, &ca.current_cert_der).unwrap()
}

fn secure_mtls(svid: &rcgen_impl::SignedSvid, ca: &TrustBundle) -> MtlsConfig {
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

struct SoftwareQuote {
    ak_pub: Vec<u8>,
    quote: Vec<u8>,
    signature: Vec<u8>,
    pcr_values: Vec<fleetos_core::attestation::PcrValue>,
}

fn build_software_quote(nonce: &[u8], pcr0_digest: &[u8; 32]) -> SoftwareQuote {
    use p256::ecdsa::signature::Signer;
    let mut scalar = [0u8; 32];
    scalar[31] = 0x42; // fixed key
    let signing_key = p256::ecdsa::SigningKey::from_slice(&scalar).unwrap();
    let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
    let sec1 = verifying_key.to_sec1_bytes();
    let (x, y) = (&sec1[1..33], &sec1[33..65]);

    let mut ak_pub = Vec::new();
    ak_pub.extend_from_slice(&0x0023u16.to_be_bytes()); // type = ECC
    ak_pub.extend_from_slice(&0x000Bu16.to_be_bytes()); // nameAlg = SHA256
    ak_pub.extend_from_slice(&0x00000000u32.to_be_bytes()); // objectAttributes
    ak_pub.extend_from_slice(&0x0000u16.to_be_bytes()); // authPolicy len = 0
    ak_pub.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric = NULL
    ak_pub.extend_from_slice(&0x0010u16.to_be_bytes()); // scheme = NULL
    ak_pub.extend_from_slice(&0x0003u16.to_be_bytes()); // curve = P256
    ak_pub.extend_from_slice(&0x0010u16.to_be_bytes()); // kdf = NULL
    ak_pub.extend_from_slice(&(x.len() as u16).to_be_bytes());
    ak_pub.extend_from_slice(x);
    ak_pub.extend_from_slice(&(y.len() as u16).to_be_bytes());
    ak_pub.extend_from_slice(y);

    let pcr_digest = ring::digest::digest(&ring::digest::SHA256, pcr0_digest);
    let mut quote = Vec::new();
    quote.extend_from_slice(&[0xff, 0x54, 0x43, 0x47]); // TPM_GENERATED
    quote.extend_from_slice(&0x8018u16.to_be_bytes()); // TPM_ST_ATTEST_QUOTE
    quote.extend_from_slice(&0x0000u16.to_be_bytes()); // qualifiedSigner len
    quote.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    quote.extend_from_slice(nonce);
    quote.extend_from_slice(&[0u8; 17]); // clockInfo
    quote.extend_from_slice(&[0u8; 8]); // firmwareVersion
    quote.extend_from_slice(&1u32.to_be_bytes()); // one PCR bank
    quote.extend_from_slice(&0x000Bu16.to_be_bytes()); // SHA-256
    quote.push(3); // sizeofSelect
    quote.extend_from_slice(&[0x01, 0x00, 0x00]); // PCR0
    quote.extend_from_slice(&(pcr_digest.as_ref().len() as u16).to_be_bytes());
    quote.extend_from_slice(pcr_digest.as_ref());

    let signature: p256::ecdsa::Signature = signing_key.sign(&quote);
    SoftwareQuote {
        ak_pub,
        quote,
        signature: signature.to_vec(),
        pcr_values: vec![fleetos_core::attestation::PcrValue {
            index: 0,
            hash_algorithm: 0x000B,
            digest: pcr0_digest.to_vec(),
        }],
    }
}

async fn spawn_dc_server(
    attestation: AttestationServiceImpl,
    ca_service: CaServiceImpl,
    mtls: &MtlsConfig,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    tokio::sync::watch::Sender<bool>,
) {
    let mut server_config = mtls::build_server_config_optional_auth(mtls).unwrap();
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
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
                            Ok::<TlsConn, std::io::Error>(TlsConn { inner: tls, peer_addr })
                        }
                        .await;
                    }
                    Err(e) => eprintln!("dc test listener accept failed: {}", e),
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
        let _ = tonic::transport::Server::builder()
            .add_service(AttestationServiceServer::new(attestation))
            .add_service(CaServiceServer::new(ca_service))
            .serve_with_incoming_shutdown(incoming, shutdown_fut)
            .await;
    });
    (addr, handle, shutdown_tx)
}

async fn wait_for_key(keyspace: &fjall::Keyspace, key: &[u8]) -> Vec<u8> {
    for _ in 0..200 {
        if let Some(v) = keyspace.get(key).unwrap() {
            return v.to_vec();
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("key never appeared in keyspace");
}

#[tokio::test]
async fn secure_join_attestation_to_membership_over_real_tls() {
    install_crypto_provider();

    let ca = TrustBundle::generate_root(SECURE_TRUST_DOMAIN).unwrap();
    let donor_svid = secure_control_svid(&ca, "donor");
    let trust_bundle_pem = ca.trust_bundle_pem();
    let dc_bundle = Arc::new(parking_lot::RwLock::new(ca));

    let dc_read = dc_bundle.read();
    let donor_factory = TonicRaftNetworkFactory::new(
        HashMap::new(),
        RaftClientTls {
            cert_der: donor_svid.cert_der.clone(),
            key_der: donor_svid.private_key_der.to_vec(),
            trust_bundle_pem: dc_read.trust_bundle_pem(),
            domain: SECURE_TRUST_DOMAIN.to_owned(),
        },
    );
    let donor_config = Config {
        heartbeat_interval: 100,
        election_timeout_min: 300,
        election_timeout_max: 600,
        ..Default::default()
    };
    let donor = create_node(SECURE_DONOR_ID, donor_factory, donor_config, true).await;
    wait_for_leader(&donor.raft).await;

    propose_tenant(&donor, "tenant-r3", 0xF100_0000).await;
    wait_for_tenant(&donor.keyspaces, "tenant-r3").await;

    let pcr_store = Arc::new(PcrPolicyStore::new(donor.keyspaces.pcr_policies.clone()));
    let attestation_service = AttestationServiceImpl::new(
        Arc::new(NonceManager::new(donor.keyspaces.nonces.clone())),
        Arc::new(JoinTokenStore::new(donor.keyspaces.join_tokens.clone())),
        pcr_store.clone(),
        donor.keyspaces.nonce_claims.clone(),
        donor.keyspaces.svid_grants.clone(),
        donor.raft.clone(),
        donor.keyspaces.control_addresses.clone(),
        donor.keyspaces.node_eks.clone(),
        donor.keyspaces.pending_activations.clone(),
        Some(dc_bundle.clone()),
        3600,
        fleetos_control::config::AttestationMode::Secure,
        fleetos_control::config::TpmConfig::default(),
        donor.keyspaces.svids.clone(),
    );
    let ca_service = CaServiceImpl::new(
        dc_bundle.clone(),
        3600,
        donor.keyspaces.svids.clone(),
        donor.keyspaces.svid_grants.clone(),
        donor.keyspaces.placements.clone(),
        donor.keyspaces.control_addresses.clone(),
        donor.raft.clone(),
    );
    let dc_read2 = dc_bundle.read();
    let (dc_addr, _dc_handle, dc_shutdown) = spawn_dc_server(
        attestation_service,
        ca_service,
        &secure_mtls(&donor_svid, &dc_read2),
    )
    .await;

    let joiner_spiffe = format!("spiffe://{}/ns/system/control/joiner", SECURE_TRUST_DOMAIN);
    let server_nonce = [0xABu8; 32];
    let secret = [0x5Au8; 32];
    let sw_quote = build_software_quote(&server_nonce, &[0x42u8; 32]);

    let ek_pub_bytes = vec![0x30u8, 0x82, 0x01, 0x00];
    let fingerprint = fleetos_core::attestation::EkFingerprint::of_ek_pub(&ek_pub_bytes);
    donor
        .raft
        .client_write(AuditedCommand::system(FleetosCommand::RegisterNodeEk {
            record: fleetos_control::raft::records::NodeEkRecord {
                ek_fingerprint: fingerprint.to_hex(),
                ek_pub: ek_pub_bytes,
                ek_cert_der: vec![],
                node_id: String::new(),
                registered_at: 1_700_000_000,
                expires_at: None,
                state: fleetos_control::raft::records::EkRegistrationState::Pending,
            },
        }))
        .await
        .unwrap();
    wait_for_key(&donor.keyspaces.node_eks, fingerprint.to_hex().as_bytes()).await;

    pcr_store
        .set_policy(&PcrPolicy {
            node_id: joiner_spiffe.clone(),
            expected_pcrs: sw_quote.pcr_values.clone(),
            updated_at: 1_700_000_000,
            active: true,
        })
        .unwrap();

    // Wall-clock expiry: the server sweeps records whose expires_at is in
    // the past, so these MUST be real timestamps — fixed test epochs are
    // expired on sight.
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let pending = PendingActivationRecord {
        ek_fingerprint: fingerprint.to_hex(),
        ak_pub: sw_quote.ak_pub.clone(),
        server_nonce: server_nonce.to_vec(),
        secret: secret.to_vec(),
        created_at: now_unix,
        expires_at: now_unix + 300,
    };
    donor
        .keyspaces
        .pending_activations
        .insert(
            server_nonce.as_slice(),
            postcard::to_allocvec(&pending).unwrap().as_slice(),
        )
        .unwrap();

    let channel = tonic::transport::Channel::from_shared(fleetos_control::join::channel_addr(
        &dc_addr.to_string(),
    ))
    .expect("valid endpoint")
    .tls_config(
        tonic::transport::ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(&trust_bundle_pem))
            .domain_name(SECURE_TRUST_DOMAIN),
    )
    .expect("valid TLS config")
    .connect()
    .await
    .expect("attestation-leg TLS handshake must succeed");
    let mut att_client = AttestationServiceClient::new(channel.clone());

    let gated = att_client
        .submit_quote(AttestationQuote {
            join_token: "x".to_owned(),
            ..Default::default()
        })
        .await;
    assert_eq!(gated.unwrap_err().code(), tonic::Code::PermissionDenied);

    let csr_bundle = rcgen_impl::build_csr(&SvidParams {
        spiffe_id: joiner_spiffe.clone(),
        kind: SvidKind::Control,
        role: None,
        ordinal: None,
        degraded: false,
        ttl_secs: 3600,
    })
    .unwrap();
    let proof = ActivationProof {
        hmac: fleetos_core::attestation::compute_activation_proof(&secret, &server_nonce).to_vec(),
        quote: sw_quote.quote.clone(),
        quote_signature: sw_quote.signature.clone(),
        pcr_selection: postcard::to_allocvec(&sw_quote.pcr_values).unwrap(),
        csr_der: csr_bundle.csr_der.clone(),
        agent_x25519_pubkey: vec![0x11u8; 32],
    };
    let svid_resp = att_client
        .submit_activation_proof(proof)
        .await
        .expect("secure attestation must succeed over real TLS")
        .into_inner();
    assert!(!svid_resp.cert_chain_der.is_empty());
    assert!(
        svid_resp.keypair_der.is_empty(),
        "CR-10: node keeps its own key"
    );
    assert_eq!(
        svid_resp.svid_version, 1,
        "R-5: real version, not hardcoded"
    );

    let ek_bytes = wait_for_key(&donor.keyspaces.node_eks, fingerprint.to_hex().as_bytes()).await;
    let ek_rec: fleetos_control::raft::records::NodeEkRecord =
        postcard::from_bytes(&ek_bytes).unwrap();
    assert_eq!(
        ek_rec.state,
        fleetos_control::raft::records::EkRegistrationState::Joined
    );
    assert_eq!(ek_rec.node_id, joiner_spiffe);
    let svid_bytes = wait_for_key(&donor.keyspaces.svids, joiner_spiffe.as_bytes()).await;
    let svid_rec: fleetos_control::ca::SvidRecord = postcard::from_bytes(&svid_bytes).unwrap();
    assert_eq!(svid_rec.svid_version, 1);
    assert_eq!(svid_rec.agent_x25519_pubkey, vec![0x11u8; 32]);

    let grantee = format!("spiffe://{}/ns/system/control/grantee", SECURE_TRUST_DOMAIN);
    let grant = fleetos_control::ca::SvidGrantRecord {
        spiffe_id: grantee.clone(),
        node_kind: 0,
        granted_at: now_unix,
        expires_at: now_unix + 300,
        agent_x25519_pubkey: vec![0x22; 32],
    };
    donor
        .keyspaces
        .svid_grants
        .insert(
            grantee.as_bytes(),
            postcard::to_allocvec(&grant).unwrap().as_slice(),
        )
        .unwrap();
    let grantee_csr = rcgen_impl::build_csr(&SvidParams {
        spiffe_id: grantee.clone(),
        kind: SvidKind::Control,
        role: None,
        ordinal: None,
        degraded: false,
        ttl_secs: 3600,
    })
    .unwrap();
    let mut ca_client = CaServiceClient::new(channel.clone());
    assert!(
        ca_client
            .submit_csr(CsrRequest {
                csr_der: grantee_csr.csr_der.clone(),
            })
            .await
            .is_ok(),
        "grant-backed CSR must be signed over the real transport"
    );
    assert!(
        donor
            .keyspaces
            .svid_grants
            .get(grantee.as_bytes())
            .unwrap()
            .is_none(),
        "grant must be consumed exactly once"
    );
    assert_eq!(
        ca_client
            .submit_csr(CsrRequest {
                csr_der: grantee_csr.csr_der,
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied,
        "second use of the grant must be rejected"
    );

    let bundle_resp = ca_client
        .get_trust_bundle(TrustBundleRequest {})
        .await
        .unwrap()
        .into_inner();
    let mut join_pem = String::new();
    for root in &bundle_resp.roots_der {
        join_pem.push_str(&der_to_pem(root, "CERTIFICATE"));
    }

    let joiner_client_tls = RaftClientTls {
        cert_der: svid_resp.cert_chain_der.clone(),
        key_der: csr_bundle.private_key.to_vec(),
        trust_bundle_pem: join_pem.clone(),
        domain: SECURE_TRUST_DOMAIN.to_owned(),
    };

    // The shutdown sender must live for the whole membership phase:
    // spawn_raft_server's shutdown future exits as soon as every sender is
    // dropped, which would tear the listener down mid-test.
    let dc_read3 = dc_bundle.read();
    let (donor_raft_addr, _donor_raft_handle, _donor_raft_shutdown) =
        spawn_raft_server(donor.raft.clone(), &secure_mtls(&donor_svid, &dc_read3)).await;
    let donor_raft_addr_str = donor_raft_addr.to_string();

    let mut peers = HashMap::new();
    peers.insert(SECURE_DONOR_ID, donor_raft_addr_str.clone());
    let joiner_factory = TonicRaftNetworkFactory::new(peers, joiner_client_tls);
    let joiner_config = Config {
        heartbeat_interval: 100,
        election_timeout_min: 300,
        election_timeout_max: 600,
        ..Default::default()
    };
    let joiner = create_node(SECURE_JOINER_ID, joiner_factory, joiner_config, false).await;
    let joiner_mtls = MtlsConfig {
        cert_chain: vec![rustls::pki_types::CertificateDer::from(
            svid_resp.cert_chain_der.clone(),
        )],
        private_key: rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(csr_bundle.private_key.to_vec()),
        ),
        trust_bundle_pem: join_pem.clone(),
        role: TrustDomainRole::DataControl,
    };
    let (joiner_raft_addr, _joiner_handle, _joiner_shutdown) =
        spawn_raft_server(joiner.raft.clone(), &joiner_mtls).await;

    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        fleetos_control::join::request_membership(
            &donor_raft_addr_str,
            SECURE_JOINER_ID,
            &joiner_raft_addr.to_string(),
            &joiner_raft_addr.to_string(),
            &svid_resp.cert_chain_der,
            &csr_bundle.private_key.to_vec(),
            &join_pem,
            SECURE_TRUST_DOMAIN,
        ),
    )
    .await
    .expect("membership must complete in time")
    .expect("membership request must succeed over real mTLS");

    let mut joined = false;
    for _ in 0..200 {
        let voters: Vec<u64> = donor
            .raft
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .voter_ids()
            .collect();
        if voters.contains(&SECURE_JOINER_ID) {
            joined = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(joined, "joiner must be promoted to voter");

    wait_for_tenant(&joiner.keyspaces, "tenant-r3").await;

    let _ = dc_shutdown.send(true);
}

#[tokio::test]
async fn secure_join_request_activation_with_swtpm() {
    if std::env::var("FLEETOS_TPM_TESTS").as_deref() != Ok("1") {
        eprintln!("skipping hardware join leg: set FLEETOS_TPM_TESTS=1 with swtpm running");
        return;
    }
    install_crypto_provider();

    let tpm = fleetos_control::config::TpmConfig {
        backend: fleetos_control::config::TpmBackend::Swtpm,
        host: std::env::var("FLEETOS_TPM_HOST").unwrap_or_else(|_| "localhost".into()),
        port: std::env::var("FLEETOS_TPM_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(2321),
        ..Default::default()
    };

    let ca = TrustBundle::generate_root(SECURE_TRUST_DOMAIN).unwrap();
    let donor_svid = secure_control_svid(&ca, "donor");
    let trust_bundle_pem = ca.trust_bundle_pem();
    let dc_bundle = Arc::new(parking_lot::RwLock::new(ca));

    let dc_read = dc_bundle.read();
    // The donor's raft client verifies the joiner's SVID against
    // SECURE_TRUST_DOMAIN (its DNS SAN). raft_client_tls hardcodes the E14
    // TRUST_DOMAIN constant, which would fail hostname verification on the
    // donor -> joiner replication handshake that blocking add_learner needs.
    let donor_factory = TonicRaftNetworkFactory::new(
        HashMap::new(),
        RaftClientTls {
            cert_der: donor_svid.cert_der.clone(),
            key_der: donor_svid.private_key_der.to_vec(),
            trust_bundle_pem: dc_read.trust_bundle_pem(),
            domain: SECURE_TRUST_DOMAIN.to_owned(),
        },
    );
    let donor = create_node(
        SECURE_DONOR_ID,
        donor_factory,
        Config {
            heartbeat_interval: 100,
            election_timeout_min: 300,
            election_timeout_max: 600,
            ..Default::default()
        },
        true,
    )
    .await;
    wait_for_leader(&donor.raft).await;

    let pcr_store = Arc::new(PcrPolicyStore::new(donor.keyspaces.pcr_policies.clone()));
    let attestation_service = AttestationServiceImpl::new(
        Arc::new(NonceManager::new(donor.keyspaces.nonces.clone())),
        Arc::new(JoinTokenStore::new(donor.keyspaces.join_tokens.clone())),
        pcr_store.clone(),
        donor.keyspaces.nonce_claims.clone(),
        donor.keyspaces.svid_grants.clone(),
        donor.raft.clone(),
        donor.keyspaces.control_addresses.clone(),
        donor.keyspaces.node_eks.clone(),
        donor.keyspaces.pending_activations.clone(),
        Some(dc_bundle.clone()),
        3600,
        fleetos_control::config::AttestationMode::Secure,
        tpm.clone(),
        donor.keyspaces.svids.clone(),
    );
    let ca_service = CaServiceImpl::new(
        dc_bundle.clone(),
        3600,
        donor.keyspaces.svids.clone(),
        donor.keyspaces.svid_grants.clone(),
        donor.keyspaces.placements.clone(),
        donor.keyspaces.control_addresses.clone(),
        donor.raft.clone(),
    );
    let dc_read2 = dc_bundle.read();
    let (dc_addr, _h, sd) = spawn_dc_server(
        attestation_service,
        ca_service,
        &secure_mtls(&donor_svid, &dc_read2),
    )
    .await;

    let endpoint = fleetos_core::attestation::tpm::TpmEndpoint::Swtpm {
        host: tpm.host.clone(),
        port: tpm.port,
    };
    let mut session = fleetos_core::attestation::tpm::AttestationSession::begin(&endpoint)
        .expect("TPM session begin failed");
    let ak_pub = session.ak_pub().unwrap();
    let ek_pub = session.ek_pub().unwrap();
    let fingerprint = fleetos_core::attestation::EkFingerprint::of_ek_pub(&ek_pub);

    donor
        .raft
        .client_write(AuditedCommand::system(FleetosCommand::RegisterNodeEk {
            record: fleetos_control::raft::records::NodeEkRecord {
                ek_fingerprint: fingerprint.to_hex(),
                ek_pub,
                ek_cert_der: vec![],
                node_id: String::new(),
                registered_at: 1_700_000_000,
                expires_at: None,
                state: fleetos_control::raft::records::EkRegistrationState::Pending,
            },
        }))
        .await
        .unwrap();
    wait_for_key(&donor.keyspaces.node_eks, fingerprint.to_hex().as_bytes()).await;

    let channel = tonic::transport::Channel::from_shared(fleetos_control::join::channel_addr(
        &dc_addr.to_string(),
    ))
    .unwrap()
    .tls_config(
        tonic::transport::ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(&trust_bundle_pem))
            .domain_name(SECURE_TRUST_DOMAIN),
    )
    .unwrap()
    .connect()
    .await
    .unwrap();
    let mut att_client = AttestationServiceClient::new(channel);

    let challenge = att_client
        .request_activation(fleetos_core::proto::identity::ActivationRequest {
            ak_pub: ak_pub.clone(),
            ek_cert_der: vec![],
            ek_pub: vec![],
        })
        .await
        .expect("RequestActivation must succeed against swtpm")
        .into_inner();

    let recovered = session
        .activate(&challenge.credential_blob, &challenge.secret)
        .expect("TPM ActivateCredential failed");
    let secret: [u8; 32] = recovered.as_slice().try_into().unwrap();
    let pcr_indices: Vec<u8> = vec![0, 7, 9];
    let quote_out = session
        .quote(&challenge.server_nonce, &pcr_indices)
        .unwrap();

    let joiner_spiffe = format!(
        "spiffe://{}/ns/system/control/joiner-hw",
        SECURE_TRUST_DOMAIN
    );
    pcr_store
        .set_policy(&PcrPolicy {
            node_id: joiner_spiffe.clone(),
            expected_pcrs: quote_out.pcr_values.clone(),
            updated_at: 1_700_000_000,
            active: true,
        })
        .unwrap();

    let csr_bundle = rcgen_impl::build_csr(&SvidParams {
        spiffe_id: joiner_spiffe.clone(),
        kind: SvidKind::Control,
        role: None,
        ordinal: None,
        degraded: false,
        ttl_secs: 3600,
    })
    .unwrap();
    let proof = ActivationProof {
        hmac: fleetos_core::attestation::compute_activation_proof(&secret, &challenge.server_nonce)
            .to_vec(),
        quote: quote_out.quote,
        quote_signature: quote_out.signature,
        pcr_selection: postcard::to_allocvec(&quote_out.pcr_values).unwrap(),
        csr_der: csr_bundle.csr_der,
        agent_x25519_pubkey: vec![0x33u8; 32],
    };
    let resp = att_client
        .submit_activation_proof(proof)
        .await
        .expect("hardware attestation must succeed over real TLS")
        .into_inner();
    assert!(!resp.cert_chain_der.is_empty());
    assert_eq!(resp.svid_version, 1);

    let ek_bytes = wait_for_key(&donor.keyspaces.node_eks, fingerprint.to_hex().as_bytes()).await;
    let ek_rec: fleetos_control::raft::records::NodeEkRecord =
        postcard::from_bytes(&ek_bytes).unwrap();
    assert_eq!(
        ek_rec.state,
        fleetos_control::raft::records::EkRegistrationState::Joined
    );
    let _ = sd.send(true);
}
