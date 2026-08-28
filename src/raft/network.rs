use std::collections::HashMap;
use std::sync::Arc;

use openraft::error::{
    Fatal, InstallSnapshotError, NetworkError, RPCError, RaftError, ReplicationClosed,
    StreamingError,
};
use openraft::network::RPCOption;
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    SnapshotResponse, VoteRequest, VoteResponse,
};
use openraft::{RaftNetwork, RaftNetworkFactory, Snapshot, Vote};
use parking_lot::Mutex;
use tokio::sync::Mutex as AsyncMutex;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use super::{FleetosRaftConfig, RaftRpc, RaftTransportClient};

fn der_to_pem(der: &[u8], label: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let b64 = STANDARD.encode(der);
    let mut pem = String::new();
    pem.push_str(&format!("-----BEGIN {}-----\n", label));
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SnapshotWire {
    meta: openraft::SnapshotMeta<u64, openraft::BasicNode>,
    data: Vec<u8>,
}

/// Client TLS material for the Raft transport (Step 17 / S-2).
#[derive(Clone)]
pub struct RaftClientTls {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub trust_bundle_pem: String,
    /// Trust domain used as the TLS `domain_name`; control SVIDs carry it as a DNS SAN.
    pub domain: String,
}

pub struct TonicRaftNetworkFactory {
    peer_addresses: Arc<Mutex<HashMap<u64, String>>>,
    tls: RaftClientTls,
}

impl TonicRaftNetworkFactory {
    pub fn new(peer_addresses: HashMap<u64, String>, tls: RaftClientTls) -> Self {
        Self {
            peer_addresses: Arc::new(Mutex::new(peer_addresses)),
            tls,
        }
    }
}

impl RaftNetworkFactory<FleetosRaftConfig> for TonicRaftNetworkFactory {
    type Network = TonicRaftNetwork;

    async fn new_client(&mut self, target: u64, node: &openraft::BasicNode) -> Self::Network {
        let address = {
            let peers = self.peer_addresses.lock();
            peers
                .get(&target)
                .cloned()
                .unwrap_or_else(|| node.addr.clone())
        };
        TonicRaftNetwork {
            target,
            address,
            tls: self.tls.clone(),
            client: Arc::new(AsyncMutex::new(None)),
        }
    }
}

pub struct TonicRaftNetwork {
    target: u64,
    address: String,
    tls: RaftClientTls,
    client: Arc<AsyncMutex<Option<RaftTransportClient<Channel>>>>,
}

impl TonicRaftNetwork {
    async fn get_client(&self) -> Result<RaftTransportClient<Channel>, std::io::Error> {
        let mut client_guard = self.client.lock().await;
        if client_guard.is_none() {
            let cert_pem = der_to_pem(&self.tls.cert_der, "CERTIFICATE");
            let key_pem = der_to_pem(&self.tls.key_der, "PRIVATE KEY");
            let identity = Identity::from_pem(cert_pem, key_pem);
            let ca = Certificate::from_pem(&self.tls.trust_bundle_pem);
            let tls_config = ClientTlsConfig::new()
                .identity(identity)
                .ca_certificate(ca)
                .domain_name(self.tls.domain.clone());

            let endpoint_str = format!(
                "https://{}",
                self.address
                    .trim_start_matches("http://")
                    .trim_start_matches("https://")
            );
            let channel = Endpoint::from_shared(endpoint_str)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?
                .tls_config(tls_config)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?
                .connect()
                .await
                .map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e.to_string())
                })?;
            *client_guard = Some(RaftTransportClient::new(channel));
        }
        Ok(client_guard.as_ref().unwrap().clone())
    }

    fn serialize<T: serde::Serialize>(val: &T) -> Result<Vec<u8>, std::io::Error> {
        postcard::to_allocvec(val)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }

    fn deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, std::io::Error> {
        postcard::from_bytes(bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }

    fn map_io_to_rpc_err(
        &self,
        e: std::io::Error,
    ) -> RPCError<u64, openraft::BasicNode, RaftError<u64>> {
        RPCError::Network(NetworkError::new(&e))
    }
}

impl RaftNetwork<FleetosRaftConfig> for TonicRaftNetwork {
    async fn append_entries(
        &mut self,
        req: AppendEntriesRequest<FleetosRaftConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, openraft::BasicNode, RaftError<u64>>>
    {
        let mut client = self
            .get_client()
            .await
            .map_err(|e| self.map_io_to_rpc_err(e))?;

        let payload = Self::serialize(&req).map_err(|e| self.map_io_to_rpc_err(e))?;

        let rpc = RaftRpc {
            sender_id: req.vote.leader_id.node_id,
            target_id: self.target,
            payload,
        };

        let response = client.append_entries(rpc).await.map_err(|e| {
            self.map_io_to_rpc_err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;

        Self::deserialize(&response.into_inner().payload).map_err(|e| self.map_io_to_rpc_err(e))
    }

    async fn vote(
        &mut self,
        req: VoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, openraft::BasicNode, RaftError<u64>>> {
        let mut client = self
            .get_client()
            .await
            .map_err(|e| self.map_io_to_rpc_err(e))?;

        let payload = Self::serialize(&req).map_err(|e| self.map_io_to_rpc_err(e))?;

        let rpc = RaftRpc {
            sender_id: req.vote.leader_id.node_id,
            target_id: self.target,
            payload,
        };

        let response = client.vote(rpc).await.map_err(|e| {
            self.map_io_to_rpc_err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;

        Self::deserialize(&response.into_inner().payload).map_err(|e| self.map_io_to_rpc_err(e))
    }

    async fn full_snapshot(
        &mut self,
        vote: Vote<u64>,
        snapshot: Snapshot<FleetosRaftConfig>,
        _cancel: impl std::future::Future<Output = ReplicationClosed> + openraft::OptionalSend + 'static,
        _option: RPCOption,
    ) -> Result<SnapshotResponse<u64>, StreamingError<FleetosRaftConfig, Fatal<u64>>> {
        use std::io::Read;

        let mut client = self
            .get_client()
            .await
            .map_err(|e| StreamingError::Network(NetworkError::new(&e)))?;

        // Extract bytes from the Cursor<Vec<u8>>
        let mut cursor = snapshot.snapshot;
        cursor.set_position(0);
        let mut data = Vec::new();
        cursor
            .read_to_end(&mut data)
            .map_err(|e| StreamingError::Network(NetworkError::new(&e)))?;

        let wire = SnapshotWire {
            meta: snapshot.meta,
            data,
        };

        let payload =
            Self::serialize(&wire).map_err(|e| StreamingError::Network(NetworkError::new(&e)))?;

        let rpc = RaftRpc {
            sender_id: vote.leader_id.node_id,
            target_id: self.target,
            payload,
        };

        let response = client.install_snapshot(rpc).await.map_err(|e| {
            let io_err = std::io::Error::new(std::io::ErrorKind::Other, e.to_string());
            StreamingError::Network(NetworkError::new(&io_err))
        })?;

        let resp: InstallSnapshotResponse<u64> = Self::deserialize(&response.into_inner().payload)
            .map_err(|e| StreamingError::Network(NetworkError::new(&e)))?;

        Ok(SnapshotResponse { vote: resp.vote })
    }

    async fn install_snapshot(
        &mut self,
        req: InstallSnapshotRequest<FleetosRaftConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, openraft::BasicNode, RaftError<u64, InstallSnapshotError>>,
    > {
        let mut client = self
            .get_client()
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;

        let payload =
            Self::serialize(&req).map_err(|e| RPCError::Network(NetworkError::new(&e)))?;

        let rpc = RaftRpc {
            sender_id: req.vote.leader_id.node_id,
            target_id: self.target,
            payload,
        };

        let response = client.install_snapshot(rpc).await.map_err(|e| {
            RPCError::Network(NetworkError::new(&std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            )))
        })?;

        Self::deserialize(&response.into_inner().payload)
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))
    }
}
