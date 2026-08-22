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
use tonic::transport::Channel;

use super::{FleetosRaftConfig, RaftRpc, RaftTransportClient};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SnapshotWire {
    meta: openraft::SnapshotMeta<u64, openraft::BasicNode>,
    data: Vec<u8>,
}

pub struct TonicRaftNetworkFactory {
    peer_addresses: Arc<Mutex<HashMap<u64, String>>>,
}

impl TonicRaftNetworkFactory {
    pub fn new(peer_addresses: HashMap<u64, String>) -> Self {
        Self {
            peer_addresses: Arc::new(Mutex::new(peer_addresses)),
        }
    }
}

impl RaftNetworkFactory<FleetosRaftConfig> for TonicRaftNetworkFactory {
    type Network = TonicRaftNetwork;

    async fn new_client(&mut self, target: u64, _node: &openraft::BasicNode) -> Self::Network {
        let address = self
            .peer_addresses
            .lock()
            .get(&target)
            .cloned()
            .unwrap_or_default();
        TonicRaftNetwork {
            target,
            address,
            client: Arc::new(AsyncMutex::new(None)),
        }
    }
}

pub struct TonicRaftNetwork {
    target: u64,
    address: String,
    client: Arc<AsyncMutex<Option<RaftTransportClient<Channel>>>>,
}

impl TonicRaftNetwork {
    async fn get_client(&self) -> Result<RaftTransportClient<Channel>, std::io::Error> {
        let mut client_guard = self.client.lock().await;
        if client_guard.is_none() {
            let channel = Channel::from_shared(self.address.clone())
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
