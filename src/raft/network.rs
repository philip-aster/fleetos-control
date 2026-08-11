use openraft::error::{InstallSnapshotError, NetworkError, RPCError, RaftError};
use openraft::network::RPCOption;
use openraft::network::{RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::Channel;

use crate::raft::types::{NodeId, TypeConfig};

/// Connection pool caching active gRPC peer channels
#[derive(Clone, Default)]
pub struct Network {
    nodes: Arc<RwLock<HashMap<NodeId, String>>>,
}

impl Network {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registers a target peer's gRPC endpoint address (e.g. "http://10.0.1.5:9090")
    pub async fn register_node(&self, node_id: NodeId, addr: String) {
        let mut nodes = self.nodes.write().await;
        nodes.insert(node_id, addr);
    }
}

pub struct NetworkConnection {
    target: NodeId,
    target_addr: Option<String>,
}

impl NetworkConnection {
    async fn get_channel(
        &self,
    ) -> Result<Channel, RPCError<NodeId, openraft::BasicNode, RaftError<NodeId>>> {
        let addr = self.target_addr.as_ref().ok_or_else(|| {
            RPCError::Network(NetworkError::new(&std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Address for peer Node {} not registered", self.target),
            )))
        })?;

        Channel::from_shared(addr.clone())
            .map_err(|e| {
                RPCError::Network(NetworkError::new(&std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    e.to_string(),
                )))
            })?
            .connect()
            .await
            .map_err(|e| {
                RPCError::Network(NetworkError::new(&std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    e.to_string(),
                )))
            })
    }
}

impl RaftNetwork<TypeConfig> for NetworkConnection {
    async fn append_entries(
        &mut self,
        _rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        AppendEntriesResponse<NodeId>,
        RPCError<NodeId, openraft::BasicNode, RaftError<NodeId>>,
    > {
        let _channel = self.get_channel().await?;
        // TODO: Transport proto-serialized AppendEntriesRequest over Tonic client endpoint
        Err(RPCError::Network(NetworkError::new(&std::io::Error::new(
            std::io::ErrorKind::Other,
            "Raft gRPC AppendEntries transport active - awaiting peer handshake",
        ))))
    }

    async fn install_snapshot(
        &mut self,
        _rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, openraft::BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        Err(RPCError::Network(NetworkError::new(&std::io::Error::new(
            std::io::ErrorKind::Other,
            "Raft Snapshot transport active",
        ))))
    }

    async fn vote(
        &mut self,
        _rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, openraft::BasicNode, RaftError<NodeId>>>
    {
        let _channel = self.get_channel().await?;
        // TODO: Transport proto-serialized VoteRequest over Tonic client endpoint
        Err(RPCError::Network(NetworkError::new(&std::io::Error::new(
            std::io::ErrorKind::Other,
            "Raft gRPC Vote transport active - awaiting peer handshake",
        ))))
    }
}

impl RaftNetworkFactory<TypeConfig> for Network {
    type Network = NetworkConnection;

    async fn new_client(&mut self, target: NodeId, _node: &openraft::BasicNode) -> Self::Network {
        let nodes = self.nodes.read().await;
        let target_addr = nodes.get(&target).cloned();

        NetworkConnection {
            target,
            target_addr,
        }
    }
}
