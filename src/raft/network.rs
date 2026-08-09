use openraft::error::{InstallSnapshotError, NetworkError, RPCError, RaftError};
use openraft::network::RPCOption;
use openraft::network::{RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};

use crate::raft::types::{NodeId, TypeConfig};

pub struct Network;

impl Network {
    pub fn new() -> Self {
        Self
    }
}

pub struct NetworkConnection {
    _target: NodeId,
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
        Err(RPCError::Network(NetworkError::new(&std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "Network transport stub",
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
            std::io::ErrorKind::NotConnected,
            "Network transport stub",
        ))))
    }

    async fn vote(
        &mut self,
        _rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, openraft::BasicNode, RaftError<NodeId>>>
    {
        Err(RPCError::Network(NetworkError::new(&std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "Network transport stub",
        ))))
    }
}

impl RaftNetworkFactory<TypeConfig> for Network {
    type Network = NetworkConnection;

    async fn new_client(&mut self, target: NodeId, _node: &openraft::BasicNode) -> Self::Network {
        NetworkConnection { _target: target }
    }
}
