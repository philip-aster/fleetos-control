use openraft::error::{
    Fatal, InstallSnapshotError, RPCError, RaftError, ReplicationClosed, StreamingError,
};
use openraft::network::RPCOption;
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    SnapshotResponse, VoteRequest, VoteResponse,
};
use openraft::{RaftNetwork, RaftNetworkFactory, Snapshot, Vote};

use super::FleetosRaftConfig;

pub struct TonicRaftNetworkFactory;

impl RaftNetworkFactory<FleetosRaftConfig> for TonicRaftNetworkFactory {
    type Network = TonicRaftNetwork;

    async fn new_client(&mut self, target: u64, _node: &openraft::BasicNode) -> Self::Network {
        TonicRaftNetwork { target }
    }
}

pub struct TonicRaftNetwork {
    #[allow(dead_code)]
    target: u64,
}

impl RaftNetwork<FleetosRaftConfig> for TonicRaftNetwork {
    async fn append_entries(
        &mut self,
        _req: AppendEntriesRequest<FleetosRaftConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, openraft::BasicNode, RaftError<u64>>>
    {
        todo!("tonic raft transport not yet implemented")
    }

    async fn vote(
        &mut self,
        _req: VoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, openraft::BasicNode, RaftError<u64>>> {
        todo!("tonic raft transport not yet implemented")
    }

    async fn full_snapshot(
        &mut self,
        _vote: Vote<u64>,
        _snapshot: Snapshot<FleetosRaftConfig>,
        _cancel: impl std::future::Future<Output = ReplicationClosed> + openraft::OptionalSend + 'static,
        _option: RPCOption,
    ) -> Result<SnapshotResponse<u64>, StreamingError<FleetosRaftConfig, Fatal<u64>>> {
        todo!("tonic raft transport not yet implemented")
    }

    async fn install_snapshot(
        &mut self,
        _req: InstallSnapshotRequest<FleetosRaftConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, openraft::BasicNode, RaftError<u64, InstallSnapshotError>>,
    > {
        todo!("tonic raft transport not yet implemented — deprecated in favor of full_snapshot")
    }
}
