use std::sync::Arc;

use openraft::raft::{AppendEntriesRequest, InstallSnapshotRequest, VoteRequest};
use openraft::{Raft, Vote};
use tonic::{Request, Response, Status};

use super::{FleetosRaftConfig, RaftRpc, RaftTransportService};

/// Wire format for snapshot transmission.
/// openraft::Snapshot contains Cursor<Vec<u8>> which doesn't implement Serialize,
/// so we extract the bytes and send them with the metadata separately.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SnapshotWire {
    meta: openraft::SnapshotMeta<u64, openraft::BasicNode>,
    data: Vec<u8>,
}

pub struct RaftTransportServerImpl {
    raft: Arc<Raft<FleetosRaftConfig>>,
}

impl RaftTransportServerImpl {
    pub fn new(raft: Arc<Raft<FleetosRaftConfig>>) -> Self {
        Self { raft }
    }
}

#[tonic::async_trait]
impl RaftTransportService for RaftTransportServerImpl {
    async fn append_entries(&self, request: Request<RaftRpc>) -> Result<Response<RaftRpc>, Status> {
        let rpc = request.into_inner();

        let req: AppendEntriesRequest<FleetosRaftConfig> = postcard::from_bytes(&rpc.payload)
            .map_err(|e| Status::invalid_argument(format!("deserialize failed: {}", e)))?;

        let resp = self
            .raft
            .append_entries(req)
            .await
            .map_err(|e| Status::internal(format!("raft error: {}", e)))?;

        let payload = postcard::to_allocvec(&resp)
            .map_err(|e| Status::internal(format!("serialize failed: {}", e)))?;

        Ok(Response::new(RaftRpc {
            sender_id: rpc.target_id,
            target_id: rpc.sender_id,
            payload,
        }))
    }

    async fn vote(&self, request: Request<RaftRpc>) -> Result<Response<RaftRpc>, Status> {
        let rpc = request.into_inner();

        let req: VoteRequest<u64> = postcard::from_bytes(&rpc.payload)
            .map_err(|e| Status::invalid_argument(format!("deserialize failed: {}", e)))?;

        let resp = self
            .raft
            .vote(req)
            .await
            .map_err(|e| Status::internal(format!("raft error: {}", e)))?;

        let payload = postcard::to_allocvec(&resp)
            .map_err(|e| Status::internal(format!("serialize failed: {}", e)))?;

        Ok(Response::new(RaftRpc {
            sender_id: rpc.target_id,
            target_id: rpc.sender_id,
            payload,
        }))
    }

    async fn install_snapshot(
        &self,
        request: Request<RaftRpc>,
    ) -> Result<Response<RaftRpc>, Status> {
        let rpc = request.into_inner();

        // Try InstallSnapshotRequest first (chunked installs)
        let resp = if let Ok(req) =
            postcard::from_bytes::<InstallSnapshotRequest<FleetosRaftConfig>>(&rpc.payload)
        {
            self.raft.install_snapshot(req).await
        } else {
            // Try SnapshotWire format (from full_snapshot)
            let wire: SnapshotWire = postcard::from_bytes(&rpc.payload)
                .map_err(|e| Status::invalid_argument(format!("deserialize failed: {}", e)))?;

            let req = InstallSnapshotRequest {
                vote: Vote::new(
                    wire.meta
                        .last_log_id
                        .map(|id| id.leader_id.term)
                        .unwrap_or(0),
                    rpc.sender_id,
                ),
                meta: wire.meta,
                offset: 0,
                data: wire.data, // InstallSnapshotRequest.data is Vec<u8>, not Cursor
                done: true,
            };
            self.raft.install_snapshot(req).await
        };

        let resp = resp.map_err(|e| Status::internal(format!("raft error: {}", e)))?;

        let payload = postcard::to_allocvec(&resp)
            .map_err(|e| Status::internal(format!("serialize failed: {}", e)))?;

        Ok(Response::new(RaftRpc {
            sender_id: rpc.target_id,
            target_id: rpc.sender_id,
            payload,
        }))
    }
}
