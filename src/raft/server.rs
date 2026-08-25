use openraft::raft::{AppendEntriesRequest, InstallSnapshotRequest, VoteRequest};
use openraft::{Raft, Vote};
use std::sync::Arc;
use tonic::{Request, Response, Status};

use super::{
    FleetosRaftConfig, JoinRequestPayload, JoinResponsePayload, RaftRpc, RaftTransportService,
};

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

    /// Handle a join request: add the node as a learner (blocking until it
    /// catches up — including snapshot transfer), then promote it to voter.
    ///
    /// If we are not the leader, respond with the leader's address so the
    /// joiner can retry against it.
    async fn request_join(&self, request: Request<RaftRpc>) -> Result<Response<RaftRpc>, Status> {
        let rpc = request.into_inner();
        let req: JoinRequestPayload = postcard::from_bytes(&rpc.payload)
            .map_err(|e| Status::invalid_argument(format!("deserialize failed: {}", e)))?;

        tracing::info!(
            node_id = req.node_id,
            addr = %req.address,
            "join request received"
        );

        let node = openraft::BasicNode {
            addr: req.address.clone(),
        };

        // blocking = true: wait until the learner has caught up (log
        // replication or snapshot transfer) before returning. This RPC is
        // therefore long-running by design.
        let resp = match self.raft.add_learner(req.node_id, node.clone(), true).await {
            Ok(_) => {
                // Learner caught up — promote to voter so manual join is self-service.
                let mut voters = std::collections::BTreeMap::new();
                voters.insert(req.node_id, node);
                let change = openraft::ChangeMembers::AddVoters(voters);
                match self.raft.change_membership(change, false).await {
                    Ok(_) => {
                        tracing::info!(node_id = req.node_id, "joiner promoted to voter");
                        JoinResponsePayload {
                            success: true,
                            leader_address: None,
                        }
                    }
                    Err(e) => {
                        tracing::error!(node_id = req.node_id, error = %e, "joiner promotion failed");
                        JoinResponsePayload {
                            success: false,
                            leader_address: None,
                        }
                    }
                }
            }
            Err(e) => {
                // When this node is not the leader, add_learner returns
                // RaftError::APIError(ClientWriteError::ForwardToLeader) carrying
                // the leader's address.
                let leader_address = match &e {
                    openraft::error::RaftError::APIError(
                        openraft::error::ClientWriteError::ForwardToLeader(fwd),
                    ) => fwd.leader_node.as_ref().map(|n| n.addr.clone()),
                    _ => None,
                };
                tracing::info!(
                    node_id = req.node_id,
                    leader_address = ?leader_address,
                    error = %e,
                    "not leader, redirecting join request"
                );
                JoinResponsePayload {
                    success: false,
                    leader_address,
                }
            }
        };

        let payload = postcard::to_allocvec(&resp)
            .map_err(|e| Status::internal(format!("serialize failed: {}", e)))?;

        Ok(Response::new(RaftRpc {
            sender_id: rpc.target_id,
            target_id: rpc.sender_id,
            payload,
        }))
    }
}
