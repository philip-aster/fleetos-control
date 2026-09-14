//! PolicyService implementation — WatchSag stream for agents.
//!
//! Streams SAG rule updates + revoked delegation/SVID lists to agents. This is
//! the agent's primary policy-ingress path (Master audit item 3a). The state
//! machine publishes `SagUpdateEvent` to the `BroadcastHub`; this service
//! subscribes and decodes the rules into proto `SagRule` messages at the
//! stream boundary.
use super::broadcast::BroadcastHub;
use fleetos_core::proto::state::{PolicyService, SagRule, SagUpdate, WatchRequest};
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

pub struct PolicyServiceImpl {
    hub: Arc<BroadcastHub>,
    sag_rules: fjall::Keyspace,
    versioned_state: crate::storage::version::VersionedState,
    revoked_delegations: fjall::Keyspace,
    revoked_svids: fjall::Keyspace,
}

impl PolicyServiceImpl {
    pub fn new(
        hub: Arc<BroadcastHub>,
        sag_rules: fjall::Keyspace,
        versioned_state: crate::storage::version::VersionedState,
        revoked_delegations: fjall::Keyspace,
        revoked_svids: fjall::Keyspace,
    ) -> Self {
        Self {
            hub,
            sag_rules,
            versioned_state,
            revoked_delegations,
            revoked_svids,
        }
    }
}

#[tonic::async_trait]
impl PolicyService for PolicyServiceImpl {
    type WatchSagStream = Pin<Box<dyn Stream<Item = Result<SagUpdate, Status>> + Send + 'static>>;

    async fn watch_sag(
        &self,
        _request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchSagStream>, Status> {
        // Ruling B ordering: subscribe FIRST, then read committed state, then
        // yield frame one, then stream deltas. Deltas published during the
        // snapshot build buffer in `rx` and drain after frame one — never dropped.
        let mut rx = self.hub.subscribe_sag();
        let snap = super::snapshot::build_sag_snapshot(
            &self.sag_rules,
            &self.revoked_delegations,
            &self.revoked_svids,
        );
        let frame_one_rules = match decode_rules(&snap.rules_bytes) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "failed to build initial SAG frame");
                return Err(Status::internal("failed to build initial SAG frame"));
            }
        };
        let frame_one = SagUpdate {
            version: self.versioned_state.current_version().get(),
            rules: frame_one_rules,
            revoked_delegation_ids: snap.revoked_delegation_ids,
            revoked_spiffe_ids: snap.revoked_spiffe_ids,
        };
        let stream = async_stream::stream! {
            yield Ok(frame_one);
            loop {
                match rx.recv().await {
                    Ok(update) => {
                        let rules = match decode_rules(&update.rules_bytes) {
                            Ok(r) => r,
                            Err(e) => {
                                tracing::error!(error = %e, "failed to decode SAG rules");
                                continue;
                            }
                        };
                        yield Ok(SagUpdate {
                            version: update.version.get(),
                            rules,
                            revoked_delegation_ids: update.revoked_delegation_ids,
                            revoked_spiffe_ids: update.revoked_spiffe_ids,
                        });
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(lagged = n, "sag subscriber lagged");
                        continue;
                    }
                }
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }
}

/// Errors decoding the length-prefixed SAG rule buffer.
#[derive(Debug, thiserror::Error)]
enum DecodeRulesError {
    #[error("truncated SAG rules buffer")]
    Truncated,
    #[error("SAG rule proto decode failed: {0}")]
    Proto(#[from] prost::DecodeError),
}

/// Inverse of `state_machine.rs::publish_sag_update`: each rule is encoded as
/// `[u32 LE length][proto SagRule bytes]`, concatenated. Read the length, then
/// decode that many bytes as a `SagRule`, repeat.
fn decode_rules(bytes: &[u8]) -> Result<Vec<SagRule>, DecodeRulesError> {
    use prost::Message;
    let mut rules = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let len_slice = bytes
            .get(offset..offset + 4)
            .ok_or(DecodeRulesError::Truncated)?;
        let len =
            u32::from_le_bytes([len_slice[0], len_slice[1], len_slice[2], len_slice[3]]) as usize;
        offset += 4;
        let rule_slice = bytes
            .get(offset..offset + len)
            .ok_or(DecodeRulesError::Truncated)?;
        rules.push(SagRule::decode(rule_slice)?);
        offset += len;
    }
    Ok(rules)
}
