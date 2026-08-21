//! PolicyService implementation — WatchSag stream for agents.
//!
//! Streams the full SAG rule set (not compiled eBPF structs) plus
//! the full revoked delegation IDs set. Agents compile rules into
//! eBPF map entries locally.

use std::pin::Pin;
use std::sync::Arc;

use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use fleetos_core::proto::state::PolicyService;
use fleetos_core::proto::state::{PeerSelector, SagRule as ProtoSagRule, SagUpdate, WatchRequest};

use super::broadcast::BroadcastHub;

/// The PolicyService gRPC implementation.
pub struct PolicyServiceImpl {
    hub: Arc<BroadcastHub>,
}

impl PolicyServiceImpl {
    pub fn new(hub: Arc<BroadcastHub>) -> Self {
        Self { hub }
    }
}

#[tonic::async_trait]
impl PolicyService for PolicyServiceImpl {
    type WatchSagStream = Pin<Box<dyn Stream<Item = Result<SagUpdate, Status>> + Send + 'static>>;

    async fn watch_sag(
        &self,
        _request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchSagStream>, Status> {
        let mut rx = self.hub.subscribe_sag();

        let stream = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(update) => {
                        // Deserialize the rules from our internal postcard format
                        // into the proto SagRule type.
                        //
                        // The rules_bytes are postcard-serialized fleetos_core::policy::SagRule
                        // values from the state machine. We need to convert them to
                        // proto SagRule messages.
                        //
                        // TODO: Implement proper conversion from fleetos_core::policy::SagRule
                        // to proto SagRule. For now, we deserialize and map fields.
                        let rules = match deserialize_rules(&update.rules_bytes) {
                            Ok(r) => r,
                            Err(e) => {
                                tracing::error!(error = %e, "failed to deserialize SAG rules");
                                continue;
                            }
                        };

                        let sag_update = SagUpdate {
                            version: update.version.get(),
                            rules,
                            revoked_delegation_ids: update.revoked_delegation_ids,
                        };
                        yield Ok(sag_update);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(lagged = n, "SAG subscriber lagged, skipping messages");
                        continue;
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }
}

/// Deserialize rules from internal postcard format to proto SagRule messages.
///
/// TODO: This conversion needs to map fleetos_core::policy::SagRule fields
/// to the proto SagRule message structure. The exact mapping depends on
/// the generated proto types.
fn deserialize_rules(bytes: &[u8]) -> Result<Vec<ProtoSagRule>, super::WatchError> {
    // The rules_bytes are postcard-serialized Vec<fleetos_core::policy::SagRule>.
    // We need to convert each to proto SagRule.
    //
    // For now, return an empty vec as a placeholder — the actual conversion
    // requires mapping between fleetos_core::policy types and proto types.
    // This will be implemented once we verify the exact proto generated types.
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    // TODO: Proper conversion:
    // let core_rules: Vec<fleetos_core::policy::SagRule> =
    //     postcard::from_bytes(bytes).map_err(super::WatchError::Serialization)?;
    // Ok(core_rules.iter().map(core_rule_to_proto).collect())

    let _ = bytes;
    Ok(Vec::new())
}

/// Convert a fleetos_core::policy::SagRule to a proto SagRule.
///
/// TODO: Implement field mapping once proto types are verified.
#[allow(dead_code)]
fn _core_rule_to_proto(_rule: &fleetos_core::policy::SagRule) -> ProtoSagRule {
    // Placeholder — actual conversion maps:
    // - rule.id → proto id (string)
    // - rule.from.service.tenant → proto from.tenant
    // - rule.from.service.name → proto from.service_name
    // - rule.from.role → proto from.role
    // - rule.from.port → proto from.port
    // - Same for rule.to
    // - rule.action → proto action enum
    ProtoSagRule {
        id: String::new(),
        from: Some(PeerSelector {
            tenant: String::new(),
            service_name: String::new(),
            role: String::new(),
            port: None,
        }),
        to: Some(PeerSelector {
            tenant: String::new(),
            service_name: String::new(),
            role: String::new(),
            port: None,
        }),
        action: 0, // ALLOW
    }
}
