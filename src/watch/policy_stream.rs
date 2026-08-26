//! PolicyService implementation — WatchSag stream for agents.
//!
//! Streams the full SAG rule set (not compiled eBPF structs) plus
//! the full revoked delegation IDs set. Agents compile rules into
//! eBPF map entries locally.
use super::broadcast::BroadcastHub;
use fleetos_core::proto::state::PolicyService;
use fleetos_core::proto::state::{PeerSelector, SagRule as ProtoSagRule, SagUpdate, WatchRequest};
use prost::Message;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

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
                        let rules = match decode_rules(&update.rules_bytes) {
                            Ok(r) => r,
                            Err(e) => {
                                tracing::error!(error = %e, "failed to decode SAG rules");
                                continue;
                            }
                        };
                        let sag_update = SagUpdate {
                            version: update.version.get(),
                            rules,
                            revoked_delegation_ids: update.revoked_delegation_ids,
                            // Step 19 (G-4) will populate this from the revocation set.
                            revoked_spiffe_ids: Vec::new(),
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

/// Decode rules from proto-encoded bytes to proto SagRule messages.
///
/// Wire format: sequence of length-prefixed proto-encoded SagRule messages.
/// Each entry is: [4-byte LE length][proto bytes].
/// The state machine produces this format by converting internal
/// `fleetos_core::policy::SagRule` values to proto `SagRule` and encoding
/// with `prost::Message::encode_to_vec()`.
fn decode_rules(bytes: &[u8]) -> Result<Vec<ProtoSagRule>, super::WatchError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut rules = Vec::new();
    let mut offset = 0;
    while offset + 4 <= bytes.len() {
        let len = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;
        if offset + len > bytes.len() {
            return Err(super::WatchError::Serialization(
                postcard::Error::DeserializeUnexpectedEnd,
            ));
        }
        let rule = ProtoSagRule::decode(&bytes[offset..offset + len])
            .map_err(|e| super::WatchError::SendFailed(format!("proto decode failed: {}", e)))?;
        rules.push(rule);
        offset += len;
    }
    Ok(rules)
}

/// Encode a list of proto SagRule messages into the wire format.
///
/// Wire format: sequence of [4-byte LE length][proto bytes].
/// Called by the state machine when publishing SAG updates to the BroadcastHub.
pub fn encode_rules(rules: &[ProtoSagRule]) -> Vec<u8> {
    let mut buf = Vec::new();
    for rule in rules {
        let encoded = rule.encode_to_vec();
        buf.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        buf.extend_from_slice(&encoded);
    }
    buf
}

// --- Internal-to-proto conversion helpers ---
// These are used by the state machine when publishing SAG updates.

/// Convert a `fleetos_core::policy::SagRule` to a proto `SagRule`.
///
/// The `SagRuleId` is recomputed via BLAKE3 (same algorithm as
/// `SagRuleId::of_rule`) to produce a hex string for the proto `id` field,
/// since the inner `[u8; 16]` is private.
pub fn core_rule_to_proto(rule: &fleetos_core::policy::SagRule) -> ProtoSagRule {
    ProtoSagRule {
        id: rule_id_to_hex(rule),
        from: Some(peer_selector_to_proto(&rule.from)),
        to: Some(peer_selector_to_proto(&rule.to)),
        action: match rule.action {
            fleetos_core::policy::SagAction::Allow => 0,
            fleetos_core::policy::SagAction::Deny => 1,
        },
    }
}

/// Convert a `fleetos_core::policy::PeerSelector` to a proto `PeerSelector`.
fn peer_selector_to_proto(selector: &fleetos_core::policy::PeerSelector) -> PeerSelector {
    PeerSelector {
        tenant: selector.service.tenant.as_str().to_owned(),
        service_name: selector.service.name.clone(),
        role: selector
            .role
            .as_ref()
            .map(|r| r.as_str().to_owned())
            .unwrap_or_default(),
        port: selector.port.map(|p| p as u32),
    }
}

/// Compute the `SagRuleId` hex string by replicating the BLAKE3 algorithm
/// from `SagRuleId::of_rule`. This avoids needing access to the private
/// inner `[u8; 16]` field.
fn rule_id_to_hex(rule: &fleetos_core::policy::SagRule) -> String {
    let mut hasher = blake3::Hasher::new();

    // Replicate the exact field order and separators from SagRuleId::of_rule
    hasher.update(rule.from.service.tenant.as_str().as_bytes());
    hasher.update(&[0x00]);
    hasher.update(rule.from.service.name.as_bytes());
    hasher.update(&[0x00]);
    if let Some(ref r) = rule.from.role {
        hasher.update(r.as_str().as_bytes());
    }
    hasher.update(&[0x00]);
    if let Some(p) = rule.from.port {
        hasher.update(&p.to_be_bytes());
    }
    hasher.update(&[0x00]);
    hasher.update(rule.to.service.name.as_bytes());
    hasher.update(&[0x00]);
    if let Some(ref r) = rule.to.role {
        hasher.update(r.as_str().as_bytes());
    }
    hasher.update(&[0x00]);
    if let Some(p) = rule.to.port {
        hasher.update(&p.to_be_bytes());
    }
    hasher.update(&[0x00]);
    let action_str = match rule.action {
        fleetos_core::policy::SagAction::Allow => "ALLOW",
        fleetos_core::policy::SagAction::Deny => "DENY",
    };
    hasher.update(action_str.as_bytes());

    let hash = hasher.finalize();
    hash.as_bytes()[..16]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}
