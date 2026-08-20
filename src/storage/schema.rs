//! Composite key scheme for fjall keyspaces.
//!
//! Key design decision: delegations are one-to-many per node. A single node
//! can hold multiple concurrently-valid `DelegatedSigningKey`s (one per
//! workload it hosts). This requires efficient range-scan by `node_id` prefix.
//!
//! Key layout: `node_id || delegation_id`
//!   - Prefix scan by `node_id` retrieves all delegations for a node.
//!   - Exact lookup by full key for individual delegation operations.

use fleetos_core::spiffe::SpiffeId;

/// Size of a serialized `SpiffeId` used as a node identifier prefix.
pub const SPIFFE_ID_LEN_SIZE: usize = 2;

/// Build a composite key: `node_id || delegation_id`.
pub fn composite_delegation_key(node_id: &SpiffeId, delegation_id: &str) -> Vec<u8> {
    let node_bytes = node_id.to_string();
    let node_len = node_bytes.len() as u16;

    let mut key = Vec::with_capacity(SPIFFE_ID_LEN_SIZE + node_bytes.len() + delegation_id.len());
    key.extend_from_slice(&node_len.to_le_bytes());
    key.extend_from_slice(node_bytes.as_bytes());
    key.extend_from_slice(delegation_id.as_bytes());
    key
}

/// Build just the prefix for range-scanning all delegations belonging to a node.
pub fn node_delegation_prefix(node_id: &SpiffeId) -> Vec<u8> {
    let node_bytes = node_id.to_string();
    let node_len = node_bytes.len() as u16;

    let mut prefix = Vec::with_capacity(SPIFFE_ID_LEN_SIZE + node_bytes.len());
    prefix.extend_from_slice(&node_len.to_le_bytes());
    prefix.extend_from_slice(node_bytes.as_bytes());
    prefix
}

/// Extract the `node_id` prefix length from a composite key.
pub fn node_prefix_len(key: &[u8]) -> Option<usize> {
    if key.len() < SPIFFE_ID_LEN_SIZE {
        return None;
    }
    let node_len = u16::from_le_bytes([key[0], key[1]]) as usize;
    Some(SPIFFE_ID_LEN_SIZE + node_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_key_roundtrip() {
        let node_id: SpiffeId = "spiffe://fleet.example.internal/ns/system/control/node-1"
            .parse()
            .unwrap();
        let delegation_id = "delegation-abc-123";

        let key = composite_delegation_key(&node_id, delegation_id);
        let prefix = node_delegation_prefix(&node_id);

        assert!(key.starts_with(&prefix));
        let prefix_len = node_prefix_len(&key).unwrap();
        assert_eq!(prefix_len, prefix.len());
    }
}
