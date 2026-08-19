// SPDX-License-Identifier: Apache-2.0
//! Composite key scheme for redb tables.
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
/// SpiffeId is variable-length UTF-8; we length-prefix it for composite keys.
pub const SPIFFE_ID_LEN_SIZE: usize = 2; // u16 length prefix

/// Build a composite key: `node_id || delegation_id`.
///
/// Format: `[node_id_len: u16][node_id: UTF-8 bytes][delegation_id: UTF-8 bytes]`
///
/// This supports:
///   - Exact lookup: full key match
///   - Range scan by node: prefix match on `[node_id_len][node_id]`
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
///
/// Format: `[node_id_len: u16][node_id: UTF-8 bytes]`
pub fn node_delegation_prefix(node_id: &SpiffeId) -> Vec<u8> {
    let node_bytes = node_id.to_string();
    let node_len = node_bytes.len() as u16;

    let mut prefix = Vec::with_capacity(SPIFFE_ID_LEN_SIZE + node_bytes.len());
    prefix.extend_from_slice(&node_len.to_le_bytes());
    prefix.extend_from_slice(node_bytes.as_bytes());
    prefix
}

/// Extract the `node_id` prefix length from a composite key (for validation).
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

        // Composite key starts with the node prefix.
        assert!(key.starts_with(&prefix));

        // Prefix length is correct.
        let prefix_len = node_prefix_len(&key).unwrap();
        assert_eq!(prefix_len, prefix.len());
    }

    #[test]
    fn prefix_scan_isolates_nodes() {
        let node_a: SpiffeId = "spiffe://fleet.example.internal/ns/system/control/node-a"
            .parse()
            .unwrap();
        let node_b: SpiffeId = "spiffe://fleet.example.internal/ns/system/control/node-b"
            .parse()
            .unwrap();

        let key_a = composite_delegation_key(&node_a, "del-1");
        let key_b = composite_delegation_key(&node_b, "del-1");
        let prefix_a = node_delegation_prefix(&node_a);

        assert!(key_a.starts_with(&prefix_a));
        assert!(!key_b.starts_with(&prefix_a));
    }
}
