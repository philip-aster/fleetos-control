//! DelegationId derivation.
//!
//! `DelegationId` is deterministically derived from:
//! - `node_id`: The node holding the delegation
//! - `target_svid_id`: The workload SVID this key can renew
//! - `target_ordinal`: The ordinal of the target workload
//! - `issued_at`: Timestamp when the delegation was issued
//!
//! This means a single node can hold multiple concurrently-valid delegations
//! (one per workload it hosts), each with a unique `DelegationId`.

use time::OffsetDateTime;

use super::DelegationError;

/// Compute a `DelegationId` from its constituent parts.
///
/// Format: `{node_id}:{target_svid_id}:{target_ordinal}:{issued_at}`
///
/// The `DelegationId` type itself is defined in `fleetos-core`. This function
/// computes the string that will be parsed into that type.
pub fn compute_delegation_id(
    node_id: &str,
    target_svid_id: &str,
    target_ordinal: Option<u32>,
    issued_at: OffsetDateTime,
) -> Result<String, DelegationError> {
    let ordinal_str = target_ordinal
        .map(|o| o.to_string())
        .unwrap_or_else(|| "none".to_owned());

    let id = format!(
        "{}:{}:{}:{}",
        node_id,
        target_svid_id,
        ordinal_str,
        issued_at.unix_timestamp()
    );

    Ok(id)
}

/// Parse a `DelegationId` string back into its constituent parts.
///
/// Returns `(node_id, target_svid_id, target_ordinal, issued_at)`.
pub fn parse_delegation_id(
    delegation_id: &str,
) -> Result<(String, String, Option<u32>, i64), DelegationError> {
    let parts: Vec<&str> = delegation_id.split(':').collect();
    if parts.len() != 4 {
        return Err(DelegationError::IdComputation(format!(
            "invalid delegation ID format: expected 4 colon-separated parts, got {}",
            parts.len()
        )));
    }

    let node_id = parts[0].to_owned();
    let target_svid_id = parts[1].to_owned();

    let target_ordinal = if parts[2] == "none" {
        None
    } else {
        parts[2].parse::<u32>().map(Some).map_err(|_| {
            DelegationError::IdComputation(format!(
                "invalid ordinal in delegation ID: {}",
                parts[2]
            ))
        })?
    };

    let issued_at = parts[3].parse::<i64>().map_err(|_| {
        DelegationError::IdComputation(format!("invalid timestamp in delegation ID: {}", parts[3]))
    })?;

    Ok((node_id, target_svid_id, target_ordinal, issued_at))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_and_parse_roundtrip() {
        let node_id = "spiffe://fleet.example.internal/ns/system/node/agent-1";
        let target_svid_id = "spiffe://fleet.example.internal/ns/my-tenant/sa/my-service";
        let target_ordinal = Some(2);
        let issued_at = OffsetDateTime::now_utc();

        let id = compute_delegation_id(node_id, target_svid_id, target_ordinal, issued_at).unwrap();
        let (parsed_node, parsed_svid, parsed_ordinal, parsed_time) =
            parse_delegation_id(&id).unwrap();

        assert_eq!(parsed_node, node_id);
        assert_eq!(parsed_svid, target_svid_id);
        assert_eq!(parsed_ordinal, target_ordinal);
        assert_eq!(parsed_time, issued_at.unix_timestamp());
    }

    #[test]
    fn compute_without_ordinal() {
        let node_id = "spiffe://fleet.example.internal/ns/system/node/agent-1";
        let target_svid_id = "spiffe://fleet.example.internal/ns/my-tenant/sa/my-service";
        let issued_at = OffsetDateTime::now_utc();

        let id = compute_delegation_id(node_id, target_svid_id, None, issued_at).unwrap();
        assert!(id.contains(":none:"));

        let (_, _, parsed_ordinal, _) = parse_delegation_id(&id).unwrap();
        assert_eq!(parsed_ordinal, None);
    }
}
