//! Delegation revocation management.

use fjall::Keyspace;

use super::{DelegationError, DelegationRecord};
use crate::storage::schema;
use fleetos_core::spiffe::SpiffeId;

/// Manages delegation revocation.
pub struct DelegationRevocationStore {
    active_keyspace: Keyspace,
    revoked_keyspace: Keyspace,
}

impl DelegationRevocationStore {
    pub fn new(active_keyspace: Keyspace, revoked_keyspace: Keyspace) -> Self {
        Self {
            active_keyspace,
            revoked_keyspace,
        }
    }

    /// Record a new active delegation.
    pub fn record_active(&self, record: &DelegationRecord) -> Result<(), DelegationError> {
        // Direct access to node_id now that SpiffeId is natively serializable
        let key = schema::composite_delegation_key(&record.node_id, &record.delegation_id);
        let serialized = postcard::to_allocvec(record).map_err(DelegationError::Serialization)?;

        self.active_keyspace
            .insert(key.as_slice(), serialized.as_slice())
            .map_err(|e| DelegationError::Storage(crate::storage::StorageError::Storage(e)))?;

        Ok(())
    }

    /// Revoke a specific delegation.
    pub fn revoke(&self, node_id: &SpiffeId, delegation_id: &str) -> Result<(), DelegationError> {
        let key = schema::composite_delegation_key(node_id, delegation_id);

        // Read the record first (for the revoked table).
        let record_bytes = self
            .active_keyspace
            .get(key.as_slice())
            .map_err(|e| DelegationError::Storage(crate::storage::StorageError::Storage(e)))?
            .ok_or_else(|| DelegationError::NotFound(delegation_id.to_owned()))?;

        let record: DelegationRecord =
            postcard::from_bytes(&record_bytes).map_err(DelegationError::Serialization)?;

        // Remove from active.
        self.active_keyspace
            .remove(key.as_slice())
            .map_err(|e| DelegationError::Storage(crate::storage::StorageError::Storage(e)))?;

        // Add to revoked with expiry timestamp.
        let revoked_key = schema::composite_delegation_key(node_id, delegation_id);
        let serialized = postcard::to_allocvec(&record).map_err(DelegationError::Serialization)?;

        self.revoked_keyspace
            .insert(revoked_key.as_slice(), serialized.as_slice())
            .map_err(|e| DelegationError::Storage(crate::storage::StorageError::Storage(e)))?;

        tracing::info!(
            node_id = %node_id,
            delegation_id = %delegation_id,
            "delegation revoked"
        );

        Ok(())
    }

    /// Revoke all delegations for a node (one-to-many).
    pub fn revoke_all_for_node(&self, node_id: &SpiffeId) -> Result<Vec<String>, DelegationError> {
        let prefix = schema::node_delegation_prefix(node_id);
        let mut revoked_ids = Vec::new();

        // Collect all delegation IDs for this node via prefix scan.
        let mut delegation_ids = Vec::new();
        for guard in self.active_keyspace.prefix(prefix.as_slice()) {
            let key_slice = guard
                .key()
                .map_err(|e| DelegationError::Storage(crate::storage::StorageError::Storage(e)))?;
            let key_bytes: &[u8] = key_slice.as_ref();

            // Extract delegation_id from composite key (after node_id prefix).
            if let Some(prefix_len) = schema::node_prefix_len(key_bytes) {
                if key_bytes.len() > prefix_len {
                    let delegation_id =
                        String::from_utf8_lossy(&key_bytes[prefix_len..]).to_string();
                    delegation_ids.push(delegation_id);
                }
            }
        }

        // Revoke each delegation.
        for delegation_id in delegation_ids {
            self.revoke(node_id, &delegation_id)?;
            revoked_ids.push(delegation_id);
        }

        tracing::info!(
            node_id = %node_id,
            count = revoked_ids.len(),
            "revoked all delegations for node"
        );

        Ok(revoked_ids)
    }

    /// Get the full set of currently-revoked delegation IDs.
    pub fn get_revoked_set(&self) -> Result<Vec<String>, DelegationError> {
        let mut revoked = Vec::new();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        for guard in self.revoked_keyspace.prefix(Vec::<u8>::new()) {
            let value = guard
                .value()
                .map_err(|e| DelegationError::Storage(crate::storage::StorageError::Storage(e)))?;

            if let Ok(record) = postcard::from_bytes::<DelegationRecord>(value.as_ref()) {
                if record.expires_at > now {
                    revoked.push(record.delegation_id);
                }
            }
        }

        Ok(revoked)
    }

    /// Clean up expired revocations (older than 4 hours).
    ///
    /// Called periodically to prevent unbounded growth of the revoked set.
    pub fn cleanup_expired_revocations(&self) -> Result<usize, DelegationError> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut keys_to_remove = Vec::new();

        for guard in self.revoked_keyspace.prefix(Vec::<u8>::new()) {
            // .value() moves the guard, so only access it once.
            let value = guard
                .value()
                .map_err(|e| DelegationError::Storage(crate::storage::StorageError::Storage(e)))?;

            if let Ok(record) = postcard::from_bytes::<DelegationRecord>(value.as_ref()) {
                if record.expires_at <= now {
                    // Reconstruct the composite key from the record's own fields
                    // instead of calling guard.key() (which would be a use-after-move).
                    let key =
                        schema::composite_delegation_key(&record.node_id, &record.delegation_id);
                    keys_to_remove.push(key);
                }
            }
        }

        for key in &keys_to_remove {
            self.revoked_keyspace
                .remove(key.as_slice())
                .map_err(|e| DelegationError::Storage(crate::storage::StorageError::Storage(e)))?;
        }

        tracing::debug!(
            count = keys_to_remove.len(),
            "cleaned up expired revocations"
        );

        Ok(keys_to_remove.len())
    }
}
