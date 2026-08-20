//! PCR policy management.
//!
//! PCR policies define the expected firmware + bootloader + kernel measurements
//! for each node. Operators configure expected PCR values per fleet.
//!
//! Stored per-node in fjall, keyed by node SPIFFE ID.

use fjall::Keyspace;

use super::AttestationError;
use super::tpm::PcrValue;

/// A PCR policy for a specific node.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PcrPolicy {
    /// The node this policy applies to.
    pub node_id: String,

    /// Expected PCR values (index → digest).
    pub expected_pcrs: Vec<PcrValue>,

    /// When this policy was last updated.
    pub updated_at: i64,

    /// Whether this policy is currently active.
    pub active: bool,
}

/// Manages PCR policy storage.
pub struct PcrPolicyStore {
    keyspace: Keyspace,
}

impl PcrPolicyStore {
    pub fn new(keyspace: Keyspace) -> Self {
        Self { keyspace }
    }

    /// Store or update a PCR policy for a node.
    pub fn set_policy(&self, policy: &PcrPolicy) -> Result<(), AttestationError> {
        let serialized = postcard::to_allocvec(policy).map_err(AttestationError::Serialization)?;
        self.keyspace
            .insert(policy.node_id.as_bytes(), serialized.as_slice())
            .map_err(|e| AttestationError::Storage(crate::storage::StorageError::Storage(e)))?;
        Ok(())
    }

    /// Get the PCR policy for a node.
    pub fn get_policy(&self, node_id: &str) -> Result<Option<PcrPolicy>, AttestationError> {
        match self
            .keyspace
            .get(node_id.as_bytes())
            .map_err(|e| AttestationError::Storage(crate::storage::StorageError::Storage(e)))?
        {
            Some(bytes) => {
                let policy: PcrPolicy =
                    postcard::from_bytes(&bytes).map_err(AttestationError::Serialization)?;
                Ok(Some(policy))
            }
            None => Ok(None),
        }
    }

    /// Get the expected PCR values for a node.
    ///
    /// Returns None if no policy exists (node attestation will fail
    /// unless a default policy is configured).
    pub fn get_expected_pcrs(
        &self,
        node_id: &str,
    ) -> Result<Option<Vec<PcrValue>>, AttestationError> {
        match self.get_policy(node_id)? {
            Some(policy) if policy.active => Ok(Some(policy.expected_pcrs)),
            _ => Ok(None),
        }
    }

    /// Delete a PCR policy for a node.
    pub fn delete_policy(&self, node_id: &str) -> Result<(), AttestationError> {
        self.keyspace
            .remove(node_id.as_bytes())
            .map_err(|e| AttestationError::Storage(crate::storage::StorageError::Storage(e)))?;
        Ok(())
    }
}
