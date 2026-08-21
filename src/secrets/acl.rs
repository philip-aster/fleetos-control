//! SPIFFE-ID authorization matrix for secrets.
//!
//! The ACL is checked BEFORE either encryption layer (at-rest or delivery) is
//! touched. A SpiffeId not in the ACL for a given secret is denied access
//! regardless of whether it holds a valid SVID.
//!
//! SpiffeIds are stored as their canonical string form (`spiffe://...`) to avoid
//! depending on `SpiffeId` implementing `Ord`/`Hash`. String comparison is safe
//! because `SpiffeId`'s `Display` produces a canonical form.

use std::collections::{BTreeMap, BTreeSet};

use fleetos_core::spiffe::SpiffeId;

use super::SecretError;

/// The secret authorization matrix.
///
/// Maps `secret_key` → set of authorized SpiffeIds (as canonical strings).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SecretAcl {
    entries: BTreeMap<String, BTreeSet<String>>,
}

impl SecretAcl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant a SpiffeId access to a secret.
    pub fn grant(&mut self, secret_key: &str, spiffe_id: &SpiffeId) {
        self.entries
            .entry(secret_key.to_owned())
            .or_default()
            .insert(spiffe_id.to_string());
    }

    /// Revoke a SpiffeId's access to a secret.
    pub fn revoke(&mut self, secret_key: &str, spiffe_id: &SpiffeId) {
        if let Some(set) = self.entries.get_mut(secret_key) {
            set.remove(&spiffe_id.to_string());
            if set.is_empty() {
                self.entries.remove(secret_key);
            }
        }
    }

    /// Check if a SpiffeId is authorized to access a secret.
    pub fn is_authorized(&self, secret_key: &str, spiffe_id: &SpiffeId) -> bool {
        self.entries
            .get(secret_key)
            .map(|set| set.contains(&spiffe_id.to_string()))
            .unwrap_or(false)
    }

    /// Authorize access, returning an error if denied.
    pub fn authorize(&self, secret_key: &str, spiffe_id: &SpiffeId) -> Result<(), SecretError> {
        if self.is_authorized(secret_key, spiffe_id) {
            Ok(())
        } else {
            Err(SecretError::AccessDenied {
                secret_key: secret_key.to_owned(),
                spiffe_id: spiffe_id.to_string(),
            })
        }
    }

    /// List all SpiffeIds authorized for a secret (as canonical strings).
    pub fn authorized_for(&self, secret_key: &str) -> Vec<String> {
        self.entries
            .get(secret_key)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spiffe(s: &str) -> SpiffeId {
        s.parse().unwrap()
    }

    #[test]
    fn granted_id_is_authorized() {
        let mut acl = SecretAcl::new();
        let id = spiffe("spiffe://fleet.example.internal/ns/system/node/agent-1");

        acl.grant("db-password", &id);
        assert!(acl.is_authorized("db-password", &id));
    }

    #[test]
    fn ungranted_id_is_denied() {
        let acl = SecretAcl::new();
        let id = spiffe("spiffe://fleet.example.internal/ns/system/node/agent-1");

        assert!(!acl.is_authorized("db-password", &id));
    }

    #[test]
    fn revoked_id_is_denied() {
        let mut acl = SecretAcl::new();
        let id = spiffe("spiffe://fleet.example.internal/ns/system/node/agent-1");

        acl.grant("db-password", &id);
        acl.revoke("db-password", &id);
        assert!(!acl.is_authorized("db-password", &id));
    }

    #[test]
    fn authorize_returns_error_when_denied() {
        let acl = SecretAcl::new();
        let id = spiffe("spiffe://fleet.example.internal/ns/system/node/agent-1");

        let result = acl.authorize("db-password", &id);
        assert!(matches!(result, Err(SecretError::AccessDenied { .. })));
    }
}
