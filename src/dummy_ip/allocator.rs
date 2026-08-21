//! Allocates dummy IPs from the `240.0.0.0/4` space.
//!
//! Two-level allocation:
//! 1. **Tenant block:** each tenant gets a `/16` (configurable) carved from the `/4`.
//! 2. **Service address:** each `(service, role)` pair gets one IP from the tenant's block.
//!
//! NOTE: the `tenant_block_prefix` must remain stable for the lifetime of the cluster.
//! Changing it after tenants have been allocated invalidates block-index recovery.
//! In the full system, all mutations here are applied via the Raft state machine for
//! cross-node atomicity.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use fjall::Keyspace;

use super::DummyIpError;

/// Base of the dummy IP space: `240.0.0.0`.
const DUMMY_SPACE_BASE: u32 = 0xF000_0000;
/// Prefix of the dummy IP space: `/4`.
const DUMMY_SPACE_PREFIX: u8 = 4;

/// Default per-tenant block prefix: `/16`.
///
/// Do NOT use `/8` — that exhausts the `240.0.0.0/4` space after 16 tenants.
/// `/16` (65,536 addresses) supports up to 4,096 tenants, which is generous
/// headroom since a tenant realistically needs one dummy IP per `(service, role)` pair.
pub const DEFAULT_TENANT_BLOCK_PREFIX: u8 = 16;

/// Key prefix for tenant block records.
const TENANT_KEY_PREFIX: &str = "tenant:";
/// Key prefix for service address records.
const SERVICE_KEY_PREFIX: &str = "service:";

/// A tenant's allocated block.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TenantBlock {
    pub tenant_id: String,
    /// Base address of the block (as `u32`).
    pub base: u32,
    /// Prefix length of the block.
    pub prefix: u8,
    /// Next available host offset within the block.
    pub next_offset: u32,
}

impl TenantBlock {
    /// Number of addresses in the block.
    pub fn max_hosts(&self) -> u32 {
        1u32 << (32 - self.prefix)
    }
}

/// A service address assignment: one dummy IP per `(tenant, service, role)`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceAddress {
    pub tenant_id: String,
    pub service: String,
    pub role: String,
    /// The allocated dummy IP (as `u32`).
    pub address: u32,
}

impl ServiceAddress {
    pub fn ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.address)
    }
}

/// Allocates dummy IPs from the `240.0.0.0/4` space.
pub struct DummyIpAllocator {
    keyspace: Keyspace,
    tenant_block_prefix: u8,
}

impl DummyIpAllocator {
    pub fn new(keyspace: Keyspace, tenant_block_prefix: u8) -> Result<Self, DummyIpError> {
        if tenant_block_prefix <= DUMMY_SPACE_PREFIX || tenant_block_prefix > 32 {
            return Err(DummyIpError::InvalidPrefixLength(tenant_block_prefix));
        }
        Ok(Self {
            keyspace,
            tenant_block_prefix,
        })
    }

    /// Maximum number of tenant blocks that fit in the `/4` space.
    fn max_tenant_blocks(&self) -> u32 {
        1u32 << (self.tenant_block_prefix - DUMMY_SPACE_PREFIX)
    }

    /// Compute the base address for a given block index.
    fn block_base(&self, block_index: u32) -> u32 {
        let host_bits = 32 - self.tenant_block_prefix;
        DUMMY_SPACE_BASE.wrapping_add(block_index << host_bits)
    }

    /// Collect all currently-used block indices.
    fn used_block_indices(&self) -> Result<BTreeSet<u32>, DummyIpError> {
        let mut used = BTreeSet::new();

        // prefix() yields Guard items directly; Guard::value() moves the guard.
        for guard in self.keyspace.prefix(TENANT_KEY_PREFIX.as_bytes()) {
            let value = guard
                .value()
                .map_err(|e| DummyIpError::Storage(crate::storage::StorageError::Storage(e)))?;

            if let Ok(block) = postcard::from_bytes::<TenantBlock>(value.as_ref()) {
                // Recover block index from the stored base address.
                let host_bits = 32 - self.tenant_block_prefix;
                let index = (block.base - DUMMY_SPACE_BASE) >> host_bits;
                used.insert(index);
            }
        }

        Ok(used)
    }

    /// Allocate a block for a new tenant.
    pub fn allocate_tenant_block(&self, tenant_id: &str) -> Result<TenantBlock, DummyIpError> {
        // Idempotency guard: a tenant gets exactly one block.
        if self.get_tenant_block(tenant_id)?.is_some() {
            return Err(DummyIpError::TenantAlreadyAllocated(tenant_id.to_owned()));
        }

        // Find the first free block index (handles gaps from deleted tenants).
        let used = self.used_block_indices()?;
        let max_blocks = self.max_tenant_blocks();
        let block_index = (0..max_blocks)
            .find(|i| !used.contains(i))
            .ok_or(DummyIpError::TenantSpaceExhausted)?;

        let block = TenantBlock {
            tenant_id: tenant_id.to_owned(),
            base: self.block_base(block_index),
            prefix: self.tenant_block_prefix,
            next_offset: 0,
        };

        // Persist.
        let key = format!("{}{}", TENANT_KEY_PREFIX, tenant_id);
        let serialized = postcard::to_allocvec(&block).map_err(DummyIpError::Serialization)?;
        self.keyspace
            .insert(key.as_bytes(), serialized.as_slice())
            .map_err(|e| DummyIpError::Storage(crate::storage::StorageError::Storage(e)))?;

        tracing::info!(
            tenant_id = %tenant_id,
            base = %Ipv4Addr::from(block.base),
            prefix = block.prefix,
            "allocated tenant dummy-IP block"
        );

        Ok(block)
    }

    /// Get a tenant's block.
    pub fn get_tenant_block(&self, tenant_id: &str) -> Result<Option<TenantBlock>, DummyIpError> {
        let key = format!("{}{}", TENANT_KEY_PREFIX, tenant_id);
        match self
            .keyspace
            .get(key.as_bytes())
            .map_err(|e| DummyIpError::Storage(crate::storage::StorageError::Storage(e)))?
        {
            Some(bytes) => {
                let block: TenantBlock =
                    postcard::from_bytes(&bytes).map_err(DummyIpError::Serialization)?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Allocate a dummy IP for a `(tenant, service, role)` tuple.
    ///
    /// Idempotent: if the tuple already has an address, returns the existing one.
    pub fn allocate_service_address(
        &self,
        tenant_id: &str,
        service: &str,
        role: &str,
    ) -> Result<ServiceAddress, DummyIpError> {
        // Idempotency: return existing assignment if present.
        if let Some(existing) = self.get_service_address(tenant_id, service, role)? {
            return Ok(existing);
        }

        // Load the tenant's block.
        let mut block = self
            .get_tenant_block(tenant_id)?
            .ok_or_else(|| DummyIpError::TenantNotFound(tenant_id.to_owned()))?;

        // Check the block isn't exhausted.
        if block.next_offset >= block.max_hosts() {
            return Err(DummyIpError::ServiceSpaceExhausted(tenant_id.to_owned()));
        }

        let address = block.base + block.next_offset;
        block.next_offset += 1;

        // Persist updated block (next_offset incremented).
        let tenant_key = format!("{}{}", TENANT_KEY_PREFIX, tenant_id);
        let block_serialized =
            postcard::to_allocvec(&block).map_err(DummyIpError::Serialization)?;
        self.keyspace
            .insert(tenant_key.as_bytes(), block_serialized.as_slice())
            .map_err(|e| DummyIpError::Storage(crate::storage::StorageError::Storage(e)))?;

        // Persist the service address assignment.
        let assignment = ServiceAddress {
            tenant_id: tenant_id.to_owned(),
            service: service.to_owned(),
            role: role.to_owned(),
            address,
        };
        let service_key = format!("{}{}:{}:{}", SERVICE_KEY_PREFIX, tenant_id, service, role);
        let assignment_serialized =
            postcard::to_allocvec(&assignment).map_err(DummyIpError::Serialization)?;
        self.keyspace
            .insert(service_key.as_bytes(), assignment_serialized.as_slice())
            .map_err(|e| DummyIpError::Storage(crate::storage::StorageError::Storage(e)))?;

        tracing::debug!(
            tenant_id = %tenant_id,
            service = %service,
            role = %role,
            address = %assignment.ip(),
            "allocated service dummy IP"
        );

        Ok(assignment)
    }

    /// Get a service address assignment.
    pub fn get_service_address(
        &self,
        tenant_id: &str,
        service: &str,
        role: &str,
    ) -> Result<Option<ServiceAddress>, DummyIpError> {
        let key = format!("{}{}:{}:{}", SERVICE_KEY_PREFIX, tenant_id, service, role);
        match self
            .keyspace
            .get(key.as_bytes())
            .map_err(|e| DummyIpError::Storage(crate::storage::StorageError::Storage(e)))?
        {
            Some(bytes) => {
                let assignment: ServiceAddress =
                    postcard::from_bytes(&bytes).map_err(DummyIpError::Serialization)?;
                Ok(Some(assignment))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_base_computation() {
        // For /16 blocks in a /4 space:
        // block 0 → 240.0.0.0, block 1 → 240.1.0.0
        let host_bits = 32 - 16;
        let base0 = DUMMY_SPACE_BASE + (0u32 << host_bits);
        let base1 = DUMMY_SPACE_BASE + (1u32 << host_bits);

        assert_eq!(Ipv4Addr::from(base0), Ipv4Addr::new(240, 0, 0, 0));
        assert_eq!(Ipv4Addr::from(base1), Ipv4Addr::new(240, 1, 0, 0));
    }

    #[test]
    fn default_prefix_is_16_not_8() {
        // Regression guard: /8 exhausts the /4 space after 16 tenants.
        assert_eq!(DEFAULT_TENANT_BLOCK_PREFIX, 16);

        let max_at_16 = 1u32 << (16 - DUMMY_SPACE_PREFIX);
        let max_at_8 = 1u32 << (8 - DUMMY_SPACE_PREFIX);
        assert_eq!(max_at_16, 4096);
        assert_eq!(max_at_8, 16); // The bug we explicitly avoid.
    }

    #[test]
    fn max_hosts_for_16() {
        let block = TenantBlock {
            tenant_id: "t".to_owned(),
            base: DUMMY_SPACE_BASE,
            prefix: 16,
            next_offset: 0,
        };
        assert_eq!(block.max_hosts(), 65_536);
    }
}
