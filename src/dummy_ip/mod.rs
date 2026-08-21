//! Dummy IP allocation — `240.0.0.0/4` space.
//!
//! FleetOS workloads dial "dummy IPs" that map to SPIFFE URIs. These come from
//! the `240.0.0.0/4` reserved space (Class E, never routed on the public internet).
//!
//! Allocation model:
//! - Per-tenant blocks allocated on tenant creation (default `/16`).
//! - Per-service addresses allocated within a tenant's block as services register
//!   (one IP per `(service, role)` pair).
//! - All allocation state is Raft-replicated.
//!
//! **Sizing (locked):** `240.0.0.0/4` = `2^28` (~268M) addresses. A `/16` per tenant
//! (65,536 addresses) supports up to 4,096 tenants. Do NOT default to `/8` — that
//! exhausts the entire space after only 16 tenants.

pub mod allocator;

use thiserror::Error;

/// Errors from dummy IP allocation.
#[derive(Debug, Error)]
pub enum DummyIpError {
    #[error("address space exhausted: cannot allocate tenant block")]
    TenantSpaceExhausted,

    #[error("tenant block exhausted for {0}: cannot allocate service address")]
    ServiceSpaceExhausted(String),

    #[error("tenant not found: {0}")]
    TenantNotFound(String),

    #[error("tenant already has a block: {0}")]
    TenantAlreadyAllocated(String),

    #[error("invalid prefix length: {0} (must be > 4 and <= 32)")]
    InvalidPrefixLength(u8),

    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),

    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),
}
