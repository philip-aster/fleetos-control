//! SAG Policy Compiler — Module 4.
//!
//! Compiles admin-defined intent (`SagRule`) into kernel-enforceable eBPF map entries.
//!
//! **CRITICAL (Part 0):** This module MUST use `IdentityFingerprint::of(id, role)` —
//! the role-only constructor — as the only sanctioned fingerprint path.
//! `of_with_ordinal` MUST NOT appear anywhere in this crate. Using it would silently
//! convert a load-balanced replica pool into N independently unreachable identities.
//!
//! Two-tier compilation:
//! - `protocol: None` or `port: None` → `POLICY_WILDCARD`
//!   (keyed on 32-byte `EbpfPolicyWildcardKey`: src + dst fingerprints only)
//! - Both specified → `POLICY_EXACT`
//!   (keyed on full 40-byte `EbpfPolicyKey`: fingerprints + protocol + port)
//!
//! Precedence (highest to lowest):
//! 1. Default Deny (no rule = drop) — implicit, never represented as an entry
//! 2. Explicit `SagAction::Deny` always overrides `Allow`
//! 3. `POLICY_EXACT` wins over `POLICY_WILDCARD` on agent-side lookup
//! 4. `SagAction::Allow`

pub mod compiler;
pub mod fingerprint;
pub mod port_validation;
pub mod precedence;
pub mod staleness;

use thiserror::Error;

/// Errors from SAG policy compilation.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("port value {0} exceeds valid u16 range (max 65535)")]
    PortOutOfRange(u32),

    #[error("invalid protocol value: {0}")]
    InvalidProtocol(u8),

    #[error("fingerprint computation failed: {0}")]
    Fingerprint(String),

    #[error("rule compilation failed: {0}")]
    Compilation(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),
}

/// The decision encoded in `EbpfPolicyValue.decision`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Deny = 0,
    Allow = 1,
}

impl PolicyDecision {
    pub fn from_raw(value: u8) -> Self {
        match value {
            1 => PolicyDecision::Allow,
            _ => PolicyDecision::Deny,
        }
    }

    pub fn to_raw(self) -> u8 {
        self as u8
    }
}

/// A compiled policy entry, ready for eBPF map insertion.
///
/// Stores raw `[u8; 16]` fingerprint bytes (not `IdentityFingerprint`)
/// because `IdentityFingerprint` does not implement serde traits.
/// Conversion to `IdentityFingerprint` happens in `compiler.rs` when
/// constructing the actual eBPF structs for streaming to agents.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CompiledPolicyEntry {
    Wildcard {
        src_fingerprint: [u8; 16],
        dst_fingerprint: [u8; 16],
        decision: u8,
        sag_version: u64,
    },
    Exact {
        src_fingerprint: [u8; 16],
        dst_fingerprint: [u8; 16],
        protocol: u8,
        dst_port: u16,
        decision: u8,
        sag_version: u64,
    },
}

/// The full compiled policy set for a cluster, at a specific version.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompiledPolicySet {
    pub version: u64,
    pub entries: Vec<CompiledPolicyEntry>,
    pub wildcard_count: usize,
    pub exact_count: usize,
}
