// SPDX-License-Identifier: Apache-2.0

//! Centralized re-exports of all protobuf-generated types consumed by this crate.
//!
//! All proto types are generated inside `fleetos-core` and consumed identically
//! by both `fleetos-control` and `fleetos-agent`. Never define duplicate message
//! types here.

// --- Admin overlay (gated to `ctrl` SVID kind) ---
pub use fleetos_core::proto::admin;

// --- Data/Control overlay ---
pub use fleetos_core::proto::identity;
pub use fleetos_core::proto::secret;
pub use fleetos_core::proto::state;
pub use fleetos_core::proto::workload;

// --- Provisioning (outbound client) ---
pub use fleetos_core::proto::provisioning;
