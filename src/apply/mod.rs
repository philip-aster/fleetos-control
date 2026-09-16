//! Declarative server-side apply (CR-CTRL-10).
//!
//! Implements three-way merge semantics for FleetOS manifests. This module
//! bridges the gap between the imperative RPC surface and the declarative
//! `fleetctl apply` workflow, enabling idempotent reconciliation and
//! conflict detection.

pub mod merge;

pub use merge::{MergeOutcome, merge_workload};
