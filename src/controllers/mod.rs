//! Controllers — leader-gated reconciliation loops.
//!
//! Controllers run only on the Raft leader node. They watch desired state
//! (WorkloadSpec, node registry, placements) and drive actual state to match.
//!
//! Three controllers:
//! - `workload_controller`: Expands WorkloadSpec into PodSpecs, drives UpdateStrategy
//! - `pod_controller`: Per-ordinal reconciliation, replace-in-place semantics
//! - `node_controller`: Node lifecycle, eviction, delegation revocation
//!
//! All controllers are leader-gated: they only run when this node is the Raft leader.
//! When leadership is lost, all controller tasks are cancelled.

pub mod cron_controller;
pub mod leader;
pub mod node_controller;
pub mod pod_controller;
pub mod workload_controller;

pub use cron_controller::CronController;
pub use workload_controller::WorkloadController;

use thiserror::Error;

/// Errors from controller operations.
#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),

    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("scheduler error: {0}")]
    Scheduler(#[from] crate::scheduler::SchedulerError),

    #[error("delegation error: {0}")]
    Delegation(#[from] crate::delegation::DelegationError),

    #[error("policy error: {0}")]
    Policy(#[from] crate::policy::PolicyError),

    #[error("raft error: {0}")]
    Raft(String),

    #[error("not leader")]
    NotLeader,
}

/// Controller task handle.
///
/// When leadership is lost, the handle is dropped and the task is cancelled.
pub struct ControllerHandle {
    task: tokio::task::JoinHandle<()>,
}

impl ControllerHandle {
    pub fn new(task: tokio::task::JoinHandle<()>) -> Self {
        Self { task }
    }

    /// Cancel the controller task.
    pub fn cancel(self) {
        self.task.abort();
    }
}

impl Drop for ControllerHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}
