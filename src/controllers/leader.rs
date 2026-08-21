//! Leader gating for controllers.
//!
//! Controllers only run on the Raft leader. This module provides the
//! infrastructure to start/stop controllers based on leadership changes.

use std::sync::Arc;

use openraft::Raft;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::raft::FleetosRaftConfig;

/// Monitors Raft leadership and gates controller execution.
///
/// When this node becomes leader, all controllers are started.
/// When leadership is lost, all controllers are stopped.
pub struct LeaderGate {
    raft: Raft<FleetosRaftConfig>,
}

impl LeaderGate {
    pub fn new(raft: Raft<FleetosRaftConfig>) -> Self {
        Self { raft }
    }

    /// Run the leader gate loop.
    ///
    /// This task runs for the lifetime of the process. It watches the Raft
    /// metrics channel for leadership changes and starts/stops controllers
    /// accordingly.
    pub async fn run(
        self,
        controller_factory: Arc<dyn ControllerFactory>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut metrics_rx = self.raft.metrics();
        let mut active_controllers: JoinSet<()> = JoinSet::new();
        let mut is_leader = false;

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("shutdown signal received, stopping all controllers");
                        active_controllers.shutdown().await;
                        return;
                    }
                }
                metrics = metrics_rx.changed() => {
                    if metrics.is_err() {
                        tracing::error!("Raft metrics channel closed");
                        active_controllers.shutdown().await;
                        return;
                    }

                    let metrics = metrics_rx.borrow();
                    let currently_leader = metrics.state == openraft::ServerState::Leader;

                    if currently_leader && !is_leader {
                        // Became leader — start all controllers
                        tracing::info!("became Raft leader, starting controllers");
                        is_leader = true;
                        controller_factory.start_controllers(&mut active_controllers);
                    } else if !currently_leader && is_leader {
                        // Lost leadership — stop all controllers
                        tracing::info!("lost Raft leadership, stopping controllers");
                        is_leader = false;
                        active_controllers.shutdown().await;
                    }
                }
            }
        }
    }
}

/// Factory for creating controller tasks.
///
/// Implemented by the main application to wire up all controllers with
/// their dependencies (storage, scheduler, broadcast hub, etc.).
pub trait ControllerFactory: Send + Sync {
    /// Start all controller tasks and add them to the JoinSet.
    fn start_controllers(&self, join_set: &mut JoinSet<()>);
}
