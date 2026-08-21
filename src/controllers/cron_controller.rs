//! Cron controller — time-based workload triggering.
//!
//! Evaluates `CronWorkload` schedules and submits the inner `WorkloadSpec`
//! to the `WorkloadController` when triggered. Each triggered run gets a
//! unique `workload_id` (e.g., `{cron_id}-{timestamp}`) to ensure ordinal
//! stability doesn't collide across runs.

use std::str::FromStr;
use std::sync::Arc;

use cron::Schedule;
use fleetos_core::proto::workload::CronWorkload;

use super::{ControllerError, WorkloadController};
use crate::storage::StorageEngine;

/// The cron controller.
pub struct CronController {
    #[allow(dead_code)]
    storage: Arc<StorageEngine>,
    workload_controller: Arc<WorkloadController>,
}

impl CronController {
    pub fn new(storage: Arc<StorageEngine>, workload_controller: Arc<WorkloadController>) -> Self {
        Self {
            storage,
            workload_controller,
        }
    }

    /// Trigger a specific CronWorkload.
    ///
    /// Clones the inner WorkloadSpec template, assigns a unique workload_id
    /// for this specific run, and submits it to the WorkloadController for
    /// expansion and scheduling.
    pub async fn trigger(&self, cron: &CronWorkload) -> Result<(), ControllerError> {
        // Check if suspended (proto message fields are Option<T>)
        if cron.schedule.as_ref().map_or(false, |s| s.suspend) {
            tracing::debug!(cron_id = %cron.cron_workload_id, "cron suspended, skipping");
            return Ok(());
        }

        // Validate the cron expression before triggering
        if let Some(schedule) = &cron.schedule {
            Self::validate_expression(&schedule.expression)?;
        } else {
            return Err(ControllerError::Raft(
                "cron workload missing schedule".to_owned(),
            ));
        }

        // Generate a unique workload_id for this specific run.
        // This ensures that if the cron runs again, it doesn't collide with
        // the previous run's ordinals.
        let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
        let run_workload_id = format!("{}-{}", cron.cron_workload_id, timestamp);

        // Clone the template and overwrite the workload_id and tenant_id.
        let mut spec = cron.workload_template.clone().ok_or_else(|| {
            ControllerError::Raft("cron workload missing workload_template".to_owned())
        })?;

        spec.workload_id = run_workload_id.clone();
        spec.tenant_id = cron.tenant_id.clone();

        tracing::info!(
            cron_id = %cron.cron_workload_id,
            run_id = %run_workload_id,
            "triggering cron workload"
        );

        // Submit to the workload controller for expansion.
        self.workload_controller.reconcile(&spec).await?;

        Ok(())
    }

    /// Validate a cron expression.
    pub fn validate_expression(expr: &str) -> Result<(), ControllerError> {
        Schedule::from_str(expr).map_err(|e| {
            ControllerError::Raft(format!("invalid cron expression '{}': {}", expr, e))
        })?;
        Ok(())
    }
}
