use super::{ControllerError, WorkloadController};
use crate::raft::records::{CronCheckpointRecord, WorkloadSpecRecord};
use crate::raft::{AuditedCommand, FleetosCommand, FleetosRaftConfig};
use chrono::{DateTime, Utc};
use cron::Schedule;
use fleetos_core::proto::workload::CronWorkload;
use openraft::Raft;
use std::str::FromStr;
use std::sync::Arc;

pub struct CronController {
    workload_controller: Arc<WorkloadController>,
    raft: Arc<Raft<FleetosRaftConfig>>,
    /// Replicated cron checkpoints (G-11).
    cron_checkpoints: fjall::Keyspace,
}

impl CronController {
    pub fn new(
        workload_controller: Arc<WorkloadController>,
        raft: Arc<Raft<FleetosRaftConfig>>,
        cron_checkpoints: fjall::Keyspace,
    ) -> Self {
        Self {
            workload_controller,
            raft,
            cron_checkpoints,
        }
    }

    /// Evaluate whether a cron workload is due and trigger it if so (G-11).
    ///
    /// Returns `true` if a run was triggered, `false` if not yet due. Missed
    /// runs are coalesced into a single trigger (standard cron catch-up).
    pub async fn evaluate_and_trigger(&self, cron: &CronWorkload) -> Result<bool, ControllerError> {
        if cron.schedule.as_ref().map_or(false, |s| s.suspend) {
            return Ok(false);
        }
        let schedule_expr = &cron
            .schedule
            .as_ref()
            .ok_or_else(|| ControllerError::Raft("cron workload missing schedule".to_owned()))?
            .expression;
        let schedule = Self::validate_expression(schedule_expr)?;

        let now: DateTime<Utc> = Utc::now();
        let checkpoint = self.load_checkpoint(&cron.tenant_id, &cron.cron_workload_id)?;
        let since: DateTime<Utc> = match checkpoint {
            Some(cp) => DateTime::from_timestamp(cp.last_triggered_at_unix, 0)
                .ok_or_else(|| ControllerError::Raft("invalid checkpoint timestamp".to_owned()))?,
            // No checkpoint — SubmitCronWorkload records one at submission, so this
            // only happens for pre-existing rows; fall back to now (no backfill).
            None => now,
        };

        // Latest scheduled time in (since, now]; coalesce missed runs into one.
        let Some(latest_due) = schedule.after(&since).take_while(|t| *t <= now).last() else {
            return Ok(false); // not due yet
        };

        // Instantiate the workload for this run.
        let run_workload_id = format!("{}-{}", cron.cron_workload_id, latest_due.timestamp());
        let mut spec = cron.workload_template.clone().ok_or_else(|| {
            ControllerError::Raft("cron workload missing workload_template".to_owned())
        })?;
        spec.workload_id = run_workload_id.clone();
        spec.tenant_id = cron.tenant_id.clone();

        let workload_record = WorkloadSpecRecord {
            tenant_id: spec.tenant_id.clone(),
            workload_id: spec.workload_id.clone(),
            spec_bytes: prost::Message::encode_to_vec(&spec),
        };
        let checkpoint = CronCheckpointRecord {
            tenant_id: cron.tenant_id.clone(),
            cron_workload_id: cron.cron_workload_id.clone(),
            last_triggered_at_unix: latest_due.timestamp(),
        };

        // Atomic: store the run's spec AND advance the checkpoint in one entry.
        self.raft
            .client_write(AuditedCommand::system(
                FleetosCommand::TriggerCronWorkload {
                    workload_record,
                    checkpoint,
                },
            ))
            .await
            .map_err(|e| ControllerError::Raft(e.to_string()))?;

        self.workload_controller.reconcile(&spec).await?;

        tracing::info!(
            cron_id = %cron.cron_workload_id,
            run_id = %run_workload_id,
            scheduled_for = latest_due.timestamp(),
            "cron workload triggered"
        );
        Ok(true)
    }

    fn load_checkpoint(
        &self,
        tenant_id: &str,
        cron_workload_id: &str,
    ) -> Result<Option<CronCheckpointRecord>, ControllerError> {
        let key = format!("{}:{}", tenant_id, cron_workload_id);
        match self
            .cron_checkpoints
            .get(key.as_bytes())
            .map_err(|e| ControllerError::Storage(crate::storage::StorageError::Storage(e)))?
        {
            Some(bytes) => {
                let cp: CronCheckpointRecord =
                    postcard::from_bytes(&bytes).map_err(ControllerError::Serialization)?;
                Ok(Some(cp))
            }
            None => Ok(None),
        }
    }

    pub fn validate_expression(expr: &str) -> Result<Schedule, ControllerError> {
        Schedule::from_str(expr).map_err(|e| {
            ControllerError::Raft(format!("invalid cron expression '{}': {}", expr, e))
        })
    }
}
