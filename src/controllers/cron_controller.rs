use super::{ControllerError, WorkloadController};
use crate::raft::{FleetosCommand, FleetosRaftConfig};
use cron::Schedule;
use fleetos_core::proto::workload::CronWorkload;
use openraft::Raft;
use std::str::FromStr;
use std::sync::Arc;

pub struct CronController {
    workload_controller: Arc<WorkloadController>,
    raft: Arc<Raft<FleetosRaftConfig>>,
}

impl CronController {
    pub fn new(
        workload_controller: Arc<WorkloadController>,
        raft: Arc<Raft<FleetosRaftConfig>>,
    ) -> Self {
        Self {
            workload_controller,
            raft,
        }
    }

    pub async fn trigger(&self, cron: &CronWorkload) -> Result<(), ControllerError> {
        if cron.schedule.as_ref().map_or(false, |s| s.suspend) {
            tracing::debug!(cron_id = %cron.cron_workload_id, "cron suspended, skipping");
            return Ok(());
        }
        if let Some(schedule) = &cron.schedule {
            Self::validate_expression(&schedule.expression)?;
        } else {
            return Err(ControllerError::Raft(
                "cron workload missing schedule".to_owned(),
            ));
        }

        let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
        let run_workload_id = format!("{}-{}", cron.cron_workload_id, timestamp);
        let mut spec = cron.workload_template.clone().ok_or_else(|| {
            ControllerError::Raft("cron workload missing workload_template".to_owned())
        })?;
        spec.workload_id = run_workload_id.clone();
        spec.tenant_id = cron.tenant_id.clone();

        tracing::info!(
            cron_id = %cron.cron_workload_id, run_id = %run_workload_id,
            "triggering cron workload"
        );

        // Persist the generated run spec via Raft so schedule broadcasts can
        // resolve its image/runtime, then schedule it.
        let record = crate::raft::records::WorkloadSpecRecord {
            tenant_id: spec.tenant_id.clone(),
            workload_id: spec.workload_id.clone(),
            spec_bytes: prost::Message::encode_to_vec(&spec),
        };
        self.raft
            .client_write(crate::raft::AuditedCommand::system(
                FleetosCommand::SubmitWorkloadSpec { record },
            ))
            .await
            .map_err(|e| ControllerError::Raft(e.to_string()))?;

        self.workload_controller.reconcile(&spec).await?;
        Ok(())
    }

    pub fn validate_expression(expr: &str) -> Result<(), ControllerError> {
        Schedule::from_str(expr).map_err(|e| {
            ControllerError::Raft(format!("invalid cron expression '{}': {}", expr, e))
        })?;
        Ok(())
    }
}
