//! SQLite repository implementation for bounded overdue Assignment recovery.
//!
//! Candidate reads use persisted Controller dispatch time and Job timeout.
//! Conditional recovery updates status, aggregate, and audit atomically.

use super::{SqliteStore, StoreError, system_time_to_unix_secs, unix_secs_to_system_time};
use fleet_application::assignment_recovery::{
    AssignmentRecoveryCandidate, AssignmentRecoveryCommitOutcome, AssignmentRecoveryRepository,
    MAX_ASSIGNMENT_RECOVERY_BATCH,
};
use fleet_domain::delivery::InterruptedExecution;
use fleet_domain::{
    AssignmentStatus, AuditActor, AuditCategory, AuditEvent, AuditTarget, AuditValue, JobId, TaskId,
};
use rusqlite::params;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

impl AssignmentRecoveryRepository for SqliteStore {
    type Error = StoreError;

    fn list_overdue_assignment_recovery_candidates(
        &self,
        now: SystemTime,
        grace: Duration,
        limit: usize,
    ) -> Result<Vec<AssignmentRecoveryCandidate>, Self::Error> {
        if limit == 0 || limit > MAX_ASSIGNMENT_RECOVERY_BATCH {
            return Err(StoreError::Domain(
                "invalid assignment recovery batch limit".to_owned(),
            ));
        }
        let now_millis = recovery_epoch_millis(now)?;
        let grace_millis = recovery_duration_millis(grace)?;
        let now_seconds = now_millis / 1000;
        let mut statement = self.connection.prepare(
            "SELECT ta.job_id, ta.id, ta.status, ta.dispatched_at, j.timeout_ms
             FROM task_assignments ta
             JOIN jobs j ON j.id = ta.job_id
             WHERE ta.status IN ('dispatched', 'accepted', 'started')
               AND ta.dispatched_at IS NOT NULL
               AND ta.dispatched_at >= 0
               AND ta.dispatched_at <= ?1
             AND j.timeout_ms > 0
               AND ((?2 - ta.dispatched_at * 1000) - ?3) >= j.timeout_ms
             ORDER BY
               ta.dispatched_at * 1000 + j.timeout_ms + ?3,
               ta.id
             LIMIT ?4",
        )?;
        let rows = statement
            .query_map(
                params![now_seconds, now_millis, grace_millis, limit as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        rows.into_iter()
            .map(
                |(job_id, task_id, status, dispatched_at, execution_timeout_ms)| {
                    let job_id = JobId::new(job_id)
                        .map_err(|_| StoreError::Domain("invalid recovery job identity".into()))?;
                    let task_id = TaskId::new(task_id)
                        .map_err(|_| StoreError::Domain("invalid recovery task identity".into()))?;
                    let status = AssignmentStatus::parse(&status).ok_or_else(|| {
                        StoreError::Domain("invalid recovery assignment status".into())
                    })?;
                    let execution_timeout_ms =
                        u64::try_from(execution_timeout_ms).map_err(|_| {
                            StoreError::Domain("invalid recovery execution timeout".into())
                        })?;
                    Ok(AssignmentRecoveryCandidate {
                        job_id,
                        task_id,
                        status,
                        dispatched_at: Some(unix_secs_to_system_time(dispatched_at)),
                        execution_timeout: Duration::from_millis(execution_timeout_ms),
                    })
                },
            )
            .collect()
    }

    fn commit_unknown_execution_outcome(
        &mut self,
        candidate: &AssignmentRecoveryCandidate,
        reason: InterruptedExecution,
        now: SystemTime,
    ) -> Result<AssignmentRecoveryCommitOutcome, Self::Error> {
        if !matches!(
            candidate.status,
            AssignmentStatus::Dispatched | AssignmentStatus::Accepted | AssignmentStatus::Started
        ) {
            return Ok(AssignmentRecoveryCommitOutcome::NoLongerEligible);
        }
        let Some(dispatched_at) = candidate.dispatched_at else {
            return Ok(AssignmentRecoveryCommitOutcome::NoLongerEligible);
        };
        let execution_timeout_ms = i64::try_from(candidate.execution_timeout.as_millis())
            .map_err(|_| StoreError::Domain("invalid recovery execution timeout".into()))?;
        if execution_timeout_ms <= 0 {
            return Ok(AssignmentRecoveryCommitOutcome::NoLongerEligible);
        }
        let dispatched_at = system_time_to_unix_secs(dispatched_at);
        let reason_code = reason.reason_code();
        let changed = self.run_sqlite_transaction(|| {
            let changed = self.connection.execute(
                "UPDATE task_assignments
                 SET status = 'failed', completed_at = ?6, last_error = ?7
                 WHERE id = ?1
                   AND job_id = ?2
                   AND status = ?3
                   AND status IN ('dispatched', 'accepted', 'started')
                   AND dispatched_at = ?4
                   AND EXISTS (
                       SELECT 1 FROM jobs
                       WHERE jobs.id = task_assignments.job_id AND jobs.timeout_ms = ?5
                   )",
                params![
                    candidate.task_id.as_str(),
                    candidate.job_id.as_str(),
                    candidate.status.as_str(),
                    dispatched_at,
                    execution_timeout_ms,
                    system_time_to_unix_secs(now),
                    reason_code,
                ],
            )?;
            if changed != 1 {
                return Ok(AssignmentRecoveryCommitOutcome::NoLongerEligible);
            }
            self.recompute_job_status_from_assignments(candidate.job_id.as_str())?;
            self.insert_audit(&AuditEvent {
                category: AuditCategory::Job,
                action: "assignment_execution_outcome_unknown".to_owned(),
                actor: AuditActor::new("controller-recovery"),
                target: AuditTarget::new(candidate.task_id.as_str()),
                value: AuditValue::Plain(reason_code.to_owned()),
                occurred_at: now,
            })?;
            Ok(AssignmentRecoveryCommitOutcome::Recovered)
        })?;
        Ok(changed)
    }
}

fn recovery_epoch_millis(value: SystemTime) -> Result<i64, StoreError> {
    let duration = value.duration_since(UNIX_EPOCH).unwrap_or_default();
    i64::try_from(duration.as_millis())
        .map_err(|_| StoreError::Domain("invalid assignment recovery clock".to_owned()))
}

fn recovery_duration_millis(value: Duration) -> Result<i64, StoreError> {
    i64::try_from(value.as_millis())
        .map_err(|_| StoreError::Domain("invalid assignment recovery grace".to_owned()))
}
