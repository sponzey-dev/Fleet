//! Human cancellation owns canonical assignment selection, aggregate state and audit.
//! The caller may attempt bounded Agent delivery only after the transaction succeeds.

use crate::admin_identity::{
    AdminAccessError, AdminMutationPrincipal, AdminOperation, AdminWriteRead, AuthorizeAdminWrite,
    OrderedAdminOperation,
};
use fleet_domain::{
    AgentId, AssignmentStatus, AuditCategory, AuditEvent, AuditTarget, AuditValue, JobId,
    JobStatus, TaskId, aggregate_job_status,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct CancellationAssignment {
    pub job_id: JobId,
    pub task_id: TaskId,
    pub agent_id: AgentId,
    pub status: AssignmentStatus,
}
pub struct CancellationSnapshot {
    pub status: JobStatus,
    pub max_failures: Option<u32>,
    pub assignments: Vec<CancellationAssignment>,
}
/// Private construction ensures adapters only apply the use case's selected transitions.
pub struct PreparedCancellation {
    job_id: JobId,
    before: JobStatus,
    status: JobStatus,
    assignments: Vec<CancellationAssignment>,
    reason: String,
    occurred_at: SystemTime,
    audit: Option<AuditEvent>,
}
impl PreparedCancellation {
    pub fn job_id(&self) -> &JobId {
        &self.job_id
    }
    pub fn before(&self) -> JobStatus {
        self.before
    }
    pub fn status(&self) -> JobStatus {
        self.status
    }
    pub fn assignments(&self) -> &[CancellationAssignment] {
        &self.assignments
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }
    pub fn occurred_at(&self) -> SystemTime {
        self.occurred_at
    }
    pub fn audit(&self) -> Option<&AuditEvent> {
        self.audit.as_ref()
    }
    pub fn update_job(&self) -> bool {
        !preserve_terminal_job(self.before)
    }
}
fn preserve_terminal_job(status: JobStatus) -> bool {
    matches!(
        status,
        JobStatus::Success | JobStatus::Failed | JobStatus::Canceled | JobStatus::Expired
    )
}

/// Snapshot and effects share one transaction; terminal assignments never become canceled.
pub trait AdminCancellationTransaction: AdminWriteRead {
    fn cancellation_snapshot(
        &self,
        job_id: &JobId,
    ) -> Result<Option<CancellationSnapshot>, AdminAccessError>;
    fn apply_cancellation(
        &mut self,
        prepared: &PreparedCancellation,
    ) -> Result<(), AdminAccessError>;
}
pub trait AdminCancellationRepository {
    fn cancellation_transaction<T>(
        &mut self,
        work: impl FnOnce(&mut dyn AdminCancellationTransaction) -> Result<T, AdminAccessError>,
    ) -> Result<T, AdminAccessError>;
}

pub struct CancelAdminJobOutput {
    pub job_id: JobId,
    pub status: JobStatus,
    pub canceled: Vec<CancellationAssignment>,
    pub reason: String,
}
pub struct CancelAdminJob;
impl CancelAdminJob {
    /// The trusted redactor runs before storage locks. Raw reasons belong only to
    /// operational assignment records; actor and audit effects come from this use case.
    pub fn execute<R: AdminCancellationRepository>(
        repository: &mut R,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        job_id: &str,
        reason: String,
        redact: impl FnOnce(&str) -> String,
    ) -> Result<CancelAdminJobOutput, AdminAccessError> {
        let operation = OrderedAdminOperation::new(operation);
        operation.checked_now()?;
        let job_id = JobId::new(job_id).map_err(|_| AdminAccessError::InvalidRequest)?;
        let audit_reason = redact(&reason);
        repository.cancellation_transaction(|transaction| {
            let actor = AuthorizeAdminWrite::execute(
                transaction,
                principal,
                &operation,
                fleet_domain::AdminPermission::JobCancel,
            )?;
            let snapshot = transaction
                .cancellation_snapshot(&job_id)?
                .ok_or(AdminAccessError::NotFound)?;
            let now = operation.checked_now()?;
            let occurred_at = UNIX_EPOCH
                .checked_add(Duration::from_secs(now as u64))
                .ok_or(AdminAccessError::Unavailable)?;
            if snapshot
                .assignments
                .iter()
                .any(|assignment| assignment.job_id != job_id)
            {
                return Err(AdminAccessError::Unavailable);
            }
            let statuses = snapshot
                .assignments
                .iter()
                .map(|assignment| {
                    if assignment.status.is_terminal() {
                        assignment.status
                    } else {
                        AssignmentStatus::Canceled
                    }
                })
                .collect::<Vec<_>>();
            let assignments = snapshot
                .assignments
                .into_iter()
                .filter(|assignment| !assignment.status.is_terminal())
                .collect::<Vec<_>>();
            let status = if preserve_terminal_job(snapshot.status) {
                snapshot.status
            } else {
                aggregate_job_status(&statuses, snapshot.max_failures)
            };
            let audit = if preserve_terminal_job(snapshot.status) {
                None
            } else {
                Some(AuditEvent {
                    category: AuditCategory::Job,
                    action: "job_canceled".to_owned(),
                    actor,
                    target: AuditTarget::new(job_id.as_str()),
                    value: AuditValue::Plain(format!(
                        "reason={},canceled_count={},cancel_dispatch_candidate_count={}",
                        audit_reason,
                        assignments.len(),
                        assignments
                            .iter()
                            .filter(|assignment| assignment.status != AssignmentStatus::Queued)
                            .count()
                    )),
                    occurred_at,
                })
            };
            let prepared = PreparedCancellation {
                job_id,
                before: snapshot.status,
                status,
                assignments,
                reason,
                occurred_at,
                audit,
            };
            transaction.apply_cancellation(&prepared)?;
            AuthorizeAdminWrite::execute(
                transaction,
                principal,
                &operation,
                fleet_domain::AdminPermission::JobCancel,
            )?;
            Ok(CancelAdminJobOutput {
                job_id: prepared.job_id,
                status: prepared.status,
                canceled: prepared.assignments,
                reason: prepared.reason,
            })
        })
    }
}
