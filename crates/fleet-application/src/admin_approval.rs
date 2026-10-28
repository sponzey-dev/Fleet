//! Human approval decisions share the identity, approval, Job and audit transaction.
//! The repository owns serialization; this use case owns authority and state transitions.

use crate::admin_identity::{
    AdminAccessError, AdminMutationPrincipal, AdminOperation, AdminWriteRead, AuthorizeAdminWrite,
    OrderedAdminOperation,
};
use crate::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminApprovalDecision {
    Approve,
    Reject,
}

#[derive(Debug)]
pub enum AdminApprovalError {
    Access(AdminAccessError),
    Domain(JobError),
}

impl From<AdminAccessError> for AdminApprovalError {
    fn from(error: AdminAccessError) -> Self {
        Self::Access(error)
    }
}
impl Display for AdminApprovalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Access(_) => "approval authority or persistence rejected",
            Self::Domain(_) => "approval transition rejected",
        })
    }
}
impl std::error::Error for AdminApprovalError {}

/// All methods operate on the same serialized transaction. Failed writes and audits
/// must roll back; adapters never dispatch or modify Agent sessions here.
pub trait AdminApprovalTransaction:
    AdminWriteRead + crate::admin_remediation::AdminRemediationRead
{
    fn save_remediation_action(
        &mut self,
        creation: &crate::admin_remediation::PreparedAdminRemediation<'_>,
    ) -> Result<(), AdminApprovalError>;
    fn pending_approvals(
        &self,
        limit: usize,
    ) -> Result<Vec<ApprovalRequestRecord>, AdminApprovalError>;
    fn save_expiry(
        &mut self,
        before: &ApprovalRequestRecord,
        after: &ApprovalRequestRecord,
        audit: &AuditEvent,
    ) -> Result<(), AdminApprovalError>;
    fn approval(&self, id: &str) -> Result<Option<ApprovalRequestRecord>, AdminApprovalError>;
    fn save_decision(
        &mut self,
        before: &ApprovalRequestRecord,
        after: &ApprovalRequestRecord,
        status: JobStatus,
        audit: &AuditEvent,
    ) -> Result<(), AdminApprovalError>;
}

/// No sequential fallback. Serializes human revocation and competing decisions,
/// and rolls back every effect when the callback or commit fails.
pub trait AdminApprovalRepository {
    fn approval_transaction<T>(
        &mut self,
        work: impl FnOnce(&mut dyn AdminApprovalTransaction) -> Result<T, AdminApprovalError>,
    ) -> Result<T, AdminApprovalError>;
}

pub struct DecideAdminApproval;

pub(crate) struct ApprovalDeadline<'a> {
    operation: &'a dyn AdminOperation,
    expires_at: SystemTime,
}

impl<'a> ApprovalDeadline<'a> {
    pub(crate) fn new(operation: &'a dyn AdminOperation, expires_at: SystemTime) -> Self {
        Self {
            operation,
            expires_at,
        }
    }
}

impl AdminOperation for ApprovalDeadline<'_> {
    fn checked_now(&self) -> Result<i64, AdminAccessError> {
        let now = self.operation.checked_now()?;
        if UNIX_EPOCH
            .checked_add(Duration::from_secs(now as u64))
            .ok_or(AdminAccessError::Unavailable)?
            >= self.expires_at
        {
            return Err(AdminAccessError::Conflict);
        }
        Ok(now)
    }
}

impl DecideAdminApproval {
    pub fn execute<R: AdminApprovalRepository>(
        repository: &mut R,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        id: &str,
        decision: AdminApprovalDecision,
        reason: String,
    ) -> Result<ApprovalWorkflowOutput, AdminApprovalError> {
        let ordered = OrderedAdminOperation::new(operation);
        ordered.checked_now()?;
        repository.approval_transaction(|transaction| {
            let actor = AuthorizeAdminWrite::execute(
                transaction,
                principal,
                &ordered,
                fleet_domain::AdminPermission::JobApprove,
            )?;
            let before = transaction
                .approval(id)?
                .ok_or(AdminAccessError::NotFound)?;
            let occurred_at = UNIX_EPOCH
                .checked_add(Duration::from_secs(ordered.checked_now()? as u64))
                .ok_or(AdminAccessError::Unavailable)?;
            let mut approval =
                approval_record_to_request(&before).map_err(AdminApprovalError::Domain)?;
            let (status, action) = match decision {
                AdminApprovalDecision::Approve => {
                    approval
                        .approve(actor.as_str(), reason, occurred_at)
                        .map_err(AdminApprovalError::Domain)?;
                    (JobStatus::Queued, "approval_approved")
                }
                AdminApprovalDecision::Reject => {
                    approval
                        .reject(actor.as_str(), reason, occurred_at)
                        .map_err(AdminApprovalError::Domain)?;
                    (JobStatus::Failed, "approval_rejected")
                }
            };
            let after = approval_request_to_record(&approval);
            transaction.save_decision(
                &before,
                &after,
                status,
                &AuditEvent {
                    category: AuditCategory::Approval,
                    action: action.to_owned(),
                    actor,
                    target: AuditTarget::new(after.job_id.clone()),
                    value: AuditValue::Plain(format!(
                        "approval_id={},reason={}",
                        after.id, after.reason
                    )),
                    occurred_at,
                },
            )?;
            // One final guarded clock view applies both the human credential's
            // lifetime and the approval deadline; no unchecked time read follows it.
            AuthorizeAdminWrite::execute(
                transaction,
                principal,
                &ApprovalDeadline {
                    operation: &ordered,
                    expires_at: before.expires_at,
                },
                fleet_domain::AdminPermission::JobApprove,
            )?;
            Ok(ApprovalWorkflowOutput { approval: after })
        })
    }
}

/// Keeps the existing bounded manual-expiry scan; it is not a background scheduler.
pub const ADMIN_EXPIRY_SCAN_LIMIT: usize = 500;

pub struct ExpireAdminApprovals;
impl ExpireAdminApprovals {
    /// One human-authorized batch commits decisions, pending Job expiry and audits
    /// together. Accepted or terminal Jobs are preserved, including canceled Jobs.
    pub fn execute<R: AdminApprovalRepository>(
        repository: &mut R,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
    ) -> Result<ExpireApprovalsOutput, AdminApprovalError> {
        let operation = OrderedAdminOperation::new(operation);
        operation.checked_now()?;
        repository.approval_transaction(|transaction| {
            let actor = AuthorizeAdminWrite::execute(
                transaction,
                principal,
                &operation,
                fleet_domain::AdminPermission::JobApprove,
            )?;
            let occurred_at = UNIX_EPOCH
                .checked_add(Duration::from_secs(operation.checked_now()? as u64))
                .ok_or(AdminAccessError::Unavailable)?;
            let pending = transaction.pending_approvals(ADMIN_EXPIRY_SCAN_LIMIT)?;
            let mut expired = Vec::new();
            for before in pending
                .into_iter()
                .filter(|record| record.expires_at <= occurred_at)
            {
                let mut approval =
                    approval_record_to_request(&before).map_err(AdminApprovalError::Domain)?;
                approval
                    .expire(occurred_at)
                    .map_err(AdminApprovalError::Domain)?;
                let after = approval_request_to_record(&approval);
                transaction.save_expiry(
                    &before,
                    &after,
                    &AuditEvent {
                        category: AuditCategory::Approval,
                        action: "approval_expired".to_owned(),
                        actor: actor.clone(),
                        target: AuditTarget::new(after.job_id.clone()),
                        value: AuditValue::Plain(format!("approval_id={}", after.id)),
                        occurred_at,
                    },
                )?;
                expired.push(after);
            }
            AuthorizeAdminWrite::execute(
                transaction,
                principal,
                &operation,
                fleet_domain::AdminPermission::JobApprove,
            )?;
            Ok(ExpireApprovalsOutput { expired })
        })
    }
}
