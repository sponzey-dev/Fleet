//! Human remediation decisions prepare signed work before one protected approval
//! transaction. Current identity and the exact prior lifecycle records authorize commit.

use crate::admin_approval::{AdminApprovalError, AdminApprovalRepository, ApprovalDeadline};
use crate::admin_identity::{
    AdminAccessError, AdminMutationPrincipal, AdminOperation, AuthorizeAdminWrite,
    OrderedAdminOperation,
};
use crate::*;
use std::convert::Infallible;

/// Immutable preparation reads; concrete storage and transport errors are classified.
pub trait AdminRemediationRead {
    fn remediation_for_action(
        &self,
        id: &str,
    ) -> Result<Option<RemediationRequestRecord>, AdminAccessError>;
    fn approval_for_remediation_action(
        &self,
        id: &str,
    ) -> Result<Option<ApprovalRequestRecord>, AdminAccessError>;
}

#[derive(Clone, Copy)]
pub struct PreparedRemediationExecution<'a> {
    job: &'a Job,
    task: &'a RunbookExecutionTask,
    assignments: &'a [TaskEnvelope],
}
impl PreparedRemediationExecution<'_> {
    pub fn job(&self) -> &Job {
        self.job
    }
    pub fn task(&self) -> &RunbookExecutionTask {
        self.task
    }
    pub fn assignments(&self) -> &[TaskEnvelope] {
        self.assignments
    }
}

/// Only these use cases construct this read-only view. No caller actor or role
/// becomes an authority grant, and adapters cannot mutate the prepared lifecycle.
pub struct PreparedAdminRemediation<'a> {
    before: &'a RemediationRequestRecord,
    approval_before: Option<&'a ApprovalRequestRecord>,
    after: &'a RemediationRequestRecord,
    approval: &'a ApprovalRequestRecord,
    execution: Option<PreparedRemediationExecution<'a>>,
    audits: &'a [AuditEvent],
}
impl PreparedAdminRemediation<'_> {
    pub fn before(&self) -> &RemediationRequestRecord {
        self.before
    }
    pub fn after(&self) -> &RemediationRequestRecord {
        self.after
    }
    pub fn approval(&self) -> &ApprovalRequestRecord {
        self.approval
    }
    pub fn execution(&self) -> Option<PreparedRemediationExecution<'_>> {
        self.execution
    }
    pub fn audits(&self) -> &[AuditEvent] {
        self.audits
    }
}

#[derive(Debug)]
pub enum AdminRemediationError<S = Infallible> {
    Access(AdminAccessError),
    Invalid(String),
    Sign(S),
}
impl<S> From<AdminAccessError> for AdminRemediationError<S> {
    fn from(error: AdminAccessError) -> Self {
        Self::Access(error)
    }
}
impl<S> Display for AdminRemediationError<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Access(_) => "remediation authority or persistence rejected",
            Self::Invalid(_) => "remediation transition rejected",
            Self::Sign(_) => "remediation signing failed",
        })
    }
}
impl<S: Debug> std::error::Error for AdminRemediationError<S> {}

fn commit<R: AdminApprovalRepository>(
    repository: &mut R,
    principal: &AdminMutationPrincipal,
    operation: &dyn AdminOperation,
    creation: &PreparedAdminRemediation<'_>,
) -> Result<(), AdminAccessError> {
    let operation = ApprovalDeadline::new(operation, creation.approval.expires_at);
    repository
        .approval_transaction(|transaction| {
            let actor = AuthorizeAdminWrite::execute(
                transaction,
                principal,
                &operation,
                fleet_domain::AdminPermission::JobApprove,
            )?;
            let identity_matches = if creation.execution.is_some() {
                creation.approval.approver.as_deref() == Some(actor.as_str())
            } else {
                creation.approval.requester == actor.as_str()
            };
            if !identity_matches
                || creation
                    .audits
                    .iter()
                    .any(|event| event.actor.as_str() != actor.as_str())
            {
                return Err(AdminAccessError::Unauthorized.into());
            }
            if transaction
                .remediation_for_action(&creation.before.id)?
                .as_ref()
                != Some(creation.before)
            {
                return Err(AdminAccessError::Conflict.into());
            }
            let current_approval =
                transaction.approval_for_remediation_action(&creation.approval.id)?;
            if current_approval.as_ref() != creation.approval_before {
                return Err(AdminAccessError::Conflict.into());
            }
            transaction.save_remediation_action(creation)?;
            AuthorizeAdminWrite::execute(
                transaction,
                principal,
                &operation,
                fleet_domain::AdminPermission::JobApprove,
            )?;
            Ok(())
        })
        .map_err(|error| match error {
            AdminApprovalError::Access(error) => error,
            AdminApprovalError::Domain(_) => AdminAccessError::Unavailable,
        })
}

pub struct RequestAdminRemediationApproval;
impl RequestAdminRemediationApproval {
    /// Derives the requester from current server identity and commits approval,
    /// lifecycle metadata and audit together, including duplicate/stale guards.
    pub fn execute<R: AdminApprovalRepository + AdminRemediationRead>(
        repository: &mut R,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        mut input: RequestRemediationApprovalInput,
    ) -> Result<RequestRemediationApprovalOutput, AdminRemediationError> {
        let operation = OrderedAdminOperation::new(operation);
        operation.checked_now()?;
        input.requester = principal.actor_id().to_owned();
        let before = repository
            .remediation_for_action(&input.remediation_id)?
            .ok_or(AdminAccessError::NotFound)?;
        let mut request =
            remediation_record_to_request(&before).map_err(|_| AdminAccessError::Unavailable)?;
        request
            .request_approval()
            .map_err(|error| AdminRemediationError::Invalid(format!("{error:?}")))?;
        let approval = ApprovalRequest::new(
            ApprovalId::new(input.approval_id)
                .map_err(|error| AdminRemediationError::Invalid(error.to_string()))?,
            JobId::new(input.job_id)
                .map_err(|error| AdminRemediationError::Invalid(error.to_string()))?,
            input.requester.clone(),
            input.reason,
            input.expires_at,
            input.now,
        )
        .map_err(|error| AdminRemediationError::Invalid(error.to_string()))?;
        let approval = approval_request_to_record(&approval);
        let after = RemediationRequestRecord {
            status: request.status.as_str().to_owned(),
            job_id: request.job_id.clone(),
            updated_at: input.now,
            ..before.clone()
        };
        let audit = AuditEvent {
            category: AuditCategory::Policy,
            action: "remediation_approval_requested".to_owned(),
            actor: AuditActor::new(input.requester),
            target: AuditTarget::new(request.agent_id.clone()),
            value: AuditValue::Plain(format!(
                "remediation_id={},approval_id={},policy_id={},agent_id={},job_id={},status={}",
                request.id,
                approval.id,
                request.policy_id,
                request.agent_id,
                approval.job_id,
                request.status.as_str()
            )),
            occurred_at: input.now,
        };
        commit(
            repository,
            principal,
            &operation,
            &PreparedAdminRemediation {
                before: &before,
                approval_before: None,
                after: &after,
                approval: &approval,
                execution: None,
                audits: &[audit],
            },
        )?;
        Ok(RequestRemediationApprovalOutput {
            remediation: after,
            approval,
        })
    }
}

pub struct ApproveAdminRemediationJob;
impl ApproveAdminRemediationJob {
    /// Signs outside storage locks, then compares both prior lifecycle records and
    /// current human authority before committing the approved Job and every audit.
    pub fn execute<R: AdminApprovalRepository + AdminRemediationRead, S: TaskEnvelopeSigner>(
        repository: &mut R,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        signer: &mut S,
        mut input: ApproveRemediationRunbookJobInput,
    ) -> Result<ApproveRemediationRunbookJobOutput, AdminRemediationError<S::Error>> {
        let operation = OrderedAdminOperation::new(operation);
        operation.checked_now()?;
        input.approver = principal.actor_id().to_owned();
        i64::try_from(input.timeout.as_millis()).map_err(|_| AdminAccessError::InvalidRequest)?;
        let before = repository
            .remediation_for_action(&input.remediation_id)?
            .ok_or(AdminAccessError::NotFound)?;
        let mut request =
            remediation_record_to_request(&before).map_err(|_| AdminAccessError::Unavailable)?;
        request
            .approve()
            .map_err(|error| AdminRemediationError::Invalid(format!("{error:?}")))?;
        let approval_before = repository
            .approval_for_remediation_action(&input.approval_id)?
            .ok_or(AdminAccessError::NotFound)?;
        if approval_before.job_id != input.job_id {
            return Err(AdminRemediationError::Invalid(
                "approval job id does not match remediation job id".to_owned(),
            ));
        }
        let mut approval = approval_record_to_request(&approval_before)
            .map_err(|error| AdminRemediationError::Invalid(error.to_string()))?;
        approval
            .approve(
                input.approver.clone(),
                input.approval_reason,
                input.issued_at,
            )
            .map_err(|error| AdminRemediationError::Invalid(error.to_string()))?;
        let approval = approval_request_to_record(&approval);
        let mut signed = build_signed_runbook_job(
            signer,
            BuildSignedRunbookJobInput {
                job_id: input.job_id.clone(),
                target_agent_ids: vec![request.agent_id.clone()],
                runbook_document: input.runbook_document,
                timeout: input.timeout,
                issued_at: input.issued_at,
                expires_at: input.expires_at,
                nonce_prefix: input.nonce_prefix,
            },
        )
        .map_err(|error| match error {
            BuildSignedRunbookJobError::Domain(error) => {
                AdminRemediationError::Invalid(error.to_string())
            }
            BuildSignedRunbookJobError::Agent(error) => {
                AdminRemediationError::Invalid(error.to_string())
            }
            BuildSignedRunbookJobError::InvalidRunbook(error) => {
                AdminRemediationError::Invalid(error)
            }
            BuildSignedRunbookJobError::NoTargets => {
                AdminRemediationError::Invalid("runbook job requires a target".to_owned())
            }
            BuildSignedRunbookJobError::Sign(error) => AdminRemediationError::Sign(error),
        })?;
        signed
            .job
            .queue(true)
            .map_err(|error| AdminRemediationError::Invalid(error.to_string()))?;
        request
            .create_job(input.job_id.clone())
            .map_err(|error| AdminRemediationError::Invalid(format!("{error:?}")))?;
        let after = RemediationRequestRecord {
            status: request.status.as_str().to_owned(),
            job_id: request.job_id.clone(),
            updated_at: input.issued_at,
            ..before.clone()
        };
        let actor = AuditActor::new(input.approver.clone());
        let audits = [
            AuditEvent {
                category: AuditCategory::Approval,
                action: "approval_approved".to_owned(),
                actor: actor.clone(),
                target: AuditTarget::new(input.job_id.clone()),
                value: AuditValue::Plain(format!(
                    "approval_id={},reason={}",
                    approval.id, approval.reason
                )),
                occurred_at: input.issued_at,
            },
            AuditEvent {
                category: AuditCategory::Job,
                action: "runbook_job_created".to_owned(),
                actor: actor.clone(),
                target: AuditTarget::new(input.job_id.clone()),
                value: AuditValue::Plain(format!(
                    "confirmed_high_risk=true,confirmed_by={},target_count={}",
                    input.approver,
                    signed.targets.len()
                )),
                occurred_at: input.issued_at,
            },
            AuditEvent {
                category: AuditCategory::Policy,
                action: "remediation_job_created".to_owned(),
                actor,
                target: AuditTarget::new(request.agent_id.clone()),
                value: AuditValue::Plain(format!(
                    "remediation_id={},approval_id={},policy_id={},agent_id={},job_id={},status={}",
                    request.id,
                    approval.id,
                    request.policy_id,
                    request.agent_id,
                    input.job_id,
                    request.status.as_str()
                )),
                occurred_at: input.issued_at,
            },
        ];
        commit(
            repository,
            principal,
            &operation,
            &PreparedAdminRemediation {
                before: &before,
                approval_before: Some(&approval_before),
                after: &after,
                approval: &approval,
                execution: Some(PreparedRemediationExecution {
                    job: &signed.job,
                    task: &signed.task,
                    assignments: &signed.envelopes,
                }),
                audits: &audits,
            },
        )?;
        Ok(ApproveRemediationRunbookJobOutput {
            remediation: after,
            approval,
            task: signed.task,
            targets: signed.targets,
            envelopes: signed.envelopes,
        })
    }
}
