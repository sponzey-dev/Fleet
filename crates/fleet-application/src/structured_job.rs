//! Structured Job preparation and protected creation through injected ports.\n//! Signatures precede the canonical transaction; no direct store or transport I/O.

use super::*;
use crate::admin_identity::{
    AdminAccessError, AdminMutationPrincipal, AdminOperation, AdminWriteRead, AuthorizeAdminWrite,
    OrderedAdminOperation,
};
use std::convert::Infallible;

pub(super) struct DriftJobParts {
    pub(super) job: Job,
    pub(super) task: DriftCheckTask,
    pub(super) targets: Vec<JobTarget>,
    pub(super) envelopes: Vec<TaskEnvelope>,
    pub(super) approval_requirement: fleet_domain::ApprovalRequirement,
}

pub(super) fn prepare_drift_parts<R, A, S: TaskEnvelopeSigner>(
    input: &CreateDriftCheckJobInput,
    signer: &mut S,
) -> Result<DriftJobParts, CreateDriftCheckJobError<R, A, S::Error>> {
    if input.target_agent_ids.is_empty() {
        return Err(CreateDriftCheckJobError::NoTargets);
    }

    let task = DriftCheckTask::new(input.policy_document.clone(), input.timeout)
        .map_err(CreateDriftCheckJobError::Domain)?;
    let task_kind = TaskKind::DriftCheck(task.clone());
    let approval_requirement =
        approval_requirement_for_task(&task_kind, input.target_agent_ids.len());
    let mut job = Job::new(
        JobId::new(input.job_id.clone()).map_err(CreateDriftCheckJobError::Domain)?,
        task.risk(),
        approval_requirement,
        input.timeout,
    );
    if approval_requirement == fleet_domain::ApprovalRequirement::NotRequired {
        job.queue(false).map_err(CreateDriftCheckJobError::Domain)?;
    }

    let targets = input
        .target_agent_ids
        .iter()
        .map(|id| {
            AgentId::new(id.clone())
                .map(|agent_id| JobTarget { agent_id })
                .map_err(CreateDriftCheckJobError::Agent)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut envelopes = Vec::with_capacity(targets.len());
    for (index, target) in targets.iter().enumerate() {
        let payload_hash = drift_check_payload_hash(&task, target, index);
        let signature = signer
            .sign(&payload_hash)
            .map_err(CreateDriftCheckJobError::Sign)?;
        envelopes.push(TaskEnvelope {
            job_id: JobId::new(input.job_id.clone()).map_err(CreateDriftCheckJobError::Domain)?,
            task_id: TaskId::new(format!("{}-task-{index}", input.job_id))
                .map_err(CreateDriftCheckJobError::Domain)?,
            target_agent_id: target.agent_id.clone(),
            issued_at: input.issued_at,
            expires_at: TaskExpiry::new(input.expires_at),
            nonce: TaskNonce::new(format!("{}-{index}", input.nonce_prefix))
                .map_err(CreateDriftCheckJobError::Domain)?,
            payload_hash,
            signature: Some(
                TaskSignature::new(signature).map_err(CreateDriftCheckJobError::Domain)?,
            ),
        });
    }

    Ok(DriftJobParts {
        job,
        task,
        targets,
        envelopes,
        approval_requirement,
    })
}

pub(super) struct JobAuditInput {
    job_id: String,
    actor: String,
    approval_id: String,
    expires_at: SystemTime,
    issued_at: SystemTime,
    kind: AuditJobKind,
}
enum AuditJobKind {
    Drift,
    Runbook { confirmed: bool },
}

impl JobAuditInput {
    pub(super) fn drift(input: &CreateDriftCheckJobInput) -> Self {
        Self {
            job_id: input.job_id.clone(),
            actor: input.created_by.clone(),
            approval_id: input.approval_request_id.clone(),
            expires_at: input.approval_expires_at,
            issued_at: input.issued_at,
            kind: AuditJobKind::Drift,
        }
    }
    pub(super) fn runbook(input: &CreateRunbookJobInput) -> Self {
        Self {
            job_id: input.job_id.clone(),
            actor: input.confirmed_by.clone(),
            approval_id: input.approval_request_id.clone(),
            expires_at: input.approval_expires_at,
            issued_at: input.issued_at,
            kind: AuditJobKind::Runbook {
                confirmed: input.confirmed_high_risk,
            },
        }
    }
    pub(super) fn approval(
        &self,
        requirement: fleet_domain::ApprovalRequirement,
    ) -> Result<Option<ApprovalRequestRecord>, JobError> {
        if requirement == fleet_domain::ApprovalRequirement::NotRequired {
            return Ok(None);
        }
        let reason = match self.kind {
            AuditJobKind::Drift => "broad drift check requires manual approval",
            AuditJobKind::Runbook { .. } => "runbook execution requires manual approval",
        };
        let approval = ApprovalRequest::new(
            ApprovalId::new(self.approval_id.clone())?,
            JobId::new(self.job_id.clone())?,
            self.actor.clone(),
            reason,
            self.expires_at,
            self.issued_at,
        )?;
        Ok(Some(approval_request_to_record(&approval)))
    }
    pub(super) fn requested_audit(
        &self,
        approval: &ApprovalRequestRecord,
        count: usize,
    ) -> AuditEvent {
        let value = match self.kind {
            AuditJobKind::Drift => format!(
                "approval_id={},reason={},target_count={}",
                approval.id, approval.reason, count
            ),
            AuditJobKind::Runbook { confirmed } => format!(
                "approval_id={},reason={},confirmed_high_risk={},target_count={}",
                approval.id, approval.reason, confirmed, count
            ),
        };
        AuditEvent {
            category: AuditCategory::Approval,
            action: "approval_requested".to_owned(),
            actor: AuditActor::new(self.actor.clone()),
            target: AuditTarget::new(self.job_id.clone()),
            value: AuditValue::Plain(value),
            occurred_at: self.issued_at,
        }
    }
    pub(super) fn created_audit(&self, count: usize) -> AuditEvent {
        let (category, action, value) = match self.kind {
            AuditJobKind::Drift => (
                AuditCategory::Drift,
                "drift_check_job_created",
                format!("created_by={},target_count={}", self.actor, count),
            ),
            AuditJobKind::Runbook { confirmed } => (
                AuditCategory::Job,
                "runbook_job_created",
                format!(
                    "confirmed_high_risk={},confirmed_by={},target_count={}",
                    confirmed, self.actor, count
                ),
            ),
        };
        AuditEvent {
            category,
            action: action.to_owned(),
            actor: AuditActor::new(self.actor.clone()),
            target: AuditTarget::new(self.job_id.clone()),
            value: AuditValue::Plain(value),
            occurred_at: self.issued_at,
        }
    }
}

/// The two existing document execution kinds; construction of their effects remains private.
pub enum PreparedStructuredTask {
    DriftCheck(DriftCheckTask),
    Runbook(RunbookExecutionTask),
}

pub struct PreparedStructuredJob {
    job: Job,
    task: PreparedStructuredTask,
    envelopes: Vec<TaskEnvelope>,
    target_count: usize,
    provenance: Option<DriftJobProvenance>,
    approval: Option<ApprovalRequestRecord>,
    audits: Vec<AuditEvent>,
    actor_id: String,
}
impl PreparedStructuredJob {
    pub fn job(&self) -> &Job {
        &self.job
    }
    pub fn task(&self) -> &PreparedStructuredTask {
        &self.task
    }
    pub fn assignments(&self) -> &[TaskEnvelope] {
        &self.envelopes
    }
    pub fn provenance(&self) -> Option<&DriftJobProvenance> {
        self.provenance.as_ref()
    }
    pub fn approval(&self) -> Option<&ApprovalRequestRecord> {
        self.approval.as_ref()
    }
    pub fn audits(&self) -> &[AuditEvent] {
        &self.audits
    }
    /// Must run inside the transaction that commits every supplied effect.
    pub fn authorize<R: AdminWriteRead + ?Sized>(
        &self,
        repository: &R,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
    ) -> Result<(), AdminAccessError> {
        let actor = AuthorizeAdminWrite::execute(
            repository,
            principal,
            operation,
            fleet_domain::AdminPermission::JobCreate,
        )?;
        if actor.as_str() != self.actor_id {
            return Err(AdminAccessError::Unauthorized);
        }
        Ok(())
    }
    fn drift<S: TaskEnvelopeSigner>(
        signer: &mut S,
        input: CreateDriftCheckJobInput,
    ) -> Result<Self, CreateDriftCheckJobError<Infallible, Infallible, S::Error>> {
        let audit = JobAuditInput::drift(&input);
        let parts = prepare_drift_parts(&input, signer)?;
        let approval = audit
            .approval(parts.approval_requirement)
            .map_err(CreateDriftCheckJobError::Domain)?;
        let mut audits = Vec::new();
        if let Some(record) = &approval {
            audits.push(audit.requested_audit(record, parts.targets.len()));
        }
        audits.push(audit.created_audit(parts.targets.len()));
        Ok(Self {
            job: parts.job,
            task: PreparedStructuredTask::DriftCheck(parts.task),
            envelopes: parts.envelopes,
            target_count: parts.targets.len(),
            provenance: input.provenance,
            approval,
            audits,
            actor_id: input.created_by,
        })
    }
    fn runbook<S: TaskEnvelopeSigner>(
        signer: &mut S,
        input: CreateRunbookJobInput,
    ) -> Result<Self, CreateRunbookJobError<Infallible, Infallible, S::Error>> {
        let audit = JobAuditInput::runbook(&input);
        let mut signed = build_signed_runbook_job(
            signer,
            BuildSignedRunbookJobInput {
                job_id: input.job_id,
                target_agent_ids: input.target_agent_ids,
                runbook_document: input.runbook_document,
                timeout: input.timeout,
                issued_at: input.issued_at,
                expires_at: input.expires_at,
                nonce_prefix: input.nonce_prefix,
            },
        )
        .map_err(map_create_runbook_job_error)?;
        if signed.approval_requirement == fleet_domain::ApprovalRequirement::NotRequired {
            signed
                .job
                .queue(false)
                .map_err(CreateRunbookJobError::Domain)?;
        }
        let approval = audit
            .approval(signed.approval_requirement)
            .map_err(CreateRunbookJobError::Domain)?;
        let mut audits = Vec::new();
        if let Some(record) = &approval {
            audits.push(audit.requested_audit(record, signed.targets.len()));
        }
        audits.push(audit.created_audit(signed.targets.len()));
        Ok(Self {
            job: signed.job,
            task: PreparedStructuredTask::Runbook(signed.task),
            envelopes: signed.envelopes,
            target_count: signed.targets.len(),
            provenance: None,
            approval,
            audits,
            actor_id: input.confirmed_by,
        })
    }
}

pub struct AuthorizedJobCreationOutput {
    pub target_count: usize,
    pub assignment_count: usize,
    pub approval_request: Option<ApprovalRequestRecord>,
}

/// Identity and Job/assignment/provenance/approval/audit/settings share one commit.
/// Signatures are already prepared; no sequential fallback or dispatch is permitted.
pub trait AdminStructuredJobRepository {
    type Error;
    fn commit_admin_structured_job(
        &mut self,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        creation: &PreparedStructuredJob,
        metadata: &JobCreationMetadata,
    ) -> Result<(), AdminJobCommitError<Self::Error>>;
}

#[derive(Debug)]
pub enum AdminStructuredJobError<R, S> {
    Drift(CreateDriftCheckJobError<Infallible, Infallible, S>),
    Runbook(CreateRunbookJobError<Infallible, Infallible, S>),
    Commit(AdminJobCommitError<R>),
    Operation(AdminAccessError),
}
impl<R, S> Display for AdminStructuredJobError<R, S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("structured Job preparation or protected commit failed")
    }
}
impl<R: Debug, S: Debug> std::error::Error for AdminStructuredJobError<R, S> {}

fn commit_prepared<R: AdminStructuredJobRepository, S>(
    repository: &mut R,
    principal: &AdminMutationPrincipal,
    operation: &dyn AdminOperation,
    creation: PreparedStructuredJob,
    metadata: &JobCreationMetadata,
) -> Result<AuthorizedJobCreationOutput, AdminStructuredJobError<R::Error, S>> {
    operation
        .checked_now()
        .map_err(AdminStructuredJobError::Operation)?;
    repository
        .commit_admin_structured_job(principal, operation, &creation, metadata)
        .map_err(AdminStructuredJobError::Commit)?;
    Ok(AuthorizedJobCreationOutput {
        target_count: creation.target_count,
        assignment_count: creation.envelopes.len(),
        approval_request: creation.approval,
    })
}
pub struct CreateAuthorizedStructuredJob;
impl CreateAuthorizedStructuredJob {
    pub fn drift<R: AdminStructuredJobRepository, S: TaskEnvelopeSigner>(
        repository: &mut R,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        signer: &mut S,
        mut input: CreateDriftCheckJobInput,
        metadata: &JobCreationMetadata,
    ) -> Result<AuthorizedJobCreationOutput, AdminStructuredJobError<R::Error, S::Error>> {
        let operation = OrderedAdminOperation::new(operation);
        operation
            .checked_now()
            .map_err(AdminStructuredJobError::Operation)?;
        input.created_by = principal.actor_id().to_owned();
        let creation =
            PreparedStructuredJob::drift(signer, input).map_err(AdminStructuredJobError::Drift)?;
        commit_prepared(repository, principal, &operation, creation, metadata)
    }
    pub fn runbook<R: AdminStructuredJobRepository, S: TaskEnvelopeSigner>(
        repository: &mut R,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        signer: &mut S,
        mut input: CreateRunbookJobInput,
        metadata: &JobCreationMetadata,
    ) -> Result<AuthorizedJobCreationOutput, AdminStructuredJobError<R::Error, S::Error>> {
        let operation = OrderedAdminOperation::new(operation);
        operation
            .checked_now()
            .map_err(AdminStructuredJobError::Operation)?;
        input.confirmed_by = principal.actor_id().to_owned();
        let creation = PreparedStructuredJob::runbook(signer, input)
            .map_err(AdminStructuredJobError::Runbook)?;
        commit_prepared(repository, principal, &operation, creation, metadata)
    }
}
