//! Command preparation and canonical creation orchestration. Signatures precede the
//! required protected transaction port; this module owns no direct store or transport I/O.

use super::*;
use crate::admin_identity::{
    AdminAccessError, AdminMutationPrincipal, AdminOperation, AdminWriteRead, AuthorizeAdminWrite,
    OrderedAdminOperation,
};
use std::convert::Infallible;

/// Immutable selector/strategy origin accompanying one canonical Job creation.
/// The source is the interface's existing serialized metadata, never execution authority.
pub struct JobCreationMetadata {
    concurrency: u32,
    max_failures: Option<u32>,
    selector_kind: String,
    selector_source: String,
}

impl JobCreationMetadata {
    pub fn new(
        concurrency: u32,
        max_failures: Option<u32>,
        kind: &str,
        source: String,
    ) -> Result<Self, AdminAccessError> {
        if concurrency == 0
            || max_failures == Some(0)
            || source.is_empty()
            || !matches!(
                kind,
                "explicit_ids"
                    | "selector"
                    | "matchLabels"
                    | "resolved_ids"
                    | "runbook_selector"
                    | "runbook_matchLabels"
            )
        {
            return Err(AdminAccessError::InvalidRequest);
        }
        Ok(Self {
            concurrency,
            max_failures,
            selector_kind: kind.to_owned(),
            selector_source: source,
        })
    }
    pub fn concurrency(&self) -> u32 {
        self.concurrency
    }
    pub fn max_failures(&self) -> Option<u32> {
        self.max_failures
    }
    pub fn selector_kind(&self) -> &str {
        &self.selector_kind
    }
    pub fn selector_source(&self) -> &str {
        &self.selector_source
    }
}

/// Command consumers retain their existing type name; all Job kinds share this metadata.
pub type CommandCreationMetadata = JobCreationMetadata;

/// Prepared effects have private construction and no persistence or dispatch authority.
pub struct PreparedCommandJob {
    parts: CommandJobParts,
    approval: Option<ApprovalRequestRecord>,
    audits: Vec<AuditEvent>,
    actor_id: String,
}

impl PreparedCommandJob {
    pub fn job(&self) -> &Job {
        &self.parts.job
    }
    pub fn task(&self) -> &CommandTask {
        &self.parts.task
    }
    pub fn assignments(&self) -> &[TaskEnvelope] {
        &self.parts.envelopes
    }
    pub fn approval(&self) -> Option<&ApprovalRequestRecord> {
        self.approval.as_ref()
    }
    pub fn audits(&self) -> &[AuditEvent] {
        &self.audits
    }

    /// Adapters must call this within the same serialized transaction as all effects.
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

    fn prepare<S: TaskEnvelopeSigner>(
        signer: &mut S,
        input: CreateCommandJobInput,
    ) -> Result<Self, CreateCommandJobError<Infallible, Infallible, S::Error>> {
        let parts = prepare_parts::<Infallible, Infallible, S>(&input, signer)?;
        let approval = prepare_approval(&input, parts.approval_requirement)
            .map_err(CreateCommandJobError::Domain)?;
        let mut audits = Vec::new();
        if let Some(record) = &approval {
            audits.push(approval_audit(&input, record, parts.targets.len()));
        }
        audits.push(creation_audit(&input, parts.targets.len()));
        Ok(Self {
            parts,
            approval,
            audits,
            actor_id: input.confirmed_by,
        })
    }

    fn into_output(self) -> CreateCommandJobOutput {
        CreateCommandJobOutput {
            task: self.parts.task,
            targets: self.parts.targets,
            envelopes: self.parts.envelopes,
            approval_request: self.approval,
        }
    }
}

#[derive(Debug)]
pub enum AdminJobCommitError<E> {
    Authorization(AdminAccessError),
    DuplicateJob,
    Repository(E),
}

impl<E> Display for AdminJobCommitError<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Authorization(_) => "job authorization rejected",
            Self::DuplicateJob => "job already exists",
            Self::Repository(_) => "job persistence unavailable",
        })
    }
}
impl<E: Debug> std::error::Error for AdminJobCommitError<E> {}

/// Existing Command consumers use the same classified canonical-commit failures.
pub type AdminCommandCommitError<E> = AdminJobCommitError<E>;

/// No sequential fallback: authority and every supplied Job/assignment/approval/audit/
/// selector/strategy effect must commit or roll back together. Never dispatch here.
pub trait AdminCommandJobRepository {
    type Error;
    fn commit_admin_command_job(
        &mut self,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        creation: &PreparedCommandJob,
        metadata: &CommandCreationMetadata,
    ) -> Result<(), AdminCommandCommitError<Self::Error>>;
}

#[derive(Debug)]
pub enum CreateAuthorizedCommandJobError<R, S> {
    Preparation(CreateCommandJobError<Infallible, Infallible, S>),
    Commit(AdminCommandCommitError<R>),
    Operation(AdminAccessError),
}

impl<R, S> Display for CreateAuthorizedCommandJobError<R, S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Preparation(_) => "command preparation failed",
            Self::Commit(_) => "command commit failed",
            Self::Operation(_) => "command operation expired or unavailable",
        })
    }
}
impl<R: Debug, S: Debug> std::error::Error for CreateAuthorizedCommandJobError<R, S> {}

pub struct CreateAuthorizedCommandJob;

impl CreateAuthorizedCommandJob {
    /// Prepares signatures outside the transaction and derives every human audit actor
    /// from the authenticated principal. Only the repository's canonical guard authorizes commit.
    pub fn execute<R: AdminCommandJobRepository, S: TaskEnvelopeSigner>(
        repository: &mut R,
        principal: &AdminMutationPrincipal,
        operation: &dyn AdminOperation,
        signer: &mut S,
        mut input: CreateCommandJobInput,
        metadata: &CommandCreationMetadata,
    ) -> Result<CreateCommandJobOutput, CreateAuthorizedCommandJobError<R::Error, S::Error>> {
        let ordered = OrderedAdminOperation::new(operation);
        let operation: &dyn AdminOperation = &ordered;
        operation
            .checked_now()
            .map_err(CreateAuthorizedCommandJobError::Operation)?;
        input.confirmed_by = principal.actor_id().to_owned();
        let prepared = PreparedCommandJob::prepare(signer, input)
            .map_err(CreateAuthorizedCommandJobError::Preparation)?;
        operation
            .checked_now()
            .map_err(CreateAuthorizedCommandJobError::Operation)?;
        repository
            .commit_admin_command_job(principal, operation, &prepared, metadata)
            .map_err(CreateAuthorizedCommandJobError::Commit)?;
        Ok(prepared.into_output())
    }
}

pub(super) fn prepare_approval(
    input: &CreateCommandJobInput,
    requirement: fleet_domain::ApprovalRequirement,
) -> Result<Option<ApprovalRequestRecord>, JobError> {
    if requirement == fleet_domain::ApprovalRequirement::NotRequired {
        return Ok(None);
    }
    let approval = ApprovalRequest::new(
        ApprovalId::new(input.approval_request_id.clone())?,
        JobId::new(input.job_id.clone())?,
        input.confirmed_by.clone(),
        "high-risk command requires manual approval",
        input.approval_expires_at,
        input.issued_at,
    )?;
    Ok(Some(approval_request_to_record(&approval)))
}

pub(super) fn approval_audit(
    input: &CreateCommandJobInput,
    record: &ApprovalRequestRecord,
    target_count: usize,
) -> AuditEvent {
    AuditEvent {
        category: AuditCategory::Approval,
        action: "approval_requested".to_owned(),
        actor: AuditActor::new(input.confirmed_by.clone()),
        target: AuditTarget::new(input.job_id.clone()),
        value: AuditValue::Plain(format!(
            "approval_id={},reason={},confirmed_high_risk={},target_count={}",
            record.id, record.reason, input.confirmed_high_risk, target_count
        )),
        occurred_at: input.issued_at,
    }
}

pub(super) fn creation_audit(input: &CreateCommandJobInput, target_count: usize) -> AuditEvent {
    AuditEvent {
        category: AuditCategory::Job,
        action: "job_created".to_owned(),
        actor: AuditActor::new(input.confirmed_by.clone()),
        target: AuditTarget::new(input.job_id.clone()),
        value: AuditValue::Plain(format!(
            "confirmed_high_risk={},confirmed_by={},target_count={}",
            input.confirmed_high_risk, input.confirmed_by, target_count
        )),
        occurred_at: input.issued_at,
    }
}

pub(super) struct CommandJobParts {
    pub(super) job: Job,
    pub(super) task: CommandTask,
    pub(super) targets: Vec<JobTarget>,
    pub(super) envelopes: Vec<TaskEnvelope>,
    pub(super) approval_requirement: fleet_domain::ApprovalRequirement,
}

pub(super) fn prepare_parts<R, A, S: TaskEnvelopeSigner>(
    input: &CreateCommandJobInput,
    signer: &mut S,
) -> Result<CommandJobParts, CreateCommandJobError<R, A, S::Error>> {
    if input.target_agent_ids.is_empty() {
        return Err(CreateCommandJobError::NoTargets);
    }

    let task = CommandTask::new(input.program.clone(), input.args.clone(), input.timeout)
        .map_err(CreateCommandJobError::Domain)?;
    let task_kind = TaskKind::Command(task.clone());
    let approval_requirement =
        approval_requirement_for_task(&task_kind, input.target_agent_ids.len());
    let mut job = Job::new(
        JobId::new(input.job_id.clone()).map_err(CreateCommandJobError::Domain)?,
        task.risk(),
        approval_requirement,
        input.timeout,
    );
    if approval_requirement == fleet_domain::ApprovalRequirement::NotRequired {
        job.queue(false).map_err(CreateCommandJobError::Domain)?;
    }

    let targets = input
        .target_agent_ids
        .iter()
        .map(|id| {
            AgentId::new(id.clone())
                .map(|agent_id| JobTarget { agent_id })
                .map_err(CreateCommandJobError::Agent)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut envelopes = Vec::with_capacity(targets.len());
    for (index, target) in targets.iter().enumerate() {
        let payload_hash = command_payload_hash(&task, target, index);
        let signature = signer
            .sign(&payload_hash)
            .map_err(CreateCommandJobError::Sign)?;
        envelopes.push(TaskEnvelope {
            job_id: JobId::new(input.job_id.clone()).map_err(CreateCommandJobError::Domain)?,
            task_id: TaskId::new(format!("{}-task-{index}", input.job_id))
                .map_err(CreateCommandJobError::Domain)?,
            target_agent_id: target.agent_id.clone(),
            issued_at: input.issued_at,
            expires_at: TaskExpiry::new(input.expires_at),
            nonce: TaskNonce::new(format!("{}-{index}", input.nonce_prefix))
                .map_err(CreateCommandJobError::Domain)?,
            payload_hash,
            signature: Some(TaskSignature::new(signature).map_err(CreateCommandJobError::Domain)?),
        });
    }

    Ok(CommandJobParts {
        job,
        task,
        targets,
        envelopes,
        approval_requirement,
    })
}
