//! Agent journal and Controller inbox report-persistence boundary. No transport,
//! SQL, filesystem, or clock I/O. Implementations must commit reports before
//! returning success and must never treat a socket write as permission to delete one.

use crate::{
    ArtifactStoreRecord, JobOutputStream, PersistVerifiedDriftProposalInput,
    RemediationRequestRecord,
};
use fleet_domain::delivery::{
    ExecutionRecord, JournalCapacity, ReportClass, ReportDigest, ReportKey,
};
use fleet_domain::{
    AssignmentStatus, AuditEvent, DriftReport, DriftReportProvenance, RenderedArtifactMetadata,
};
use std::fmt::{Debug, Display, Formatter};

/// Controller delivery identity is durable state, not a signing-key or TLS
/// fingerprint. The namespace survives key rotation and backup restore; the
/// epoch changes on explicit restore so old receipts cannot be replayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerDeliveryIdentity {
    pub namespace: String,
    pub store_epoch: String,
}

pub trait ControllerDeliveryIdentityRepository {
    type Error;

    fn controller_delivery_identity(&self) -> Result<ControllerDeliveryIdentity, Self::Error>;
    fn rotate_controller_store_epoch(&mut self) -> Result<ControllerDeliveryIdentity, Self::Error>;
}

pub struct RotateControllerStoreEpoch;

impl RotateControllerStoreEpoch {
    /// Restore-only use case; signing-key rotation must not call it.
    pub fn execute<R: ControllerDeliveryIdentityRepository>(
        repository: &mut R,
    ) -> Result<ControllerDeliveryIdentity, R::Error> {
        repository.rotate_controller_store_epoch()
    }
}

/// Incoming encoded report bytes. Staging is not effect commit or ACK authority.
#[derive(Clone, PartialEq, Eq)]
pub struct ControllerInboxReport {
    pub key: ReportKey,
    pub class: ReportClass,
    body: Vec<u8>,
}

impl ControllerInboxReport {
    pub fn new(key: ReportKey, class: ReportClass, body: Vec<u8>) -> Self {
        Self { key, class, body }
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl Debug for ControllerInboxReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControllerInboxReport")
            .field("class", &self.class)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// `AlreadyCommitted` is a repository assertion that prior required effects
/// committed, not something inferred from Assignment terminal status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboxStageOutcome {
    StagedPendingEffects,
    DuplicatePendingEffects,
    AlreadyCommitted,
    ConflictingBody,
    CapacityExceeded,
}

pub trait ControllerInboxRepository {
    type Error;

    fn stage_report(
        &mut self,
        report: &ControllerInboxReport,
    ) -> Result<InboxStageOutcome, Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboxAdmissionError<E> {
    ControllerMismatch,
    AgentMismatch,
    InvalidBody,
    BodyTooLarge,
    Repository(E),
}

pub struct StageControllerInboxReport;

impl StageControllerInboxReport {
    /// The authenticated Agent and local namespace must come from session and
    /// bootstrap state, never from the received body. No outcome is an ACK yet.
    pub fn execute<R: ControllerInboxRepository>(
        repository: &mut R,
        authenticated_agent_id: &str,
        controller_namespace: &str,
        max_body_bytes: usize,
        report: &ControllerInboxReport,
    ) -> Result<InboxStageOutcome, InboxAdmissionError<R::Error>> {
        let [controller, agent, _, _, _] = report.key.parts();
        if controller != controller_namespace || controller_namespace.is_empty() {
            return Err(InboxAdmissionError::ControllerMismatch);
        }
        if agent != authenticated_agent_id || authenticated_agent_id.is_empty() {
            return Err(InboxAdmissionError::AgentMismatch);
        }
        if report.body().is_empty() {
            return Err(InboxAdmissionError::InvalidBody);
        }
        if max_body_bytes == 0 || report.body().len() > max_body_bytes {
            return Err(InboxAdmissionError::BodyTooLarge);
        }
        repository
            .stage_report(report)
            .map_err(InboxAdmissionError::Repository)
    }
}

/// Pending final-result bytes are recovery work, never storage-receipt
/// authority. Implementations must return exact persisted bytes in stable
/// order and reject corruption rather than silently skipping a report.
pub trait ControllerInboxFinalRecoveryRepository {
    type Error;

    fn load_pending_final_reports(
        &self,
        limit: u32,
    ) -> Result<Vec<ControllerInboxReport>, Self::Error>;
}

pub struct LoadPendingFinalReports;

impl LoadPendingFinalReports {
    /// A bounded scan may be repeated after a crash; reading alone must not
    /// change inbox state or imply that a final effect was committed.
    pub fn execute<R: ControllerInboxFinalRecoveryRepository>(
        repository: &R,
        limit: u32,
    ) -> Result<Vec<ControllerInboxReport>, R::Error> {
        repository.load_pending_final_reports(limit)
    }
}

/// A final effect already committed to the inbox but not yet represented by
/// durable receipt bytes. Reconciliation may issue its receipt, never reapply
/// the final effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedFinalReportMissingReceipt {
    pub key: ReportKey,
    pub digest: ReportDigest,
}

pub trait ControllerCommittedFinalReceiptRecoveryRepository {
    type Error;

    fn load_committed_final_reports_missing_receipt(
        &self,
        limit: u32,
    ) -> Result<Vec<CommittedFinalReportMissingReceipt>, Self::Error>;
}

pub struct LoadCommittedFinalReportsMissingReceipt;

impl LoadCommittedFinalReportsMissingReceipt {
    /// A bounded scan returns only committed identities/digests. It grants no
    /// effect authority and never reads or reconstructs the original body.
    pub fn execute<R: ControllerCommittedFinalReceiptRecoveryRepository>(
        repository: &R,
        limit: u32,
    ) -> Result<Vec<CommittedFinalReportMissingReceipt>, R::Error> {
        repository.load_committed_final_reports_missing_receipt(limit)
    }
}

/// Parsed output effect accompanied by the exact bytes already staged. The
/// repository compares those bytes before atomically committing the effect.
#[derive(Clone, PartialEq, Eq)]
pub struct ControllerInboxOutputEffect {
    pub key: ReportKey,
    encoded_report: Vec<u8>,
    pub stream: JobOutputStream,
    pub sequence: u64,
    output_body: String,
}

impl ControllerInboxOutputEffect {
    pub fn new(
        key: ReportKey,
        encoded_report: Vec<u8>,
        stream: JobOutputStream,
        sequence: u64,
        output_body: String,
    ) -> Self {
        Self {
            key,
            encoded_report,
            stream,
            sequence,
            output_body,
        }
    }

    pub fn encoded_report(&self) -> &[u8] {
        &self.encoded_report
    }
    pub fn output_body(&self) -> &str {
        &self.output_body
    }
}

impl Debug for ControllerInboxOutputEffect {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControllerInboxOutputEffect")
            .field("stream", &self.stream)
            .field("sequence", &self.sequence)
            .field("encoded_bytes", &self.encoded_report.len())
            .field("output_bytes", &self.output_body.len())
            .finish_non_exhaustive()
    }
}

/// A committed effect or G2 late-report disposition is not an Agent ACK by itself:
/// receipt signing and authenticated transport must still succeed before cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboxEffectOutcome {
    Committed(ReportDigest),
    /// A matching late report was durably dispositioned after G2 recovery or
    /// cancellation of a dispatched Assignment. Its canonical terminal state,
    /// reason and Job aggregate remain unchanged; this is not execution success.
    LateDispositionCommitted(ReportDigest),
    AlreadyCommitted(ReportDigest),
    ConflictingBody,
    NotStaged,
}

/// Opaque signed receipt bytes paired with their durable inbox owner. The
/// Controller interface must validate the wire shape and signature before
/// constructing this record; storage independently checks committed state.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredReportReceipt {
    key: ReportKey,
    digest: ReportDigest,
    store_epoch: String,
    signer_fingerprint: String,
    encoded_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredReceiptError {
    InvalidEpoch,
    InvalidSigner,
    InvalidBody,
}

impl Display for StoredReceiptError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            Self::InvalidEpoch => "invalid stored receipt epoch",
            Self::InvalidSigner => "invalid stored receipt signer",
            Self::InvalidBody => "invalid stored receipt body",
        };
        formatter.write_str(reason)
    }
}

impl std::error::Error for StoredReceiptError {}

impl StoredReportReceipt {
    pub fn new(
        key: ReportKey,
        digest: ReportDigest,
        store_epoch: String,
        signer_fingerprint: String,
        encoded_bytes: Vec<u8>,
    ) -> Result<Self, StoredReceiptError> {
        if store_epoch.trim().is_empty()
            || store_epoch.len() > 256
            || store_epoch.chars().any(char::is_control)
        {
            return Err(StoredReceiptError::InvalidEpoch);
        }
        if signer_fingerprint.len() != 64
            || !signer_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(StoredReceiptError::InvalidSigner);
        }
        if encoded_bytes.is_empty() || encoded_bytes.len() > 8192 {
            return Err(StoredReceiptError::InvalidBody);
        }
        Ok(Self {
            key,
            digest,
            store_epoch,
            signer_fingerprint,
            encoded_bytes,
        })
    }

    pub fn key(&self) -> &ReportKey {
        &self.key
    }

    pub fn digest(&self) -> ReportDigest {
        self.digest
    }

    pub fn store_epoch(&self) -> &str {
        &self.store_epoch
    }

    pub fn signer_fingerprint(&self) -> &str {
        &self.signer_fingerprint
    }

    pub fn encoded_bytes(&self) -> &[u8] {
        &self.encoded_bytes
    }
}

impl Debug for StoredReportReceipt {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredReportReceipt")
            .field("encoded_bytes", &self.encoded_bytes.len())
            .finish_non_exhaustive()
    }
}

/// Same-epoch, same-signer `AlreadyStored` bytes are authoritative for exact
/// retries. A changed signer may replace the row only for the same committed
/// report digest; the Controller caller must have signed and verified the
/// replacement with its active identity before calling the repository.
#[derive(Clone, PartialEq, Eq)]
pub enum StoredReceiptOutcome {
    Stored(Vec<u8>),
    AlreadyStored(Vec<u8>),
    NotCommitted,
    ConflictingDigest,
    StaleEpoch,
    SigningKeyChanged,
}

impl Debug for StoredReceiptOutcome {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stored(bytes) => formatter.debug_tuple("Stored").field(&bytes.len()).finish(),
            Self::AlreadyStored(bytes) => formatter
                .debug_tuple("AlreadyStored")
                .field(&bytes.len())
                .finish(),
            Self::NotCommitted => formatter.write_str("NotCommitted"),
            Self::ConflictingDigest => formatter.write_str("ConflictingDigest"),
            Self::StaleEpoch => formatter.write_str("StaleEpoch"),
            Self::SigningKeyChanged => formatter.write_str("SigningKeyChanged"),
        }
    }
}

pub trait ControllerStoredReceiptRepository {
    type Error;

    /// Stores a verified receipt for a committed, exact report. Same-signer
    /// retries return the original bytes; a new active signer may replace old
    /// bytes only without changing namespace/epoch/key/digest or report effects.
    fn persist_stored_receipt(
        &mut self,
        receipt: &StoredReportReceipt,
    ) -> Result<StoredReceiptOutcome, Self::Error>;
}

pub struct PersistControllerStoredReceipt;

impl PersistControllerStoredReceipt {
    pub fn execute<R: ControllerStoredReceiptRepository>(
        repository: &mut R,
        receipt: &StoredReportReceipt,
    ) -> Result<StoredReceiptOutcome, R::Error> {
        repository.persist_stored_receipt(receipt)
    }
}

pub trait ControllerInboxOutputRepository {
    type Error;

    fn commit_output_effect(
        &mut self,
        effect: &ControllerInboxOutputEffect,
    ) -> Result<InboxEffectOutcome, Self::Error>;
}

pub struct CommitControllerInboxOutput;

impl CommitControllerInboxOutput {
    pub fn execute<R: ControllerInboxOutputRepository>(
        repository: &mut R,
        effect: &ControllerInboxOutputEffect,
    ) -> Result<InboxEffectOutcome, R::Error> {
        repository.commit_output_effect(effect)
    }
}

/// Parsed task-accepted effect paired with the exact bytes staged in the inbox.
#[derive(Clone, PartialEq, Eq)]
pub struct ControllerInboxTaskAckEffect {
    pub key: ReportKey,
    encoded_report: Vec<u8>,
    pub occurred_at: std::time::SystemTime,
}

impl ControllerInboxTaskAckEffect {
    pub fn new(
        key: ReportKey,
        encoded_report: Vec<u8>,
        occurred_at: std::time::SystemTime,
    ) -> Self {
        Self {
            key,
            encoded_report,
            occurred_at,
        }
    }

    pub fn encoded_report(&self) -> &[u8] {
        &self.encoded_report
    }
}

impl Debug for ControllerInboxTaskAckEffect {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControllerInboxTaskAckEffect")
            .field("encoded_bytes", &self.encoded_report.len())
            .field("occurred_at", &self.occurred_at)
            .finish_non_exhaustive()
    }
}

pub trait ControllerInboxTaskAckRepository {
    type Error;

    fn commit_task_ack_effect(
        &mut self,
        effect: &ControllerInboxTaskAckEffect,
    ) -> Result<InboxEffectOutcome, Self::Error>;
}

pub struct CommitControllerInboxTaskAck;

impl CommitControllerInboxTaskAck {
    pub fn execute<R: ControllerInboxTaskAckRepository>(
        repository: &mut R,
        effect: &ControllerInboxTaskAckEffect,
    ) -> Result<InboxEffectOutcome, R::Error> {
        repository.commit_task_ack_effect(effect)
    }
}

/// Parsed task-started effect paired with the exact bytes staged in the inbox.
#[derive(Clone, PartialEq, Eq)]
pub struct ControllerInboxTaskStartedEffect {
    pub key: ReportKey,
    encoded_report: Vec<u8>,
    pub occurred_at: std::time::SystemTime,
    pub remediation: Option<RemediationRequestRecord>,
    pub remediation_audit: Option<AuditEvent>,
}

impl ControllerInboxTaskStartedEffect {
    pub fn new(
        key: ReportKey,
        encoded_report: Vec<u8>,
        occurred_at: std::time::SystemTime,
    ) -> Self {
        Self {
            key,
            encoded_report,
            occurred_at,
            remediation: None,
            remediation_audit: None,
        }
    }

    pub fn with_remediation_transition(
        mut self,
        transition: Option<(RemediationRequestRecord, AuditEvent)>,
    ) -> Self {
        if let Some((remediation, audit)) = transition {
            self.remediation = Some(remediation);
            self.remediation_audit = Some(audit);
        }
        self
    }

    pub fn encoded_report(&self) -> &[u8] {
        &self.encoded_report
    }
}

impl Debug for ControllerInboxTaskStartedEffect {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControllerInboxTaskStartedEffect")
            .field("encoded_bytes", &self.encoded_report.len())
            .field("occurred_at", &self.occurred_at)
            .field("has_remediation", &self.remediation.is_some())
            .field("has_remediation_audit", &self.remediation_audit.is_some())
            .finish_non_exhaustive()
    }
}

pub trait ControllerInboxTaskStartedRepository {
    type Error;

    fn commit_task_started_effect(
        &mut self,
        effect: &ControllerInboxTaskStartedEffect,
    ) -> Result<InboxEffectOutcome, Self::Error>;
}

pub struct CommitControllerInboxTaskStarted;

impl CommitControllerInboxTaskStarted {
    pub fn execute<R: ControllerInboxTaskStartedRepository>(
        repository: &mut R,
        effect: &ControllerInboxTaskStartedEffect,
    ) -> Result<InboxEffectOutcome, R::Error> {
        repository.commit_task_started_effect(effect)
    }
}

/// Parsed task-rejected effect paired with the exact bytes staged in the inbox.
/// The interface adapter supplies a redacted reason; storage keeps it on the
/// Assignment so operators can distinguish policy rejection from task failure.
#[derive(Clone, PartialEq, Eq)]
pub struct ControllerInboxTaskRejectedEffect {
    pub key: ReportKey,
    encoded_report: Vec<u8>,
    pub reason_code: String,
    pub reason: String,
    pub occurred_at: std::time::SystemTime,
}

impl ControllerInboxTaskRejectedEffect {
    pub fn new(
        key: ReportKey,
        encoded_report: Vec<u8>,
        reason_code: String,
        reason: String,
        occurred_at: std::time::SystemTime,
    ) -> Self {
        Self {
            key,
            encoded_report,
            reason_code,
            reason,
            occurred_at,
        }
    }

    pub fn encoded_report(&self) -> &[u8] {
        &self.encoded_report
    }
}

impl Debug for ControllerInboxTaskRejectedEffect {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControllerInboxTaskRejectedEffect")
            .field("encoded_bytes", &self.encoded_report.len())
            .field("reason_code", &self.reason_code)
            .field("reason", &"[redacted]")
            .field("occurred_at", &self.occurred_at)
            .finish_non_exhaustive()
    }
}

pub trait ControllerInboxTaskRejectedRepository {
    type Error;

    fn commit_task_rejected_effect(
        &mut self,
        effect: &ControllerInboxTaskRejectedEffect,
    ) -> Result<InboxEffectOutcome, Self::Error>;
}

pub struct CommitControllerInboxTaskRejected;

impl CommitControllerInboxTaskRejected {
    pub fn execute<R: ControllerInboxTaskRejectedRepository>(
        repository: &mut R,
        effect: &ControllerInboxTaskRejectedEffect,
    ) -> Result<InboxEffectOutcome, R::Error> {
        repository.commit_task_rejected_effect(effect)
    }
}

/// Parsed correlated verification evidence and the exact bytes already staged.
/// The Controller must derive provenance from its stored Job/Assignment, never
/// from an Agent-supplied field. Storage rechecks that binding transactionally.
#[derive(Clone, PartialEq, Eq)]
pub struct ControllerInboxEvidenceEffect {
    pub key: ReportKey,
    encoded_report: Vec<u8>,
    pub report: DriftReport,
    pub provenance: DriftReportProvenance,
    pub checked_at: std::time::SystemTime,
    /// Optional proposal prepared from the same verified evidence; Store persists it atomically.
    pub remediation_proposal: Option<PersistVerifiedDriftProposalInput>,
}

impl ControllerInboxEvidenceEffect {
    /// Creates a verified-provenance evidence effect for an exact staged report body.
    pub fn new(
        key: ReportKey,
        encoded_report: Vec<u8>,
        report: DriftReport,
        provenance: DriftReportProvenance,
        checked_at: std::time::SystemTime,
    ) -> Self {
        Self {
            key,
            encoded_report,
            report,
            provenance,
            checked_at,
            remediation_proposal: None,
        }
    }

    /// Includes the candidate remediation proposal in the evidence transaction.
    pub fn with_remediation_proposal(
        mut self,
        proposal: PersistVerifiedDriftProposalInput,
    ) -> Self {
        self.remediation_proposal = Some(proposal);
        self
    }

    pub fn encoded_report(&self) -> &[u8] {
        &self.encoded_report
    }
}

impl Debug for ControllerInboxEvidenceEffect {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControllerInboxEvidenceEffect")
            .field("encoded_bytes", &self.encoded_report.len())
            .finish_non_exhaustive()
    }
}

pub trait ControllerInboxEvidenceRepository {
    type Error;

    fn commit_evidence_effect(
        &mut self,
        effect: &ControllerInboxEvidenceEffect,
    ) -> Result<InboxEffectOutcome, Self::Error>;
}

pub struct CommitControllerInboxEvidence;

impl CommitControllerInboxEvidence {
    pub fn execute<R: ControllerInboxEvidenceRepository>(
        repository: &mut R,
        effect: &ControllerInboxEvidenceEffect,
    ) -> Result<InboxEffectOutcome, R::Error> {
        repository.commit_evidence_effect(effect)
    }
}

/// Parsed final effect. The caller must derive `artifact_count` and prepared
/// bodies from the decoded report. Exact encoded bytes are compared with the
/// inbox before the DB effect can commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Per-stream output chunks committed by the Agent before its final report.
/// This confirms transport coverage, not capture of every byte produced by the process.
pub struct TaskOutputSummary {
    pub stdout_chunks: u64,
    pub stderr_chunks: u64,
    pub truncated: bool,
}

impl TaskOutputSummary {
    /// Builds a summary of committed chunks and whether capture was incomplete.
    pub const fn new(stdout_chunks: u64, stderr_chunks: u64, truncated: bool) -> Self {
        Self {
            stdout_chunks,
            stderr_chunks,
            truncated,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ControllerInboxFinalEffect {
    pub key: ReportKey,
    encoded_report: Vec<u8>,
    pub status: AssignmentStatus,
    pub occurred_at: std::time::SystemTime,
    last_error: Option<String>,
    pub artifact_count: usize,
    prepared_artifacts: Vec<ControllerPreparedArtifact>,
    prepared_remediation: Option<ControllerPreparedRemediation>,
    output_summary: Option<TaskOutputSummary>,
}

/// Pure remediation transition prepared from the stored lifecycle snapshot.
/// The repository rechecks the expected status inside the final transaction.
#[derive(Clone, PartialEq, Eq)]
pub struct ControllerPreparedRemediation {
    expected_status: String,
    pub updated: RemediationRequestRecord,
    pub audit: AuditEvent,
}

impl ControllerPreparedRemediation {
    pub fn new(
        expected_status: impl Into<String>,
        updated: RemediationRequestRecord,
        audit: AuditEvent,
    ) -> Self {
        Self {
            expected_status: expected_status.into(),
            updated,
            audit,
        }
    }

    pub fn expected_status(&self) -> &str {
        &self.expected_status
    }
}

impl Debug for ControllerPreparedRemediation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControllerPreparedRemediation")
            .finish_non_exhaustive()
    }
}

/// Artifact metadata paired with a completed body put. `None` means the
/// decoded report omitted its optional body, not that a body write failed.
#[derive(Clone, PartialEq, Eq)]
pub struct ControllerPreparedArtifact {
    pub metadata: RenderedArtifactMetadata,
    pub stored_body: Option<ArtifactStoreRecord>,
}

impl ControllerPreparedArtifact {
    pub fn new(
        metadata: RenderedArtifactMetadata,
        stored_body: Option<ArtifactStoreRecord>,
    ) -> Self {
        Self {
            metadata,
            stored_body,
        }
    }
}

impl Debug for ControllerPreparedArtifact {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControllerPreparedArtifact")
            .field("body_prepared", &self.stored_body.is_some())
            .finish_non_exhaustive()
    }
}

impl ControllerInboxFinalEffect {
    pub fn new(
        key: ReportKey,
        encoded_report: Vec<u8>,
        status: AssignmentStatus,
        occurred_at: std::time::SystemTime,
        last_error: Option<String>,
        artifact_count: usize,
    ) -> Self {
        Self {
            key,
            encoded_report,
            status,
            occurred_at,
            last_error,
            artifact_count,
            prepared_artifacts: Vec::new(),
            prepared_remediation: None,
            output_summary: None,
        }
    }

    pub fn with_output_summary(mut self, summary: TaskOutputSummary) -> Self {
        self.output_summary = Some(summary);
        self
    }

    pub fn output_summary(&self) -> Option<TaskOutputSummary> {
        self.output_summary
    }

    pub fn with_prepared_remediation(mut self, prepared: ControllerPreparedRemediation) -> Self {
        self.prepared_remediation = Some(prepared);
        self
    }

    pub fn prepared_remediation(&self) -> Option<&ControllerPreparedRemediation> {
        self.prepared_remediation.as_ref()
    }

    pub fn with_prepared_artifacts(mut self, prepared: Vec<ControllerPreparedArtifact>) -> Self {
        self.prepared_artifacts = prepared;
        self
    }

    pub fn prepared_artifacts(&self) -> &[ControllerPreparedArtifact] {
        &self.prepared_artifacts
    }

    pub fn encoded_report(&self) -> &[u8] {
        &self.encoded_report
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }
}

impl Debug for ControllerInboxFinalEffect {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControllerInboxFinalEffect")
            .field("status", &self.status)
            .field("encoded_bytes", &self.encoded_report.len())
            .field("artifact_count", &self.artifact_count)
            .field("output_summary", &self.output_summary)
            .finish_non_exhaustive()
    }
}

pub trait ControllerInboxFinalRepository {
    type Error;

    fn commit_final_effect(
        &mut self,
        effect: &ControllerInboxFinalEffect,
    ) -> Result<InboxEffectOutcome, Self::Error>;
}

pub struct CommitControllerInboxFinal;

impl CommitControllerInboxFinal {
    /// Only the repository's committed outcome establishes final DB effect
    /// durability. Signing and transporting a receipt remain separate steps.
    pub fn execute<R: ControllerInboxFinalRepository>(
        repository: &mut R,
        effect: &ControllerInboxFinalEffect,
    ) -> Result<InboxEffectOutcome, R::Error> {
        repository.commit_final_effect(effect)
    }
}

/// Immutable transport bytes; Debug deliberately omits the body and identifiers.
#[derive(Clone, PartialEq, Eq)]
pub struct JournalReport {
    pub key: ReportKey,
    pub class: ReportClass,
    body: Vec<u8>,
}

impl JournalReport {
    pub fn new(key: ReportKey, class: ReportClass, body: Vec<u8>) -> Result<Self, JournalError> {
        if body.is_empty() {
            return Err(JournalError::InvalidReport);
        }
        Ok(Self { key, class, body })
    }

    /// Exact immutable bytes for transmission, never an operational log field.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Logical quota counts body, UTF-8 identity bytes, digest, and fixed metadata.
    /// SQLite pages/journaling overhead and actual free disk space are additional.
    pub fn accounted_bytes(&self) -> u64 {
        self.body.len() as u64
            + self
                .key
                .parts()
                .iter()
                .map(|part| part.len() as u64)
                .sum::<u64>()
            + 64
    }
}

impl Debug for JournalReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JournalReport")
            .field("class", &self.class)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReport {
    pub report: JournalReport,
    pub digest: ReportDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendReportOutcome {
    Inserted,
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionAdmission {
    New,
    AlreadyRecorded,
}

/// Admission follows signature/target/expiry verification and durable nonce
/// consumption. A nonce consumed before admission failure stays consumed.
/// Only New followed by a successful start-intent commit permits host effects.
/// Reconnection does not recover a live execution; only process bootstrap does.
pub trait AgentExecutionRepository {
    fn admit_execution(
        &mut self,
        record: &ExecutionRecord,
        capacity: JournalCapacity,
    ) -> Result<ExecutionAdmission, JournalError>;
    fn start_execution(&mut self, final_report_key: &ReportKey) -> Result<(), JournalError>;
    /// At most one record; ResultCommitted records are replayed as reports only.
    fn interrupted_execution(&self) -> Result<Option<ExecutionRecord>, JournalError>;
}

pub struct AdmitAgentExecution;

impl AdmitAgentExecution {
    /// A duplicate admission is observation only, never a second execution grant.
    pub fn execute(
        repository: &mut impl AgentExecutionRepository,
        record: &ExecutionRecord,
        capacity: JournalCapacity,
    ) -> Result<ExecutionAdmission, JournalError> {
        repository.admit_execution(record, capacity)
    }
}

pub struct StartAgentExecution;

impl StartAgentExecution {
    /// Caller must hold the live single-task owner and a New admission result.
    pub fn execute(
        repository: &mut impl AgentExecutionRepository,
        key: &ReportKey,
    ) -> Result<(), JournalError> {
        repository.start_execution(key)
    }
}

/// Atomic persistence operations owned by the reporting use cases.
/// Implementations bind to one controller/agent identity for their entire life.
pub trait AgentReportRepository {
    /// Same key/body/class is a no-op even at capacity. Different contents conflict.
    /// Capacity checking and insertion must be in the same durable transaction.
    fn append(
        &mut self,
        report: &JournalReport,
        capacity: JournalCapacity,
    ) -> Result<AppendReportOutcome, JournalError>;

    /// Reads in committed order, bounded by BOTH row count and accounted bytes.
    /// If even the first row cannot fit, return CapacityExceeded rather than starve.
    fn pending(&self, max_reports: u32, max_bytes: u64)
    -> Result<Vec<PendingReport>, JournalError>;

    /// Caller must first authenticate the receipt's sender and durable disposition.
    /// Matching all ownership fields AND digest is required in the delete transaction.
    /// Missing records (including repeated ACKs) return false; mismatch never deletes.
    fn acknowledge(&mut self, key: &ReportKey, digest: ReportDigest) -> Result<bool, JournalError>;
}

pub struct QueueAgentReport;

impl QueueAgentReport {
    /// Returns only after the repository commits; failure grants no send authority.
    pub fn execute(
        repository: &mut impl AgentReportRepository,
        report: &JournalReport,
        capacity: JournalCapacity,
    ) -> Result<AppendReportOutcome, JournalError> {
        repository.append(report, capacity)
    }
}

pub struct ConfirmAgentReport;

impl ConfirmAgentReport {
    /// Commit acknowledgement-driven cleanup, never cleanup based on send success.
    pub fn execute(
        repository: &mut impl AgentReportRepository,
        key: &ReportKey,
        digest: ReportDigest,
    ) -> Result<bool, JournalError> {
        repository.acknowledge(key, digest)
    }
}

/// Deliberately excludes raw DB errors, paths, report bodies, and credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalError {
    InvalidReport,
    IdentityMismatch,
    Conflict,
    CapacityExceeded,
    InvalidReceipt,
    Unavailable,
    Corrupt,
    UnsupportedVersion,
    InsecurePermissions,
    AlreadyOpen,
    ExecutionBusy,
    InvalidExecutionTransition,
    /// A v2 local journal has a started task whose earlier output receipts may have deleted chunks.
    ActiveExecutionNeedsDrain,
}

impl Display for JournalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidReport => "invalid journal report",
            Self::IdentityMismatch => "journal identity mismatch",
            Self::Conflict => "journal report conflict",
            Self::CapacityExceeded => "journal capacity exceeded",
            Self::InvalidReceipt => "journal receipt mismatch",
            Self::Unavailable => "journal storage unavailable",
            Self::Corrupt => "journal data is corrupt",
            Self::UnsupportedVersion => "unsupported journal version",
            Self::InsecurePermissions => "journal requires owner-only permissions",
            Self::AlreadyOpen => "journal is already open",
            Self::ExecutionBusy => "journal already has an unfinished execution",
            Self::InvalidExecutionTransition => "invalid journal execution transition",
            Self::ActiveExecutionNeedsDrain => {
                "active execution must finish before upgrading its journal"
            }
        })
    }
}

impl std::error::Error for JournalError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_evidence_effect_debug_omits_sensitive_body() {
        let key = ReportKey::new("controller", "agent", "job", "task", "evidence").unwrap();
        let effect = ControllerInboxEvidenceEffect::new(
            key,
            b"private-evidence-marker".to_vec(),
            DriftReport {
                policy_name: "policy".into(),
                status: fleet_domain::DriftStatus::Unknown,
                severity: fleet_domain::DriftSeverity::Unknown,
                acknowledgement: fleet_domain::DriftAcknowledgement::Open,
                expected: "private-evidence-marker".into(),
                actual: "private-evidence-marker".into(),
            },
            DriftReportProvenance::uncorrelated(),
            std::time::UNIX_EPOCH,
        );
        assert!(!format!("{effect:?}").contains("private-evidence-marker"));
    }

    #[test]
    fn stored_receipt_record_bounds_bytes_and_redacts_diagnostics() {
        let key = ReportKey::new("controller", "agent", "job", "task", "report").unwrap();
        let build = |epoch: &str, signer: &str, body: Vec<u8>| {
            StoredReportReceipt::new(
                key.clone(),
                ReportDigest([1; 32]),
                epoch.into(),
                signer.into(),
                body,
            )
        };
        assert_eq!(
            build("", &"a".repeat(64), b"receipt".to_vec()),
            Err(StoredReceiptError::InvalidEpoch)
        );
        assert_eq!(
            build("epoch", "bad", b"receipt".to_vec()),
            Err(StoredReceiptError::InvalidSigner)
        );
        assert_eq!(
            build("epoch", &"a".repeat(64), Vec::new()),
            Err(StoredReceiptError::InvalidBody)
        );
        assert_eq!(
            build("epoch", &"a".repeat(64), vec![0; 8193]),
            Err(StoredReceiptError::InvalidBody)
        );
        let record = build(
            "epoch",
            &"a".repeat(64),
            b"sensitive-receipt-marker".to_vec(),
        )
        .unwrap();
        assert!(!format!("{record:?}").contains("sensitive-receipt-marker"));
        assert!(
            !format!(
                "{:?}",
                StoredReceiptOutcome::Stored(b"sensitive-receipt-marker".to_vec())
            )
            .contains("sensitive-receipt-marker")
        );
    }

    struct FakeInbox {
        calls: usize,
        outcome: InboxStageOutcome,
    }

    impl ControllerInboxRepository for FakeInbox {
        type Error = ();

        fn stage_report(
            &mut self,
            _report: &ControllerInboxReport,
        ) -> Result<InboxStageOutcome, ()> {
            self.calls += 1;
            Ok(self.outcome)
        }
    }

    #[test]
    fn inbox_admission_rejects_untrusted_owner_and_oversized_body_before_repository() {
        let key = ReportKey::new("controller", "agent", "job", "task", "report").unwrap();
        let report = ControllerInboxReport::new(key, ReportClass::Output, b"secret-body".to_vec());
        let mut repository = FakeInbox {
            calls: 0,
            outcome: InboxStageOutcome::StagedPendingEffects,
        };
        assert_eq!(
            StageControllerInboxReport::execute(
                &mut repository,
                "other-agent",
                "controller",
                100,
                &report
            ),
            Err(InboxAdmissionError::AgentMismatch)
        );
        assert_eq!(
            StageControllerInboxReport::execute(
                &mut repository,
                "agent",
                "other-controller",
                100,
                &report
            ),
            Err(InboxAdmissionError::ControllerMismatch)
        );
        assert_eq!(
            StageControllerInboxReport::execute(&mut repository, "agent", "controller", 4, &report),
            Err(InboxAdmissionError::BodyTooLarge)
        );
        assert_eq!(repository.calls, 0);
        assert!(!format!("{report:?}").contains("secret-body"));
        let empty = ControllerInboxReport::new(report.key.clone(), ReportClass::Output, Vec::new());
        assert_eq!(
            StageControllerInboxReport::execute(
                &mut repository,
                "agent",
                "controller",
                100,
                &empty
            ),
            Err(InboxAdmissionError::InvalidBody)
        );
        assert_eq!(repository.calls, 0);
    }

    #[test]
    fn inbox_admission_preserves_typed_repository_outcomes_without_inventing_ack() {
        let key = ReportKey::new("controller", "agent", "job", "task", "report").unwrap();
        let report = ControllerInboxReport::new(key, ReportClass::Output, b"body".to_vec());
        for outcome in [
            InboxStageOutcome::StagedPendingEffects,
            InboxStageOutcome::DuplicatePendingEffects,
            InboxStageOutcome::AlreadyCommitted,
            InboxStageOutcome::ConflictingBody,
            InboxStageOutcome::CapacityExceeded,
        ] {
            let mut repository = FakeInbox { calls: 0, outcome };
            assert_eq!(
                StageControllerInboxReport::execute(
                    &mut repository,
                    "agent",
                    "controller",
                    64,
                    &report
                ),
                Ok(outcome)
            );
            assert_eq!(repository.calls, 1);
        }
    }

    #[test]
    fn debug_excludes_report_body_and_empty_report_is_rejected() {
        let key = ReportKey::new("controller", "agent", "job", "task", "report").unwrap();
        assert_eq!(
            JournalReport::new(key.clone(), ReportClass::Output, vec![]),
            Err(JournalError::InvalidReport)
        );
        let report =
            JournalReport::new(key, ReportClass::Output, b"secret-marker".to_vec()).unwrap();
        assert!(!format!("{report:?}").contains("secret-marker"));
        assert!(report.accounted_bytes() > report.body().len() as u64);
    }
}
