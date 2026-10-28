//! SQLite Controller report staging. Pending effects are durable but never ACKed.
//! The inbox keeps exact bytes until effect commit; receipt persistence is a
//! separate step. No raw body enters errors or application logs.

use crate::{
    SqliteStore, StoreError, aggregate_job_status, job_status_to_str, system_time_to_unix_secs,
};
use fleet_application::delivery::{
    CommittedFinalReportMissingReceipt, ControllerCommittedFinalReceiptRecoveryRepository,
    ControllerInboxEvidenceEffect, ControllerInboxEvidenceRepository, ControllerInboxFinalEffect,
    ControllerInboxFinalRecoveryRepository, ControllerInboxFinalRepository,
    ControllerInboxOutputEffect, ControllerInboxOutputRepository, ControllerInboxReport,
    ControllerInboxRepository, ControllerInboxTaskAckEffect, ControllerInboxTaskAckRepository,
    ControllerInboxTaskRejectedEffect, ControllerInboxTaskRejectedRepository,
    ControllerInboxTaskStartedEffect, ControllerInboxTaskStartedRepository, InboxEffectOutcome,
    InboxStageOutcome,
};
use fleet_domain::delivery::{ReportClass, ReportDigest, ReportKey};
use fleet_domain::{
    AssignmentStatus, AuditActor, AuditCategory, AuditEvent, AuditTarget, AuditValue,
    DriftAcknowledgement, DriftCheckPurpose, DriftSeverity,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

const MAX_PENDING_REPORTS_PER_AGENT: i64 = 4096;
const MAX_PENDING_BYTES_PER_AGENT: i64 = 64 * 1024 * 1024;
const FINAL_RESERVED_REPORTS: i64 = 4;
const FINAL_RESERVED_BYTES: i64 = 4 * 1024 * 1024;
const MAX_ONE_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECOVERY_BATCH: u32 = 100;
const MAX_RECOVERY_BYTES: usize = 8 * 1024 * 1024;

struct StoredVerificationProvenance {
    has_drift_document: bool,
    policy_id: Option<String>,
    policy_version: Option<i64>,
    purpose: Option<String>,
}

fn class_name(class: ReportClass) -> &'static str {
    match class {
        ReportClass::Lifecycle => "lifecycle",
        ReportClass::DriftEvidence => "drift_evidence",
        ReportClass::Output => "output",
        ReportClass::FinalResult => "final_result",
    }
}

fn verify_task_output_prefix(
    connection: &rusqlite::Connection,
    job_id: &str,
    agent_id: &str,
    stream: &str,
    expected_chunks: u64,
) -> Result<(), StoreError> {
    let expected = i64::try_from(expected_chunks)
        .map_err(|_| StoreError::Domain("task output chunk count exceeds storage range".into()))?;
    let (count, minimum, maximum): (i64, Option<i64>, Option<i64>) = connection.query_row(
        "SELECT COUNT(*), MIN(chunk_index), MAX(chunk_index)
         FROM job_output_chunks WHERE job_id = ?1 AND agent_id = ?2 AND stream = ?3",
        params![job_id, agent_id, stream],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let exact_prefix = if expected == 0 {
        count == 0 && minimum.is_none() && maximum.is_none()
    } else {
        count == expected && minimum == Some(0) && maximum == Some(expected - 1)
    };
    if !exact_prefix {
        return Err(StoreError::Domain(
            "task output chunks do not match final summary".into(),
        ));
    }
    Ok(())
}

fn insert_task_output_summary_audit(
    store: &SqliteStore,
    job_id: &str,
    summary: fleet_application::delivery::TaskOutputSummary,
    occurred_at: std::time::SystemTime,
) -> Result<(), StoreError> {
    store.insert_audit(&AuditEvent {
        category: AuditCategory::Job,
        action: "task_output_capture_summary".into(),
        actor: AuditActor::new("controller"),
        target: AuditTarget::new(job_id),
        value: AuditValue::Plain(format!(
            "stdout_chunks={},stderr_chunks={},truncated={}",
            summary.stdout_chunks, summary.stderr_chunks, summary.truncated
        )),
        occurred_at,
    })
}

fn digest_hex(body: &[u8]) -> String {
    Sha256::digest(body)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn accounted_bytes(report: &ControllerInboxReport) -> Option<i64> {
    let mut bytes = report.body().len() as u64 + 64 + 96;
    for part in report.key.parts() {
        bytes = bytes.checked_add(part.len() as u64)?;
    }
    i64::try_from(bytes).ok()
}

impl ControllerInboxRepository for SqliteStore {
    type Error = StoreError;

    fn stage_report(
        &mut self,
        report: &ControllerInboxReport,
    ) -> Result<InboxStageOutcome, Self::Error> {
        if report.body().is_empty() || report.body().len() > MAX_ONE_BODY_BYTES {
            return Ok(InboxStageOutcome::CapacityExceeded);
        }
        let [controller, agent, job, task, report_id] = report.key.parts();
        let class = class_name(report.class);
        let digest = digest_hex(report.body());
        let bytes = accounted_bytes(report)
            .ok_or_else(|| StoreError::Domain("inbox report size overflow".into()))?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let local_namespace: String = tx.query_row(
            "SELECT namespace FROM controller_delivery_identity WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        if controller != local_namespace {
            return Err(StoreError::Domain(
                "inbox controller ownership mismatch".into(),
            ));
        }
        let existing: Option<(String, String, Option<Vec<u8>>, String)> = tx
            .query_row(
                "SELECT class, digest_hex, body, status FROM controller_report_inbox
             WHERE controller_namespace = ?1 AND agent_id = ?2 AND job_id = ?3
               AND task_id = ?4 AND report_id = ?5",
                params![controller, agent, job, task, report_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if let Some((old_class, old_digest, old_body, status)) = existing {
            if old_class != class
                || old_digest != digest
                || old_body
                    .as_deref()
                    .is_some_and(|body| body != report.body())
            {
                return Ok(InboxStageOutcome::ConflictingBody);
            }
            return match status.as_str() {
                "pending_effects" if old_body.is_some() => {
                    Ok(InboxStageOutcome::DuplicatePendingEffects)
                }
                "committed" => Ok(InboxStageOutcome::AlreadyCommitted),
                _ => Err(StoreError::Domain("inbox status is invalid".into())),
            };
        }
        let owns_task: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM task_assignments
             WHERE id = ?1 AND job_id = ?2 AND agent_id = ?3)",
            params![task, job, agent],
            |row| row.get(0),
        )?;
        if !owns_task {
            return Err(StoreError::Domain("inbox task ownership mismatch".into()));
        }
        let (count, used_bytes): (i64, i64) = tx.query_row(
            "SELECT COUNT(*), COALESCE(SUM(accounted_bytes), 0) FROM controller_report_inbox
             WHERE agent_id = ?1 AND status = 'pending_effects'",
            params![agent],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let (max_count, max_bytes) = if report.class == ReportClass::FinalResult {
            (MAX_PENDING_REPORTS_PER_AGENT, MAX_PENDING_BYTES_PER_AGENT)
        } else {
            (
                MAX_PENDING_REPORTS_PER_AGENT - FINAL_RESERVED_REPORTS,
                MAX_PENDING_BYTES_PER_AGENT - FINAL_RESERVED_BYTES,
            )
        };
        if count >= max_count
            || used_bytes
                .checked_add(bytes)
                .is_none_or(|used| used > max_bytes)
        {
            return Ok(InboxStageOutcome::CapacityExceeded);
        }
        tx.execute(
            "INSERT INTO controller_report_inbox (
                controller_namespace, agent_id, job_id, task_id, report_id,
                class, digest_hex, body, accounted_bytes, status
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'pending_effects')",
            params![
                controller,
                agent,
                job,
                task,
                report_id,
                class,
                digest,
                report.body(),
                bytes
            ],
        )?;
        tx.commit()?;
        Ok(InboxStageOutcome::StagedPendingEffects)
    }
}

impl ControllerInboxFinalRecoveryRepository for SqliteStore {
    type Error = StoreError;

    fn load_pending_final_reports(
        &self,
        limit: u32,
    ) -> Result<Vec<ControllerInboxReport>, Self::Error> {
        if limit == 0 || limit > MAX_RECOVERY_BATCH {
            return Err(StoreError::Domain(
                "invalid pending final recovery limit".into(),
            ));
        }
        let mut statement = self.connection.prepare(
            "SELECT controller_namespace, agent_id, job_id, task_id, report_id, digest_hex, body,
                    EXISTS(SELECT 1 FROM task_assignments AS assignment
                           WHERE assignment.id = inbox.task_id
                             AND assignment.job_id = inbox.job_id
                             AND assignment.agent_id = inbox.agent_id)
             FROM controller_report_inbox AS inbox
             WHERE class = 'final_result' AND status = 'pending_effects'
               AND controller_namespace = (SELECT namespace FROM controller_delivery_identity WHERE id = 1)
             ORDER BY rowid LIMIT ?1",
        )?;
        let rows = statement.query_map(params![i64::from(limit)], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, bool>(7)?,
            ))
        })?;
        let mut reports = Vec::new();
        let mut batch_bytes = 0usize;
        for row in rows {
            let (controller, agent, job, task, report, digest, body, owns_task) = row?;
            let body =
                body.ok_or_else(|| StoreError::Domain("pending final body missing".into()))?;
            if body.len() > MAX_ONE_BODY_BYTES {
                return Err(StoreError::Domain("pending final report corrupt".into()));
            }
            if batch_bytes + body.len() > MAX_RECOVERY_BYTES {
                break;
            }
            if !owns_task || body.is_empty() || digest_hex(&body) != digest {
                return Err(StoreError::Domain("pending final report corrupt".into()));
            }
            let key = ReportKey::new(&controller, &agent, &job, &task, &report)
                .map_err(|_| StoreError::Domain("pending final report identity invalid".into()))?;
            batch_bytes += body.len();
            reports.push(ControllerInboxReport::new(
                key,
                ReportClass::FinalResult,
                body,
            ));
        }
        Ok(reports)
    }
}

impl ControllerCommittedFinalReceiptRecoveryRepository for SqliteStore {
    type Error = StoreError;

    fn load_committed_final_reports_missing_receipt(
        &self,
        limit: u32,
    ) -> Result<Vec<CommittedFinalReportMissingReceipt>, Self::Error> {
        if limit == 0 || limit > MAX_RECOVERY_BATCH {
            return Err(StoreError::Domain(
                "invalid committed final receipt recovery limit".into(),
            ));
        }
        let mut statement = self.connection.prepare(
            "SELECT inbox.controller_namespace, inbox.agent_id, inbox.job_id, inbox.task_id,
                    inbox.report_id, inbox.digest_hex,
                    EXISTS(SELECT 1 FROM task_assignments AS assignment
                           WHERE assignment.id = inbox.task_id
                             AND assignment.job_id = inbox.job_id
                             AND assignment.agent_id = inbox.agent_id)
             FROM controller_report_inbox AS inbox
             WHERE inbox.class = 'final_result' AND inbox.status = 'committed'
               AND inbox.controller_namespace = (SELECT namespace FROM controller_delivery_identity WHERE id = 1)
               AND NOT EXISTS(SELECT 1 FROM controller_report_receipts AS receipt
                              WHERE receipt.controller_namespace = inbox.controller_namespace
                                AND receipt.agent_id = inbox.agent_id
                                AND receipt.job_id = inbox.job_id
                                AND receipt.task_id = inbox.task_id
                                AND receipt.report_id = inbox.report_id)
             ORDER BY inbox.rowid LIMIT ?1",
        )?;
        let rows = statement.query_map(params![i64::from(limit)], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, bool>(6)?,
            ))
        })?;
        let mut reports = Vec::new();
        for row in rows {
            let (controller, agent, job, task, report, digest, owns_task) = row?;
            if !owns_task {
                return Err(StoreError::AssignmentOwnershipMismatch);
            }
            let key = ReportKey::new(&controller, &agent, &job, &task, &report)
                .map_err(|_| StoreError::Domain("committed final identity invalid".into()))?;
            let digest_bytes = parse_digest_hex(&digest)
                .ok_or_else(|| StoreError::Domain("committed final digest corrupt".into()))?;
            reports.push(CommittedFinalReportMissingReceipt {
                key,
                digest: ReportDigest(digest_bytes),
            });
        }
        Ok(reports)
    }
}

fn parse_digest_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut digest = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).ok()?;
        digest[index] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(digest)
}

impl ControllerInboxOutputRepository for SqliteStore {
    type Error = StoreError;

    fn commit_output_effect(
        &mut self,
        effect: &ControllerInboxOutputEffect,
    ) -> Result<InboxEffectOutcome, Self::Error> {
        let [controller, agent, job, task, report_id] = effect.key.parts();
        let calculated_digest = digest_hex(effect.encoded_report());
        let digest_bytes: [u8; 32] = Sha256::digest(effect.encoded_report()).into();
        let digest = ReportDigest(digest_bytes);
        let sequence = i64::try_from(effect.sequence).map_err(|_| {
            StoreError::Domain("inbox output sequence exceeds storage range".into())
        })?;
        let stream = crate::output_stream_to_str(effect.stream);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let staged: Option<(String, String, Option<Vec<u8>>, String)> = tx
            .query_row(
                "SELECT class, digest_hex, body, status FROM controller_report_inbox
             WHERE controller_namespace = ?1 AND agent_id = ?2 AND job_id = ?3
               AND task_id = ?4 AND report_id = ?5",
                params![controller, agent, job, task, report_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((class, staged_digest, body, status)) = staged else {
            return Ok(InboxEffectOutcome::NotStaged);
        };
        if class != "output"
            || staged_digest != calculated_digest
            || body
                .as_deref()
                .is_some_and(|bytes| bytes != effect.encoded_report())
        {
            return Ok(InboxEffectOutcome::ConflictingBody);
        }
        match status.as_str() {
            "committed" => return Ok(InboxEffectOutcome::AlreadyCommitted(digest)),
            "pending_effects" if body.is_some() => {}
            _ => return Err(StoreError::Domain("inbox status is invalid".into())),
        }
        let existing_output: Option<String> = tx
            .query_row(
                "SELECT body FROM job_output_chunks WHERE job_id = ?1 AND agent_id = ?2
             AND stream = ?3 AND chunk_index = ?4",
                params![job, agent, stream, sequence],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing_output {
            if existing != effect.output_body() {
                return Ok(InboxEffectOutcome::ConflictingBody);
            }
        } else {
            tx.execute(
                "INSERT INTO job_output_chunks (job_id, agent_id, stream, chunk_index, body)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![job, agent, stream, sequence, effect.output_body()],
            )?;
        }
        let changed = tx.execute(
            "UPDATE controller_report_inbox SET status = 'committed', body = NULL
             WHERE controller_namespace = ?1 AND agent_id = ?2 AND job_id = ?3
               AND task_id = ?4 AND report_id = ?5 AND status = 'pending_effects'",
            params![controller, agent, job, task, report_id],
        )?;
        if changed != 1 {
            return Err(StoreError::Domain(
                "inbox transition changed unexpectedly".into(),
            ));
        }
        tx.commit()?;
        Ok(InboxEffectOutcome::Committed(digest))
    }
}

#[derive(Clone, Copy)]
enum TaskLifecycleTransition {
    Accepted,
    Started,
    Rejected,
}

impl TaskLifecycleTransition {
    fn report_id(self) -> &'static str {
        match self {
            Self::Accepted => "task-ack",
            Self::Started => "task-started",
            Self::Rejected => "task-rejected",
        }
    }

    fn target(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Started => "started",
            Self::Rejected => "rejected",
        }
    }

    fn audit_action(self) -> &'static str {
        match self {
            Self::Accepted => "task_accepted",
            Self::Started => "task_started",
            Self::Rejected => "task_rejected",
        }
    }

    fn is_duplicate(self, assignment_status: &str) -> bool {
        match self {
            Self::Accepted => matches!(assignment_status, "accepted" | "started"),
            Self::Started => assignment_status == "started",
            Self::Rejected => false,
        }
    }

    fn update_assignment(
        self,
        tx: &rusqlite::Transaction<'_>,
        task: &str,
        job: &str,
        agent: &str,
        occurred_at: std::time::SystemTime,
        rejection: Option<(&str, &str)>,
    ) -> Result<usize, rusqlite::Error> {
        match self {
            Self::Accepted => tx.execute(
                "UPDATE task_assignments SET status = 'accepted', accepted_at = ?4
                 WHERE id = ?1 AND job_id = ?2 AND agent_id = ?3 AND status = 'dispatched'",
                params![task, job, agent, system_time_to_unix_secs(occurred_at)],
            ),
            Self::Started => tx.execute(
                "UPDATE task_assignments SET status = 'started', started_at = ?4
                 WHERE id = ?1 AND job_id = ?2 AND agent_id = ?3 AND status = 'accepted'",
                params![task, job, agent, system_time_to_unix_secs(occurred_at)],
            ),
            Self::Rejected => {
                let last_error = rejection
                    .map(|(code, reason)| format!("{code}: {reason}"))
                    .unwrap_or_else(|| "task rejected".to_owned());
                tx.execute(
                    "UPDATE task_assignments
                     SET status = 'rejected', completed_at = ?4, last_error = ?5
                     WHERE id = ?1 AND job_id = ?2 AND agent_id = ?3 AND status = 'dispatched'",
                    params![
                        task,
                        job,
                        agent,
                        system_time_to_unix_secs(occurred_at),
                        last_error
                    ],
                )
            }
        }
    }
}

struct TaskLifecycleCommit<'a> {
    occurred_at: std::time::SystemTime,
    transition: TaskLifecycleTransition,
    remediation: Option<&'a fleet_application::RemediationRequestRecord>,
    remediation_audit: Option<&'a AuditEvent>,
    rejection: Option<(&'a str, &'a str)>,
}

fn commit_task_lifecycle_effect(
    store: &mut SqliteStore,
    key: &ReportKey,
    encoded_report: &[u8],
    commit: TaskLifecycleCommit<'_>,
) -> Result<InboxEffectOutcome, StoreError> {
    let TaskLifecycleCommit {
        occurred_at,
        transition,
        remediation,
        remediation_audit,
        rejection,
    } = commit;
    let [controller, agent, job, task, report_id] = key.parts();
    if report_id != transition.report_id() {
        return Err(StoreError::Domain(
            "lifecycle report identity is invalid".into(),
        ));
    }
    let calculated_digest = digest_hex(encoded_report);
    let digest_bytes: [u8; 32] = Sha256::digest(encoded_report).into();
    let digest = ReportDigest(digest_bytes);
    let tx = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let staged: Option<(String, String, Option<Vec<u8>>, String)> = tx
        .query_row(
            "SELECT class, digest_hex, body, status FROM controller_report_inbox
             WHERE controller_namespace = ?1 AND agent_id = ?2 AND job_id = ?3
               AND task_id = ?4 AND report_id = ?5",
            params![controller, agent, job, task, report_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((class, staged_digest, body, status)) = staged else {
        return Ok(InboxEffectOutcome::NotStaged);
    };
    if class != "lifecycle"
        || staged_digest != calculated_digest
        || body.as_deref().is_some_and(|bytes| bytes != encoded_report)
    {
        return Ok(InboxEffectOutcome::ConflictingBody);
    }
    match status.as_str() {
        "committed" => return Ok(InboxEffectOutcome::AlreadyCommitted(digest)),
        "pending_effects" if body.is_some() => {}
        _ => return Err(StoreError::Domain("inbox status is invalid".into())),
    }

    let assignment: Option<(String, String, String, Option<String>, bool)> = tx
        .query_row(
            "SELECT status, job_id, agent_id, last_error, dispatched_at IS NOT NULL
             FROM task_assignments WHERE id = ?1",
            params![task],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    let Some((assignment_status, stored_job, stored_agent, last_error, was_dispatched)) =
        assignment
    else {
        return Err(StoreError::Domain("lifecycle assignment missing".into()));
    };
    if stored_job != job || stored_agent != agent {
        return Err(StoreError::AssignmentOwnershipMismatch);
    }
    let late_reason = if assignment_status == "failed"
        && last_error.as_deref() == Some("execution_outcome_unknown")
    {
        Some("execution_outcome_unknown")
    } else if assignment_status == "canceled" && was_dispatched {
        Some("controller_canceled")
    } else {
        None
    };
    if let Some(reason) = late_reason {
        let event = AuditEvent {
            category: AuditCategory::Job,
            action: if assignment_status == "canceled" {
                "assignment_canceled_lifecycle_report_received"
            } else {
                "assignment_late_lifecycle_report_received"
            }
            .into(),
            actor: AuditActor::new("controller"),
            target: AuditTarget::new(task),
            value: AuditValue::Plain(format!(
                "report_id={report_id},assignment_status={assignment_status},reason={reason}"
            )),
            occurred_at,
        };
        let (value_kind, value_text) = crate::encode_audit_value(&event.value);
        tx.execute(
            "INSERT INTO audit_events (
                category, action, actor, target, value_kind, value_text, occurred_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                event.category.as_str(),
                event.action,
                event.actor.as_str(),
                event.target.as_str(),
                value_kind,
                value_text,
                system_time_to_unix_secs(event.occurred_at),
            ],
        )?;
        let updated = tx.execute(
            "UPDATE controller_report_inbox SET status = 'committed', body = NULL
             WHERE controller_namespace = ?1 AND agent_id = ?2 AND job_id = ?3
               AND task_id = ?4 AND report_id = ?5 AND digest_hex = ?6
               AND status = 'pending_effects'",
            params![controller, agent, job, task, report_id, calculated_digest],
        )?;
        if updated != 1 {
            return Err(StoreError::Domain(
                "late lifecycle inbox disposition failed".into(),
            ));
        }
        tx.commit()?;
        return Ok(InboxEffectOutcome::LateDispositionCommitted(digest));
    }
    let changed = if transition.is_duplicate(&assignment_status) {
        false
    } else {
        let expected_status = match transition {
            TaskLifecycleTransition::Accepted => "dispatched",
            TaskLifecycleTransition::Started => "accepted",
            TaskLifecycleTransition::Rejected => "dispatched",
        };
        if assignment_status != expected_status {
            if matches!(
                assignment_status.as_str(),
                "succeeded" | "failed" | "rejected" | "canceled" | "expired"
            ) {
                return Err(StoreError::Domain(
                    "lifecycle report cannot change a terminal assignment".into(),
                ));
            }
            return Err(StoreError::Domain(
                "lifecycle assignment is not in the expected state".into(),
            ));
        }
        let updated =
            transition.update_assignment(&tx, task, job, agent, occurred_at, rejection)?;
        if updated != 1 {
            return Err(StoreError::Domain(
                "lifecycle assignment transition changed unexpectedly".into(),
            ));
        }
        true
    };

    if changed {
        let strategy_max_failures: Option<i64> = tx
            .query_row(
                "SELECT strategy_max_failures FROM jobs WHERE id = ?1",
                params![job],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        let mut statement = tx.prepare("SELECT status FROM task_assignments WHERE job_id = ?1")?;
        let statuses = statement
            .query_map(params![job], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let statuses = statuses
            .iter()
            .map(|status| {
                AssignmentStatus::parse(status)
                    .ok_or_else(|| StoreError::Domain("invalid task assignment status".into()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let max_failures = strategy_max_failures.and_then(|value| u32::try_from(value).ok());
        let aggregate = aggregate_job_status(&statuses, max_failures);
        tx.execute(
            "UPDATE jobs SET status = ?2 WHERE id = ?1",
            params![job, job_status_to_str(aggregate)],
        )?;

        let target_status = transition.target();
        let event = AuditEvent {
            category: AuditCategory::Job,
            action: transition.audit_action().into(),
            actor: AuditActor::new("controller"),
            target: AuditTarget::new(job),
            value: AuditValue::Plain(format!(
                "agent_id={agent},task_id={task},assignment_status={target_status}{}",
                rejection
                    .map(|(code, reason)| format!(",reason_code={code},reason={reason}"))
                    .unwrap_or_default()
            )),
            occurred_at,
        };
        let (value_kind, value_text) = crate::encode_audit_value(&event.value);
        tx.execute(
            "INSERT INTO audit_events (
                category, action, actor, target, value_kind, value_text, occurred_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                event.category.as_str(),
                event.action,
                event.actor.as_str(),
                event.target.as_str(),
                value_kind,
                value_text,
                system_time_to_unix_secs(event.occurred_at),
            ],
        )?;

        if let Some(remediation) = remediation {
            if remediation.agent_id != agent || remediation.job_id.as_deref() != Some(job) {
                return Err(StoreError::AssignmentOwnershipMismatch);
            }
            let changed = tx.execute(
                "UPDATE remediation_requests SET status = ?2, job_id = ?3, updated_at = ?4
                 WHERE id = ?1 AND agent_id = ?5 AND job_id = ?3 AND status = 'job_created'",
                params![
                    remediation.id,
                    remediation.status,
                    job,
                    system_time_to_unix_secs(remediation.updated_at),
                    agent,
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::Domain(
                    "remediation start transition changed unexpectedly".into(),
                ));
            }
            if let Some(event) = remediation_audit {
                let (value_kind, value_text) = crate::encode_audit_value(&event.value);
                tx.execute(
                    "INSERT INTO audit_events (
                        category, action, actor, target, value_kind, value_text, occurred_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        event.category.as_str(),
                        event.action,
                        event.actor.as_str(),
                        event.target.as_str(),
                        value_kind,
                        value_text,
                        system_time_to_unix_secs(event.occurred_at),
                    ],
                )?;
            }
        }
    }

    let updated = tx.execute(
        "UPDATE controller_report_inbox SET status = 'committed', body = NULL
         WHERE controller_namespace = ?1 AND agent_id = ?2 AND job_id = ?3
           AND task_id = ?4 AND report_id = ?5 AND status = 'pending_effects'",
        params![controller, agent, job, task, report_id],
    )?;
    if updated != 1 {
        return Err(StoreError::Domain(
            "inbox transition changed unexpectedly".into(),
        ));
    }
    tx.commit()?;
    Ok(InboxEffectOutcome::Committed(digest))
}

impl ControllerInboxTaskAckRepository for SqliteStore {
    type Error = StoreError;

    fn commit_task_ack_effect(
        &mut self,
        effect: &ControllerInboxTaskAckEffect,
    ) -> Result<InboxEffectOutcome, Self::Error> {
        commit_task_lifecycle_effect(
            self,
            &effect.key,
            effect.encoded_report(),
            TaskLifecycleCommit {
                occurred_at: effect.occurred_at,
                transition: TaskLifecycleTransition::Accepted,
                remediation: None,
                remediation_audit: None,
                rejection: None,
            },
        )
    }
}

impl ControllerInboxTaskStartedRepository for SqliteStore {
    type Error = StoreError;

    fn commit_task_started_effect(
        &mut self,
        effect: &ControllerInboxTaskStartedEffect,
    ) -> Result<InboxEffectOutcome, Self::Error> {
        commit_task_lifecycle_effect(
            self,
            &effect.key,
            effect.encoded_report(),
            TaskLifecycleCommit {
                occurred_at: effect.occurred_at,
                transition: TaskLifecycleTransition::Started,
                remediation: effect.remediation.as_ref(),
                remediation_audit: effect.remediation_audit.as_ref(),
                rejection: None,
            },
        )
    }
}

impl ControllerInboxTaskRejectedRepository for SqliteStore {
    type Error = StoreError;

    fn commit_task_rejected_effect(
        &mut self,
        effect: &ControllerInboxTaskRejectedEffect,
    ) -> Result<InboxEffectOutcome, Self::Error> {
        commit_task_lifecycle_effect(
            self,
            &effect.key,
            effect.encoded_report(),
            TaskLifecycleCommit {
                occurred_at: effect.occurred_at,
                transition: TaskLifecycleTransition::Rejected,
                remediation: None,
                remediation_audit: None,
                rejection: Some((effect.reason_code.as_str(), effect.reason.as_str())),
            },
        )
    }
}

impl ControllerInboxEvidenceRepository for SqliteStore {
    type Error = StoreError;

    fn commit_evidence_effect(
        &mut self,
        effect: &ControllerInboxEvidenceEffect,
    ) -> Result<InboxEffectOutcome, Self::Error> {
        let [controller, agent, job, task, report_id] = effect.key.parts();
        let provenance = &effect.provenance;
        if provenance.job_id.as_ref().map(|id| id.as_str()) != Some(job)
            || provenance.task_id.as_ref().map(|id| id.as_str()) != Some(task)
            || provenance.purpose.is_none()
            || provenance.policy_id.as_deref() != Some(effect.report.policy_name.as_str())
            || provenance.policy_version.is_none()
            || effect.report.acknowledgement != DriftAcknowledgement::Open
            || effect.report.severity != DriftSeverity::for_status(effect.report.status.clone())
        {
            return Err(StoreError::Domain("inbox drift evidence invalid".into()));
        }
        if let Some(proposal) = &effect.remediation_proposal
            && (proposal.agent_id != agent
                || proposal.report != effect.report
                || proposal.provenance != effect.provenance
                || proposal.checked_at != effect.checked_at)
        {
            return Err(StoreError::Domain(
                "inbox drift proposal does not match evidence".into(),
            ));
        }
        let digest = digest_hex(effect.encoded_report());
        let digest_bytes: [u8; 32] = Sha256::digest(effect.encoded_report()).into();
        self.run_sqlite_transaction(|| {
            let staged: Option<(String, String, Option<Vec<u8>>, String)> = self.connection.query_row(
                "SELECT class, digest_hex, body, status FROM controller_report_inbox
                 WHERE controller_namespace = ?1 AND agent_id = ?2 AND job_id = ?3
                   AND task_id = ?4 AND report_id = ?5",
                params![controller, agent, job, task, report_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            ).optional()?;
            let Some((class, stored_digest, body, status)) = staged else {
                return Ok(InboxEffectOutcome::NotStaged);
            };
            if class != "drift_evidence"
                || stored_digest != digest
                || body.as_deref().is_some_and(|bytes| bytes != effect.encoded_report())
            {
                return Ok(InboxEffectOutcome::ConflictingBody);
            }
            match status.as_str() {
                "committed" => return Ok(InboxEffectOutcome::AlreadyCommitted(ReportDigest(digest_bytes))),
                "pending_effects" if body.is_some() => {}
                _ => return Err(StoreError::Domain("inbox evidence status invalid".into())),
            }
            let assignment_exists: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM task_assignments WHERE id = ?1 AND job_id = ?2 AND agent_id = ?3)",
                params![task, job, agent], |row| row.get(0)
            )?;
            if !assignment_exists {
                return Err(StoreError::AssignmentOwnershipMismatch);
            }
            let job_provenance: Option<StoredVerificationProvenance> = self.connection.query_row(
                "SELECT drift_policy_document IS NOT NULL, drift_policy_id, drift_policy_version, drift_purpose
                 FROM jobs WHERE id = ?1", params![job],
                |row| Ok(StoredVerificationProvenance {
                    has_drift_document: row.get(0)?,
                    policy_id: row.get(1)?,
                    policy_version: row.get(2)?,
                    purpose: row.get(3)?,
                })
            ).optional()?;
            let expected_version = provenance.policy_version.map(i64::from);
            if !matches!(job_provenance, Some(ref stored)
                if stored.has_drift_document
                    && stored.policy_id.as_deref() == provenance.policy_id.as_deref()
                    && stored.policy_version == expected_version
                    && stored.purpose.as_deref() == provenance.purpose.map(DriftCheckPurpose::as_str))
            {
                return Err(StoreError::Domain("inbox drift provenance mismatch".into()));
            }
            if let Some(proposal) = &effect.remediation_proposal {
                self.save_verified_drift_proposal_in_transaction(proposal)?;
            } else {
                self.insert_drift_report_with_provenance(
                    agent,
                    &effect.report,
                    provenance,
                    effect.checked_at,
                )?;
                self.insert_audit(&AuditEvent {
                    category: AuditCategory::Drift,
                    action: "drift_report_received".into(),
                    actor: AuditActor::new(agent),
                    target: AuditTarget::new(agent),
                    value: AuditValue::Redacted,
                    occurred_at: effect.checked_at,
                })?;
            }
            let changed = self.connection.execute(
                "UPDATE controller_report_inbox SET status = 'committed', body = NULL
                 WHERE controller_namespace = ?1 AND agent_id = ?2 AND job_id = ?3
                   AND task_id = ?4 AND report_id = ?5 AND status = 'pending_effects'",
                params![controller, agent, job, task, report_id],
            )?;
            if changed != 1 {
                return Err(StoreError::Domain("inbox evidence marker update failed".into()));
            }
            Ok(InboxEffectOutcome::Committed(ReportDigest(digest_bytes)))
        })
    }
}

impl ControllerInboxFinalRepository for SqliteStore {
    type Error = StoreError;

    fn commit_final_effect(
        &mut self,
        effect: &ControllerInboxFinalEffect,
    ) -> Result<InboxEffectOutcome, Self::Error> {
        let audit_action = match effect.status {
            AssignmentStatus::Succeeded => "job_completed",
            AssignmentStatus::Failed => "job_failed",
            AssignmentStatus::Canceled => "job_canceled",
            AssignmentStatus::Expired => "job_timed_out",
            _ => return Err(StoreError::Domain("inbox final status is invalid".into())),
        };
        if effect.artifact_count != effect.prepared_artifacts().len() {
            return Err(StoreError::Domain(
                "inbox final artifacts are not fully prepared".into(),
            ));
        }
        let [controller, agent, job, task, report] = effect.key.parts();
        for prepared in effect.prepared_artifacts() {
            let metadata = &prepared.metadata;
            if metadata.job_id.as_str() != job
                || metadata.agent_id.as_str() != agent
                || metadata.task_id.as_str() != task
            {
                return Err(StoreError::AssignmentOwnershipMismatch);
            }
            if let Some(stored) = &prepared.stored_body
                && (stored.id != metadata.id
                    || stored.retention_class != metadata.retention_class
                    || stored.checksum != metadata.checksum
                    || stored.size_bytes != metadata.size_bytes)
            {
                return Err(StoreError::Domain(
                    "inbox final artifact body mismatch".into(),
                ));
            }
        }
        let digest = digest_hex(effect.encoded_report());
        let digest_bytes: [u8; 32] = Sha256::digest(effect.encoded_report()).into();
        self.run_sqlite_transaction(|| {
            let staged: Option<(String, String, Option<Vec<u8>>, String)> = self
                .connection
                .query_row(
                    "SELECT class, digest_hex, body, status FROM controller_report_inbox
                 WHERE controller_namespace = ?1 AND agent_id = ?2 AND job_id = ?3
                   AND task_id = ?4 AND report_id = ?5",
                    params![controller, agent, job, task, report],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            let Some((class, stored_digest, body, inbox_status)) = staged else {
                return Ok(InboxEffectOutcome::NotStaged);
            };
            if class != "final_result"
                || stored_digest != digest
                || body
                    .as_deref()
                    .is_some_and(|bytes| bytes != effect.encoded_report())
            {
                return Ok(InboxEffectOutcome::ConflictingBody);
            }
            match inbox_status.as_str() {
                "committed" => {
                    return Ok(InboxEffectOutcome::AlreadyCommitted(ReportDigest(
                        digest_bytes,
                    )));
                }
                "pending_effects" if body.is_some() => {}
                _ => return Err(StoreError::Domain("inbox final status is invalid".into())),
            }
            let owner: Option<(String, String, String, Option<String>, bool)> = self
                .connection
                .query_row(
                    "SELECT status, job_id, agent_id, last_error, dispatched_at IS NOT NULL
                     FROM task_assignments WHERE id = ?1",
                    params![task],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()?;
            let Some((assignment_status, stored_job, stored_agent, last_error, was_dispatched)) =
                owner
            else {
                return Err(StoreError::Domain("inbox final assignment missing".into()));
            };
            if stored_job != job || stored_agent != agent {
                return Err(StoreError::AssignmentOwnershipMismatch);
            }
            let job_shape: Option<(bool, bool, bool)> = self
                .connection
                .query_row(
                    "SELECT command_program IS NOT NULL, runbook_document IS NOT NULL,
                        drift_policy_document IS NOT NULL
                 FROM jobs WHERE id = ?1",
                    params![job],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let output_tracked_job =
                matches!(job_shape, Some((true, false, false) | (false, true, false)));
            let output_summary = effect.output_summary();
            if output_tracked_job {
                let summary = output_summary.ok_or_else(|| {
                    StoreError::Domain("task final output summary missing".into())
                })?;
                if summary.truncated && effect.status == AssignmentStatus::Succeeded {
                    return Err(StoreError::Domain(
                        "truncated task output cannot be succeeded".into(),
                    ));
                }
                verify_task_output_prefix(
                    &self.connection,
                    job,
                    agent,
                    "stdout",
                    summary.stdout_chunks,
                )?;
                verify_task_output_prefix(
                    &self.connection,
                    job,
                    agent,
                    "stderr",
                    summary.stderr_chunks,
                )?;
            } else if output_summary.is_some_and(|summary| {
                summary.stdout_chunks != 0 || summary.stderr_chunks != 0 || summary.truncated
            }) {
                return Err(StoreError::Domain(
                    "non-output task final has output summary".into(),
                ));
            }
            if crate::assignment_status_value_is_terminal(&assignment_status) {
                let non_artifact_job_without_remediation: bool = self.connection.query_row(
                    "SELECT (
                                (command_program IS NOT NULL AND runbook_document IS NULL
                                    AND drift_policy_document IS NULL)
                                OR (command_program IS NULL AND runbook_document IS NOT NULL
                                    AND drift_policy_document IS NULL)
                                OR (command_program IS NULL AND runbook_document IS NULL
                                    AND drift_policy_document IS NOT NULL)
                            )
                            AND NOT EXISTS (
                                SELECT 1 FROM remediation_requests WHERE job_id = jobs.id
                            )
                     FROM jobs WHERE id = ?1",
                    params![job],
                    |row| row.get(0),
                )?;
                let late_g2 = assignment_status == "failed"
                    && last_error.as_deref() == Some("execution_outcome_unknown");
                let canceled_assignment =
                    assignment_status == "canceled" && was_dispatched && output_tracked_job;
                if (late_g2 || canceled_assignment)
                    && non_artifact_job_without_remediation
                    && effect.artifact_count == 0
                    && effect.prepared_artifacts().is_empty()
                    && effect.prepared_remediation().is_none()
                {
                    if output_tracked_job && let Some(summary) = output_summary {
                        insert_task_output_summary_audit(self, job, summary, effect.occurred_at)?;
                    }
                    self.insert_audit(&AuditEvent {
                        category: AuditCategory::Job,
                        action: if canceled_assignment {
                            "assignment_canceled_final_result_received"
                        } else {
                            "assignment_late_final_result_received"
                        }
                        .into(),
                        actor: AuditActor::new("controller"),
                        target: AuditTarget::new(task),
                        value: AuditValue::Plain(effect.status.as_str().to_owned()),
                        occurred_at: effect.occurred_at,
                    })?;
                    let changed = self.connection.execute(
                        "UPDATE controller_report_inbox SET status = 'committed', body = NULL
                         WHERE controller_namespace = ?1 AND agent_id = ?2 AND job_id = ?3
                           AND task_id = ?4 AND report_id = ?5
                           AND digest_hex = ?6 AND status = 'pending_effects'",
                        params![controller, agent, job, task, report, digest],
                    )?;
                    if changed != 1 {
                        return Err(StoreError::Domain(
                            "late final inbox disposition failed".into(),
                        ));
                    }
                    return Ok(InboxEffectOutcome::LateDispositionCommitted(ReportDigest(
                        digest_bytes,
                    )));
                }
                return Err(StoreError::Domain(
                    "inbox final assignment already terminal".into(),
                ));
            }
            let supported_job: Option<(bool, bool, bool)> = self
                .connection
                .query_row(
                    "SELECT command_program IS NOT NULL, runbook_document IS NOT NULL,
                            drift_policy_document IS NOT NULL
                 FROM jobs WHERE id = ?1",
                    params![job],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let has_remediation: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM remediation_requests WHERE job_id = ?1)",
                params![job],
                |row| row.get(0),
            )?;
            if has_remediation != effect.prepared_remediation().is_some()
                || !matches!(
                    supported_job,
                    Some((true, false, false) | (false, true, false) | (false, false, true))
                )
                || (effect.artifact_count > 0 && supported_job != Some((false, true, false)))
                || (has_remediation && supported_job != Some((false, true, false)))
            {
                return Err(StoreError::Domain(
                    "inbox final follow-up effects unsupported".into(),
                ));
            }
            let changed = self.connection.execute(
                "UPDATE task_assignments SET status = ?4, completed_at = ?5,
                        last_error = COALESCE(?6, last_error)
                 WHERE id = ?1 AND job_id = ?2 AND agent_id = ?3",
                params![
                    task,
                    job,
                    agent,
                    effect.status.as_str(),
                    crate::system_time_to_unix_secs(effect.occurred_at),
                    effect.last_error()
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::Domain(
                    "inbox final assignment update failed".into(),
                ));
            }
            for prepared in effect.prepared_artifacts() {
                self.save_rendered_artifact_metadata_record(&prepared.metadata)?;
            }
            if let Some(prepared) = effect.prepared_remediation() {
                let (expected_update, expected_action) = match effect.status {
                    AssignmentStatus::Succeeded => (
                        "succeeded_pending_verify",
                        "remediation_job_succeeded_pending_verify",
                    ),
                    AssignmentStatus::Failed => ("failed", "remediation_job_failed"),
                    AssignmentStatus::Canceled => ("canceled", "remediation_job_canceled"),
                    AssignmentStatus::Expired => ("expired", "remediation_job_expired"),
                    _ => return Err(StoreError::Domain("inbox final status is invalid".into())),
                };
                let valid_prior = if effect.status == AssignmentStatus::Succeeded {
                    prepared.expected_status() == "running"
                } else {
                    matches!(prepared.expected_status(), "job_created" | "running")
                };
                if !valid_prior
                    || prepared.updated.job_id.as_deref() != Some(job)
                    || prepared.updated.agent_id != agent
                    || prepared.updated.status != expected_update
                    || prepared.updated.updated_at != effect.occurred_at
                    || prepared.audit.category != AuditCategory::Policy
                    || prepared.audit.action != expected_action
                    || prepared.audit.actor.as_str() != agent
                    || prepared.audit.target.as_str() != agent
                    || prepared.audit.occurred_at != effect.occurred_at
                {
                    return Err(StoreError::Domain(
                        "inbox final remediation mismatch".into(),
                    ));
                }
                let changed = self.connection.execute(
                    "UPDATE remediation_requests SET status = ?5, updated_at = ?6
                     WHERE id = ?1 AND job_id = ?2 AND agent_id = ?3 AND status = ?4",
                    params![
                        prepared.updated.id,
                        job,
                        agent,
                        prepared.expected_status(),
                        prepared.updated.status,
                        crate::system_time_to_unix_secs(prepared.updated.updated_at),
                    ],
                )?;
                if changed != 1 {
                    return Err(StoreError::Domain("inbox final remediation stale".into()));
                }
                self.insert_audit(&prepared.audit)?;
            }
            let canceled = self.cancel_queued_assignments_after_max_failures(
                job,
                effect.occurred_at,
                "maxFailures reached",
            )?;
            if canceled > 0 {
                self.insert_audit(&AuditEvent {
                    category: AuditCategory::Job,
                    action: "job_max_failures_reached".into(),
                    actor: AuditActor::new("controller"),
                    target: AuditTarget::new(job),
                    value: AuditValue::Redacted,
                    occurred_at: effect.occurred_at,
                })?;
            }
            self.recompute_job_status_from_assignments(job)?;
            if output_tracked_job && let Some(summary) = output_summary {
                insert_task_output_summary_audit(self, job, summary, effect.occurred_at)?;
            }
            self.insert_audit(&AuditEvent {
                category: AuditCategory::Job,
                action: audit_action.into(),
                actor: AuditActor::new("controller"),
                target: AuditTarget::new(job),
                value: AuditValue::Redacted,
                occurred_at: effect.occurred_at,
            })?;
            let changed = self.connection.execute(
                "UPDATE controller_report_inbox SET status = 'committed', body = NULL
                 WHERE controller_namespace = ?1 AND agent_id = ?2 AND job_id = ?3
                   AND task_id = ?4 AND report_id = ?5 AND status = 'pending_effects'",
                params![controller, agent, job, task, report],
            )?;
            if changed != 1 {
                return Err(StoreError::Domain(
                    "inbox final marker update failed".into(),
                ));
            }
            Ok(InboxEffectOutcome::Committed(ReportDigest(digest_bytes)))
        })
    }
}
