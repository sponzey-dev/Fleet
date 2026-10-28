//! Dedicated agent report store, separate from the Controller database.
//! SQLite commit, not WebSocket delivery, is the durability boundary.

use fleet_application::delivery::{
    AgentExecutionRepository, AgentReportRepository, AppendReportOutcome, ExecutionAdmission,
    JournalError, JournalReport, PendingReport,
};
use fleet_domain::delivery::{
    ExecutionPhase, ExecutionRecord, ExecutionSnapshot, JournalCapacity, JournalUsage, ReportClass,
    ReportDigest, ReportKey, TaskOutputStream, validate_report_ack,
};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::path::Path;

/// A single-process SQLite owner with FULL synchronous commits. The parent must
/// already be an owner-only directory; this adapter never chmods existing data.
pub struct SqliteAgentJournal {
    connection: Connection,
    controller: String,
    agent: String,
}

impl SqliteAgentJournal {
    /// Opens only the dedicated journal schema. Other owners, newer schemas,
    /// symlinks, insecure Unix permissions, and concurrent openers fail closed.
    /// Power-loss durability still depends on the filesystem honoring fsync.
    pub fn open(path: &Path, controller: &str, agent: &str) -> Result<Self, JournalError> {
        for value in [controller, agent] {
            if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err(JournalError::IdentityMismatch);
            }
        }
        prepare_path(path)?;
        let mut connection = Connection::open(path).map_err(sql_error)?;
        connection
            .busy_timeout(std::time::Duration::ZERO)
            .map_err(sql_error)?;
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(sql_error)?;
        let application: i64 = connection
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .map_err(sql_error)?;
        if !matches!(version, 0..=4) || (version != 0 && application != 0x464a4e4c) {
            return Err(JournalError::UnsupportedVersion);
        }
        if version == 0 {
            let tables: i64 = connection
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                    [],
                    |row| row.get(0),
                )
                .map_err(sql_error)?;
            if tables != 0 || application != 0 {
                return Err(JournalError::UnsupportedVersion);
            }
        }
        connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA locking_mode=EXCLUSIVE;").map_err(sql_error)?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        if version == 0 {
            transaction.execute_batch("CREATE TABLE journal_owner (id INTEGER PRIMARY KEY CHECK(id=1), controller TEXT NOT NULL, agent TEXT NOT NULL);
                CREATE TABLE reports (id INTEGER PRIMARY KEY AUTOINCREMENT, job TEXT NOT NULL, task TEXT NOT NULL, report TEXT NOT NULL,
                    class INTEGER NOT NULL CHECK(class BETWEEN 0 AND 3), body BLOB NOT NULL, digest BLOB NOT NULL CHECK(length(digest)=32),
                    accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0), UNIQUE(job,task,report));
                PRAGMA user_version=1; PRAGMA application_id=1179274828;").map_err(sql_error)?;
            transaction
                .execute(
                    "INSERT INTO journal_owner VALUES(1,?1,?2)",
                    params![controller, agent],
                )
                .map_err(sql_error)?;
        }
        let owner: (String, String) = transaction
            .query_row(
                "SELECT controller,agent FROM journal_owner WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(sql_error)?;
        if owner.0 != controller || owner.1 != agent {
            return Err(JournalError::IdentityMismatch);
        }
        if version < 2 {
            transaction
                .execute_batch(
                    "CREATE TABLE executions (
                job TEXT NOT NULL, task TEXT NOT NULL, final_report TEXT NOT NULL,
                nonce_digest BLOB NOT NULL UNIQUE CHECK(length(nonce_digest)=32),
                envelope_digest BLOB NOT NULL CHECK(length(envelope_digest)=32),
                phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 2),
                admitted_at_ms INTEGER NOT NULL CHECK(admitted_at_ms>=0),
                final_max_bytes INTEGER NOT NULL CHECK(final_max_bytes>0),
                accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0), PRIMARY KEY(job,task));
                CREATE UNIQUE INDEX executions_single_active ON executions((1)) WHERE phase IN(0,1);
                PRAGMA user_version=2;",
                )
                .map_err(sql_error)?;
        }
        if version < 3 {
            let has_started_execution: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM executions WHERE phase=1)",
                    [],
                    |row| row.get(0),
                )
                .map_err(sql_error)?;
            if has_started_execution {
                return Err(JournalError::ActiveExecutionNeedsDrain);
            }
            transaction
                .execute_batch(
                    "ALTER TABLE executions ADD COLUMN stdout_chunks INTEGER NOT NULL DEFAULT 0 CHECK(stdout_chunks>=0);
                ALTER TABLE executions ADD COLUMN stderr_chunks INTEGER NOT NULL DEFAULT 0 CHECK(stderr_chunks>=0);
                UPDATE executions SET accounted_bytes=accounted_bytes+16;
                PRAGMA user_version=3;",
                )
                .map_err(sql_error)?;
        }
        if version < 4 {
            transaction
                .execute_batch(
                    "ALTER TABLE reports RENAME TO reports_v3;
                    CREATE TABLE reports (id INTEGER PRIMARY KEY AUTOINCREMENT, job TEXT NOT NULL, task TEXT NOT NULL, report TEXT NOT NULL,
                        class INTEGER NOT NULL CHECK(class BETWEEN 0 AND 3), body BLOB NOT NULL, digest BLOB NOT NULL CHECK(length(digest)=32),
                        accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0), UNIQUE(job,task,report));
                    INSERT INTO reports(id,job,task,report,class,body,digest,accounted_bytes)
                        SELECT id,job,task,report,class,body,digest,accounted_bytes FROM reports_v3;
                    DROP TABLE reports_v3;
                    PRAGMA user_version=4;",
                )
                .map_err(sql_error)?;
        }
        let integrity: String = transaction
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(sql_error)?;
        if integrity != "ok" {
            return Err(JournalError::Corrupt);
        }
        transaction.commit().map_err(sql_error)?;
        #[cfg(unix)]
        std::fs::File::open(path.parent().ok_or(JournalError::Unavailable)?)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| JournalError::Unavailable)?;
        Ok(Self {
            connection,
            controller: controller.to_owned(),
            agent: agent.to_owned(),
        })
    }

    fn validate_owner(&self, key: &ReportKey) -> Result<(), JournalError> {
        let [controller, agent, _, _, _] = key.parts();
        if controller != self.controller || agent != self.agent {
            return Err(JournalError::IdentityMismatch);
        }
        Ok(())
    }
}

impl AgentExecutionRepository for SqliteAgentJournal {
    fn admit_execution(
        &mut self,
        record: &ExecutionRecord,
        capacity: JournalCapacity,
    ) -> Result<ExecutionAdmission, JournalError> {
        let snapshot = record.snapshot();
        self.validate_owner(&snapshot.final_report_key)?;
        if snapshot.phase != ExecutionPhase::Admitted {
            return Err(JournalError::InvalidExecutionTransition);
        }
        let [_, _, job, task, final_report] = snapshot.final_report_key.parts();
        let admitted_at_ms =
            i64::try_from(snapshot.admitted_at_ms).map_err(|_| JournalError::InvalidReport)?;
        let final_max_bytes =
            i64::try_from(snapshot.final_max_bytes).map_err(|_| JournalError::CapacityExceeded)?;
        let accounted_bytes =
            i64::try_from(record.accounted_bytes()).map_err(|_| JournalError::CapacityExceeded)?;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        if let Some(existing) =
            load_execution(&transaction, &self.controller, &self.agent, job, task)?
        {
            let mut expected = snapshot.clone();
            expected.phase = existing.snapshot().phase;
            expected.admitted_at_ms = existing.snapshot().admitted_at_ms;
            expected.final_max_bytes = existing.snapshot().final_max_bytes;
            expected.stdout_chunks = existing.snapshot().stdout_chunks;
            expected.stderr_chunks = existing.snapshot().stderr_chunks;
            if &expected != existing.snapshot() {
                return Err(JournalError::Conflict);
            }
            return Ok(ExecutionAdmission::AlreadyRecorded);
        }
        let conflicting: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM executions WHERE nonce_digest=?1) OR EXISTS(SELECT 1 FROM reports WHERE job=?2 AND task=?3)", params![snapshot.nonce_digest.0.as_slice(), job, task], |row| row.get(0)).map_err(sql_error)?;
        if conflicting {
            return Err(JournalError::Conflict);
        }
        let busy: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM executions WHERE phase IN(0,1))",
                [],
                |row| row.get(0),
            )
            .map_err(sql_error)?;
        if busy {
            return Err(JournalError::ExecutionBusy);
        }
        capacity
            .reserve_execution(
                journal_usage(&transaction)?,
                record.accounted_bytes(),
                snapshot.final_max_bytes,
            )
            .map_err(|_| JournalError::CapacityExceeded)?;
        transaction.execute("INSERT INTO executions(job,task,final_report,nonce_digest,envelope_digest,phase,admitted_at_ms,final_max_bytes,accounted_bytes,stdout_chunks,stderr_chunks) VALUES(?1,?2,?3,?4,?5,0,?6,?7,?8,0,0)", params![job, task, final_report, snapshot.nonce_digest.0.as_slice(), snapshot.envelope_digest.0.as_slice(), admitted_at_ms, final_max_bytes, accounted_bytes]).map_err(sql_error)?;
        transaction.commit().map_err(sql_error)?;
        Ok(ExecutionAdmission::New)
    }

    fn start_execution(&mut self, key: &ReportKey) -> Result<(), JournalError> {
        self.validate_owner(key)?;
        let [_, _, job, task, _] = key.parts();
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let mut record = load_execution(&transaction, &self.controller, &self.agent, job, task)?
            .ok_or(JournalError::InvalidExecutionTransition)?;
        if &record.snapshot().final_report_key != key {
            return Err(JournalError::Conflict);
        }
        record
            .record_start_intent()
            .map_err(|_| JournalError::InvalidExecutionTransition)?;
        transaction
            .execute(
                "UPDATE executions SET phase=1 WHERE job=?1 AND task=?2",
                params![job, task],
            )
            .map_err(sql_error)?;
        transaction.commit().map_err(sql_error)?;
        Ok(())
    }

    fn interrupted_execution(&self) -> Result<Option<ExecutionRecord>, JournalError> {
        let key: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT job,task FROM executions WHERE phase IN(0,1)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sql_error)?;
        match key {
            Some((job, task)) => {
                load_execution(&self.connection, &self.controller, &self.agent, &job, &task)
            }
            None => Ok(None),
        }
    }
}

impl AgentReportRepository for SqliteAgentJournal {
    fn append(
        &mut self,
        report: &JournalReport,
        capacity: JournalCapacity,
    ) -> Result<AppendReportOutcome, JournalError> {
        self.validate_owner(&report.key)?;
        let [_, _, job, task, report_id] = report.key.parts();
        let digest = Sha256::digest(report.body()).to_vec();
        let class = encode_class(report.class);
        let accounted =
            i64::try_from(report.accounted_bytes()).map_err(|_| JournalError::CapacityExceeded)?;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let existing: Option<(i64, Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT class,body,digest FROM reports WHERE job=?1 AND task=?2 AND report=?3",
                params![job, task, report_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(sql_error)?;
        if let Some((stored_class, body, stored_digest)) = existing {
            if stored_class != class || body != report.body() || stored_digest != digest {
                return Err(JournalError::Conflict);
            }
            return Ok(AppendReportOutcome::Duplicate);
        }
        let mut completion =
            load_execution(&transaction, &self.controller, &self.agent, job, task)?;
        let mut capacity_class = report.class;
        let mut output_progress_changed = false;
        if let Some(record) = &mut completion {
            match report.class {
                ReportClass::Output => {
                    let (stream, sequence) = output_report_fields(report.body())?;
                    record
                        .record_output_chunk(stream, sequence)
                        .map_err(|_| JournalError::InvalidReport)?;
                    output_progress_changed = true;
                }
                ReportClass::FinalResult => {
                    if record.snapshot().final_report_key != report.key {
                        return Err(JournalError::Conflict);
                    }
                    if report.accounted_bytes() > record.snapshot().final_max_bytes {
                        return Err(JournalError::CapacityExceeded);
                    }
                    let (stdout_chunks, stderr_chunks) =
                        final_report_output_summary(report.body())?;
                    if stdout_chunks != record.snapshot().stdout_chunks
                        || stderr_chunks != record.snapshot().stderr_chunks
                    {
                        return Err(JournalError::InvalidReport);
                    }
                    record
                        .record_result()
                        .map_err(|_| JournalError::InvalidExecutionTransition)?;
                }
                ReportClass::DriftEvidence => return Err(JournalError::InvalidReport),
                ReportClass::Lifecycle => {
                    if record.snapshot().final_report_key == report.key {
                        return Err(JournalError::InvalidReport);
                    }
                }
            }
        } else if report.class == ReportClass::FinalResult {
            let busy: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM executions WHERE phase IN(0,1))",
                    [],
                    |row| row.get(0),
                )
                .map_err(sql_error)?;
            if busy {
                capacity_class = ReportClass::Lifecycle;
            }
        }
        capacity
            .after_append(
                journal_usage(&transaction)?,
                capacity_class,
                report.accounted_bytes(),
            )
            .map_err(|_| JournalError::CapacityExceeded)?;
        transaction.execute("INSERT INTO reports(job,task,report,class,body,digest,accounted_bytes) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![job, task, report_id, class, report.body(), digest, accounted]).map_err(sql_error)?;
        if let Some(record) = completion
            && (report.class == ReportClass::FinalResult || output_progress_changed)
        {
            let snapshot = record.snapshot();
            let phase = if report.class == ReportClass::FinalResult {
                2
            } else {
                match snapshot.phase {
                    ExecutionPhase::Admitted => 0,
                    ExecutionPhase::StartIntent => 1,
                    ExecutionPhase::ResultCommitted => 2,
                }
            };
            transaction
                .execute(
                    "UPDATE executions SET phase=?1,stdout_chunks=?2,stderr_chunks=?3 WHERE job=?4 AND task=?5",
                    params![phase, snapshot.stdout_chunks, snapshot.stderr_chunks, job, task],
                )
                .map_err(sql_error)?;
        }
        transaction.commit().map_err(sql_error)?;
        Ok(AppendReportOutcome::Inserted)
    }

    fn pending(
        &self,
        max_reports: u32,
        max_bytes: u64,
    ) -> Result<Vec<PendingReport>, JournalError> {
        if max_reports == 0 || max_bytes == 0 {
            return Err(JournalError::InvalidReport);
        }
        let mut statement = self.connection.prepare("SELECT job,task,report,class,body,digest,accounted_bytes,length(body) FROM reports ORDER BY id LIMIT ?1").map_err(sql_error)?;
        let mut rows = statement.query([max_reports]).map_err(sql_error)?;
        let mut pending = Vec::new();
        let mut remaining = max_bytes;
        while let Some(row) = rows.next().map_err(sql_error)? {
            let bytes: u64 = row.get(6).map_err(sql_error)?;
            let body_bytes: u64 = row.get(7).map_err(sql_error)?;
            if body_bytes > bytes {
                return Err(JournalError::Corrupt);
            }
            if bytes > remaining {
                if pending.is_empty() {
                    return Err(JournalError::CapacityExceeded);
                }
                break;
            }
            let job: String = row.get(0).map_err(sql_error)?;
            let task: String = row.get(1).map_err(sql_error)?;
            let report_id: String = row.get(2).map_err(sql_error)?;
            let key = ReportKey::new(&self.controller, &self.agent, &job, &task, &report_id)
                .map_err(|_| JournalError::Corrupt)?;
            let class = match row.get::<_, i64>(3).map_err(sql_error)? {
                0 => ReportClass::Lifecycle,
                1 => ReportClass::Output,
                2 => ReportClass::FinalResult,
                3 => ReportClass::DriftEvidence,
                _ => return Err(JournalError::Corrupt),
            };
            let body: Vec<u8> = row.get(4).map_err(sql_error)?;
            let stored_digest: Vec<u8> = row.get(5).map_err(sql_error)?;
            if Sha256::digest(&body).as_slice() != stored_digest {
                return Err(JournalError::Corrupt);
            }
            let report = JournalReport::new(key, class, body).map_err(|_| JournalError::Corrupt)?;
            if report.accounted_bytes() != bytes {
                return Err(JournalError::Corrupt);
            }
            let digest = ReportDigest(
                stored_digest
                    .try_into()
                    .map_err(|_| JournalError::Corrupt)?,
            );
            remaining -= bytes;
            pending.push(PendingReport { report, digest });
        }
        Ok(pending)
    }

    fn acknowledge(&mut self, key: &ReportKey, digest: ReportDigest) -> Result<bool, JournalError> {
        self.validate_owner(key)?;
        let [_, _, job, task, report_id] = key.parts();
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let stored: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT digest FROM reports WHERE job=?1 AND task=?2 AND report=?3",
                params![job, task, report_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_error)?;
        let Some(stored) = stored else {
            return Ok(false);
        };
        let expected = ReportDigest(stored.try_into().map_err(|_| JournalError::Corrupt)?);
        validate_report_ack(key, expected, key, digest)
            .map_err(|_| JournalError::InvalidReceipt)?;
        transaction
            .execute(
                "DELETE FROM executions WHERE job=?1 AND task=?2 AND final_report=?3 AND phase=2",
                params![job, task, report_id],
            )
            .map_err(sql_error)?;
        transaction
            .execute(
                "DELETE FROM reports WHERE job=?1 AND task=?2 AND report=?3",
                params![job, task, report_id],
            )
            .map_err(sql_error)?;
        transaction.commit().map_err(sql_error)?;
        Ok(true)
    }
}

fn output_report_fields(body: &[u8]) -> Result<(TaskOutputStream, u64), JournalError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| JournalError::InvalidReport)?;
    let stream = match value.get("stream").and_then(serde_json::Value::as_str) {
        Some("stdout") => TaskOutputStream::Stdout,
        Some("stderr") => TaskOutputStream::Stderr,
        _ => return Err(JournalError::InvalidReport),
    };
    let sequence = value
        .get("sequence")
        .and_then(serde_json::Value::as_u64)
        .ok_or(JournalError::InvalidReport)?;
    Ok((stream, sequence))
}

fn final_report_output_summary(body: &[u8]) -> Result<(u64, u64), JournalError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| JournalError::InvalidReport)?;
    let output = value.get("output").ok_or(JournalError::InvalidReport)?;
    let stdout_chunks = output
        .get("stdout_chunks")
        .and_then(serde_json::Value::as_u64)
        .ok_or(JournalError::InvalidReport)?;
    let stderr_chunks = output
        .get("stderr_chunks")
        .and_then(serde_json::Value::as_u64)
        .ok_or(JournalError::InvalidReport)?;
    Ok((stdout_chunks, stderr_chunks))
}

fn journal_usage(connection: &Connection) -> Result<JournalUsage, JournalError> {
    connection.query_row("SELECT (SELECT count(*) FROM reports), (SELECT coalesce(sum(accounted_bytes),0) FROM reports) + (SELECT coalesce(sum(accounted_bytes),0) FROM executions)", [], |row| Ok(JournalUsage { reports: row.get(0)?, bytes: row.get(1)? })).map_err(sql_error)
}

fn load_execution(
    connection: &Connection,
    controller: &str,
    agent: &str,
    job: &str,
    task: &str,
) -> Result<Option<ExecutionRecord>, JournalError> {
    struct StoredExecution {
        final_report: String,
        nonce: Vec<u8>,
        envelope: Vec<u8>,
        phase: i64,
        admitted_at_ms: u64,
        final_max_bytes: u64,
        accounted_bytes: u64,
        stdout_chunks: u64,
        stderr_chunks: u64,
    }
    let row = connection.query_row("SELECT final_report,nonce_digest,envelope_digest,phase,admitted_at_ms,final_max_bytes,accounted_bytes,stdout_chunks,stderr_chunks FROM executions WHERE job=?1 AND task=?2", params![job, task], |row| Ok(StoredExecution { final_report: row.get(0)?, nonce: row.get(1)?, envelope: row.get(2)?, phase: row.get(3)?, admitted_at_ms: row.get(4)?, final_max_bytes: row.get(5)?, accounted_bytes: row.get(6)?, stdout_chunks: row.get(7)?, stderr_chunks: row.get(8)? })).optional().map_err(sql_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let phase = match row.phase {
        0 => ExecutionPhase::Admitted,
        1 => ExecutionPhase::StartIntent,
        2 => ExecutionPhase::ResultCommitted,
        _ => return Err(JournalError::Corrupt),
    };
    let record = ExecutionRecord::restore(ExecutionSnapshot {
        final_report_key: ReportKey::new(controller, agent, job, task, &row.final_report)
            .map_err(|_| JournalError::Corrupt)?,
        nonce_digest: ReportDigest(row.nonce.try_into().map_err(|_| JournalError::Corrupt)?),
        envelope_digest: ReportDigest(row.envelope.try_into().map_err(|_| JournalError::Corrupt)?),
        phase,
        admitted_at_ms: row.admitted_at_ms,
        final_max_bytes: row.final_max_bytes,
        stdout_chunks: row.stdout_chunks,
        stderr_chunks: row.stderr_chunks,
    })
    .map_err(|_| JournalError::Corrupt)?;
    if record.accounted_bytes() != row.accounted_bytes {
        return Err(JournalError::Corrupt);
    }
    Ok(Some(record))
}

fn encode_class(class: ReportClass) -> i64 {
    match class {
        ReportClass::Lifecycle => 0,
        ReportClass::Output => 1,
        ReportClass::FinalResult => 2,
        ReportClass::DriftEvidence => 3,
    }
}

fn sql_error(error: rusqlite::Error) -> JournalError {
    if let rusqlite::Error::SqliteFailure(code, _) = &error {
        match code.code {
            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked => {
                return JournalError::AlreadyOpen;
            }
            rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase => {
                return JournalError::Corrupt;
            }
            _ => {}
        }
    }
    JournalError::Unavailable
}

fn prepare_path(path: &Path) -> Result<(), JournalError> {
    let parent = path.parent().ok_or(JournalError::InsecurePermissions)?;
    verify_private_path(parent, true)?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => verify_private_path(path, false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(path).map_err(|_| JournalError::Unavailable)?;
            verify_private_path(path, false)
        }
        Err(_) => Err(JournalError::Unavailable),
    }
}

fn verify_private_path(path: &Path, directory: bool) -> Result<(), JournalError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| JournalError::Unavailable)?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(JournalError::InsecurePermissions);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !private_metadata_matches(
            metadata.mode(),
            metadata.uid(),
            rustix::process::geteuid().as_raw(),
            metadata.nlink(),
            directory,
        ) {
            return Err(JournalError::InsecurePermissions);
        }
    }
    #[cfg(not(unix))]
    return Err(JournalError::InsecurePermissions);
    #[cfg(unix)]
    Ok(())
}

#[cfg(unix)]
fn private_metadata_matches(
    mode: u32,
    owner: u32,
    current: u32,
    links: u64,
    directory: bool,
) -> bool {
    owner == current && mode & 0o077 == 0 && (directory || links == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_application::delivery::{ConfirmAgentReport, QueueAgentReport};
    use fleet_domain::delivery::{JournalUsage, ReportClass};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(std::path::PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "fleet-agent-journal-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> std::path::PathBuf {
            self.0.join("journal.sqlite3")
        }

        fn open(&self) -> SqliteAgentJournal {
            SqliteAgentJournal::open(&self.path(), "controller", "agent").unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn report() -> JournalReport {
        JournalReport::new(
            ReportKey::new("controller", "agent", "job", "task", "report").unwrap(),
            ReportClass::Output,
            b"private-output-fixture".to_vec(),
        )
        .unwrap()
    }

    fn capacity() -> JournalCapacity {
        JournalCapacity::new(
            JournalUsage {
                reports: 10,
                bytes: 10_000,
            },
            JournalUsage {
                reports: 2,
                bytes: 1000,
            },
        )
        .unwrap()
    }

    fn final_summary(stdout_chunks: u64, stderr_chunks: u64, truncated: bool) -> Vec<u8> {
        serde_json::json!({
            "output": {
                "stdout_chunks": stdout_chunks,
                "stderr_chunks": stderr_chunks,
                "truncated": truncated,
            }
        })
        .to_string()
        .into_bytes()
    }

    fn execution(task: &str, nonce: u8) -> ExecutionRecord {
        ExecutionRecord::restore(ExecutionSnapshot {
            final_report_key: ReportKey::new("controller", "agent", "job", task, "final").unwrap(),
            nonce_digest: ReportDigest([nonce; 32]),
            envelope_digest: ReportDigest([9; 32]),
            phase: ExecutionPhase::Admitted,
            admitted_at_ms: 100,
            final_max_bytes: 1000,
            stdout_chunks: 0,
            stderr_chunks: 0,
        })
        .unwrap()
    }

    #[test]
    fn execution_admission_and_start_intent_survive_restart_without_reexecution() {
        let fixture = Fixture::new();
        let record = execution("task", 1);
        let key = &record.snapshot().final_report_key;
        let mut store = fixture.open();
        assert_eq!(
            store.admit_execution(&record, capacity()),
            Ok(ExecutionAdmission::New)
        );
        assert_eq!(
            store.admit_execution(&record, capacity()),
            Ok(ExecutionAdmission::AlreadyRecorded)
        );
        assert_eq!(
            store.admit_execution(&execution("other", 2), capacity()),
            Err(JournalError::ExecutionBusy)
        );
        drop(store);
        let mut store = fixture.open();
        assert_eq!(store.interrupted_execution().unwrap(), Some(record.clone()));
        store.start_execution(key).unwrap();
        assert_eq!(
            store.start_execution(key),
            Err(JournalError::InvalidExecutionTransition)
        );
        drop(store);
        let store = fixture.open();
        assert_eq!(
            store
                .interrupted_execution()
                .unwrap()
                .unwrap()
                .snapshot()
                .phase,
            ExecutionPhase::StartIntent
        );
    }

    #[test]
    fn final_report_and_execution_completion_commit_together() {
        let fixture = Fixture::new();
        let record = execution("task", 1);
        let mut store = fixture.open();
        store.admit_execution(&record, capacity()).unwrap();
        store
            .start_execution(&record.snapshot().final_report_key)
            .unwrap();
        let final_report = JournalReport::new(
            record.snapshot().final_report_key.clone(),
            ReportClass::FinalResult,
            final_summary(0, 0, false),
        )
        .unwrap();
        store.append(&final_report, capacity()).unwrap();
        assert_eq!(store.interrupted_execution().unwrap(), None);
        assert_eq!(
            store.admit_execution(&record, capacity()),
            Ok(ExecutionAdmission::AlreadyRecorded)
        );
        assert_eq!(
            store.admit_execution(&execution("other", 2), capacity()),
            Ok(ExecutionAdmission::New)
        );
    }

    #[test]
    fn repeated_execution_admission_ignores_local_admission_metadata() {
        let fixture = Fixture::new();
        let record = execution("task", 1);
        let mut retried_snapshot = record.snapshot().clone();
        retried_snapshot.admitted_at_ms += 1000;
        retried_snapshot.final_max_bytes += 128;
        let retried = ExecutionRecord::restore(retried_snapshot).unwrap();
        let mut store = fixture.open();
        assert_eq!(
            store.admit_execution(&record, capacity()),
            Ok(ExecutionAdmission::New)
        );
        store
            .start_execution(&record.snapshot().final_report_key)
            .unwrap();
        let final_report = JournalReport::new(
            record.snapshot().final_report_key.clone(),
            ReportClass::FinalResult,
            final_summary(0, 0, false),
        )
        .unwrap();
        store.append(&final_report, capacity()).unwrap();

        assert_eq!(
            store.admit_execution(&retried, capacity()),
            Ok(ExecutionAdmission::AlreadyRecorded)
        );
    }

    #[test]
    fn execution_output_counts_survive_receipt_cleanup_and_gate_final_summary() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let record = execution("task", 1);
        store.admit_execution(&record, capacity()).unwrap();
        store
            .start_execution(&record.snapshot().final_report_key)
            .unwrap();
        for (stream, sequence) in [("stdout", 0), ("stderr", 0)] {
            let report = JournalReport::new(
                ReportKey::new(
                    "controller",
                    "agent",
                    "job",
                    "task",
                    &format!("output-{stream}-{sequence:020}"),
                )
                .unwrap(),
                ReportClass::Output,
                serde_json::json!({
                    "stream": stream,
                    "sequence": sequence,
                    "data": "private output",
                })
                .to_string()
                .into_bytes(),
            )
            .unwrap();
            store.append(&report, capacity()).unwrap();
        }
        let output_reports = store.pending(16, 10_000).unwrap();
        assert_eq!(output_reports.len(), 2);
        for report in output_reports {
            store
                .acknowledge(&report.report.key, report.digest)
                .unwrap();
        }

        let interrupted = store.interrupted_execution().unwrap().unwrap();
        assert_eq!(interrupted.snapshot().stdout_chunks, 1);
        assert_eq!(interrupted.snapshot().stderr_chunks, 1);
        let wrong_summary = JournalReport::new(
            record.snapshot().final_report_key.clone(),
            ReportClass::FinalResult,
            final_summary(0, 0, true),
        )
        .unwrap();
        assert_eq!(
            store.append(&wrong_summary, capacity()),
            Err(JournalError::InvalidReport)
        );
        assert_eq!(store.interrupted_execution().unwrap(), Some(interrupted));

        let recovered_summary = JournalReport::new(
            record.snapshot().final_report_key.clone(),
            ReportClass::FinalResult,
            final_summary(1, 1, true),
        )
        .unwrap();
        store.append(&recovered_summary, capacity()).unwrap();
        assert!(store.interrupted_execution().unwrap().is_none());
        assert_eq!(store.pending(16, 10_000).unwrap().len(), 1);
    }

    #[test]
    fn failed_final_transaction_preserves_start_intent_and_no_partial_report() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let record = execution("task", 1);
        store.admit_execution(&record, capacity()).unwrap();
        store
            .start_execution(&record.snapshot().final_report_key)
            .unwrap();
        let final_report = JournalReport::new(
            record.snapshot().final_report_key.clone(),
            ReportClass::FinalResult,
            final_summary(0, 0, false),
        )
        .unwrap();
        store.connection.execute_batch("CREATE TRIGGER fail_execution BEFORE UPDATE ON executions WHEN NEW.phase=2 BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
        assert_eq!(
            store.append(&final_report, capacity()),
            Err(JournalError::Unavailable)
        );
        drop(store);
        let mut store = fixture.open();
        assert_eq!(
            store
                .interrupted_execution()
                .unwrap()
                .unwrap()
                .snapshot()
                .phase,
            ExecutionPhase::StartIntent
        );
        assert!(store.pending(16, 10_000).unwrap().is_empty());
        store
            .connection
            .execute_batch("DROP TRIGGER fail_execution;")
            .unwrap();
        store.append(&final_report, capacity()).unwrap();
        let pending = store.pending(16, 10_000).unwrap();
        assert_eq!(pending.len(), 1);
        assert!(store.interrupted_execution().unwrap().is_none());
        store
            .acknowledge(&final_report.key, pending[0].digest)
            .unwrap();
        let remaining: i64 = store
            .connection
            .query_row("SELECT count(*) FROM executions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            remaining, 0,
            "only matching final ACK removes completed execution metadata"
        );
    }

    #[test]
    fn execution_rejects_changed_envelope_reused_nonce_and_wrong_final_key() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let record = execution("task", 1);
        store.admit_execution(&record, capacity()).unwrap();
        let mut changed = record.snapshot().clone();
        changed.envelope_digest = ReportDigest([3; 32]);
        assert_eq!(
            store.admit_execution(&ExecutionRecord::restore(changed).unwrap(), capacity()),
            Err(JournalError::Conflict)
        );
        assert_eq!(
            store.admit_execution(&execution("other", 1), capacity()),
            Err(JournalError::Conflict)
        );
        let wrong_key = ReportKey::new("controller", "agent", "job", "task", "wrong").unwrap();
        assert_eq!(
            store.start_execution(&wrong_key),
            Err(JournalError::Conflict)
        );
        let wrong_result =
            JournalReport::new(wrong_key, ReportClass::FinalResult, b"result".to_vec()).unwrap();
        assert_eq!(
            store.append(&wrong_result, capacity()),
            Err(JournalError::Conflict)
        );
        let output_with_reserved_key = JournalReport::new(
            record.snapshot().final_report_key.clone(),
            ReportClass::Output,
            b"output".to_vec(),
        )
        .unwrap();
        assert_eq!(
            store.append(&output_with_reserved_key, capacity()),
            Err(JournalError::InvalidReport)
        );
        assert_eq!(store.interrupted_execution().unwrap(), Some(record));
    }

    #[test]
    fn active_final_reserve_cannot_be_spent_by_unrelated_reports() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let record = execution("active", 1);
        store.admit_execution(&record, capacity()).unwrap();
        store
            .start_execution(&record.snapshot().final_report_key)
            .unwrap();
        let template = report();
        let overhead = template.accounted_bytes() - template.body().len() as u64;
        let output = JournalReport::new(
            template.key,
            ReportClass::Output,
            vec![b'x'; (9000 - record.accounted_bytes() - overhead) as usize],
        )
        .unwrap();
        store.append(&output, capacity()).unwrap();
        let other_final = JournalReport::new(
            ReportKey::new("controller", "agent", "job", "other", "final").unwrap(),
            ReportClass::FinalResult,
            b"busy rejection".to_vec(),
        )
        .unwrap();
        assert_eq!(
            store.append(&other_final, capacity()),
            Err(JournalError::CapacityExceeded)
        );
        let oversized = JournalReport::new(
            record.snapshot().final_report_key.clone(),
            ReportClass::FinalResult,
            vec![b'x'; 1000],
        )
        .unwrap();
        assert_eq!(
            store.append(&oversized, capacity()),
            Err(JournalError::CapacityExceeded)
        );
        let final_report = JournalReport::new(
            record.snapshot().final_report_key.clone(),
            ReportClass::FinalResult,
            final_summary(0, 0, false),
        )
        .unwrap();
        store.append(&final_report, capacity()).unwrap();
        assert_eq!(
            store.admit_execution(&execution("other", 2), capacity()),
            Err(JournalError::CapacityExceeded)
        );
        assert_eq!(store.pending(16, 10_000).unwrap().len(), 2);
    }

    #[test]
    fn version_one_fixture_migrates_reports_without_rewriting_or_resetting_owner() {
        let fixture = Fixture::new();
        prepare_path(&fixture.path()).unwrap();
        let connection = Connection::open(fixture.path()).unwrap();
        connection.execute_batch("CREATE TABLE journal_owner (id INTEGER PRIMARY KEY CHECK(id=1), controller TEXT NOT NULL, agent TEXT NOT NULL);
            INSERT INTO journal_owner VALUES(1,'controller','agent');
            CREATE TABLE reports (id INTEGER PRIMARY KEY AUTOINCREMENT, job TEXT NOT NULL, task TEXT NOT NULL, report TEXT NOT NULL,
                class INTEGER NOT NULL CHECK(class BETWEEN 0 AND 2), body BLOB NOT NULL, digest BLOB NOT NULL CHECK(length(digest)=32),
                accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0), UNIQUE(job,task,report));
            PRAGMA user_version=1; PRAGMA application_id=1179274828;").unwrap();
        let original = report();
        let digest = Sha256::digest(original.body()).to_vec();
        connection.execute("INSERT INTO reports(job,task,report,class,body,digest,accounted_bytes) VALUES('job','task','report',1,?1,?2,?3)", params![original.body(), digest, original.accounted_bytes()]).unwrap();
        drop(connection);
        assert!(matches!(
            SqliteAgentJournal::open(&fixture.path(), "wrong", "agent"),
            Err(JournalError::IdentityMismatch)
        ));
        let connection = Connection::open(fixture.path()).unwrap();
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        drop(connection);
        for _ in 0..2 {
            let store = fixture.open();
            assert_eq!(
                store
                    .connection
                    .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                    .unwrap(),
                4
            );
            assert_eq!(store.pending(16, 10_000).unwrap()[0].report, original);
            assert!(store.interrupted_execution().unwrap().is_none());
        }
    }

    #[test]
    fn drift_evidence_class_migrates_v3_journal_and_preserves_existing_reports() {
        let fixture = Fixture::new();
        let existing = report();
        let evidence = JournalReport::new(
            ReportKey::new("controller", "agent", "job", "task", "drift-evidence").unwrap(),
            ReportClass::DriftEvidence,
            br#"{"status":"drifted","expected":"running","actual":"stopped"}"#.to_vec(),
        )
        .unwrap();
        prepare_path(&fixture.path()).unwrap();
        let connection = Connection::open(fixture.path()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE journal_owner (id INTEGER PRIMARY KEY CHECK(id=1), controller TEXT NOT NULL, agent TEXT NOT NULL);
                INSERT INTO journal_owner VALUES(1,'controller','agent');
                CREATE TABLE reports (id INTEGER PRIMARY KEY AUTOINCREMENT, job TEXT NOT NULL, task TEXT NOT NULL, report TEXT NOT NULL,
                    class INTEGER NOT NULL CHECK(class BETWEEN 0 AND 2), body BLOB NOT NULL, digest BLOB NOT NULL CHECK(length(digest)=32),
                    accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0), UNIQUE(job,task,report));
                CREATE TABLE executions (
                    job TEXT NOT NULL, task TEXT NOT NULL, final_report TEXT NOT NULL,
                    nonce_digest BLOB NOT NULL UNIQUE CHECK(length(nonce_digest)=32),
                    envelope_digest BLOB NOT NULL CHECK(length(envelope_digest)=32),
                    phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 2),
                    admitted_at_ms INTEGER NOT NULL CHECK(admitted_at_ms>=0),
                    final_max_bytes INTEGER NOT NULL CHECK(final_max_bytes>0),
                    accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0),
                    stdout_chunks INTEGER NOT NULL DEFAULT 0 CHECK(stdout_chunks>=0),
                    stderr_chunks INTEGER NOT NULL DEFAULT 0 CHECK(stderr_chunks>=0), PRIMARY KEY(job,task));
                CREATE UNIQUE INDEX executions_single_active ON executions((1)) WHERE phase IN(0,1);
                PRAGMA user_version=3; PRAGMA application_id=1179274828;",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO reports(job,task,report,class,body,digest,accounted_bytes) VALUES('job','task','report',1,?1,?2,?3)",
                params![
                    existing.body(),
                    Sha256::digest(existing.body()).as_slice(),
                    existing.accounted_bytes()
                ],
            )
            .unwrap();
        drop(connection);

        {
            let mut store = fixture.open();
            assert_eq!(
                store
                    .connection
                    .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                    .unwrap(),
                4
            );
            assert_eq!(store.pending(16, 10_000).unwrap()[0].report, existing);
            assert_eq!(
                store.append(&evidence, capacity()),
                Ok(AppendReportOutcome::Inserted)
            );
        }

        let store = fixture.open();
        let pending = store.pending(16, 10_000).unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].report, existing);
        assert_eq!(pending[1].report, evidence);
    }

    #[test]
    fn version_two_upgrade_refuses_an_active_started_execution_without_mutating_it() {
        let fixture = Fixture::new();
        prepare_path(&fixture.path()).unwrap();
        let connection = Connection::open(fixture.path()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE journal_owner (id INTEGER PRIMARY KEY CHECK(id=1), controller TEXT NOT NULL, agent TEXT NOT NULL);
                INSERT INTO journal_owner VALUES(1,'controller','agent');
                CREATE TABLE reports (id INTEGER PRIMARY KEY AUTOINCREMENT, job TEXT NOT NULL, task TEXT NOT NULL, report TEXT NOT NULL,
                    class INTEGER NOT NULL CHECK(class BETWEEN 0 AND 2), body BLOB NOT NULL, digest BLOB NOT NULL CHECK(length(digest)=32),
                    accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0), UNIQUE(job,task,report));
                CREATE TABLE executions (
                    job TEXT NOT NULL, task TEXT NOT NULL, final_report TEXT NOT NULL,
                    nonce_digest BLOB NOT NULL UNIQUE CHECK(length(nonce_digest)=32),
                    envelope_digest BLOB NOT NULL CHECK(length(envelope_digest)=32),
                    phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 2),
                    admitted_at_ms INTEGER NOT NULL CHECK(admitted_at_ms>=0),
                    final_max_bytes INTEGER NOT NULL CHECK(final_max_bytes>0),
                    accounted_bytes INTEGER NOT NULL CHECK(accounted_bytes>0), PRIMARY KEY(job,task));
                CREATE UNIQUE INDEX executions_single_active ON executions((1)) WHERE phase IN(0,1);
                PRAGMA user_version=2; PRAGMA application_id=1179274828;",
            )
            .unwrap();
        let record = execution("task", 1);
        connection
            .execute(
                "INSERT INTO executions(job,task,final_report,nonce_digest,envelope_digest,phase,admitted_at_ms,final_max_bytes,accounted_bytes)
                 VALUES('job','task','final',?1,?2,1,100,1000,?3)",
                params![
                    record.snapshot().nonce_digest.0.as_slice(),
                    record.snapshot().envelope_digest.0.as_slice(),
                    record.accounted_bytes() - 16,
                ],
            )
            .unwrap();
        drop(connection);

        assert!(matches!(
            SqliteAgentJournal::open(&fixture.path(), "controller", "agent"),
            Err(JournalError::ActiveExecutionNeedsDrain)
        ));
        let connection = Connection::open(fixture.path()).unwrap();
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let (phase, accounted_bytes): (i64, i64) = connection
            .query_row(
                "SELECT phase,accounted_bytes FROM executions WHERE job='job' AND task='task'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(version, 2);
        assert_eq!(phase, 1);
        assert_eq!(accounted_bytes as u64, record.accounted_bytes() - 16);
    }

    #[test]
    fn reports_survive_reopen_until_matching_acknowledgement() {
        let fixture = Fixture::new();
        let expected = report();
        {
            let mut store = fixture.open();
            assert_eq!(
                QueueAgentReport::execute(&mut store, &expected, capacity()).unwrap(),
                AppendReportOutcome::Inserted
            );
        }
        let mut store = fixture.open();
        let pending = store.pending(16, 10_000).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].report, expected);
        assert_eq!(
            ConfirmAgentReport::execute(&mut store, &expected.key, ReportDigest([0; 32])),
            Err(JournalError::InvalidReceipt)
        );
        assert_eq!(store.pending(16, 10_000).unwrap().len(), 1);
        assert!(ConfirmAgentReport::execute(&mut store, &expected.key, pending[0].digest).unwrap());
        drop(store);
        let mut store = fixture.open();
        assert!(store.pending(16, 10_000).unwrap().is_empty());
        assert!(
            !ConfirmAgentReport::execute(&mut store, &expected.key, pending[0].digest).unwrap()
        );
    }

    #[test]
    fn duplicate_is_noop_and_changed_body_conflicts() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let report = report();
        store.append(&report, capacity()).unwrap();
        assert_eq!(
            store.append(&report, capacity()),
            Ok(AppendReportOutcome::Duplicate)
        );
        let changed =
            JournalReport::new(report.key.clone(), report.class, b"different".to_vec()).unwrap();
        assert_eq!(
            store.append(&changed, capacity()),
            Err(JournalError::Conflict)
        );
        assert_eq!(store.pending(16, 10_000).unwrap()[0].report, report);
    }

    #[test]
    fn capacity_reserves_final_and_duplicate_stays_noop_at_limit() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let first = report();
        let limits = JournalCapacity::new(
            JournalUsage {
                reports: 2,
                bytes: first.accounted_bytes() * 2,
            },
            JournalUsage {
                reports: 1,
                bytes: first.accounted_bytes(),
            },
        )
        .unwrap();
        store.append(&first, limits).unwrap();
        assert_eq!(
            store.append(&first, limits),
            Ok(AppendReportOutcome::Duplicate)
        );
        let second_key = ReportKey::new("controller", "agent", "job", "task", "second").unwrap();
        let second =
            JournalReport::new(second_key.clone(), ReportClass::Output, b"done".to_vec()).unwrap();
        assert_eq!(
            store.append(&second, limits),
            Err(JournalError::CapacityExceeded)
        );
        let final_report =
            JournalReport::new(second_key, ReportClass::FinalResult, b"done".to_vec()).unwrap();
        store.append(&final_report, limits).unwrap();
        assert_eq!(store.pending(16, 10_000).unwrap().len(), 2);
        let digest = store.pending(16, 10_000).unwrap()[1].digest;
        store.acknowledge(&final_report.key, digest).unwrap();
        assert_eq!(
            store.pending(16, 10_000).unwrap()[0].report,
            first,
            "final ACK cannot delete output"
        );
    }

    #[test]
    fn replay_batch_is_bounded_by_bytes_and_count() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let first = report();
        store.append(&first, capacity()).unwrap();
        let second = JournalReport::new(
            ReportKey::new("controller", "agent", "job", "task", "second").unwrap(),
            ReportClass::Output,
            b"second body".to_vec(),
        )
        .unwrap();
        store.append(&second, capacity()).unwrap();
        assert_eq!(store.pending(1, 10_000).unwrap().len(), 1);
        assert_eq!(store.pending(16, first.accounted_bytes()).unwrap().len(), 1);
        assert_eq!(
            store.pending(16, first.accounted_bytes() - 1),
            Err(JournalError::CapacityExceeded)
        );
        assert_eq!(store.pending(0, 10_000), Err(JournalError::InvalidReport));
    }

    #[test]
    fn identity_mismatch_and_foreign_ack_preserve_reports() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let original = report();
        store.append(&original, capacity()).unwrap();
        let digest = store.pending(1, 10_000).unwrap()[0].digest;
        let foreign = ReportKey::new("other-controller", "agent", "job", "task", "report").unwrap();
        assert_eq!(
            store.acknowledge(&foreign, digest),
            Err(JournalError::IdentityMismatch)
        );
        let other_task =
            ReportKey::new("controller", "agent", "job", "other-task", "report").unwrap();
        assert!(!store.acknowledge(&other_task, digest).unwrap());
        let foreign_report =
            JournalReport::new(foreign, ReportClass::Output, b"wrong".to_vec()).unwrap();
        assert_eq!(
            store.append(&foreign_report, capacity()),
            Err(JournalError::IdentityMismatch)
        );
        drop(store);
        assert!(matches!(
            SqliteAgentJournal::open(&fixture.path(), "other-controller", "agent"),
            Err(JournalError::IdentityMismatch)
        ));
        assert_eq!(
            fixture.open().pending(1, 10_000).unwrap()[0].report,
            original
        );
    }

    #[test]
    fn exclusive_owner_rejects_second_open_and_unlocks_on_close() {
        let fixture = Fixture::new();
        let first = fixture.open();
        assert!(matches!(
            SqliteAgentJournal::open(&fixture.path(), "controller", "agent"),
            Err(JournalError::AlreadyOpen)
        ));
        drop(first);
        let _reopened = fixture.open();
    }

    #[test]
    fn newer_schema_is_rejected_without_resetting_reports() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        store.append(&report(), capacity()).unwrap();
        store
            .connection
            .pragma_update(None, "user_version", 99)
            .unwrap();
        drop(store);
        assert!(matches!(
            SqliteAgentJournal::open(&fixture.path(), "controller", "agent"),
            Err(JournalError::UnsupportedVersion)
        ));
        let connection = Connection::open(fixture.path()).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM reports", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            99
        );
    }

    #[test]
    fn damaged_body_and_failed_transaction_never_report_success() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        store.connection.execute_batch("CREATE TRIGGER deny_report BEFORE INSERT ON reports BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
        assert_eq!(
            store.append(&report(), capacity()),
            Err(JournalError::Unavailable)
        );
        assert!(store.pending(16, 10_000).unwrap().is_empty());
        store
            .connection
            .execute_batch("DROP TRIGGER deny_report;")
            .unwrap();
        store.append(&report(), capacity()).unwrap();
        store
            .connection
            .execute("UPDATE reports SET body=?1", [b"corrupt".to_vec()])
            .unwrap();
        assert_eq!(store.pending(16, 10_000), Err(JournalError::Corrupt));
    }

    #[test]
    fn sqlite_full_preserves_previously_committed_report() {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let original = report();
        store.append(&original, capacity()).unwrap();
        let pages: i64 = store
            .connection
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .unwrap();
        store
            .connection
            .pragma_update(None, "max_page_count", pages)
            .unwrap();
        let large = JournalReport::new(
            ReportKey::new("controller", "agent", "job", "task", "large").unwrap(),
            ReportClass::Output,
            vec![b'x'; 1024 * 1024],
        )
        .unwrap();
        let limits = JournalCapacity::new(
            JournalUsage {
                reports: 100,
                bytes: 4 * 1024 * 1024,
            },
            JournalUsage {
                reports: 1,
                bytes: 1024,
            },
        )
        .unwrap();
        assert_eq!(store.append(&large, limits), Err(JournalError::Unavailable));
        drop(store);
        assert_eq!(
            fixture.open().pending(16, 10_000).unwrap()[0].report,
            original
        );
    }

    #[cfg(unix)]
    #[test]
    fn permissions_and_links_fail_closed_without_repairing_user_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let fixture = Fixture::new();
        let store = fixture.open();
        let mode = std::fs::metadata(fixture.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        drop(store);
        std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            SqliteAgentJournal::open(&fixture.path(), "controller", "agent"),
            Err(JournalError::InsecurePermissions)
        ));
        assert_eq!(
            std::fs::metadata(fixture.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        let linked = fixture.0.join("symlink.sqlite3");
        symlink(fixture.path(), &linked).unwrap();
        assert!(matches!(
            SqliteAgentJournal::open(&linked, "controller", "agent"),
            Err(JournalError::InsecurePermissions)
        ));
        let hardlink = fixture.0.join("hardlink.sqlite3");
        std::fs::hard_link(fixture.path(), &hardlink).unwrap();
        assert!(matches!(
            SqliteAgentJournal::open(&hardlink, "controller", "agent"),
            Err(JournalError::InsecurePermissions)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn owner_only_mode_is_not_enough_for_another_users_file() {
        assert!(!private_metadata_matches(0o600, 501, 0, 1, false));
        assert!(!private_metadata_matches(0o700, 501, 0, 1, true));
        assert!(private_metadata_matches(0o600, 501, 501, 1, false));
        assert!(private_metadata_matches(0o700, 501, 501, 2, true));
    }

    #[test]
    fn committed_report_survives_abrupt_process_death() {
        let fixture = Fixture::new();
        kill_committed_journal_child(&fixture, "report");
        let mut reopened = fixture.open();
        let pending = reopened.pending(16, 10_000).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].report, report());
        assert_eq!(
            reopened.append(&report(), capacity()),
            Ok(AppendReportOutcome::Duplicate)
        );
    }

    #[test]
    fn execution_crash_boundaries_preserve_phase_or_final_report() {
        for phase in ["admitted", "start", "result"] {
            let fixture = Fixture::new();
            kill_committed_journal_child(&fixture, phase);
            let mut store = fixture.open();
            let pending = store.pending(16, 10_000).unwrap();
            if phase == "result" {
                assert!(store.interrupted_execution().unwrap().is_none());
                assert_eq!(pending.len(), 1);
                assert_eq!(
                    pending[0].report.key,
                    execution("task", 1).snapshot().final_report_key
                );
            } else {
                let execution = store.interrupted_execution().unwrap().unwrap();
                let expected = if phase == "admitted" {
                    ExecutionPhase::Admitted
                } else {
                    ExecutionPhase::StartIntent
                };
                assert_eq!(execution.snapshot().phase, expected);
                assert!(pending.is_empty());
            }
            assert_eq!(
                store.admit_execution(&execution("task", 1), capacity()),
                Ok(ExecutionAdmission::AlreadyRecorded)
            );
        }
    }

    fn kill_committed_journal_child(fixture: &Fixture, phase: &str) {
        use std::process::{Child, Command, Stdio};
        struct ChildOwner(Child);
        impl Drop for ChildOwner {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = ChildOwner(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "agent_journal::tests::journal_crash_child",
                    "--ignored",
                ])
                .env("FLEET_TEST_JOURNAL_CRASH_DIR", &fixture.0)
                .env("FLEET_TEST_JOURNAL_CRASH_PHASE", phase)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !fixture.0.join("committed").exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "child exited before commit marker"
            );
            assert!(
                std::time::Instant::now() < deadline,
                "child commit deadline exceeded"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        child.0.kill().unwrap();
        child.0.wait().unwrap();
    }

    #[test]
    #[ignore = "subprocess fixture owned and killed by committed_report_survives_abrupt_process_death"]
    fn journal_crash_child() {
        let directory = std::env::var_os("FLEET_TEST_JOURNAL_CRASH_DIR")
            .expect("parent-provided isolated test directory");
        let directory = std::path::PathBuf::from(directory);
        let phase = std::env::var("FLEET_TEST_JOURNAL_CRASH_PHASE").expect("parent-provided phase");
        let mut store =
            SqliteAgentJournal::open(&directory.join("journal.sqlite3"), "controller", "agent")
                .unwrap();
        if phase == "report" {
            store.append(&report(), capacity()).unwrap();
        } else {
            let record = execution("task", 1);
            store.admit_execution(&record, capacity()).unwrap();
            if phase != "admitted" {
                store
                    .start_execution(&record.snapshot().final_report_key)
                    .unwrap();
            }
            if phase == "result" {
                let final_report = JournalReport::new(
                    record.snapshot().final_report_key.clone(),
                    ReportClass::FinalResult,
                    final_summary(0, 0, false),
                )
                .unwrap();
                store.append(&final_report, capacity()).unwrap();
            }
        }
        std::fs::write(directory.join("committed"), b"committed").unwrap();
        // Parent owns a bounded wait and kills this process before normal Drop.
        std::thread::sleep(std::time::Duration::from_secs(30));
        panic!("parent did not terminate the crash fixture");
    }
}
