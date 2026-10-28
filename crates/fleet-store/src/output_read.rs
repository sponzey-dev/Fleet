//! SQLite snapshot adapter for byte-bounded Job output pages and atomic
//! append/retention read projections. No execution or receipt authority lives here.

use crate::{SqliteStore, StoreError};
use fleet_application::ControllerDeliveryIdentityRepository;
use fleet_application::JobOutputStream;
use fleet_application::output_read::{
    OutputFragment, OutputFragmentPosition, OutputHistory, OutputPage, OutputPageRepository,
    OutputReadCursor, OutputReadError, OutputReadLimits, OutputReadScope,
};
use fleet_domain::{AgentId, JobStatus};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};

const PROJECTION_SQL: &str = r#"
CREATE TABLE job_output_read_state (
    job_id TEXT PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK(typeof(generation) = 'integer' AND generation >= 0),
    history TEXT NOT NULL CHECK(history IN ('tracked', 'unknown', 'pruned')),
    last_row_id INTEGER NOT NULL CHECK(typeof(last_row_id) = 'integer' AND last_row_id >= 0)
);
INSERT INTO job_output_read_state
    SELECT jobs.id, 0, 'unknown', COALESCE(MAX(c.id), 0)
    FROM jobs LEFT JOIN job_output_chunks c ON c.job_id = jobs.id GROUP BY jobs.id;
CREATE INDEX job_output_chunks_append_read_idx ON job_output_chunks(job_id, id);
CREATE TRIGGER output_read_new_job AFTER INSERT ON jobs BEGIN
    INSERT INTO job_output_read_state VALUES (NEW.id, 0, 'tracked', 0);
END;
CREATE TRIGGER output_read_append_guard BEFORE INSERT ON job_output_chunks
WHEN NOT EXISTS (SELECT 1 FROM job_output_read_state WHERE job_id = NEW.job_id) BEGIN
    SELECT RAISE(ABORT, 'output read projection unavailable');
END;
CREATE TRIGGER output_read_append AFTER INSERT ON job_output_chunks BEGIN
    UPDATE job_output_read_state SET last_row_id = MAX(last_row_id, NEW.id) WHERE job_id = NEW.job_id;
END;
CREATE TRIGGER output_read_delete_guard BEFORE DELETE ON job_output_chunks
WHEN EXISTS (SELECT 1 FROM jobs WHERE id = OLD.job_id)
 AND NOT EXISTS (SELECT 1 FROM job_output_read_state WHERE job_id = OLD.job_id
                 AND typeof(generation) = 'integer' AND generation < 9223372036854775807) BEGIN
    SELECT RAISE(ABORT, 'output read generation unavailable');
END;
CREATE TRIGGER output_read_delete AFTER DELETE ON job_output_chunks BEGIN
    UPDATE job_output_read_state SET generation = generation + 1, history = 'pruned'
        WHERE job_id = OLD.job_id;
END;
"#;

/// This additive migration and its version marker commit together. An already
/// migrated but missing projection is corruption, never a request-time reset.
pub(super) fn migrate_projection(store: &SqliteStore) -> Result<(), StoreError> {
    if store.current_schema_version()?.is_some_and(|v| v >= 27) {
        let count: i64 = store.connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE
             (type='table' AND name='job_output_read_state') OR
             (type='index' AND name='job_output_chunks_append_read_idx') OR
             (type='trigger' AND name IN ('output_read_new_job','output_read_append_guard',
              'output_read_append','output_read_delete_guard','output_read_delete'))",
            [],
            |r| r.get(0),
        )?;
        if count != 7 {
            return Err(StoreError::Domain(
                "output read projection unavailable".into(),
            ));
        }
        return Ok(());
    }
    let tx = store.connection.unchecked_transaction()?;
    tx.execute_batch(PROJECTION_SQL)?;
    store.record_schema_version(27)?;
    tx.commit()?;
    Ok(())
}

const KEY_QUERY: &str = "SELECT id, length(CAST(agent_id AS BLOB)), length(CAST(stream AS BLOB)),
    length(CAST(body AS BLOB)), chunk_index, typeof(body)
    FROM job_output_chunks WHERE job_id = ?1 AND id <= ?2
      AND (id > ?3 OR (id = ?3 AND length(CAST(body AS BLOB)) > ?4))
      AND (?5 IS NULL OR agent_id = ?5) AND (?6 IS NULL OR stream = ?6)
    ORDER BY id LIMIT ?7";

fn unavailable(_: impl std::fmt::Debug) -> OutputReadError {
    OutputReadError::Unavailable
}

fn stream_name(stream: JobOutputStream) -> &'static str {
    match stream {
        JobOutputStream::Stdout => "stdout",
        JobOutputStream::Stderr => "stderr",
    }
}

fn status(value: &str) -> Result<JobStatus, OutputReadError> {
    Ok(match value {
        "draft" => JobStatus::Draft,
        "pending_approval" => JobStatus::PendingApproval,
        "queued" => JobStatus::Queued,
        "running" => JobStatus::Running,
        "partial_success" => JobStatus::PartialSuccess,
        "success" => JobStatus::Success,
        "failed" => JobStatus::Failed,
        "canceled" => JobStatus::Canceled,
        "expired" => JobStatus::Expired,
        _ => return Err(OutputReadError::Unavailable),
    })
}

fn store_stamp(store: &SqliteStore) -> Result<[u8; 32], OutputReadError> {
    let identity = store.controller_delivery_identity().map_err(unavailable)?;
    let mut hash = Sha256::new();
    hash.update(b"fleet.output-read.store.v1");
    for value in [&identity.namespace, &identity.store_epoch] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    Ok(hash.finalize().into())
}

impl OutputPageRepository for SqliteStore {
    fn read_output_page(
        &self,
        scope: &OutputReadScope,
        after: Option<&OutputReadCursor>,
        limits: OutputReadLimits,
    ) -> Result<OutputPage, OutputReadError> {
        if after.is_some_and(|c| c.scope() != scope) {
            return Err(OutputReadError::ScopeMismatch);
        }
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(unavailable)?;
        let job_status: String = tx
            .query_row(
                "SELECT status FROM jobs WHERE id=?1",
                [scope.job_id.as_str()],
                |r| r.get(0),
            )
            .optional()
            .map_err(unavailable)?
            .ok_or(OutputReadError::JobNotFound)?;
        let job_status = status(&job_status)?;
        let (generation, history, high): (i64,String,i64) = tx.query_row(
            "SELECT generation, history, last_row_id FROM job_output_read_state WHERE job_id=?1",
            [scope.job_id.as_str()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))
            .map_err(unavailable)?;
        if generation < 0 || high < 0 {
            return Err(OutputReadError::Unavailable);
        }
        let beyond_high_water: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM job_output_chunks WHERE job_id=?1 AND id>?2)",
                params![scope.job_id.as_str(), high],
                |r| r.get(0),
            )
            .map_err(unavailable)?;
        if beyond_high_water {
            return Err(OutputReadError::Unavailable);
        }
        let history = match history.as_str() {
            "tracked" => OutputHistory::Tracked,
            "unknown" => OutputHistory::Unknown,
            "pruned" => OutputHistory::Pruned,
            _ => return Err(OutputReadError::Unavailable),
        };
        let stamp = store_stamp(self)?;
        let initial = OutputReadCursor::new(scope.clone(), stamp, generation, 0, 0, None)?;
        let cursor = after.unwrap_or(&initial);
        if cursor.store_stamp() != &stamp || cursor.generation() != generation {
            return Err(OutputReadError::StaleCursor);
        }
        let fence = cursor.fence().unwrap_or(high);
        if fence > high || cursor.row() > fence {
            return Err(OutputReadError::InvalidCursor);
        }
        let agent = scope.agent_id.as_ref().map(AgentId::as_str);
        let stream = scope.stream.map(stream_name);
        if cursor.row() > 0 {
            let position: Option<(i64, Option<Vec<u8>>)> = tx
                .query_row(
                    "SELECT length(CAST(body AS BLOB)), substr(CAST(body AS BLOB), ?3+1, 1)
                 FROM job_output_chunks WHERE job_id=?1 AND id=?2
                   AND (?4 IS NULL OR agent_id=?4) AND (?5 IS NULL OR stream=?5)",
                    params![
                        scope.job_id.as_str(),
                        cursor.row(),
                        cursor.offset(),
                        agent,
                        stream
                    ],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(unavailable)?;
            let (total, next) = position.ok_or(OutputReadError::InvalidCursor)?;
            let next = match next {
                Some(next) => next,
                None if total == cursor.offset() => Vec::new(),
                None => return Err(OutputReadError::Unavailable),
            };
            if cursor.offset() > total || next.first().is_some_and(|b| b & 0xc0 == 0x80) {
                return Err(OutputReadError::InvalidCursor);
            }
        }
        let mut statement = tx.prepare(KEY_QUERY).map_err(unavailable)?;
        let mut rows = statement
            .query(params![
                scope.job_id.as_str(),
                fence,
                cursor.row(),
                cursor.offset(),
                agent,
                stream,
                limits.fragments() as i64
            ])
            .map_err(unavailable)?;
        let mut items = Vec::new();
        let mut used = 0;
        let mut row_id = cursor.row();
        let mut offset = cursor.offset();
        while let Some(row) = rows.next().map_err(unavailable)? {
            let id: i64 = row.get(0).map_err(unavailable)?;
            let agent_bytes: usize = row.get(1).map_err(unavailable)?;
            let stream_bytes: usize = row.get(2).map_err(unavailable)?;
            let total: i64 = row.get(3).map_err(unavailable)?;
            let sequence: i64 = row.get(4).map_err(unavailable)?;
            let body_type: String = row.get(5).map_err(unavailable)?;
            if id <= 0 || total < 0 || sequence < 0 || body_type != "text" {
                return Err(OutputReadError::Unavailable);
            }
            let metadata = agent_bytes
                .checked_add(stream_bytes)
                .ok_or(OutputReadError::Unavailable)?;
            let start = if id == cursor.row() {
                cursor.offset()
            } else {
                0
            };
            let remaining = limits.source_bytes() - used;
            if metadata > remaining || (metadata == remaining && start < total) {
                if items.is_empty() {
                    return Err(OutputReadError::MetadataTooLarge);
                }
                break;
            }
            let bytes_limit = remaining - metadata;
            let (agent_id, stream_value, bytes): (String, String, Option<Vec<u8>>) = tx
                .query_row(
                    "SELECT agent_id, stream, substr(CAST(body AS BLOB), ?2+1, ?3)
                 FROM job_output_chunks WHERE id=?1",
                    params![id, start, bytes_limit as i64],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .map_err(unavailable)?;
            let bytes = match bytes {
                Some(bytes) => bytes,
                None if total == 0 && start == 0 => Vec::new(),
                None => return Err(OutputReadError::Unavailable),
            };
            if agent_id.len() != agent_bytes
                || stream_value.len() != stream_bytes
                || bytes.len() as i64 != (total - start).min(bytes_limit as i64)
            {
                return Err(OutputReadError::Unavailable);
            }
            let valid = match std::str::from_utf8(&bytes) {
                Ok(_) => bytes.len(),
                Err(e) if e.error_len().is_none() && start + (bytes.len() as i64) < total => {
                    e.valid_up_to()
                }
                Err(_) => return Err(OutputReadError::Unavailable),
            };
            if valid == 0 && start < total {
                if items.is_empty() {
                    return Err(OutputReadError::MetadataTooLarge);
                }
                break;
            }
            let data = std::str::from_utf8(&bytes[..valid])
                .map_err(unavailable)?
                .to_owned();
            let stream = match stream_value.as_str() {
                "stdout" => JobOutputStream::Stdout,
                "stderr" => JobOutputStream::Stderr,
                _ => return Err(OutputReadError::Unavailable),
            };
            let fragment = OutputFragment::new(
                OutputFragmentPosition {
                    chunk_key: id,
                    sequence,
                    offset_bytes: start,
                    total_bytes: total,
                },
                AgentId::new(agent_id).map_err(unavailable)?,
                stream,
                data,
            )?;
            row_id = id;
            offset = start + valid as i64;
            used += fragment.source_bytes();
            let complete = fragment.chunk_complete();
            items.push(fragment);
            if !complete || used == limits.source_bytes() {
                break;
            }
        }
        drop(rows);
        drop(statement);
        let has_more: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM job_output_chunks WHERE job_id=?1 AND id<=?2
             AND (id>?3 OR (id=?3 AND length(CAST(body AS BLOB))>?4))
             AND (?5 IS NULL OR agent_id=?5) AND (?6 IS NULL OR stream=?6))",
                params![scope.job_id.as_str(), fence, row_id, offset, agent, stream],
                |r| r.get(0),
            )
            .map_err(unavailable)?;
        let next = OutputReadCursor::new(
            scope.clone(),
            stamp,
            generation,
            row_id,
            offset,
            if has_more { Some(fence) } else { None },
        )?;
        tx.commit().map_err(unavailable)?;
        Ok(OutputPage {
            items,
            next,
            has_more,
            caught_up: !has_more && fence == high,
            history,
            job_status,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JobOutputChunk, JobOutputStream};
    use fleet_application::output_read::OutputHistory;
    use fleet_domain::{
        Agent, AgentFingerprint, AgentId, AgentIdentity, AgentName, AgentPublicKey,
        ApprovalRequirement, Job, JobId, TaskRisk,
    };
    use std::time::Duration;

    fn fixture() -> SqliteStore {
        let store = SqliteStore::in_memory().unwrap();
        for (i, id) in ["agent-a", "agent-b"].iter().enumerate() {
            store
                .save_agent(Agent::new(
                    AgentId::new(*id).unwrap(),
                    AgentName::new(*id).unwrap(),
                    AgentIdentity {
                        public_key: AgentPublicKey::new("test-public").unwrap(),
                        fingerprint: AgentFingerprint::new(format!("{i:016x}")).unwrap(),
                    },
                ))
                .unwrap();
        }
        for id in ["job-1", "job-2"] {
            store
                .save_job_record(&Job::new(
                    JobId::new(id).unwrap(),
                    TaskRisk::Low,
                    ApprovalRequirement::NotRequired,
                    Duration::from_secs(30),
                ))
                .unwrap();
        }
        store
    }
    fn scope() -> OutputReadScope {
        OutputReadScope {
            job_id: JobId::new("job-1").unwrap(),
            agent_id: None,
            stream: None,
        }
    }
    fn append(store: &SqliteStore, agent: &str, stream: JobOutputStream, seq: u64, text: &str) {
        store
            .append_job_output_chunk_record(&JobOutputChunk {
                job_id: "job-1".into(),
                agent_id: agent.into(),
                stream,
                sequence: seq,
                body: text.into(),
            })
            .unwrap();
    }

    #[test]
    fn output_pages_keep_frozen_prefix_and_late_agent_append_without_duplicates() {
        let store = fixture();
        let s = scope();
        let limits = OutputReadLimits::new(1, 4096).unwrap();
        append(&store, "agent-b", JobOutputStream::Stdout, 1, "b1");
        append(&store, "agent-a", JobOutputStream::Stderr, 0, "aerr");
        let first = store.read_output_page(&s, None, limits).unwrap();
        assert_eq!(first.items[0].data(), "b1");
        assert!(first.has_more);
        assert!(!first.caught_up);
        assert_eq!(first.history, OutputHistory::Tracked);
        append(&store, "agent-b", JobOutputStream::Stdout, 0, "late-b0");
        let second = store
            .read_output_page(&s, Some(&first.next), limits)
            .unwrap();
        assert_eq!(second.items[0].data(), "aerr");
        assert!(!second.has_more);
        assert!(!second.caught_up);
        assert_eq!(
            store
                .read_output_page(&s, Some(&first.next), limits)
                .unwrap(),
            second
        );
        let third = store
            .read_output_page(&s, Some(&second.next), limits)
            .unwrap();
        assert_eq!(third.items[0].data(), "late-b0");
        assert!(third.caught_up);
        assert!(
            store
                .read_output_page(&s, Some(&third.next), limits)
                .unwrap()
                .items
                .is_empty()
        );
        assert_eq!(
            store
                .list_job_output_chunks_for_job("job-1")
                .unwrap()
                .iter()
                .map(|c| c.body.as_str())
                .collect::<Vec<_>>(),
            ["aerr", "late-b0", "b1"]
        );
    }

    #[test]
    fn output_pages_fragment_large_unicode_and_empty_rows_with_exact_source_budget() {
        let store = fixture();
        let s = scope();
        let limits = OutputReadLimits::new(3, 4096).unwrap();
        let original = "한🤖\0\n\"\\e\u{301}".repeat(80_000);
        append(&store, "agent-a", JobOutputStream::Stdout, 0, &original);
        append(&store, "agent-b", JobOutputStream::Stderr, 0, "");
        let mut after = None;
        let mut rebuilt = String::new();
        let mut empty = 0;
        for _ in 0..1000 {
            let page = store.read_output_page(&s, after.as_ref(), limits).unwrap();
            assert!(page.items.len() <= 3);
            assert!(page.items.iter().map(|f| f.source_bytes()).sum::<usize>() <= 4096);
            for f in &page.items {
                if f.agent_id().as_str() == "agent-a" {
                    assert_eq!(f.position().offset_bytes, rebuilt.len() as i64);
                    rebuilt.push_str(f.data());
                } else {
                    assert_eq!(f.data(), "");
                    assert!(f.chunk_complete());
                    empty += 1;
                }
            }
            let done = page.caught_up;
            after = Some(page.next);
            if done {
                break;
            }
        }
        assert_eq!(rebuilt, original);
        assert_eq!(empty, 1);
    }

    #[test]
    fn output_pages_reject_missing_job_scope_and_invalid_owned_offset() {
        let store = fixture();
        let s = scope();
        let limits = OutputReadLimits::default();
        append(&store, "agent-a", JobOutputStream::Stdout, 0, "🤖x");
        let page = store.read_output_page(&s, None, limits).unwrap();
        let mut other = s.clone();
        other.job_id = JobId::new("missing").unwrap();
        assert_eq!(
            store.read_output_page(&other, None, limits),
            Err(OutputReadError::JobNotFound)
        );
        other.job_id = JobId::new("job-2").unwrap();
        assert_eq!(
            store.read_output_page(&other, Some(&page.next), limits),
            Err(OutputReadError::ScopeMismatch)
        );
        for offset in [1, 6] {
            let invalid = OutputReadCursor::new(
                s.clone(),
                *page.next.store_stamp(),
                page.next.generation(),
                page.next.row(),
                offset,
                None,
            )
            .unwrap();
            assert_eq!(
                store.read_output_page(&s, Some(&invalid), limits),
                Err(OutputReadError::InvalidCursor)
            );
        }
    }

    #[test]
    fn output_projection_migration_preserves_v26_rows_and_records_unknown_history() {
        let store = fixture();
        append(&store, "agent-a", JobOutputStream::Stdout, 0, "legacy\0🤖");
        let before = store.list_job_output_chunks_for_job("job-1").unwrap();
        store
            .connection
            .execute_batch(
                "DROP TRIGGER IF EXISTS output_read_new_job;
            DROP TRIGGER IF EXISTS output_read_append_guard;
            DROP TRIGGER IF EXISTS output_read_append;
            DROP TRIGGER IF EXISTS output_read_delete_guard;
            DROP TRIGGER IF EXISTS output_read_delete;
            DROP TABLE IF EXISTS job_output_read_state;
            DROP INDEX IF EXISTS job_output_chunks_append_read_idx;
            DROP TABLE admin_credentials; DROP TABLE admin_accounts; DROP TABLE admin_auth_state;
            UPDATE schema_migrations SET version=26 WHERE name='fleet_store';",
            )
            .unwrap();
        store.migrate().unwrap();
        assert_eq!(
            store.current_schema_version().unwrap(),
            Some(crate::CURRENT_SCHEMA_VERSION)
        );
        let page = store
            .read_output_page(&scope(), None, OutputReadLimits::default())
            .unwrap();
        assert_eq!(page.history, OutputHistory::Unknown);
        assert_eq!(page.items[0].data(), "legacy\0🤖");
        assert_eq!(
            store.list_job_output_chunks_for_job("job-1").unwrap(),
            before
        );
        store.migrate().unwrap();
        assert_eq!(
            store
                .read_output_page(&scope(), None, OutputReadLimits::default())
                .unwrap(),
            page
        );
    }

    #[test]
    fn output_retention_invalidates_only_committed_deletions_and_preserves_receipt_epoch() {
        use fleet_application::RetentionCutoffs;
        use std::time::UNIX_EPOCH;
        let store = fixture();
        let s = scope();
        let limits = OutputReadLimits::default();
        append(&store, "agent-a", JobOutputStream::Stdout, 0, "old");
        append(&store, "agent-b", JobOutputStream::Stderr, 0, "retained");
        store.connection.execute("UPDATE job_output_chunks SET created_at=CASE chunk_index WHEN 0 THEN 0 ELSE 10 END WHERE agent_id='agent-a'",[]).unwrap();
        let before = store.read_output_page(&s, None, limits).unwrap();
        let identity = store.controller_delivery_identity().unwrap();
        let cutoffs = RetentionCutoffs {
            job_output: UNIX_EPOCH + Duration::from_secs(1),
            facts: UNIX_EPOCH,
            metrics: UNIX_EPOCH,
            agent_logs: UNIX_EPOCH,
        };
        assert_eq!(
            store
                .cleanup_retention_with_cutoffs(cutoffs, true)
                .unwrap()
                .job_output_chunks,
            1
        );
        assert!(
            store
                .read_output_page(&s, Some(&before.next), limits)
                .unwrap()
                .caught_up
        );
        {
            let tx = store.connection.unchecked_transaction().unwrap();
            tx.execute("DELETE FROM job_output_chunks WHERE agent_id='agent-a'", [])
                .unwrap();
            tx.rollback().unwrap();
        }
        assert_eq!(store.read_output_page(&s, None, limits).unwrap(), before);
        assert_eq!(
            store
                .cleanup_retention_with_cutoffs(cutoffs, false)
                .unwrap()
                .job_output_chunks,
            1
        );
        assert_eq!(
            store.read_output_page(&s, Some(&before.next), limits),
            Err(OutputReadError::StaleCursor)
        );
        let after = store.read_output_page(&s, None, limits).unwrap();
        assert_eq!(after.history, OutputHistory::Pruned);
        assert_eq!(after.items.len(), 1);
        assert_eq!(after.items[0].data(), "retained");
        assert_eq!(store.controller_delivery_identity().unwrap(), identity);
        assert_eq!(
            store
                .cleanup_retention_with_cutoffs(cutoffs, false)
                .unwrap()
                .job_output_chunks,
            0
        );
        assert!(
            store
                .read_output_page(&s, Some(&after.next), limits)
                .unwrap()
                .caught_up
        );
    }

    #[test]
    fn output_projection_missing_or_high_water_corruption_fails_closed() {
        for corrupt in [
            "DELETE FROM job_output_read_state WHERE job_id='job-1'",
            "UPDATE job_output_read_state SET last_row_id=0 WHERE job_id='job-1'",
        ] {
            let store = fixture();
            append(&store, "agent-a", JobOutputStream::Stdout, 0, "stored");
            store.connection.execute(corrupt, []).unwrap();
            assert_eq!(
                store.read_output_page(&scope(), None, OutputReadLimits::default()),
                Err(OutputReadError::Unavailable)
            );
        }
        let store = fixture();
        store
            .connection
            .execute_batch("DROP TRIGGER output_read_append")
            .unwrap();
        assert!(store.migrate().is_err());
    }

    #[test]
    fn output_delete_overflow_or_trigger_failure_rolls_back_body_and_generation() {
        for fail in [
            "UPDATE job_output_read_state SET generation=9223372036854775807 WHERE job_id='job-1'",
            "CREATE TRIGGER test_fail_projection BEFORE UPDATE ON job_output_read_state WHEN NEW.history='pruned' BEGIN SELECT RAISE(ABORT,'test fault'); END",
        ] {
            let store = fixture();
            append(&store, "agent-a", JobOutputStream::Stdout, 0, "kept");
            store.connection.execute_batch(fail).unwrap();
            let before = store
                .read_output_page(&scope(), None, OutputReadLimits::default())
                .unwrap();
            assert!(
                store
                    .connection
                    .execute("DELETE FROM job_output_chunks", [])
                    .is_err()
            );
            assert_eq!(
                store
                    .read_output_page(&scope(), None, OutputReadLimits::default())
                    .unwrap(),
                before
            );
        }
    }

    #[test]
    fn output_cursor_reopens_but_restore_epoch_and_other_store_are_stale() {
        use fleet_application::RotateControllerStoreEpoch;
        use std::time::{SystemTime, UNIX_EPOCH};
        let path = std::env::temp_dir().join(format!(
            "fleet-output-read-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = fixture();
        store
            .connection
            .execute("VACUUM INTO ?1", params![path.to_str().unwrap()])
            .unwrap();
        let page = store
            .read_output_page(&scope(), None, OutputReadLimits::default())
            .unwrap();
        drop(store);
        let mut reopened = SqliteStore::open(&path).unwrap();
        assert!(
            reopened
                .read_output_page(&scope(), Some(&page.next), OutputReadLimits::default())
                .unwrap()
                .caught_up
        );
        RotateControllerStoreEpoch::execute(&mut reopened).unwrap();
        assert_eq!(
            reopened.read_output_page(&scope(), Some(&page.next), OutputReadLimits::default()),
            Err(OutputReadError::StaleCursor)
        );
        let other = fixture();
        assert_eq!(
            other.read_output_page(&scope(), Some(&page.next), OutputReadLimits::default()),
            Err(OutputReadError::StaleCursor)
        );
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn output_pages_bound_empty_rows_and_keep_filter_and_large_sequence_identity() {
        let store = fixture();
        let s = scope();
        let limits = OutputReadLimits::new(256, 65536).unwrap();
        for seq in 0..513 {
            append(&store, "agent-a", JobOutputStream::Stdout, seq, "");
        }
        let mut after = None;
        let mut count = 0;
        for expected in [256, 256, 1] {
            let page = store.read_output_page(&s, after.as_ref(), limits).unwrap();
            assert_eq!(page.items.len(), expected);
            count += page.items.len();
            after = Some(page.next);
        }
        assert_eq!(count, 513);
        append(
            &store,
            "agent-b",
            JobOutputStream::Stderr,
            9_007_199_254_740_993,
            "large-sequence",
        );
        let filter = OutputReadScope {
            agent_id: Some(AgentId::new("agent-b").unwrap()),
            stream: Some(JobOutputStream::Stderr),
            ..s.clone()
        };
        let page = store.read_output_page(&filter, None, limits).unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].position().sequence, 9_007_199_254_740_993);
        assert_eq!(
            store.read_output_page(&s, Some(&page.next), limits),
            Err(OutputReadError::ScopeMismatch)
        );
        append(
            &store,
            "agent-b",
            JobOutputStream::Stderr,
            9_007_199_254_740_993,
            "large-sequence",
        );
        assert!(
            store
                .read_output_page(&filter, Some(&page.next), limits)
                .unwrap()
                .items
                .is_empty()
        );
    }

    #[test]
    fn output_metadata_over_budget_is_not_skipped_or_replaced_by_full_fetch() {
        let store = fixture();
        let agent = "a".repeat(4096);
        store
            .save_agent(Agent::new(
                AgentId::new(&agent).unwrap(),
                AgentName::new("long-id").unwrap(),
                AgentIdentity {
                    public_key: AgentPublicKey::new("public").unwrap(),
                    fingerprint: AgentFingerprint::new("123456789abcdef0").unwrap(),
                },
            ))
            .unwrap();
        append(&store, "agent-a", JobOutputStream::Stdout, 0, "prefix");
        append(&store, &agent, JobOutputStream::Stdout, 0, "cannot-fit");
        let limits = OutputReadLimits::new(128, 4096).unwrap();
        let page = store.read_output_page(&scope(), None, limits).unwrap();
        assert_eq!(page.items.len(), 1);
        assert!(page.has_more);
        assert_eq!(
            store.read_output_page(&scope(), Some(&page.next), limits),
            Err(OutputReadError::MetadataTooLarge)
        );
    }

    #[test]
    fn output_projection_migration_fault_is_atomic_and_keeps_previous_schema_rows() {
        let store = fixture();
        append(&store, "agent-a", JobOutputStream::Stdout, 0, "legacy");
        store.connection.execute_batch("DROP TRIGGER output_read_new_job; DROP TRIGGER output_read_append_guard;
            DROP TRIGGER output_read_append; DROP TRIGGER output_read_delete_guard; DROP TRIGGER output_read_delete;
            DROP TABLE job_output_read_state; DROP INDEX job_output_chunks_append_read_idx;
            DROP TABLE admin_credentials; DROP TABLE admin_accounts; DROP TABLE admin_auth_state;
            UPDATE schema_migrations SET version=26;
            CREATE TRIGGER output_read_new_job AFTER INSERT ON jobs BEGIN SELECT 1; END;").unwrap();
        assert!(store.migrate().is_err());
        assert_eq!(store.current_schema_version().unwrap(), Some(26));
        let exists: bool = store
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='job_output_read_state')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!exists);
        assert_eq!(
            store.list_job_output_chunks_for_job("job-1").unwrap()[0].body,
            "legacy"
        );
        store
            .connection
            .execute_batch("DROP TRIGGER output_read_new_job")
            .unwrap();
        store.migrate().unwrap();
        assert_eq!(
            store
                .read_output_page(&scope(), None, OutputReadLimits::default())
                .unwrap()
                .history,
            OutputHistory::Unknown
        );
    }

    #[test]
    fn output_page_query_plan_measures_append_index_with_bounded_payload() {
        let store = fixture();
        // Disposable fixture only: compare the existing and measured candidate
        // plans before restoring the index installed by the production migration.
        store
            .connection
            .execute_batch("DROP INDEX job_output_chunks_append_read_idx")
            .unwrap();
        let body = "x".repeat(1024);
        let tx = store.connection.unchecked_transaction().unwrap();
        for seq in 0..2048 {
            append(
                &store,
                if seq % 2 == 0 { "agent-a" } else { "agent-b" },
                JobOutputStream::Stdout,
                seq,
                &body,
            );
        }
        tx.commit().unwrap();
        let plan = || {
            let mut statement = store
                .connection
                .prepare(&format!("EXPLAIN QUERY PLAN {KEY_QUERY}"))
                .unwrap();
            statement
                .query_map(
                    params![
                        "job-1",
                        2048_i64,
                        0_i64,
                        0_i64,
                        None::<&str>,
                        None::<&str>,
                        64_i64
                    ],
                    |r| r.get::<_, String>(3),
                )
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        let measure = || {
            let start = std::time::Instant::now();
            let mut last = None;
            for _ in 0..20 {
                last = Some(
                    store
                        .read_output_page(&scope(), None, OutputReadLimits::default())
                        .unwrap(),
                );
            }
            (start.elapsed().as_micros(), last.unwrap())
        };
        let before_plan = plan();
        let (before_us, before) = measure();
        store
            .connection
            .execute_batch(
                "CREATE INDEX job_output_chunks_append_read_idx ON job_output_chunks(job_id,id)",
            )
            .unwrap();
        let after_plan = plan();
        let (after_us, after) = measure();
        assert_eq!(before, after);
        assert!(!after_plan.iter().any(|s| s.contains("TEMP B-TREE")));
        let bytes = after.items.iter().map(|f| f.source_bytes()).sum::<usize>();
        assert!(after.items.len() <= 128 && bytes <= 65536);
        let evidence = serde_json::json!({"rows":2048,"agents":2,"row_bytes":1024,"warm_reads_per_variant":20,
            "before_plan":before_plan,"after_plan":after_plan,"before_total_us":before_us,"after_total_us":after_us,
            "page_fragments":after.items.len(),"source_bytes":bytes,"same_page":true,
            "scope":"local SQLite query rehearsal; not API/UI performance or SLA"});
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/output-read-rehearsal");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("production-query.json"),
            serde_json::to_vec_pretty(&evidence).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn output_pages_keep_large_row_keys_and_reject_foreign_rows_and_future_fences() {
        let store = fixture();
        let s = scope();
        let limits = OutputReadLimits::default();
        let id = 9_007_199_254_740_993_i64;
        store
            .connection
            .execute(
                "INSERT INTO job_output_chunks(id,job_id,agent_id,stream,chunk_index,body)
            VALUES (?1,'job-1','agent-a','stdout',0,'large-key')",
                params![id],
            )
            .unwrap();
        let page = store.read_output_page(&s, None, limits).unwrap();
        assert_eq!(page.next.row(), id);
        assert_eq!(page.items[0].position().chunk_key, id);
        let future =
            OutputReadCursor::new(s.clone(), *page.next.store_stamp(), 0, id, 9, Some(id + 1))
                .unwrap();
        assert_eq!(
            store.read_output_page(&s, Some(&future), limits),
            Err(OutputReadError::InvalidCursor)
        );
        store
            .connection
            .execute(
                "INSERT INTO job_output_chunks(job_id,agent_id,stream,chunk_index,body)
            VALUES ('job-2','agent-a','stdout',0,'foreign')",
                [],
            )
            .unwrap();
        let foreign =
            OutputReadCursor::new(s.clone(), *page.next.store_stamp(), 0, id + 1, 0, None).unwrap();
        assert_eq!(
            store.read_output_page(&s, Some(&foreign), limits),
            Err(OutputReadError::InvalidCursor)
        );
        store
            .connection
            .execute("DELETE FROM jobs WHERE id='job-1'", [])
            .unwrap();
        assert_eq!(
            store.read_output_page(&s, None, limits),
            Err(OutputReadError::JobNotFound)
        );
        let count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM job_output_read_state WHERE job_id='job-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn output_exact_budget_accepts_empty_or_single_byte_and_rejects_incomplete_codepoint() {
        for (length, text, allowed) in [(4090, "", true), (4089, "x", true), (4089, "🤖", false)]
        {
            let store = fixture();
            let agent = "a".repeat(length);
            store
                .save_agent(Agent::new(
                    AgentId::new(&agent).unwrap(),
                    AgentName::new("edge").unwrap(),
                    AgentIdentity {
                        public_key: AgentPublicKey::new("public").unwrap(),
                        fingerprint: AgentFingerprint::new("123456789abcdef0").unwrap(),
                    },
                ))
                .unwrap();
            append(&store, &agent, JobOutputStream::Stdout, 0, text);
            let result =
                store.read_output_page(&scope(), None, OutputReadLimits::new(1, 4096).unwrap());
            if allowed {
                let page = result.unwrap();
                assert_eq!(page.items[0].data(), text);
                assert_eq!(page.items[0].source_bytes(), 4096);
            } else {
                assert_eq!(result, Err(OutputReadError::MetadataTooLarge));
            }
        }
    }

    #[test]
    fn output_corrupt_utf8_or_sequence_is_unavailable_without_partial_success() {
        for corruption in ["body=CAST(x'ff' AS TEXT)", "chunk_index=-1"] {
            let store = fixture();
            append(&store, "agent-a", JobOutputStream::Stdout, 0, "before");
            store
                .connection
                .execute(&format!("UPDATE job_output_chunks SET {corruption}"), [])
                .unwrap();
            assert_eq!(
                store.read_output_page(&scope(), None, OutputReadLimits::default()),
                Err(OutputReadError::Unavailable)
            );
        }
    }

    #[test]
    fn output_terminal_status_does_not_skip_a_later_stored_prefix() {
        let store = fixture();
        let s = scope();
        let limits = OutputReadLimits::new(1, 4096).unwrap();
        append(&store, "agent-a", JobOutputStream::Stdout, 0, "first");
        append(&store, "agent-b", JobOutputStream::Stderr, 0, "second");
        store
            .connection
            .execute("UPDATE jobs SET status='running' WHERE id='job-1'", [])
            .unwrap();
        let first = store.read_output_page(&s, None, limits).unwrap();
        assert_eq!(first.job_status, JobStatus::Running);
        assert!(first.has_more);
        store
            .connection
            .execute("UPDATE jobs SET status='success' WHERE id='job-1'", [])
            .unwrap();
        append(&store, "agent-a", JobOutputStream::Stdout, 1, "late-stored");
        let second = store
            .read_output_page(&s, Some(&first.next), limits)
            .unwrap();
        assert_eq!(second.job_status, JobStatus::Success);
        assert!(!second.has_more);
        assert!(!second.caught_up);
        let final_page = store
            .read_output_page(&s, Some(&second.next), limits)
            .unwrap();
        assert_eq!(final_page.job_status, JobStatus::Success);
        assert!(final_page.caught_up);
        assert_eq!(final_page.items[0].data(), "late-stored");
        assert_eq!(
            store.find_job_status_value("job-1").unwrap().as_deref(),
            Some("success")
        );
    }
}
