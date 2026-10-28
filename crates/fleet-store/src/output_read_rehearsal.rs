//! Isolated feasibility rehearsal for planned output paging, not a runtime adapter.
//! The future tracking table is installed only in disposable test databases.

use super::{JobOutputChunk, JobOutputStream, SqliteStore};
use fleet_application::ControllerDeliveryIdentityRepository;
use fleet_domain::{
    Agent, AgentFingerprint, AgentId, AgentIdentity, AgentName, AgentPublicKey,
    ApprovalRequirement, Job, JobId, TaskRisk,
};
use rusqlite::{OptionalExtension, params};
use std::time::Duration;

const DEFAULT_BYTES: usize = 64 * 1024;
const MAX_BYTES: usize = 256 * 1024;
const MAX_ENTRIES: usize = 256;
const KEY_QUERY: &str = "SELECT id, length(CAST(agent_id AS BLOB)), length(CAST(stream AS BLOB)),
                length(CAST(body AS BLOB)), chunk_index
         FROM job_output_chunks WHERE job_id = ?1 AND id <= ?2
           AND (id > ?3 OR (id = ?3 AND length(CAST(body AS BLOB)) > ?4))
           AND (?5 IS NULL OR agent_id = ?5) AND (?6 IS NULL OR stream = ?6)
         ORDER BY id LIMIT ?7";

#[derive(Clone, Copy)]
struct Limits {
    entries: usize,
    bytes: usize,
}

impl Limits {
    fn new(entries: usize, bytes: usize) -> Result<Self, ReadError> {
        if !(1..=MAX_ENTRIES).contains(&entries) || !(4096..=MAX_BYTES).contains(&bytes) {
            return Err(ReadError::InvalidLimit);
        }
        Ok(Self { entries, bytes })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Scope {
    job: String,
    agent: Option<String>,
    stream: Option<String>,
}

impl Scope {
    fn job(job: &str) -> Self {
        Self {
            job: job.into(),
            agent: None,
            stream: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cursor {
    scope: Scope,
    epoch: String,
    generation: i64,
    row: i64,
    offset: usize,
    fence: Option<i64>,
}

#[derive(Debug, PartialEq, Eq)]
enum ReadError {
    InvalidLimit,
    WrongScope,
    Stale,
    InvalidOffset,
    MetadataTooLarge,
    MissingJob,
    ReadUnavailable,
}

#[derive(Debug, PartialEq, Eq)]
struct Fragment {
    row: i64,
    agent: String,
    stream: String,
    sequence: i64,
    offset: usize,
    total: usize,
    data: String,
}

impl Fragment {
    fn payload_bytes(&self) -> usize {
        self.agent.len() + self.stream.len() + self.data.len()
    }
}

struct Page {
    items: Vec<Fragment>,
    after: Cursor,
    has_more: bool,
    history: String,
    caught_up: bool,
    job_status: String,
}

fn fixture(agents: &[&str]) -> SqliteStore {
    let store = SqliteStore::in_memory().unwrap();
    for (index, id) in agents.iter().enumerate() {
        store
            .save_agent(Agent::new(
                AgentId::new(*id).unwrap(),
                AgentName::new(format!("fixture-{index}")).unwrap(),
                AgentIdentity {
                    public_key: AgentPublicKey::new("fixture-public").unwrap(),
                    fingerprint: AgentFingerprint::new(format!("{index:016x}")).unwrap(),
                },
            ))
            .unwrap();
    }
    job(&store, "job-1");
    store
}

fn job(store: &SqliteStore, id: &str) {
    store
        .save_job_record(&Job::new(
            JobId::new(id).unwrap(),
            TaskRisk::Low,
            ApprovalRequirement::NotRequired,
            Duration::from_secs(30),
        ))
        .unwrap();
}

fn append(
    store: &SqliteStore,
    job: &str,
    agent: &str,
    stream: JobOutputStream,
    sequence: u64,
    body: &str,
) {
    store
        .append_job_output_chunk_record(&JobOutputChunk {
            job_id: job.into(),
            agent_id: agent.into(),
            stream,
            sequence,
            body: body.into(),
        })
        .unwrap();
}

// Rehearsal only. This is not a schema migration and does not change schema v26.
fn install_tracking(store: &SqliteStore) {
    store.connection.execute_batch(r#"
        CREATE TABLE IF NOT EXISTS output_read_rehearsal (
            job_id TEXT PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
            generation INTEGER NOT NULL CHECK(typeof(generation) = 'integer' AND generation >= 0),
            history TEXT NOT NULL CHECK(history IN ('tracked', 'unknown', 'pruned')),
            last_id INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO output_read_rehearsal
            SELECT jobs.id, 0, 'unknown', COALESCE(MAX(chunks.id), 0)
            FROM jobs LEFT JOIN job_output_chunks chunks ON chunks.job_id = jobs.id GROUP BY jobs.id;
        CREATE TRIGGER IF NOT EXISTS rehearsal_new_job AFTER INSERT ON jobs BEGIN
            INSERT INTO output_read_rehearsal VALUES (NEW.id, 0, 'tracked', 0);
        END;
        CREATE TRIGGER IF NOT EXISTS rehearsal_output_append AFTER INSERT ON job_output_chunks BEGIN
            UPDATE output_read_rehearsal SET last_id = MAX(last_id, NEW.id) WHERE job_id = NEW.job_id;
        END;
        CREATE TRIGGER IF NOT EXISTS rehearsal_output_delete AFTER DELETE ON job_output_chunks BEGIN
            UPDATE output_read_rehearsal SET generation = generation + 1, history = 'pruned'
                WHERE job_id = OLD.job_id;
        END;
    "#).unwrap();
}

fn read_page(
    store: &SqliteStore,
    scope: &Scope,
    after: Option<&Cursor>,
    limits: Limits,
) -> Result<Page, ReadError> {
    let tx = store.connection.unchecked_transaction().unwrap();
    let job_status = store
        .find_job_status_value(&scope.job)
        .unwrap()
        .ok_or(ReadError::MissingJob)?;
    let metadata = tx
        .query_row(
            "SELECT generation, history, last_id FROM output_read_rehearsal WHERE job_id = ?1",
            [&scope.job],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(|_| ReadError::ReadUnavailable)?;
    let epoch = store.controller_delivery_identity().unwrap().store_epoch;
    let mut cursor = after.cloned().unwrap_or(Cursor {
        scope: scope.clone(),
        epoch: epoch.clone(),
        generation: metadata.0,
        row: 0,
        offset: 0,
        fence: None,
    });
    if cursor.scope != *scope {
        return Err(ReadError::WrongScope);
    }
    if cursor.epoch != epoch || cursor.generation != metadata.0 {
        return Err(ReadError::Stale);
    }
    let fence = cursor.fence.unwrap_or(metadata.2);
    if cursor.row < 0
        || cursor.row > fence
        || fence > metadata.2
        || cursor.offset > i64::MAX as usize
    {
        return Err(ReadError::InvalidOffset);
    }
    if cursor.offset > 0 {
        let length = tx.query_row(
            "SELECT length(CAST(body AS BLOB)) FROM job_output_chunks WHERE id = ?1 AND job_id = ?2
              AND (?3 IS NULL OR agent_id = ?3) AND (?4 IS NULL OR stream = ?4)",
            params![cursor.row, scope.job, scope.agent, scope.stream], |r| r.get::<_, usize>(0),
        ).optional().unwrap();
        if length.is_none_or(|length| cursor.offset > length) {
            return Err(ReadError::InvalidOffset);
        }
    }
    let mut keys = tx.prepare(KEY_QUERY).unwrap();
    let mut rows = keys
        .query(params![
            scope.job,
            fence,
            cursor.row,
            cursor.offset as i64,
            scope.agent,
            scope.stream,
            limits.entries as i64
        ])
        .unwrap();
    let mut items = Vec::new();
    let mut used = 0;
    while let Some(row) = rows.next().unwrap() {
        let id: i64 = row.get(0).unwrap();
        let metadata_bytes = row.get::<_, usize>(1).unwrap() + row.get::<_, usize>(2).unwrap();
        let total: usize = row.get(3).unwrap();
        let offset = if id == cursor.row { cursor.offset } else { 0 };
        let minimum_data = (total - offset).min(4);
        if metadata_bytes + minimum_data > limits.bytes {
            if items.is_empty() {
                return Err(ReadError::MetadataTooLarge);
            }
            break;
        }
        if used + metadata_bytes + minimum_data > limits.bytes {
            break;
        }
        let remaining = limits.bytes - used - metadata_bytes;
        let (agent, stream, bytes): (String, String, Option<Vec<u8>>) = tx
            .query_row(
                "SELECT agent_id, stream, substr(CAST(body AS BLOB), ?2 + 1, ?3)
               FROM job_output_chunks WHERE id = ?1",
                params![id, offset as i64, remaining as i64],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        let bytes = match bytes {
            Some(bytes) => bytes,
            None if total == 0 && offset == 0 => Vec::new(),
            None => return Err(ReadError::ReadUnavailable),
        };
        let valid = match std::str::from_utf8(&bytes) {
            Ok(_) => bytes.len(),
            Err(error) if error.error_len().is_none() => error.valid_up_to(),
            Err(_) => return Err(ReadError::InvalidOffset),
        };
        if valid == 0 && total > offset {
            return Err(ReadError::InvalidOffset);
        }
        let data = std::str::from_utf8(&bytes[..valid]).unwrap().to_owned();
        cursor.row = id;
        cursor.offset = offset + data.len();
        let fragment = Fragment {
            row: id,
            agent,
            stream,
            sequence: row.get(4).unwrap(),
            offset,
            total,
            data,
        };
        used += fragment.payload_bytes();
        items.push(fragment);
        if used >= limits.bytes {
            break;
        }
    }
    drop(rows);
    drop(keys);
    let has_more = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM job_output_chunks WHERE job_id = ?1 AND id <= ?2
            AND (id > ?3 OR (id = ?3 AND length(CAST(body AS BLOB)) > ?4))
            AND (?5 IS NULL OR agent_id = ?5) AND (?6 IS NULL OR stream = ?6))",
            params![
                scope.job,
                fence,
                cursor.row,
                cursor.offset as i64,
                scope.agent,
                scope.stream
            ],
            |r| r.get(0),
        )
        .unwrap();
    cursor.fence = if has_more { Some(fence) } else { None };
    tx.commit().unwrap();
    Ok(Page {
        items,
        after: cursor,
        has_more,
        history: metadata.1,
        caught_up: !has_more && fence == metadata.2,
        job_status,
    })
}

fn wire(page: &Page) -> Vec<u8> {
    let items = page.items.iter().map(|f| serde_json::json!({
        "chunk_key": f.row.to_string(), "agent_id": f.agent, "stream": f.stream,
        "sequence": f.sequence.to_string(), "offset_bytes": f.offset.to_string(), "total_bytes": f.total.to_string(),
        "data": f.data, "chunk_complete": f.offset + f.data.len() == f.total,
    })).collect::<Vec<_>>();
    serde_json::to_vec(&serde_json::json!({
        "items": items, "next_after": "x".repeat(2048), "has_more": page.has_more,
        "history": page.history, "job_status": page.job_status, "caught_up": page.caught_up,
    }))
    .unwrap()
}

fn wire_bytes(page: &Page) -> usize {
    wire(page).len()
}

#[test]
fn oversized_utf8_rows_are_bounded_and_reassemble_exactly() {
    let store = fixture(&["a1"]);
    install_tracking(&store);
    let original = "가🤖\0\n\"\\e\u{301}".repeat(90000);
    assert!(original.len() > 1024 * 1024);
    append(&store, "job-1", "a1", JobOutputStream::Stdout, 0, &original);
    let scope = Scope::job("job-1");
    let limits = Limits::new(128, DEFAULT_BYTES).unwrap();
    let mut after = None;
    let mut rebuilt = String::new();
    for _ in 0..100 {
        let page = read_page(&store, &scope, after.as_ref(), limits).unwrap();
        assert!(page.items.len() <= limits.entries);
        assert!(
            page.items
                .iter()
                .map(Fragment::payload_bytes)
                .sum::<usize>()
                <= limits.bytes
        );
        assert!(wire_bytes(&page) <= 2 * 1024 * 1024);
        for fragment in &page.items {
            assert_eq!(fragment.offset, rebuilt.len());
            rebuilt.push_str(&fragment.data);
        }
        let finished = !page.has_more;
        if let Some(previous) = &after {
            assert_ne!(&page.after, previous, "nonempty page must advance");
        }
        after = Some(page.after);
        if finished {
            assert_eq!(rebuilt, original);
            return;
        }
    }
    panic!("bounded reads did not finish");
}

#[test]
fn late_agents_streams_and_retries_preserve_a_frozen_prefix_then_renew_it() {
    let store = fixture(&["a1", "b2"]);
    install_tracking(&store);
    job(&store, "other-job");
    append(&store, "job-1", "a1", JobOutputStream::Stdout, 0, "a-first");
    append(
        &store,
        "other-job",
        "b2",
        JobOutputStream::Stdout,
        0,
        "other",
    );
    append(
        &store,
        "job-1",
        "b2",
        JobOutputStream::Stderr,
        0,
        "b-stderr",
    );
    let scope = Scope::job("job-1");
    let limits = Limits::new(1, DEFAULT_BYTES).unwrap();
    let first = read_page(&store, &scope, None, limits).unwrap();
    assert_eq!(first.items[0].data, "a-first");
    assert!(first.has_more);
    append(&store, "job-1", "a1", JobOutputStream::Stdout, 1, "a-late");
    store
        .update_job_status("job-1", fleet_domain::JobStatus::Success)
        .unwrap();
    let second = read_page(&store, &scope, Some(&first.after), limits).unwrap();
    let retried = read_page(&store, &scope, Some(&first.after), limits).unwrap();
    assert_eq!(second.items, retried.items);
    assert_eq!(second.after, retried.after);
    assert_eq!(second.items[0].data, "b-stderr");
    assert_eq!(second.job_status, "success");
    assert!(!second.has_more);
    assert!(
        !second.caught_up,
        "terminal with an older fence is not a fully drained current prefix"
    );
    let third = read_page(&store, &scope, Some(&second.after), limits).unwrap();
    assert_eq!(third.items[0].data, "a-late");
    assert!(third.caught_up);
    append(
        &store,
        "job-1",
        "b2",
        JobOutputStream::Stdout,
        0,
        "b-stdout",
    );
    let fourth = read_page(&store, &scope, Some(&third.after), limits).unwrap();
    assert_eq!(fourth.items[0].data, "b-stdout");
    let empty = read_page(&store, &scope, Some(&fourth.after), limits).unwrap();
    assert!(empty.items.is_empty());
    assert!(empty.caught_up);
    assert!(!empty.has_more);
}

#[test]
fn limits_scope_and_invalid_utf8_offsets_are_rejected_without_fallback() {
    for (entries, bytes) in [
        (0, DEFAULT_BYTES),
        (MAX_ENTRIES + 1, DEFAULT_BYTES),
        (1, 4095),
        (1, MAX_BYTES + 1),
    ] {
        assert!(matches!(
            Limits::new(entries, bytes),
            Err(ReadError::InvalidLimit)
        ));
    }
    let store = fixture(&["a1", "b2"]);
    install_tracking(&store);
    job(&store, "job-2");
    append(
        &store,
        "job-1",
        "a1",
        JobOutputStream::Stdout,
        0,
        "가나다🤖",
    );
    append(&store, "job-1", "b2", JobOutputStream::Stderr, 0, "b-only");
    let mut scope = Scope::job("job-1");
    scope.agent = Some("a1".into());
    scope.stream = Some("stdout".into());
    let limits = Limits::new(128, DEFAULT_BYTES).unwrap();
    let page = read_page(&store, &scope, None, limits).unwrap();
    assert_eq!(page.items.len(), 1);
    for other in [Scope::job("job-1"), Scope::job("job-2")] {
        assert!(matches!(
            read_page(&store, &other, Some(&page.after), limits),
            Err(ReadError::WrongScope)
        ));
    }
    let mut offset = page.after.clone();
    offset.offset = 1;
    assert!(matches!(
        read_page(&store, &scope, Some(&offset), limits),
        Err(ReadError::InvalidOffset)
    ));
    offset.offset = usize::MAX;
    assert!(matches!(
        read_page(&store, &scope, Some(&offset), limits),
        Err(ReadError::InvalidOffset)
    ));
    offset.offset = page.items[0].total + 1;
    assert!(matches!(
        read_page(&store, &scope, Some(&offset), limits),
        Err(ReadError::InvalidOffset)
    ));
    offset = page.after.clone();
    offset.fence = Some(i64::MAX);
    assert!(matches!(
        read_page(&store, &scope, Some(&offset), limits),
        Err(ReadError::InvalidOffset)
    ));
}

#[test]
fn tracking_preserves_legacy_rows_and_distinguishes_empty_from_pruned_history() {
    let store = fixture(&["a1"]);
    append(&store, "job-1", "a1", JobOutputStream::Stdout, 0, "legacy");
    let legacy = store.list_job_output_chunks_for_job("job-1").unwrap();
    install_tracking(&store);
    job(&store, "new-job");
    let limits = Limits::new(128, DEFAULT_BYTES).unwrap();
    let before = read_page(&store, &Scope::job("job-1"), None, limits).unwrap();
    assert_eq!(before.history, "unknown");
    assert_eq!(
        store.list_job_output_chunks_for_job("job-1").unwrap(),
        legacy
    );
    install_tracking(&store);
    let fresh = read_page(&store, &Scope::job("new-job"), None, limits).unwrap();
    assert_eq!(fresh.history, "tracked");
    assert!(fresh.items.is_empty());
    store
        .connection
        .execute("UPDATE job_output_chunks SET created_at = 0", [])
        .unwrap();
    let cutoff = std::time::UNIX_EPOCH + Duration::from_secs(1);
    store.cleanup_retention(cutoff, true).unwrap();
    assert!(read_page(&store, &Scope::job("job-1"), Some(&before.after), limits).is_ok());
    store.cleanup_retention(cutoff, false).unwrap();
    assert!(matches!(
        read_page(&store, &Scope::job("job-1"), Some(&before.after), limits),
        Err(ReadError::Stale)
    ));
    let pruned = read_page(&store, &Scope::job("job-1"), None, limits).unwrap();
    assert!(pruned.items.is_empty());
    assert_eq!(pruned.history, "pruned");
    assert_eq!(
        pruned.after.epoch, before.after.epoch,
        "retention must not rotate receipt trust"
    );
    assert_eq!(
        store.current_schema_version().unwrap(),
        Some(super::CURRENT_SCHEMA_VERSION)
    );
}

#[test]
fn deletion_and_generation_rollback_together_when_tracking_write_fails() {
    let store = fixture(&["a1"]);
    install_tracking(&store);
    append(&store, "job-1", "a1", JobOutputStream::Stdout, 0, "keep");
    store
        .connection
        .execute("UPDATE job_output_chunks SET created_at = 0", [])
        .unwrap();
    let scope = Scope::job("job-1");
    let limits = Limits::new(128, DEFAULT_BYTES).unwrap();
    let before = read_page(&store, &scope, None, limits).unwrap();
    store.connection.execute_batch("CREATE TRIGGER rehearsal_fail BEFORE UPDATE ON output_read_rehearsal BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;").unwrap();
    assert!(
        store
            .cleanup_retention(std::time::UNIX_EPOCH + Duration::from_secs(1), false)
            .is_err()
    );
    let after = read_page(&store, &scope, None, limits).unwrap();
    assert_eq!(before.items, after.items);
    assert_eq!(before.after.generation, after.after.generation);
}

#[test]
fn restored_epoch_rejects_previous_cursors_without_changing_output() {
    let mut store = fixture(&["a1"]);
    install_tracking(&store);
    append(
        &store,
        "job-1",
        "a1",
        JobOutputStream::Stderr,
        0,
        "same bytes",
    );
    let scope = Scope::job("job-1");
    let limits = Limits::new(128, DEFAULT_BYTES).unwrap();
    let before = read_page(&store, &scope, None, limits).unwrap();
    store.rotate_controller_store_epoch().unwrap();
    assert!(matches!(
        read_page(&store, &scope, Some(&before.after), limits),
        Err(ReadError::Stale)
    ));
    let after = read_page(&store, &scope, None, limits).unwrap();
    assert_eq!(before.items, after.items);
    assert_ne!(before.after.epoch, after.after.epoch);
}

#[test]
fn metadata_and_control_character_json_stay_within_both_source_and_wire_budgets() {
    let agent = "\u{1}".repeat(MAX_BYTES - 16);
    let store = fixture(&[&agent]);
    install_tracking(&store);
    append(
        &store,
        "job-1",
        &agent,
        JobOutputStream::Stdout,
        0,
        "\u{1}\u{1}\0🤖",
    );
    let page = read_page(
        &store,
        &Scope::job("job-1"),
        None,
        Limits::new(MAX_ENTRIES, MAX_BYTES).unwrap(),
    )
    .unwrap();
    assert!(
        page.items
            .iter()
            .map(Fragment::payload_bytes)
            .sum::<usize>()
            <= MAX_BYTES
    );
    assert!(wire_bytes(&page) <= 2 * 1024 * 1024);
    let oversized = "x".repeat(MAX_BYTES + 1);
    let other = fixture(&[&oversized]);
    install_tracking(&other);
    append(
        &other,
        "job-1",
        &oversized,
        JobOutputStream::Stdout,
        0,
        "kept in legacy storage",
    );
    assert!(matches!(
        read_page(
            &other,
            &Scope::job("job-1"),
            None,
            Limits::new(MAX_ENTRIES, MAX_BYTES).unwrap()
        ),
        Err(ReadError::MetadataTooLarge)
    ));
    assert_eq!(
        other.list_job_output_chunks_for_job("job-1").unwrap()[0].body,
        "kept in legacy storage"
    );
}

#[test]
fn empty_chunks_advance_and_large_identifiers_are_serialized_as_decimal_strings() {
    let store = fixture(&["a1"]);
    install_tracking(&store);
    store
        .connection
        .execute(
            "INSERT INTO sqlite_sequence(name, seq) VALUES ('job_output_chunks', 9007199254740992)",
            [],
        )
        .unwrap();
    append(
        &store,
        "job-1",
        "a1",
        JobOutputStream::Stdout,
        9007199254740997,
        "",
    );
    let scope = Scope::job("job-1");
    let limits = Limits::new(128, DEFAULT_BYTES).unwrap();
    let page = read_page(&store, &scope, None, limits).unwrap();
    assert_eq!(page.items.len(), 1);
    assert!(page.items[0].row > 9007199254740992);
    assert_eq!(page.items[0].sequence.to_string(), "9007199254740997");
    let encoded: serde_json::Value = serde_json::from_slice(&wire(&page)).unwrap();
    assert_eq!(encoded["items"][0]["sequence"], "9007199254740997");
    assert_eq!(encoded["items"][0]["offset_bytes"], "0");
    assert_eq!(encoded["items"][0]["total_bytes"], "0");
    assert_eq!(
        encoded["items"][0]["chunk_key"],
        page.items[0].row.to_string()
    );
    let next = read_page(&store, &scope, Some(&page.after), limits).unwrap();
    assert!(next.items.is_empty());
    assert!(next.caught_up);
    assert!(wire_bytes(&page) < 2 * 1024 * 1024);
}

#[test]
fn missing_tracking_state_is_unavailable_rather_than_missing_job_or_empty_success() {
    let store = fixture(&["a1"]);
    install_tracking(&store);
    store
        .connection
        .execute(
            "DELETE FROM output_read_rehearsal WHERE job_id = 'job-1'",
            [],
        )
        .unwrap();
    let limits = Limits::new(128, DEFAULT_BYTES).unwrap();
    assert!(matches!(
        read_page(&store, &Scope::job("job-1"), None, limits),
        Err(ReadError::ReadUnavailable)
    ));
    assert!(matches!(
        read_page(&store, &Scope::job("missing-job"), None, limits),
        Err(ReadError::MissingJob)
    ));
}

#[test]
fn count_and_byte_limits_apply_even_when_many_rows_have_empty_output() {
    let store = fixture(&["a1"]);
    install_tracking(&store);
    for sequence in 0..513 {
        append(&store, "job-1", "a1", JobOutputStream::Stdout, sequence, "");
    }
    let scope = Scope::job("job-1");
    let limits = Limits::new(MAX_ENTRIES, DEFAULT_BYTES).unwrap();
    let mut after = None;
    let mut rows = 0;
    for expected in [256, 256, 1] {
        let page = read_page(&store, &scope, after.as_ref(), limits).unwrap();
        assert_eq!(page.items.len(), expected);
        assert!(
            page.items
                .iter()
                .map(Fragment::payload_bytes)
                .sum::<usize>()
                <= limits.bytes
        );
        assert!(wire_bytes(&page) < 2 * 1024 * 1024);
        rows += page.items.len();
        after = Some(page.after);
    }
    assert_eq!(rows, 513);
    assert!(
        read_page(&store, &scope, after.as_ref(), limits)
            .unwrap()
            .items
            .is_empty()
    );
}

#[test]
fn append_order_pages_can_reconstruct_legacy_stream_order_even_when_sequence_zero_arrives_late() {
    let store = fixture(&["a1", "b2"]);
    install_tracking(&store);
    append(&store, "job-1", "a1", JobOutputStream::Stdout, 1, "second");
    append(&store, "job-1", "b2", JobOutputStream::Stderr, 0, "error");
    append(&store, "job-1", "a1", JobOutputStream::Stdout, 0, "first");
    let scope = Scope::job("job-1");
    let limits = Limits::new(1, DEFAULT_BYTES).unwrap();
    let mut actual = std::collections::BTreeMap::new();
    let mut after = None;
    let mut drained = false;
    for _ in 0..8 {
        let page = read_page(&store, &scope, after.as_ref(), limits).unwrap();
        for f in &page.items {
            actual.insert(
                (f.agent.clone(), f.stream.clone(), f.sequence, f.offset),
                f.data.clone(),
            );
        }
        let done = !page.has_more;
        after = Some(page.after);
        if done {
            drained = true;
            break;
        }
    }
    assert!(drained, "three stored rows must drain within eight pages");
    let expected = store
        .list_job_output_chunks_for_job("job-1")
        .unwrap()
        .into_iter()
        .map(|f| {
            let stream = match f.stream {
                JobOutputStream::Stdout => "stdout",
                JobOutputStream::Stderr => "stderr",
            };
            (
                (f.agent_id, stream.to_owned(), f.sequence as i64, 0),
                f.body,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(actual, expected);
}

#[test]
fn query_plan_rehearsal_compares_an_isolated_candidate_index_without_changing_runtime_schema() {
    let store = fixture(&["a1", "b2"]);
    install_tracking(&store);
    for id in ["job-2", "job-3", "job-4"] {
        job(&store, id);
    }
    let body = "x".repeat(1024);
    store.connection.execute_batch("BEGIN").unwrap();
    for sequence in 0..512 {
        for id in ["job-1", "job-2", "job-3", "job-4"] {
            append(
                &store,
                id,
                if sequence % 2 == 0 { "a1" } else { "b2" },
                JobOutputStream::Stdout,
                sequence,
                &body,
            );
        }
    }
    store.connection.execute_batch("COMMIT").unwrap();
    let plan = || {
        store
            .connection
            .prepare(&format!("EXPLAIN QUERY PLAN {KEY_QUERY}"))
            .unwrap()
            .query_map(
                params![
                    "job-1",
                    i64::MAX,
                    0,
                    0,
                    Option::<String>::None,
                    Option::<String>::None,
                    128
                ],
                |r| r.get::<_, String>(3),
            )
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    let scope = Scope::job("job-1");
    let limits = Limits::new(128, DEFAULT_BYTES).unwrap();
    let before_plan = plan();
    let started = std::time::Instant::now();
    let before = read_page(&store, &scope, None, limits).unwrap();
    let before_us = started.elapsed().as_micros();
    store
        .connection
        .execute_batch("CREATE INDEX rehearsal_append_idx ON job_output_chunks(job_id, id)")
        .unwrap();
    let after_plan = plan();
    let started = std::time::Instant::now();
    let after = read_page(&store, &scope, None, limits).unwrap();
    let after_us = started.elapsed().as_micros();
    assert_eq!(before.items, after.items);
    assert_eq!(before.after, after.after);
    assert!(
        after
            .items
            .iter()
            .map(Fragment::payload_bytes)
            .sum::<usize>()
            <= DEFAULT_BYTES
    );
    assert!(wire_bytes(&after) <= 2 * 1024 * 1024);
    println!(
        "output_read_rehearsal: fixture_rows=2048 selected_job_rows=512 default_entries=128 payload_budget={DEFAULT_BYTES} returned_entries={} payload_bytes={} wire_bytes={} before_us={before_us} after_us={after_us} before_plan={before_plan:?} after_plan={after_plan:?}",
        after.items.len(),
        after
            .items
            .iter()
            .map(Fragment::payload_bytes)
            .sum::<usize>(),
        wire_bytes(&after)
    );
    store
        .connection
        .execute_batch("DROP INDEX rehearsal_append_idx")
        .unwrap();
    assert_eq!(
        store.current_schema_version().unwrap(),
        Some(super::CURRENT_SCHEMA_VERSION)
    );
}
