-- Frozen actual schema27 before IAM28. Synthetic legacy records only.
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE admin_tokens (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    token_hash TEXT NOT NULL,
    actor_id TEXT NOT NULL DEFAULT 'bootstrap-admin',
    role TEXT NOT NULL DEFAULT 'owner',
    created_at INTEGER NOT NULL
);
INSERT INTO "admin_tokens" VALUES(1,'be5f6ba12fe3e2ae401b9e17c28088343b064e25bda00484733f6d23e1010382','bootstrap-admin','owner',1000);
CREATE TABLE agent_capability_snapshots (
    agent_id TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    privilege_level TEXT NOT NULL,
    package_manager TEXT,
    service_manager TEXT,
    capabilities_json TEXT NOT NULL,
    reported_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE agent_certificate_lifecycle (
    agent_id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    current_serial TEXT,
    current_fingerprint TEXT,
    current_not_before INTEGER,
    current_not_after INTEGER,
    next_serial TEXT,
    next_fingerprint TEXT,
    next_not_before INTEGER,
    next_not_after INTEGER,
    grace_until INTEGER,
    revocation_reason TEXT,
    updated_at INTEGER NOT NULL
);
CREATE TABLE agent_identities (
    agent_id TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
INSERT INTO "agent_identities" VALUES('legacy-agent','synthetic-public-key','synthetic-agent-fingerprint',1000);
CREATE TABLE agent_log_chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    line TEXT NOT NULL,
    collected_at INTEGER NOT NULL
);
CREATE TABLE agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    labels TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    last_seen_at INTEGER,
    pinned_controller TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
INSERT INTO "agents" VALUES('legacy-agent','legacy-agent','synthetic-public-key','synthetic-agent-fingerprint','role=web','active',1000,'synthetic-controller',1000,1000);
CREATE TABLE approval_decisions (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    actor TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
INSERT INTO "approval_decisions" VALUES('legacy-decision','legacy-job','bootstrap-admin','approved','synthetic history',1000);
CREATE TABLE approval_requests (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    requester TEXT NOT NULL,
    approver TEXT,
    reason TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    decided_at INTEGER
);
INSERT INTO "approval_requests" VALUES('legacy-approval','legacy-job','bootstrap-admin','legacy-approver','synthetic history','approved',2000,1000,1000);
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    target TEXT NOT NULL,
    value_kind TEXT NOT NULL,
    value_text TEXT NOT NULL DEFAULT '',
    occurred_at INTEGER NOT NULL
);
INSERT INTO "audit_events" VALUES(1,'security','legacy_fixture_event','bootstrap-admin','legacy-job','redacted','',1000);
CREATE TABLE catalog_documents (
    source_id TEXT NOT NULL,
    commit_id TEXT NOT NULL,
    path TEXT NOT NULL,
    kind TEXT NOT NULL,
    checksum TEXT NOT NULL,
    body TEXT NOT NULL,
    PRIMARY KEY (source_id, commit_id, path),
    FOREIGN KEY (source_id, commit_id)
        REFERENCES catalog_revisions(source_id, commit_id) ON DELETE CASCADE
);
CREATE TABLE catalog_revisions (
    source_id TEXT NOT NULL REFERENCES catalog_sources(id) ON DELETE CASCADE,
    commit_id TEXT NOT NULL,
    state TEXT NOT NULL,
    document_count INTEGER,
    failure_code TEXT,
    PRIMARY KEY (source_id, commit_id)
);
CREATE TABLE catalog_sources (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    reference TEXT NOT NULL,
    active_revision TEXT
);
CREATE TABLE catalog_sync_operations (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES catalog_sources(id) ON DELETE CASCADE,
    commit_id TEXT,
    state TEXT NOT NULL,
    failure_code TEXT
);
CREATE TABLE controller_delivery_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    namespace TEXT NOT NULL,
    store_epoch TEXT NOT NULL
);
INSERT INTO "controller_delivery_identity" VALUES(1,'970d19f84c4b6c9a8bd5cc26632a1b3aa775e2186aa1008a409d0f0a6705ba13','eae268137c3e2d87d3c2f5fa584104bbafff5efb5d038f9940c1bb5cefa12e51');
CREATE TABLE controller_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    public_key TEXT NOT NULL,
    public_fingerprint TEXT NOT NULL,
    private_key_path TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE controller_report_inbox (
    controller_namespace TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    report_id TEXT NOT NULL,
    class TEXT NOT NULL CHECK (class IN ('lifecycle', 'drift_evidence', 'output', 'final_result')),
    digest_hex TEXT NOT NULL,
    body BLOB,
    accounted_bytes INTEGER NOT NULL CHECK (accounted_bytes > 0),
    status TEXT NOT NULL CHECK (status IN ('pending_effects', 'committed')),
    PRIMARY KEY (controller_namespace, agent_id, job_id, task_id, report_id)
);
CREATE TABLE controller_report_receipts (
    controller_namespace TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    report_id TEXT NOT NULL,
    digest_hex TEXT NOT NULL,
    store_epoch TEXT NOT NULL,
    signer_fingerprint TEXT NOT NULL,
    receipt_bytes BLOB NOT NULL,
    PRIMARY KEY (controller_namespace, agent_id, job_id, task_id, report_id),
    FOREIGN KEY (controller_namespace, agent_id, job_id, task_id, report_id)
        REFERENCES controller_report_inbox (controller_namespace, agent_id, job_id, task_id, report_id)
        ON DELETE CASCADE
);
CREATE TABLE controller_signing_key_rotation (
    controller_id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    old_fingerprint TEXT NOT NULL,
    new_fingerprint TEXT,
    requested_at INTEGER,
    validated_at INTEGER,
    activated_at INTEGER,
    old_key_verifies_until INTEGER,
    retired_at INTEGER,
    failed_at INTEGER,
    updated_at INTEGER NOT NULL
);
CREATE TABLE controller_signing_staged_rollout (
    controller_id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    target_ids TEXT NOT NULL,
    batch_size INTEGER NOT NULL,
    max_failures INTEGER NOT NULL,
    ack_timeout_seconds INTEGER NOT NULL,
    acknowledged_agent_ids TEXT NOT NULL,
    unavailable_agent_ids TEXT NOT NULL,
    failed_agent_ids TEXT NOT NULL,
    in_flight_attempts TEXT NOT NULL,
    failure_reason_code TEXT,
    current_fingerprint TEXT NOT NULL,
    previous_fingerprint TEXT,
    updated_at INTEGER NOT NULL
);
CREATE TABLE drift_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    policy_name TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'unknown',
    expected TEXT NOT NULL,
    actual TEXT NOT NULL,
    checked_at INTEGER NOT NULL,
    acknowledged_at INTEGER,
    acknowledged_by TEXT,
    resolved_at INTEGER,
    resolution_job_id TEXT
, job_id TEXT, task_id TEXT, policy_id TEXT, policy_version INTEGER, purpose TEXT);
CREATE TABLE enrollment_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    default_labels TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL,
    max_uses INTEGER NOT NULL,
    used_count INTEGER NOT NULL DEFAULT 0,
    revoked_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE facts_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    collected_at INTEGER NOT NULL
);
CREATE TABLE job_catalog_runbook_provenance (
    job_id TEXT PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
    source_id TEXT NOT NULL,
    commit_id TEXT NOT NULL,
    path TEXT NOT NULL,
    checksum TEXT NOT NULL,
    FOREIGN KEY (source_id, commit_id, path)
        REFERENCES catalog_documents(source_id, commit_id, path) ON DELETE RESTRICT
);
CREATE TABLE job_output_chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    stream TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE(job_id, agent_id, stream, chunk_index)
);
CREATE TABLE job_output_read_state (
    job_id TEXT PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK(typeof(generation) = 'integer' AND generation >= 0),
    history TEXT NOT NULL CHECK(history IN ('tracked', 'unknown', 'pruned')),
    last_row_id INTEGER NOT NULL CHECK(typeof(last_row_id) = 'integer' AND last_row_id >= 0)
);
INSERT INTO "job_output_read_state" VALUES('legacy-job',0,'tracked',0);
CREATE TABLE job_targets (
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    agent_display_name TEXT NOT NULL DEFAULT '',
    agent_status_snapshot TEXT NOT NULL DEFAULT 'unknown',
    labels_snapshot TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (job_id, agent_id)
);
INSERT INTO "job_targets" VALUES('legacy-job','legacy-agent','queued','','unknown','');
CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    risk TEXT NOT NULL,
    approval_requirement TEXT NOT NULL,
    timeout_ms INTEGER NOT NULL,
    command_program TEXT,
    command_args_json TEXT NOT NULL DEFAULT '[]',
    command_max_output_bytes INTEGER NOT NULL DEFAULT 1048576,
    drift_policy_document TEXT,
    drift_policy_id TEXT,
    drift_policy_version INTEGER,
    drift_purpose TEXT,
    runbook_document TEXT,
    selector_kind TEXT NOT NULL DEFAULT 'explicit_ids',
    selector_source TEXT NOT NULL DEFAULT '',
    strategy_concurrency INTEGER NOT NULL DEFAULT 1,
    strategy_max_failures INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
INSERT INTO "jobs" VALUES('legacy-job','queued','high','admin_confirmation',30000,'uptime','[]',1048576,NULL,NULL,NULL,NULL,NULL,'explicit_ids','',1,NULL,1000);
CREATE TABLE metrics_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    collected_at INTEGER NOT NULL
);
CREATE TABLE policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version INTEGER NOT NULL,
    source TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE policy_assignments (
    policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    assigned_at INTEGER NOT NULL,
    PRIMARY KEY (policy_id, agent_id)
);
CREATE TABLE policy_catalog_provenance (
    policy_id TEXT PRIMARY KEY REFERENCES policies(id) ON DELETE CASCADE,
    source_id TEXT NOT NULL,
    commit_id TEXT NOT NULL,
    path TEXT NOT NULL,
    checksum TEXT NOT NULL,
    FOREIGN KEY (source_id, commit_id, path)
        REFERENCES catalog_documents(source_id, commit_id, path) ON DELETE RESTRICT
);
CREATE TABLE policy_drift_schedules (
    policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    interval_seconds INTEGER NOT NULL,
    next_due_at INTEGER NOT NULL,
    last_checked_at INTEGER,
    PRIMARY KEY (policy_id, agent_id)
);
CREATE TABLE remediation_requests (
    id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    runbook_ref TEXT NOT NULL,
    status TEXT NOT NULL,
    approval_required INTEGER NOT NULL,
    risk_summary TEXT NOT NULL,
    job_id TEXT,
    origin_drift_report_id INTEGER,
    policy_version INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE remediation_verification_jobs (
                remediation_id TEXT PRIMARY KEY REFERENCES remediation_requests(id) ON DELETE CASCADE,
                job_id TEXT NOT NULL UNIQUE REFERENCES jobs(id) ON DELETE RESTRICT,
                created_at INTEGER NOT NULL
            );
CREATE TABLE rendered_artifacts (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    task_id TEXT NOT NULL,
    destination TEXT NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK(size_bytes > 0),
    retention_class TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE schema_migrations (
    name TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    applied_at INTEGER NOT NULL DEFAULT (unixepoch())
);
INSERT INTO "schema_migrations" VALUES('fleet_store',27,1000);
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('audit_events',1);
CREATE TABLE task_assignments (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'queued',
    nonce TEXT NOT NULL UNIQUE,
    payload_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    issued_at INTEGER NOT NULL DEFAULT (unixepoch()),
    expires_at INTEGER NOT NULL,
    dispatched_at INTEGER,
    accepted_at INTEGER,
    started_at INTEGER,
    completed_at INTEGER,
    last_error TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX controller_report_inbox_pending_agent_idx
    ON controller_report_inbox (agent_id, status);
CREATE UNIQUE INDEX remediation_requests_active_policy_unique_idx
    ON remediation_requests (agent_id, policy_id)
    WHERE origin_drift_report_id IS NOT NULL
      AND status NOT IN ('resolved', 'failed', 'rejected', 'expired', 'canceled');
CREATE INDEX catalog_revisions_source_state_idx
    ON catalog_revisions (source_id, state, commit_id);
CREATE TRIGGER catalog_revisions_terminal_state_immutable
BEFORE UPDATE OF state, document_count, failure_code ON catalog_revisions
WHEN OLD.state IN ('ready', 'failed')
 AND (NEW.state IS NOT OLD.state
      OR NEW.document_count IS NOT OLD.document_count
      OR NEW.failure_code IS NOT OLD.failure_code)
BEGIN
    SELECT RAISE(ABORT, 'catalog terminal revision is immutable');
END;
CREATE UNIQUE INDEX catalog_sync_operations_one_active_source_idx
    ON catalog_sync_operations (source_id)
    WHERE state = 'in_progress';
CREATE TRIGGER catalog_sync_operations_terminal_state_immutable
BEFORE UPDATE OF commit_id, state, failure_code ON catalog_sync_operations
WHEN OLD.state <> 'in_progress'
 AND (NEW.commit_id IS NOT OLD.commit_id
      OR NEW.state IS NOT OLD.state
      OR NEW.failure_code IS NOT OLD.failure_code)
BEGIN
    SELECT RAISE(ABORT, 'catalog terminal sync operation is immutable');
END;
CREATE INDEX catalog_documents_source_commit_path_idx
    ON catalog_documents (source_id, commit_id, path);
CREATE UNIQUE INDEX drift_reports_correlated_task_unique_idx
             ON drift_reports (job_id, task_id)
             WHERE job_id IS NOT NULL AND task_id IS NOT NULL;
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
COMMIT;
PRAGMA foreign_keys=ON;
