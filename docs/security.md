# Security Model

This document records the current security boundary for Sponzey Fleet. It is
implementation-facing documentation: code changes that affect authentication,
authorization, task dispatch, secrets, or audit should update this file.

Project priorities and stable feature IDs are in the
[capability map](../.docs/product/capabilities.md) and [overall plan](../.docs/plans/plan.md).
Remaining numbered Phase references are historical labels, not the active `.tasks/` phases;
the [documentation map](../.docs/README.md) records their correspondence.

## Current Scope

Sponzey Fleet supports single-organization local administrator accounts with the existing
owner/admin/operator/viewer business permissions. Bootstrap-token access is a separate legacy
mode that ends atomically at first-owner activation. Individual identity is IAM-001; project isolation is IAM-002.
The selected first path is local username/password for one organization (D-012/D-013).
Its scoped personal login/session lifecycle is implemented and exercised over HTTPS; the contract is
[IAM-001](../.docs/domains/identity/features/IAM-001-auth-contract.md). OIDC is outside this scope.

The implementation foundations now include pure account/credential rules, Application
transaction ports and synthetic-tested owner/setup/password use cases. Controller crypto
primitives use NFC, bounded input, a local weak-password blocklist, fixed Argon2id v19
(19,456 KiB, two passes, one lane, 16-byte random salt, 32-byte output), constant-time
hash comparison, and an explicitly owned wiped scratch buffer. Token generation uses
OS entropy and purpose-specific 256-bit material with purpose-bound SHA-256 lookup digests.
The primitives are crate-private behind a tested password worker with one or two owned threads,
one pending queue slot, and at most workers-plus-one outstanding computations/replies. The
30-second monotonic request deadline never renews; cancellation/drop skips queued work and
discards late results. Shutdown closes cloned clients and joins native computations. Workers
have no store or credential-issuance authority. SQLite and feature-gated Postgres v28 repositories provide atomic
account/mode/credential/audit transactions, a separate human epoch, commit-time owner guards
and conditional legacy-token rejection. Corrupt records fail closed. Controller composition,
personal login/session/logout/setup and owner account reads/mutations now consume those boundaries.
Own password replacement and PAT issuance/metadata/revocation are connected. Command, DriftCheck, direct and catalog Runbook creation plus
approval/rejection, explicit cancellation, manual approval expiry and remediation approval/job creation revalidate current human authority in the same transaction as their effects.
Personal Admin screens and personal-token CLI profiles are connected; scoped two-user HTTPS browser/API/CLI and Linux Agent acceptance have passed.
CLI login reads a personal token from a hidden terminal or explicit single-line stdin,
verifies the required personal session endpoint, and atomically saves an owned private profile.
It never submits or stores a remote account password. The existing `controller_url`/`admin_token`
profile format is retained; legacy explicit token arguments remain available but are not the
recommended personal input. Profile reads reject unsafe modes, links, unknown fields and
oversized content, with redacted diagnostics. Changing the server origin alone cannot reuse
a saved credential. Protected CLI requests have a ten-second deadline and reject redirects;
they never retry an operation under a replacement credential. Unix TTY restoration, temporary
profiles and owned HTTP tests are supplemented by actual HTTPS PAT issuance/use/revocation with a Linux Agent.
Idle dispatch polling is FieldDebug detail. Product logging records only new dispatch/failure
effects for this event, avoiding repeated no-op traffic in the default profile. Log consumers
must drain their streams; this does not introduce a general nonblocking logging guarantee.
Optional login `--tls-ca-cert` saves only a canonical public CA path in `tls_ca_cert`;
older two-field profiles remain valid and omit the optional field when resaved without a CA.
Each command reads that regular file once at bootstrap, bounded to16KiB, rejects empty/invalid
certificate sets, private-key PEM items and special files, and passes immutable public bytes
to its scoped client. Built-in roots and hostname verification remain enabled; no OS/browser
trust store is changed and no certificate/key body is printed.
The Postgres identity adapter's shared Application, migration rollback and concurrent owner/claim/revocation contracts passed on an owned PostgreSQL18.3 fixture; Controller Postgres readiness remains unsupported. No PHC cost from a
stored string can control this fixed primitive; repository adapters must validate the semantic
profile/salt/hash components before constructing a verifier.

Application login/PAT services now enforce fixed expiry, same-request password proof and current
credential/account/epoch checks at commit. Session8/global4096 and PAT16/global8192 admission uses
serialized counts after bounded128-per-purpose lookup reclamation. Ephemeral lookup deletion never
deletes account/audit history. Self metadata excludes digest/binding/secret; owner/purpose filtering
precedes row decoding, including corrupt foreign rows and page lookahead. Logout ends only the web
session; self PAT revocation can remove its own caller. Actual SQLite/Postgres tests cover both
admission races and revoke/logout audit rollback; the real worker/SQLite consumer keeps an independent
writer available through five password operations. Actual HTTP KDF probes also keep the Controller
shared mutex available during login and owner create/change/reset. Owned HTTP/HTTPS cookie/CSRF
tests are foundation evidence; full two-user browser/Linux-Agent HTTPS acceptance remains separate.

Owner create/change/reset HTTP requests require same-request current-password proof, with the
canonical actor username's failure budget shared with login and the same bounded CPU admission.
Only owner authority reaches those use cases; admin/operator/viewer cannot manage even themselves
through administrative URLs. Known DTOs reject duplicate, unknown and explicit-null change fields.
Application serializes current actor, target revision, last-owner guard, credential revocation and
Security audit. Metadata-only/same-role changes keep proofs; role/disable/reset revokes the target's
sessions, PATs and unused codes. Successful self revocation clears the caller cookie. A future-created
credential causes a safe state conflict rather than an invalid revocation timestamp. The once-returned
setup/reset code is a POST-body secret, not a link query. Audit failure rolls all effects back, and
cancelled/revoked late KDF proofs cannot create accounts. Other people's credentials and accepted
Agent work are outside this human-revocation effect. Command, DriftCheck, direct/catalog Runbook and approval/rejection/explicit-cancellation/manual-expiry/remediation approval and Job creation use canonical guards.

Self password/PAT issuance HTTP accepts all four active roles and derives the target solely from
the verified credential. Nominated user/role/expiry fields are rejected. Same-request password proof
uses the same bounded admission as owner actions. Password replacement revokes all own proofs and
clears a web caller's cookie without auto-login; PAT callers receive no Set-Cookie. PAT issuance
returns one fixed thirty-day secret and keeps the caller session intact. Native HTTP covers per-user
quota refusal followed by expired-row reclamation and fresh issuance, and safe audit rollback for both
operations. Real KDF probes keep the shared store mutex available for own password verification/hash
and PAT proof; revoked/cancelled late PAT proofs do not issue. The scoped two-user UI/CLI/API and Linux Agent journey has separate actual HTTPS evidence.

The Admin HTTP client owns a memory-only authentication generation. Identity changes and successful
logout abort prior effects; late JSON/errors cannot publish into a new identity. Only a current401
retires authenticated authority;403 remains a permission failure. Cookie business mutations receive
the current CSRF proof, while bearer effects omit cookies. Required authentication/account404 is an
error. Direct and catalog submissions never automatically retry. Uncertain direct submissions retain
only their Job ID and require an explicit stored-Job read before another submission; catalog intent
cannot be replayed by a later authentication generation. This effect boundary is connected to the
existing static Admin, including personal login, owner/self account forms and per-role Settings tabs. Scoped two-user HTTPS/Agent acceptance has passed.

Own PAT metadata/revocation HTTP now consumes the bounded query and canonical revoke use cases.
Queries are scoped by subject/purpose before row decoding and validate the whole lookahead. A
corrupt foreign row stays invisible; a corrupt owned row fails without a partial page. GET never
cleans/renews and returns only ID/label/timestamps/server-derived active state. The selected own PAT,
including the caller PAT, may be revoked without current-password proof; cookie calls still require
Origin/CSRF. Foreign/missing/non-PAT/already-revoked IDs return the same404 regardless of pending
lookup cleanup. Audit failure rolls back revocation, and names/roles never replace immutable user IDs
as audit actors. These HTTP fixtures are supplemented by separate actual browser/Linux-Agent acceptance.

Core now provides a separately tested Unix data-directory lease: current effective OS
owner, mode 0700 directory, mode 0600 singly linked regular lock, no final symlink or
special-file lock, and nonblocking exclusive flock. Existing permissions and file contents
are not changed; explicit Drop unlock prevents inherited descriptors from extending the
operation's authority. Production Controller startup acquires this lease before transport,
database and signing-identity access and retains it until runtime shutdown completes.
The local `controller admin init-owner` CLI now borrows this authority while reading bounded
hidden TTY input or explicit single-line stdin, running the bounded worker and committing the
Application owner/mode/audit transaction. Local audit actors derive from the OS UID. Init and
owner commands use the same custom SQLite settings as start. Personal/restored init preserves
signing identity and never creates a shared token; missing original keys require backup recovery.
CLI library/PTY tests cover these paths. The official debug-binary loopback rehearsal now verifies
positive legacy authentication before cutover, process contention/SIGKILL, audit-fault rollback,
one successful concurrent cutover, durable owner state and old-bearer rejection after restart,
with Agent identity, signing keys and history preserved. Separate live personal login/HTTPS acceptance has passed. The owned rehearsal is reproducible with
`python3 scripts/manual_admin_identity_smoke.py --build`; an existing marked fixture requires
explicit `--reset-fixture`, and an implicit reset leaves both data and proof unchanged.
Local `controller admin recover-owner --username <login-name>` now composes existing-person
recovery with the same OS lease, database selection and hidden/stdin password boundary.
It validates retained signing material before input and revokes only that person's old credentials;
other people, the human epoch and Agent trust remain intact. Real target password crypto and
SQLite composition tests and the fresh official-binary recovery/restore rehearsal pass on the owned private fixture.
The lock is advisory between participating processes; an older binary must be stopped
explicitly before upgrade, and a malicious process with the same OS identity is outside it.

The Application restore boundary now rotates an independent CSPRNG human epoch and appends
its Security audit atomically under local authority. Sessions/PAT/setup/reset grants from the
snapshot fail their old epoch binding; accounts, verifiers and credential history remain intact.
Without a loginable owner it selects local setup, never shared-token access. SQLite and actual
owned Postgres tests cover rollback and nonhuman-history/delivery-epoch preservation. The CLI now
composes this boundary in a private candidate under the target lease, independently rotates the
Agent delivery epoch, syncs files and atomically exchanges the target directory. Older snapshots
without a loginable owner require local setup. Actual filesystem/library tests cover four-purpose
rejection, preserved history/keys, audit rollback, syscall failure, before/after-exchange process kill
and distinct postcommit durability/cleanup warnings. The current official-binary rehearsal also
passes local recovery, dry-run, two-epoch restore, corruption/audit rollback, busy offline commands
and old-backup local setup. Its seeded credential rows prove native persistence/binding changes;
the actual file-to-Application tests prove positive-before/negative-after authentication. Separate actual
personal-login/HTTPS restore and four-purpose replay rejection have passed. See [storage safeguards](storage.md#backuprestore).

Current behavior:

- In legacy mode, `fleet controller init` prints one raw admin token; personal/restored modes skip shared-token issuance.
- The raw admin token is shown once and is not stored in plaintext.
- The controller stores only the admin token hash.
- The stored bootstrap admin token maps to actor `bootstrap-admin`.
- The bootstrap admin actor has role `owner`.
- Protected REST APIs require `Authorization: Bearer <admin-token>`.
- The controller derives the request actor from the authenticated token, not
  from a request body field.
- Audit events for admin actions use the authenticated actor.
- Existing business-role permission rules are owned by the pure Domain layer; request
  authentication/context assembly still uses the Controller adapter and Application repository.
- SQLite output-page reads require `job_read` on every request and use `Cache-Control: no-store`,
  bounded source/JSON budgets and typed errors without raw output/SQL. The opaque cursor is an
  untrusted read position, never a credential or integrity claim. Scope, persisted generation,
  restore epoch and UTF-8 position are rechecked; stale or unreadable state never becomes empty
  success. Cursor/output/error bodies are not persisted or written to Product/Field logs.

IAM-001 product admin identity must extend this model instead of replacing the
authorization boundary. Personal sessions and API tokens must produce explicit actor
ids and roles; project scope is a separate IAM-002 extension. API handlers must still receive an
authenticated request context and must not trust UI-provided actor fields.

## Command Process Ownership

Darwin/Linux command execution owns a fresh process group and polls output without detached reader
threads. Output-consumer failure, output-limit failure, cancellation and timeout unwind that owner,
which signals the group and reaps its child. `waitid(NOWAIT)` retains the leader until cleanup to avoid
signalling a recycled PID. No PID from a previous Agent process is used. This is not a sandbox:
already-completed effects are not rolled back, and a daemon that escapes the group is outside this
cleanup boundary. A synchronous caller-provided callback must return before timeout/cancel can be
checked again; runtime integration must keep disk work away from the session heartbeat owner.

## Agent Journal Library Boundary

The persistent CLI Agent connects its journal library to the active v2 session for Command and
no-artifact Runbook stdout/stderr, no-artifact Command/Runbook final results, and DriftCheck evidence
plus its separate terminal result.
It stores bounded raw output as sensitive data, not as operational logs. Its
SQLite adapter requires Unix effective-user ownership and owner-only permissions, rejects
symlinks/hardlinks and identity mismatches, and redacts report bodies from Debug/errors. The adapter
uses the Unix `rustix` process API for effective-user checks; it introduces no Domain/Application OS
dependency. The journal is not encrypted at rest and cleanup is not a forensic-erasure claim.

Persistent Command and no-artifact Runbook output sequence starts at zero independently for stdout and stderr. The Agent's
final v2 report carries counts only after each corresponding output report is committed to its local
journal. Before a persistent Command or no-artifact Runbook final effect or receipt, SQLite verifies
exact `[0, count)` coverage in both stored streams; a gap leaves the final pending. `truncated=true` is never accepted as success.
The Job audit contains only the counts and truncation flag, not output bytes. The local execution
record also retains committed per-stream counts after individual output receipts delete report bodies,
so restart recovery can produce a final accepted by the Controller's exact-prefix barrier. This
boundary verifies delivery of the Agent-committed prefix; it cannot prove that the runner captured
every byte produced by task execution. If a journal append returns an uncertain failure, the Agent
does not guess the count or write a contradictory final report; the durable start intent is left for
recovery.

Execution journal admission requires prior durable nonce consumption and verified signed task ownership.
Only a fresh admission and a committed start intent grant the live owner permission to begin host
effects. After process restart, admission/start-intent records describe interruption, not an execution
retry. Final-report persistence and execution completion share one transaction. Persistent WebSocket
Command and no-artifact Runbook paths use this order: signature/target/expiry and nonce checks precede
admission, start intent precedes host effects, and recovery after process restart or prior task-owner
exit commits `failed` with `agent_interrupted_before_start` or `execution_outcome_unknown` without
rerunning the task. A same-process reconnect while a task owner is still live skips recovery; an idle
reconnect or next admitted task retries reconciliation. Artifact-producing Runbook, one-shot and Drift
execution paths remain outside this integration; it does not replace signature and nonce checks.

Agent journal schema v3 adds committed per-stream counts and schema v4 adds the `drift_evidence`
class while preserving the v3 reports. Upgrading a v2 journal with an active
`StartIntent` is rejected before changing its schema or stored reports because the older format cannot
prove whether receipts already deleted output needed for exact recovery. Finish that execution with
the existing Agent before upgrading. This is a local-data safety guard, not support for an older wire
protocol; old wire compatibility is not supported.

If a persistent Command or Runbook's matching no-artifact final report arrives after SQLite G2 has
marked the owned Assignment `failed/execution_outcome_unknown`, the Controller commits a late-report disposition
and one redacted audit, then returns a signed `stored` receipt. It does not revise the Assignment,
Job aggregate, or G2 reason. An exact retry replays the persisted receipt without another audit;
changed bodies and unrelated terminal states are not ACKed. The receipt confirms durable disposition,
not that the earlier unknown outcome was success or that effects ran exactly once.

An owner-matching TaskAck/TaskStarted/TaskRejected arriving after SQLite G2 marked its Assignment
`failed/execution_outcome_unknown` receives an atomic late disposition and signed `stored` receipt.
It appends one redacted audit and commits the inbox marker without changing Assignment, Job, or G2
reason; exact retries replay the same receipt so ordered Agent replay can continue. This receipt is
not evidence of acceptance, execution, or success. Conflicting bodies and owner mismatches remain
fail-closed; the dispatched-cancellation exception below preserves the same terminal-state boundary.

A report from the exact authenticated owner of a previously dispatched, now-canceled Assignment
can also receive a terminal-preserving disposition. Supported no-artifact Command/Runbook finals
must have exact stored output coverage and no remediation follow-up. A valid reported outcome may
have raced cancellation; it never replaces the canonical canceled state, operator reason, completion
time or Job aggregate. Matching lifecycle reports likewise acknowledge durable receipt only. These
paths append a redacted disposition audit atomically with the inbox marker and replay the exact
signed receipt. They neither authorize execution nor delete an unacknowledged Agent report.
Undispatched cancellations, unrelated terminal states and unsupported final effects remain rejected.

The Controller's SQLite recovery worker never treats envelope expiry or disconnection as proof that
the Agent process stopped. After the persisted dispatch time plus Job timeout and a five-minute grace,
it conditionally records an active Assignment as failed with the redacted typed reason
`execution_outcome_unknown`; Assignment, Job aggregate, and audit commit atomically. It does not
replay the signed task, and a concurrent terminal result/cancel wins. Startup recovery must finish
before listener bind; a Postgres-selected runtime without this repository contract fails startup.

The generic journal worker returns success only after its repository operation succeeds. Queue
admission or a caller wait timeout grants neither transmission nor host-execution permission.
Pending/replayed output and retained replies share bounded logical memory budgets. Receipts still
require session authentication before reaching the worker. Shutdown joins the owner; it does not
abandon a disk writer that could later commit unexpected state.

The v2 receipt statement has validated, domain-separated canonical signing bytes covering
Controller namespace/store epoch, report owner/key/digest, signing time, disposition and signer fingerprint.
The active v2 report/receipt payload codec rejects wrong versions, Agent owner mismatch,
malformed or oversized base64 report bodies, wrong SHA-256 digests and malformed receipts before
an application handler can stage them. It redacts report body from Debug and errors. These checks
do not authenticate the socket or verify Ed25519. The authenticated Controller session handles
SQLite `lifecycle` TaskAck/TaskStarted/TaskRejected, `drift_evidence`, `output`, and supported
Command/Runbook/DriftCheck `final-result` reports, including artifact-bearing Runbook finals. The persistent
CLI Agent produces journal-backed reports for TaskAck/TaskStarted/TaskRejected, DriftCheck evidence,
Command/no-artifact Runbook stdout/stderr, and no-artifact final results including DriftCheck terminal results with a strict required output summary. Artifact-bearing Runbook output/final bytes are ephemeral and not journaled. The Agent consumes receipts
only after session identity, exact report, namespace, epoch and
pinned/rotated signing-trust checks. The protocol module is a **shape and preimage contract only**.
The separate Agent library verifier returns a cleanup candidate only for `stored`; the CLI then
submits an exact-row ACK to the journal worker. A forged `auth_accepted` on test-only HTTP or a
well-formed receipt shape cannot authorize journal deletion. Rejected receipts fail closed and retain
the report; explicit rejection disposition handling remains future work.
The Controller's stored-receipt helper refuses noncommitted inbox outcomes and checks the caller's
authenticated Agent ID, durable namespace/epoch, signing-key pair and fingerprint before signing.
The authenticated SQLite TaskAck/TaskStarted/TaskRejected, DriftEvidence, output, and supported final-result handlers call it only after
committing their effects; the helper itself does not authenticate its caller and cannot grant ACK
authority from a merely staged row. `ControllerIdentity` Debug output redacts its private key. Rejected receipts still need
an explicit durable disposition and separate handling.
SQLite schema v25 stores signed receipt bytes for an exact committed inbox key/digest; schema v26
adds the `drift_evidence` inbox class while preserving existing inbox and receipt rows. The storage
transaction checks active namespace/epoch and Assignment ownership; same-epoch, same-signer retries
return the original bytes. If the active Controller signer changed, an exact candidate for the same
committed digest/epoch replaces the old receipt atomically. The Controller helper signs and verifies
that candidate with its active identity before persistence, then verifies the stored bytes and
signature again before returning them. Pending, stale-epoch and digest mismatch do not produce an ACK.
The authenticated SQLite TaskAck/TaskStarted/TaskRejected, DriftEvidence, output, and supported final-result
handlers persist then queue this receipt through the session's bounded single-writer path. For
persistent TaskAck/TaskStarted/TaskRejected, Command/no-artifact Runbook output, no-artifact Command/Runbook/DriftCheck final results,
and DriftCheck evidence, the Agent verifies the receipt against current/rotation-grace
trust and removes only the matching journal row. Direct one-shot and artifact-producing Runbook
report producers and their output chunks remain outside that durable journal path; a receipt for an
ephemeral artifact report is not Agent-side replay or cleanup authority.
Controller schema v23 stores a random delivery namespace separate from signing/TLS keys and a
store epoch that is explicitly rotated during actual backup restore. The Agent journal binds to
namespace plus Agent ID and receipt verification uses the current authenticated epoch. A still-pending
exact report can be replayed after restore; if its owner-bound inbox effect is already present, the
Controller does not repeat it and issues a receipt for the current epoch. A prior-epoch receipt cannot
authorize Agent cleanup, and missing owners remain fail-closed. This only covers reports still present
in the Agent journal. A report already ACKed and deleted before restoring an older snapshot cannot be
reconstructed; external backup/reconciliation is still required for that loss window.
The Controller inbox Application admission rejects mismatched authenticated Agent ID,
local Controller namespace, empty body and oversized body before calling a repository. It returns
typed staging outcomes only; staging alone is never treated as effects-committed or a signed ACK.
The SQLite Controller inbox separately checks Assignment ownership and stores raw report bytes
under bounded per-Agent pending quotas in one transaction. Pending bytes are sensitive backup
content. Neither a staged row nor a duplicate pending row can authorize Agent journal deletion.
Its bounded final-result recovery read verifies the stored body digest and Assignment owner after
reopen. A read does not commit effects or authorize an ACK; corrupt data is rejected without raw
body in the error.
For staged command/runbook finals, the SQLite effect adapter commits prepared artifact metadata,
Assignment status, Job aggregate, redacted Job audit and inbox marker in one transaction. It
requires body-put evidence to match id/class/checksum/size when present and leaves the raw staged
report pending if a DB effect fails. A prepared remediation execution update and its Policy audit
share that transaction and are guarded by the expected prior state; successful execution persists
the existing `succeeded_pending_verify` recovery intent. A drift-check verification final can
commit its own Assignment/Job/audit/marker without fabricating evidence or resolving remediation.
The live `drift_evidence` path requires exact staged bytes, authenticated Assignment ownership, and
Controller-stored policy/version/purpose; it atomically commits the correlated drift row, redacted
audit, eligible remediation proposal and audit, and inbox marker before issuing a signed receipt.
The evidence receipt confirms stored evidence/effects only and never sets TaskResult success or
completes the Job. The live final-result handler supports Command, Runbook, and DriftCheck reports
without remediation follow-up, including artifact-bearing Runbook finals. For a Runbook artifact
body, the Controller validates size/checksum, performs an idempotent immutable file put, and then
commits metadata and final effects atomically in SQLite. A failed DB effect leaves the exact report
pending, but no worker reapplies it automatically; the Agent does not journal the artifact report/body
for replay. No-artifact Command/Runbook finals and DriftCheck terminal results are journaled/replayed
by the Agent through that path.
The local artifact store now treats an object ID/class as immutable: an identical retry succeeds,
while different or corrupted existing bytes are not overwritten. New bodies are synced in an
owner-only temporary file before no-clobber publication; this does not make the filesystem and
Controller database one atomic transaction.
The current Controller `TaskAck`/`TaskRejected`/`TaskStarted`/`TaskResult` transitions check the
authenticated Agent ID and claimed Job ID against the Assignment within the SQLite/Postgres
transaction. A mismatch leaves the Assignment unchanged and records a
`task_assignment_owner_mismatch` Security audit. Persistent TaskRejected is a strict v2 lifecycle
report: only an owned `dispatched` Assignment can become `rejected`; its reason code and redacted
reason commit with the Job aggregate, audit, and inbox marker before the signed receipt is issued.
The direct one-shot path remains on the separate ephemeral TaskResult message. Artifact-producing
persistent Runbook finals now use a strict v2 `FinalResult` message but remain ephemeral on the
Agent. Persistent DriftCheck evidence and terminal results use separate durable reports:
the evidence receipt does not change Job/Assignment status, while the final-result effect does.
No-artifact Command/Runbook final results use the same durable journal and receipt flow; a matching
no-artifact DriftCheck final arriving after G2 preserves the existing terminal state.
For a staged output chunk, SQLite commits the output effect and inbox marker together; an injected
failure rolls both back. The committed digest tombstone prevents retention from resurrecting an
already-applied output on retry. The authenticated live Controller adapter parses strict TaskAck,
TaskStarted, and TaskRejected lifecycle bodies, output, and supported final-result bodies including
artifact-bearing Runbook reports, commits effects before signing and persisting a receipt, then queues
it to the same session writer. DriftEvidence is also committed with its required evidence/proposal
effects before receipt issuance. Other lifecycle reports, remediation final-result follow-up and
Postgres remain unsupported in the live path. The Agent uses the receipt
cleanup path for persistent TaskAck/TaskStarted/TaskRejected, DriftEvidence, Command/no-artifact Runbook
stdout/stderr, no-artifact Command/Runbook final results, and DriftCheck terminal results. Direct
one-shot results and artifact-producing Runbook output/final report replay remain outside this path.

## Authentication Result

Admin authentication produces this controller-side request context:

```text
actor_id: stable admin actor id
role: owner | admin | operator | viewer
```

The request context is passed explicitly into the API route handling path. UI
state is not an authority. Request payload fields such as `created_by`,
`confirmed_by`, or approval `actor` are compatibility hints only; the controller
overrides or ignores them when an authenticated admin actor is available.

## Authenticated Agent Drift Evidence

An authenticated WebSocket session proves the reporting agent identity, but it
does not make drift-evidence provenance agent-authoritative. The v2 ReportKey
contains the correlated job/task identity; policy id, version, purpose, and
assignment ownership must match the Controller-stored signed drift assignment.
The strict `drift_evidence` body contains only status and observed expected/actual
values. The Controller, rather than the evidence body, constructs the typed
provenance written to storage.

The application proposal boundary validates the Controller-verified report,
policy id, and policy version before storage allocates the report id. The id is
then a correlation reference, never a substitute for those checks. Compliant,
unverified, missing-policy, mismatched-policy, and non-drift reports remain
observations and never create a proposal.

Creating an automated proposal is a narrow storage transaction: the verified
drift report, its typed origin id, proposed remediation metadata, and redacted
Drift/Policy audits are committed together. If any insert fails, none of those
records is emitted. A duplicate correlation returns the existing report and
request without creating a Job or another audit event.

Authenticated execution events use a separate narrow transaction. The persisted
task assignment is updated together with the matching remediation lifecycle
transition and its redacted Policy audit. Duplicate or late events cannot
overwrite a terminal assignment or create a second remediation audit; socket
delivery itself is never treated as execution authority.

A successful remediation result may create one follow-up verification drift Job
only through a separate application-owned transaction. That transaction writes
the signed single-target Job and assignment, the v19 remediation correlation,
and one redacted `remediation_verification_created` Policy audit together. A
duplicate result returns the existing correlation without a second assignment
or audit. The Controller attempts WebSocket dispatch only after commit; an
offline or disconnected agent leaves the assignment queued. Verification does
not bypass the agent's normal signature, expiry, nonce, or target checks.

Before binding its listener, the Controller performs one bounded (at most 100)
recovery scan for `succeeded_pending_verify` records that have no verification
correlation. Each candidate uses the same signed create boundary; correlated
rows are not recreated. A legacy candidate without verifiable policy, policy
version, execution Job, target, or task data is never dispatched. It receives
only a `remediation_verification_recovery_skipped` Policy audit with its
identifier and a fixed reason code—never policy source, task payload, output,
or secret material. This is not a periodic retry worker or an HA claim.

Resolution is also an application-owned transaction. The Controller joins the
persisted successful verification assignment with the persisted correlated
report, but freshness is measured against the remediation execution completion,
not the verification TaskResult completion: agents may emit a report before the
final result. The store rechecks the evidence id, agent, verification job/task,
policy/version, `remediation_verification` purpose, and compliant status while
committing the remediation status, only its origin drift resolution metadata,
and the redacted `remediation_resolved_by_verification` Policy audit. Stale,
unknown, drifted, failed, missing, or mismatched evidence is never promoted to
resolved and never updates an unrelated latest drift report. Before the
listener binds, one bounded scan also feeds already-persisted successful
final/evidence pairs through the same use case. Resolved rows are excluded on a
repeat scan, preventing a duplicate resolution audit; this is not periodic or
HA recovery.

Legacy reports with no pair, reports from raw-policy drift jobs, and reports
with missing, unknown, mismatched, or non-drift assignments remain visible as
uncorrelated observations. A supplied but invalid pair records exactly one
`websocket_drift_provenance_mismatch` Security audit. Audit values do not
include the raw policy document, task signature, report body, or secrets.

## Roles

| Role | Intent |
| --- | --- |
| `owner` | Bootstrap or organization owner. Full access. |
| `admin` | Operational admin. Full access in the current minimal model. |
| `operator` | Can operate jobs and approvals but cannot mint enrollment tokens or revoke agents. |
| `viewer` | Read-only operational visibility. |

`owner` and `admin` currently allow every defined permission. Phase 6 must split
these roles only after organization/user management, route-level authorization
tests, and audit actor attribution are implemented.

## Permissions

| Permission | Meaning |
| --- | --- |
| `agent_read` | List agents and read agent detail/snapshots. |
| `agent_write` | Change mutable agent metadata such as labels. |
| `agent_revoke` | Revoke an agent key and force re-enrollment. |
| `approval_read` | List approval requests. |
| `job_read` | List jobs and read job/output state. |
| `job_create` | Create command, runbook, and drift-check jobs. |
| `job_approve` | Approve, reject, or expire approval requests. |
| `job_cancel` | Cancel queued/running jobs. |
| `enrollment_token_read` | List enrollment token metadata. |
| `enrollment_token_create` | Create raw one-time enrollment tokens. |
| `enrollment_token_revoke` | Revoke enrollment tokens. |
| `audit_read` | Read audit events. |
| `policy_write` | Reserved for policy write APIs. |

## Permission Matrix

| Permission | owner | admin | operator | viewer |
| --- | --- | --- | --- | --- |
| `agent_read` | yes | yes | yes | yes |
| `agent_write` | yes | yes | no | no |
| `agent_revoke` | yes | yes | no | no |
| `approval_read` | yes | yes | yes | yes |
| `job_read` | yes | yes | yes | yes |
| `job_create` | yes | yes | yes | no |
| `job_approve` | yes | yes | yes | no |
| `job_cancel` | yes | yes | yes | no |
| `enrollment_token_read` | yes | yes | no | no |
| `enrollment_token_create` | yes | yes | no | no |
| `enrollment_token_revoke` | yes | yes | no | no |
| `audit_read` | yes | yes | yes | yes |
| `policy_write` | yes | yes | no | no |

## REST Error Contract

Protected API authentication and authorization errors are intentionally
separate:

```http
401 Unauthorized
{"error":"unauthorized"}
```

Use this when the admin token is missing or invalid.

```http
403 Forbidden
{"error":"forbidden","required_permission":"job_approve"}
```

Use this when the admin token is valid but the authenticated actor lacks the
permission needed by that route.

The Web Admin UI may display these errors, but it must not decide access. The
controller is the authority.

## Audit Export Boundary

The same `audit_read` permission covers recent audit list and cursor-based
audit export. Export supports category filtering and returns only redacted
values; `SecretRef` values are exposed as the marker `secret_ref`, never as raw
token or secret text.

The controller exposes no audit update or delete route. Audit events are
excluded from normal retention cleanup. The SQLite MVP store is append-only at
the application/API boundary, but it is not a tamper-proof WORM audit store.
Deployments that require long-term regulatory retention must export or back up
audit data into an external controlled store.

## Secret Provider Boundary

Secret reference handling exists as a typed contract, not as a production secret
manager integration.

- `SecretRef` accepts only validated `secret://...` references and rejects raw
  inline secret material, query strings, whitespace, unsupported schemes, and
  traversal-style paths.
- `SecretProvider` is an application-layer trait. Domain/application code must
  not depend on Vault/OpenBao/CyberArk SDKs or provider-specific clients.
- The current static provider is for tests/local contract verification. It must
  not become a runtime config editor or hidden production secret file.
- Resolved secrets use a wrapper whose `Display` and `Debug` output are
  redacted. Raw secret access is allowed only at the narrow render/runner call
  site that explicitly needs the value.
- Secret-backed template rendering requires explicit resolver/provider
  injection. Provider-free render paths continue to reject `SecretRef`
  variables.
- Secret-backed templates may write resolved content to the destination file,
  but rendered artifact body bytes are omitted by default. Controller artifact
  metadata, audit values, API responses, and Web Admin state must not carry raw
  rendered secret content.
- Secret provider bootstrap is represented by typed startup settings. The
  default provider mode is `disabled`; `static-test` accepts only a local JSON
  fixture path for contract tests and local development. Unsupported provider
  kinds and inline secret-like settings are rejected with redacted typed errors.
- Provider mode is decided at process start and then must be passed through
  explicit context/dependency injection. Request handlers, Web Admin actions,
  runbook jobs, and task execution paths must not change provider mode or read
  process environment to discover a provider.
- Controller bootstrap constructs the current provider dependency from typed
  settings. Disabled mode rejects every `SecretRef` through a typed denied
  result; `static-test` requires an explicit fixture source supplied by the
  local/test caller and is not read from environment or request state.
- Agent runbook planning adapts the selected provider into the runner's explicit
  resolver closure. The runner remains provider-agnostic and does not import
  application or infrastructure provider types.
- `fleet apply` is validation-only and does not resolve secret-backed
  templates. It must not read provider config, fixture files, or raw secret
  material.
- Product Log, Field Debug Log, audit values, API responses, Web Admin state,
  and docs examples must contain secret references or redacted markers only.
- Actual Agent Runbook entrypoints currently construct DisabledSecretProvider; helper/static tests
  do not establish production provider injection. The next confirmed scope is
  [SEC-002](../.docs/domains/security/features/SEC-002-openbao-kv-v2.md): OpenBao KV v2,
  Agent-side AppRole authentication and preparation-scoped short-lived tokens. It is planned,
  not implemented. Controller lookup/relay, dynamic secret leases and automatic file reapplication
  are excluded. KV version changes and authentication-token lifetime have separate acceptance tests.
- The confirmed review policy (D-015) keeps dryRun/checkMode/apply free of provider requests.
  Actual execution must confirm token revocation after reads and before host mutation; a failed or
  uncertain revoke ends preparation without applying files. This is planned behavior, not current support.
  Dedicated private bootstrap credentials and required OpenBao HTTPS payloads are intentional boundaries;
  they must never be copied into Fleet reports, ordinary persistence or operational diagnostics.
  The planned Controller rejects secret-bearing artifact bodies before inbox staging, and accepts
  supported body-free late metadata only as a terminal-preserving disposition with a verified receipt.

## API Boundary Rules

API handlers should stay thin:

- Parse and validate input.
- Authenticate the admin token into an admin request context.
- Check the route permission before executing the use case.
- Pass the authenticated actor into the application use case.
- Write audit with that actor.

API handlers must not:

- Trust UI-provided actor fields for authorization or audit.
- Read process environment to decide authorization.
- Bypass the permission check for dangerous actions.
- Put raw secrets, command output, or tokens into product logs.

## Artifact Storage Credential Boundary

S3-compatible artifact storage credentials are not implemented yet. The accepted
boundary for that future adapter is:

- Artifact store backend selection is represented by typed immutable
  `ArtifactStoreSettings` and is resolved during Controller bootstrap only.
- The MVP default is local filesystem storage under
  `<data-dir>/controller/artifacts`; runtime API, Web Admin, request payload,
  and process env do not change that backend or root.
- Credentials are startup secrets or secret references, not request payloads.
- Web Admin must not expose an artifact storage settings editor.
- Controller handlers and application use cases must not read process
  environment variables to discover bucket, endpoint, access key, secret key, or
  session token.
- Product Log, Field Debug Log, audit values, job output, and Web Admin state
  must not contain raw access keys, secret keys, session tokens, signed URLs,
  object bodies, local paths, or destination paths.
- Any remote adapter must live behind the `ArtifactStore` infrastructure
  boundary and must not change Domain/Application dependencies.

## CLI Profile And Login

The CLI can use the bootstrap admin token directly or store it with the
controller endpoint through `fleet login`. The default profile path is
`.fleet/cli-profile.json`. The profile is treated as a secret and protected
remote commands reject group/world-readable profile files.

The stored credential still authenticates to the controller and produces the
same `actor_id + role` request context used by Web Admin and automation clients.

CLI profiles must not edit controller runtime configuration files directly.
They should select a controller endpoint and provide credentials for protected
API calls.

## Trust And Identity Separation

The current SEC-001 trust settings boundary keeps transport identity and task
signing identity cannot be accidentally treated as the same material.

- TLS server identity is the HTTPS/WSS certificate and private key passed with
  `--tls-cert` and `--tls-key`. It proves the controller transport endpoint to
  clients and is validated at controller bootstrap.
- Controller signing identity is the Ed25519 key pair under the controller data
  directory. It signs task envelopes and is the identity pinned by agents after
  enrollment.
- Agent identity is the per-agent Ed25519 key pair generated during enrollment.
  It proves the agent session during WebSocket authentication.
- Agent client certificate trust is a future transport-auth layer. It must use a
  CA certificate path when enabled and must not replace agent key proof,
  controller-signed task envelopes, approval, expiry, nonce replay, or target
  validation.
- Until the controller listener enforces agent client certificates, explicit
  agent client CA input such as `--agent-client-ca-cert` must fail bootstrap
  with a non-leaking unsupported message rather than being silently accepted.

Required implementation rules:

- TLS server certificate/private key paths must be supplied together or not at
  all.
- TLS server private key and controller signing private key must be separate
  files.
- TLS server certificate and controller signing public key must be separate
  files.
- TLS certificate fingerprints must not be used as controller signing
  fingerprints.
- Trust settings are read only at bootstrap and passed as typed settings.
  Runtime handlers must not discover or mutate trust material through process
  environment, hidden globals, or config patch endpoints.
- Trust settings errors must not include raw key paths, secret-like filenames,
  key contents, or certificate bodies.

## Agent Client Certificate Lifecycle Policy

Agent client certificate lifecycle is a domain/application concern that must
remain separate from TLS listener enforcement. The current domain foundation
models only public certificate metadata: agent id, certificate serial,
certificate fingerprint, validity window, lifecycle state, grace window, and
revocation reason. It does not store or log private keys, PEM bodies,
certificate file paths, CA paths, process environment values, or raw request
payloads.

States:

- `not_issued`
- `issuance_requested`
- `issued`
- `renewal_requested`
- `dual_certificate_active`
- `revoked`
- `expired`
- `failed`

Rules:

- Initial issuance must be requested before a certificate can be issued.
- The current public controller surfaces are limited to admin protected
  read-only status and issuance request:
  `GET /api/agents/{agent_id}/certificate-lifecycle/status`,
  `fleet agents certificate-status <agent-id>`,
  `POST /api/agents/{agent_id}/certificate-lifecycle/request-issuance`, and
  `fleet agents request-certificate-issuance <agent-id>`.
- The lifecycle status surface requires `agent_read`, returns `not_issued` for
  a known agent without lifecycle state, and exposes only public state,
  fingerprint prefixes, timestamps, and bounded reason values.
- The issuance request surface requires `agent_write`, verifies the agent
  exists, stores lifecycle state through `RequestAgentCertificateIssuance`,
  writes Security audit, and sends only public lifecycle metadata to an
  authenticated connected session.
- Dispatch success means the controller queued an update to the session; it
  does not mean the agent accepted, installed, or began using a certificate.
- Issued certificates must be valid at the issuance operation time.
- Renewal can be requested only when the issued certificate is inside the
  configured renewal window.
- Renewal activation requires a next certificate with a distinct serial and
  fingerprint from the current certificate.
- During `dual_certificate_active`, the current certificate is trusted only
  until the explicit rotation grace deadline; the next certificate is trusted
  according to its validity window.
- Rotation completion cannot happen before the grace deadline.
- Revoked, expired, and failed lifecycle states are terminal.
- Lifecycle errors must not echo certificate bodies, private key material,
  secret-like input, or local filesystem paths.

`fleet-application` exposes the repository trait and use cases for issuance
request, issue, renewal request, renewal activation, and rotation completion.
Those use cases save lifecycle snapshots and write Security audit events with
state names only. `fleet-store` persists the snapshot in
`agent_certificate_lifecycle` using public metadata columns only.
`fleet-protocol` defines `agent_certificate_lifecycle_update` and
`agent_certificate_lifecycle_ack` as public-only lifecycle messages. The
current controller runtime records ack observations in session runtime state
and Security audit only. The current agent runtime rejects lifecycle updates
with `certificate_lifecycle_runtime_not_implemented`; it does not install,
trust, reload, or store certificate material. The controller has an internal
dispatch helper that sends public-only lifecycle updates from application
lifecycle records to authenticated connected sessions. Future runtime handlers
or public surfaces that change lifecycle state must call the application use
cases. WebSocket handlers, REST handlers, and UI code must not duplicate
transition rules or write lifecycle state directly.

## Controller Signing Key Rotation Policy

Controller signing key rotation is modeled separately from TLS certificate
rotation. The domain state machine uses public fingerprints and time windows
only; private key material, PEM bodies, key file paths, and process environment
values do not enter domain state.

States:

- `steady`
- `rotation_requested`
- `new_material_validated`
- `dual_trust_active`
- `old_key_retired`
- `rotation_failed`
- `canceled_before_activation`

Rules:

- Old and new signing fingerprints must be distinct.
- New material validation must happen after the rotation request.
- Dual trust cannot activate before new material validation.
- After dual trust activation, the new key signs new tasks.
- The old key verifies only tasks signed before activation and only until
  `old_key_verifies_until`.
- The old key cannot retire before the dual-trust verification window expires.
- Terminal failure/cancel/retired states cannot activate a rotation later.
- Rotation state persistence stores only controller id, state, public
  fingerprints, validity timestamps, and update time. It must not store private
  key material, private key paths, PEM bodies, or TLS certificate material.
- Application rotation operations own request, validation, activation,
  retirement, and failure orchestration. Interface handlers must call these use
  cases instead of mutating persisted rotation state directly.
- New controller signing material must pass keypair validation before
  `new_material_validated`: the candidate private key signs an explicit
  challenge, the candidate public key verifies it, and the derived public
  fingerprint must match the pending rotation fingerprint.
- Candidate controller signing key files are validated through the controller
  filesystem boundary before replacement. Candidate files must be separate from
  active signing files and transport/TLS key files; candidate private key
  permissions must reject group/other access.
- Active controller signing key file replacement uses explicit paths, backup
  files, temporary replacement files, post-swap verification, and rollback on
  partial failure. Swap completion does not activate dual trust by itself; the
  application rotation operation still owns state transition.
- Controller bootstrap validates the active signing public/private material by
  challenge, loads persisted rotation state, and fail-closes if the active
  public fingerprint does not match the domain-selected current signing
  fingerprint. Missing persisted rotation state is treated as active steady
  state until an explicit rotation operation creates a record.
- Rotation operation audit events record transition action, controller id,
  public fingerprint prefixes, and timestamps only. Failure summaries are
  redacted before audit/log emission and must not include private key paths,
  PEM bodies, or task payloads.
- Controller signer selection must receive the selected signing fingerprint as
  explicit context. It must not infer the signing key from process environment,
  mutable global state, or the TLS certificate fingerprint.
- Agent-side controller signing trust is represented as an explicit trust
  bundle containing public fingerprints, public keys, roles, and verification
  windows only. Legacy enrolled agents are adapted to a one-entry `current`
  bundle from their pinned signing fingerprint and current controller signing
  public key.
- Controller-to-agent trust bundle update protocol messages carry only public
  fingerprints, public keys, `current`/`previous` roles, and validity
  timestamps. Agent sessions validate the payload into the domain trust bundle
  model and store the accepted bundle in explicit in-memory session state for
  subsequent task verification. Accepted updates are also persisted to an agent
  config sidecar containing only the same public trust metadata so agent
  restart does not fall back to an obsolete pinned key during rotation. The
  message and sidecar must not carry private key material, key paths, TLS
  certificate material, or task payload bodies.
- Trust bundle verification must run after target/expiry validation and before
  nonce acceptance leads to execution. The verifier must accept the `current`
  entry for signatures issued inside its validity window, accept a `previous`
  entry only for envelopes issued before rotation and verified before its
  expiry, reject unknown fingerprints, and reject expired trust entries.
- Agent trust bundles must be passed as explicit objects into the task verifier.
  They must not be discovered through runtime environment reads, hidden globals,
  TLS certificate fingerprints, or runtime config patch endpoints.
- Agent trust bundle sidecar load happens once during bootstrap from the
  explicit agent config directory. Corrupt or invalid sidecar content is a
  startup/config error and must not leak raw public key bodies or
  private-material-like values.
- Controller signing rotation status is exposed through a read-only
  admin-authenticated API and CLI command.
  The status query may return controller id, persisted state name, readiness
  name, fingerprint prefixes, dual-trust timestamps, bootstrap guard summary,
  and agent trust rollout summary.
- Rotation status queries must not transition rotation state, read private key
  files, read TLS certificate files, inspect task payload bodies, or discover
  configuration through process environment at handler time.
- Rotation status responses and CLI output must not include private key
  material, private key paths, raw public key bodies, TLS certificate material,
  TLS key paths, task payload bodies, or secret-like diagnostic dumps.
- Controller signing rotation mutation API and CLI commands call the existing
  application request/validate/activate/retire/fail use cases. HTTP handlers
  must not duplicate transition logic or write persisted state directly.
- Mutation routes require `signing_rotation_write` permission. Request body
  actor fields are ignored; authenticated admin context supplies the audit
  actor.
- Mutation DTOs accept public fingerprints, old-key verification window values,
  redacted reason text, and controller-local candidate file paths only. They
  must reject private key bodies, raw public key bodies, PEM bodies, TLS
  certificate material, task payload bodies, and unknown secret-like fields.
- Candidate material validation reads explicit candidate file paths through the
  controller filesystem boundary. It must not read process environment,
  hidden global config, or UI-provided runtime config patches.
- Activation changes rotation state only. It must not implicitly swap key
  files, reload process state, or mutate process environment. Operators must
  use status `bootstrap_guard` and the restart-plan API/CLI to confirm the
  active runtime key matches persisted selected state.
- Controller signing rotation restart-plan API and CLI are read-only operator
  guidance surfaces. They may report `restart_required`, `reload_supported`,
  recommended action, verification commands, and safety notes, but must not
  restart the controller, reload key files, swap material, patch runtime
  config, or expose key paths/material.
- Controller signing rotation restart-action API and CLI record an audited
  external service-manager restart intent. The API returns explicit local
  service commands and verification commands but must not self-restart the HTTP
  handler, invoke systemd, reload key files, or mutate runtime config.
- Controller signing trust bundle rollout API and CLI dispatch public-only
  `controller_signing_trust_bundle_update` messages to authenticated connected
  agent sessions. Rollout requires active runtime signer to match persisted
  selected signer and must not create or modify Job/Assignment state.
- Agent trust bundle acknowledgement uses public-only
  `controller_signing_trust_bundle_ack` messages. The controller records the
  ack only in connection-scoped session registry runtime state and may skip a
  later rollout as `skipped_already_current` when the accepted current
  fingerprint matches. Ack audit values contain only accepted status, entries
  count, current fingerprint prefix, and a bounded reason code.
- Controller signing trust bundle retry API and CLI reuse the same public-only
  construction boundary with an explicit `max_agent_count` batch limit. Retry
  uses only observable session registry state and explicit operator input; it
  must not infer hidden key paths or store WebSocket handles in persisted state.
- Trust bundle rollout may read an explicit controller-local previous public
  key path for dual-trust payload construction. The path and public key bodies
  must not be returned, logged, audited, stored as domain state, or confused
  with private key material.

Audit/log policy:

- Product Log may record rotation requested, activated, retired, and failed
  summaries.
- Field Debug Log may record transition names, guard failure reasons, and
  validity window timestamps.
- No log level may record private key material, key file content, task payload
  body, or secret-like key paths.

## Current Limits

- There is no OIDC/SAML/SSO integration. IAM-001 owns the first confirmed identity/session
  lifecycle, credential revocation, and route permission tests; IAM-002 owns separate project isolation.
- The personal-account Domain/Application lifecycle, identity store, bounded password worker,
  local cutover/recovery and human restore-epoch foundations exist. HTTP login/session/logout,
  single-use setup, cookie/PAT authentication and origin/CSRF adapters are connected.
  Account-management APIs, business-effect authorization guards and Admin/CLI integration
  are connected and pass scoped two-person HTTPS/API/CLI/Linux-Agent acceptance.
  Project membership is not included.
- The legacy SQLite admin token table remains the bootstrap HTTP path; personal-mode
  storage rejects its use. It is separate from the new account and credential tables.
- `owner` and `admin` remain equivalent for existing business operations. The personal-account
  policy grants management of other users to `owner` only; all active roles manage their own
  password/PAT. Account-management HTTP enforcement and the scoped direct API matrix are tested.
- Permission checks cover the current REST route boundary. Every new public
  API must add an explicit permission and table-driven authorization test before
  becoming public.
- Public Git catalog infrastructure uses a fixed `git2` HTTPS-only dependency with an ephemeral
  bare staging directory, shallow depth, no tag download, no redirect following, a transfer-size
  ceiling, a credential callback that always fails, and a fail-closed DNS preflight that rejects
  empty, private, reserved, link-local, loopback, multicast, or mixed address answers. Each fetch
  then starts a controller-local loopback CONNECT proxy that accepts only the source's exact
  authority and opens every upstream socket directly to one of those checked addresses. Libgit2
  keeps the original hostname for HTTPS SNI and certificate validation; it cannot redirect the
  proxy to another authority. The proxy polls both its 30-second hard deadline and the
  controller-owned cancellation signal, closing both tunnel ends so stalled native I/O returns to
  the joined worker. The controller performs queued sync in the blocking pool only after releasing
  the durable-store lock, then records a source/operation-only audit event. Timeout is persisted
  as a fetch failure and shutdown as cancellation.
  A YAML blob is treated as catalog input only when its `kind` declares `Runbook` or `Policy`;
  unrelated YAML such as CI workflows is ignored. A declared catalog document still has to pass
  its strict parser and size limits, or the sync fails without changing the active revision.
  Private Git authentication remains unsupported; no URL, request, or runtime model accepts a Git
  token.
  A nondefault fetched branch is resolved from its exact origin reference when it has no local
  branch name in the bare staging repository. An absent requested branch never falls back to HEAD.
  The sync-operation status GET requires `policy_read`, checks source and operation identity, and
  returns only classified state, optional commit and a failure code. All responses are no-store;
  missing and cross-source operations share 404, and repository failures reveal no raw details.
  Reading status never fetches Git or activates a revision. HTTP 202 accepts an operation and does
  not establish completion; callers follow the canonical ID returned by the start response.
  Catalog Runbook creation prepares pending approval and body-free provenance audits before one
  required composite persistence call. SQLite and feature-gated Postgres recheck the exact active,
  ready Runbook document and body inside the transaction, then commit Job, signed assignments,
  target snapshots, approval, audits and dispatch settings together. Store failure or a changed
  selection does not authorize dispatch; duplicate Job IDs do not overwrite the original.
  The internal port itself does not authenticate callers or execute a task. The additive
  `POST /api/jobs/catalog-runbook` requires JobCreate and PolicyRead, derives the actor from the
  authenticated token and rejects raw body/actor/approval/nonce overrides and unknown fields.
  Application preflight rejects explicit unknown/disabled/duplicate targets and known incompatible
  or stale Runbook/step capabilities before persistence. Selectors preserve existing disabled/offline
  semantics; absent/unknown capability reports do not establish support and retain Agent validation.
  The handler uses the composite port and committed approval/dispatch gate. Errors are classified
  and no-store; an uncertain POST is reconciled by its stable Job ID, never automatically retried.
  Protected Job detail reads the Job-owned provenance snapshot, not a later active revision.
  Selector preview may use the Controller-owned active-session snapshot to display liveness.
  This does not update persisted Agent state or authorize a disabled target.
  Web Admin reviews the stored active Runbook and selector preview before submitting only the
  immutable reference and exact selected Agent IDs. A review checkbox does not approve execution.
  Route, token, selector and document changes retire review requests. An uncertain submission
  retains one stable Job ID; reconciliation verifies its provenance and targets before the view
  accepts it, and a confirmed missing Job permits only an explicit retry of the same request.
  No automatic POST retry, newly generated recovery ID or browser-persisted intent/token is used.
  For this POST only, a known `Fleet-Catalog-Rejection` response header classifies a definitive
  selection/target rejection before creation. The client may retire that rejected intent and let
  the operator review again. A duplicate ID or absent/unknown header keeps the original unresolved
  ID. No error body or arbitrary header value is retained or logged.

## Post-MVP Security Phase Map

| Area | Phase | Required boundary |
| --- | --- | --- |
| mTLS and agent certificate rotation | Phase 5 | Typed trust settings separate TLS server identity, agent identity, controller signing identity, and future agent client certificate trust. Explicit agent client CA bootstrap input is rejected until listener enforcement exists. Agent certificate lifecycle domain state machine, snapshot/restore boundary, application repository/use-case contract, SQLite/Postgres-shaped public metadata persistence foundation, public-only lifecycle update/ack protocol schema, controller ack observation/audit, internal controller update dispatch helper, admin protected status and issuance request API/CLI surfaces, and agent explicit rejection ack exist. Full mTLS listener enforcement, issue/renew/activate/revoke public controller surfaces, agent-side certificate application, revocation propagation, and runtime trust enforcement remain. |
| Controller signing key rotation | Phase 5 | Domain state machine, dual-trust decision policy, SQLite/Postgres-shaped persistence contract, application operation/audit boundary, signing material validation boundary, filesystem staging/swap boundary, bootstrap runtime guard, explicit signer selection context, agent-side trust bundle verification, trust-bundle update/ack protocol and session foundation, agent trust sidecar restart survival, read-only status API/CLI, mutation API/CLI, restart-plan API/CLI, audited external restart-action API/CLI, admin-triggered trust-bundle rollout API/CLI, bounded retry coordinator API/CLI, already-current ack skip, staged rollout domain state machine/persistence/worker, and Web Admin staged rollout surface exist. In-process hot reload/self-restart is not a current product path; audited external restart-action is the supported path. |
| Secret provider boundary | Phase 5 | Typed `SecretRef`, application `SecretProvider` trait, static fake provider, disabled provider, explicit runner resolver injection, typed startup `SecretProviderSettings`, controller bootstrap provider factory, agent runbook resolver handoff, and redaction tests exist; Vault/OpenBao adapter only after provider integration tests. |
| OIDC/admin identity/project RBAC | Phase 6 | Authenticated context, project scope, permission matrix, audit actor contract. |
| Public Git catalog / private credentials | Current plan / follow-up | Public HTTPS catalog transport is credential-free and bounded; private Git requires a separately approved SecretRef adapter, validation/activation audit, and no raw token in logs. |
| Notification webhooks | Phase 8 | SecretRef webhook credentials and redacted summary payloads. |
| Agent update policy | Phase 9 | Signed artifact verification before install, rollback state machine. |
| HA coordination | Phase 10 | Lease/claim tests; no WebSocket handle persisted. |
| Compliance audit hardening | Phase 11 | Tamper-evident chain and signed export manifest without claiming WORM storage. |
| Plugin/external adapter | Phase 14 | Disabled by default, signed manifest, approval/capability/audit required. |

The scoped IAM acceptance uses a private, short-lived test CA. API/CLI/Agent validate it and the hostname explicitly; a human passed the browser warning for that local site only. No OS/browser trust store was changed. Actual login bursts return typed401/429 while a connected Linux Agent continues heartbeat and a harmless approved Job. Debug/shared-host observations are cost reports, not production capacity or a whole-Fleet SLA. Follow-up heartbeat handling uses Controller receipt time, rejects a different Agent ID and preserves degraded health; ordinary valid ticks do not create Security-audit noise.
