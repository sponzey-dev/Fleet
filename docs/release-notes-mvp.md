# Sponzey Fleet Current Release Notes

This document captures the current post-MVP state and known limits.

## Unreleased personal administrator accounts

- SQLite schema 28 and the feature-gated Postgres adapter add human accounts, credential records,
  a separate human epoch and atomic account/mode/audit transactions. Previous-schema history is
  preserved; Controller Postgres readiness remains unsupported.
- `fleet controller admin init-owner` now composes local OS authority, hidden bounded TTY input
  or explicit `--password-stdin`, the fixed-profile bounded password worker, and atomic first-owner
  activation/shared-token cutover. Init/owner/start accept the same custom SQLite `--db` selection.
- Local `controller admin recover-owner --username <login-name>` uses the same authority/input
  boundary to replace an existing person's password, restore owner access and revoke only their
  credentials. Original signing-pair validation and missing-key preservation precede password input.
- Controller data directories now require the running OS user and mode `0700`; runtime and local
  setup share an exclusive lease. Stop older binaries explicitly before upgrade. Personal/restored
  initialization retains the original signing identity; missing keys require backup recovery.
- Backup/dry-run inspect SQLite without source migration and validate the retained signing pair. New archives use 0600 files and never overwrite an existing output. Actual restore holds the local lease, invalidates all human credentials and rotates the independent Agent delivery epoch in private staging before atomic directory exchange. Installation and later durability/cleanup warnings are distinct. Fresh official-binary recovery/restore and safety-backup rollback rehearsal pass on the owned marked fixture; scoped two-user HTTPS/API/CLI/Linux-Agent acceptance has passed.
- Application login now issues fixed eight-hour sessions; PAT minting requires current password proof and a current actor at commit. PATs expire after 30 days, metadata is bounded/self-scoped and excludes proof material, logout/revoke affect only the selected own credential, and retired lookup cleanup is bounded at128/purpose. Per-user/global physical-row quotas and SQLite/Postgres concurrency/audit rollback contracts pass. HTTP login/session/logout, setup and purpose-specific cookie/PAT authentication are now connected through a bounded Controller adapter; business commit guards and the personal Admin/CLI flows are connected.
- Owner-only account collection/detail metadata reads now use bounded keyset pages and scoped opaque cursors; pending/disabled accounts remain visible to owner. Valid admin/operator/viewer callers are forbidden, and malformed rows fail without partial metadata. These reads do not clean or renew credentials. Owner create/change/reset now require same-request password proof and atomic current-owner/last-owner/audit checks; target credentials are revoked and one-time grants returned only once. Audit rollback, cancelled/revoked late proofs and scoped HTTPS self-reset are tested. Own password replacement/PAT issuance now pass actual HTTP for all four roles, per-user token quota/expired lookup reclamation and private audit rollback; the authenticated credential alone determines the subject. Own PAT metadata/selected revocation are also connected: strict scoped paging, proof-free projection, foreign-row isolation, no GET cleanup/renewal, uniform404 including retained revoked rows, self-caller revocation and audit rollback pass actual HTTP. Name/role changes preserve immutable audit actors.
- Scoped two-user HTTPS browser/API/CLI acceptance, Linux execution during credential revocation,
  local recovery/restore and bounded login-load safety pass. OIDC, project isolation, a real
  SecretProvider, full capacity/SLA and release publication remain separate.
- Recurring heartbeats now update stored receipt time without clearing degraded health or producing
  unexpected-message audit noise. Idle dispatch checks use FieldDebug; Product logs retain actual
  dispatch/failure effects. CLI demo reads wait for committed output with a bounded deadline and never
  resubmit the Job.

## Unreleased execution-reliability work

- Darwin/Linux command runners now drain bounded output while checking cancel/timeout. Output callback
  failure cleans up the newly owned process group; inherited pipes cannot force an unbounded reader join.
  The leader stays unreaped until group cleanup to avoid recycled-PID signalling. Already-completed
  host effects and daemons that escape the group are not rolled back.
- Agent-local journal schema v4 persists exact reports, including DriftEvidence, and single-active
  execution admission/start intent, reserves final-result capacity, and atomically commits final
  reports with execution completion. Schema v4 migrates v3 while preserving report bytes; earlier
  additive migrations preserve pending rows, with unsafe active v2 StartIntent upgrades rejected.
  A bounded single-owner worker keeps blocking journal I/O off the session path. Persistent Command
  and no-artifact Runbook execution admission/restart recovery, TaskAck/TaskStarted/TaskRejected,
  output/final replay, and signed-receipt cleanup are connected. Persistent DriftCheck evidence and
  its terminal TaskResult are separate journaled/replayed reports with separate receipts; an evidence
  receipt confirms evidence storage, not task completion.
- The v2 receipt shape/canonical signing preimage and Agent-side Ed25519/trust/ownership verifier
  are used by persistent lifecycle, output, final-result, and DriftEvidence reports. The active v2 handshake transfers
  Controller namespace/epoch; the journal binds namespace plus Agent ID and checks receipts against
  the current session epoch.
- Active v2 `WireMessage` now carries bounded `task_report`/`report_receipt` payloads and validates
  version, body digest/size, receipt shape and outer Agent ownership before dispatch.
- The authenticated Controller WebSocket handles SQLite lifecycle, `drift_evidence`, `output`, and
  supported `final_result` reports for Command, Runbook, and persistent DriftCheck, including
  artifact-bearing persistent Runbook finals: it validates authenticated ownership, commits each
  effect and inbox marker atomically, persists a signed
  `stored` receipt, then queues it through the session's single writer. Same-key/same-body retry
  replays the exact receipt without duplicating output; changed body or owner mismatch is rejected
  and Security-audited. Postgres report handling fails closed.
- Controller schema v25 persists and replays signed receipt bytes for an exact committed inbox
  key/digest across reopen; schema v26 adds the `drift_evidence` class while preserving inbox rows
  and receipt references. Stale epoch, signer change and pending/conflicting rows fail closed.
  Persistent Command and no-artifact Runbook stdout/stderr now use the journal and receipt path. The strict final report
  includes counts of locally committed stdout/stderr chunks and a truncation flag; SQLite verifies
  exact `[0, count)` storage before final effects or receipt, and a truncated result cannot succeed.
  The Job audit keeps only counts and truncation, never output bytes. This proves delivery of the
  Agent-journaled prefix, not capture of every byte emitted by task execution. Artifact-bearing
  Runbook finals now use a strict v2 Controller effect/receipt transaction. SQLite also retries
  already-staged pending final reports before listener bind and every 30 seconds in batches bounded
  to 100 rows/8 MiB. It revalidates exact body and owner, commits effects before receipt persistence,
  and queues receipts through the active session's single writer. Output gaps, corrupt/unsupported
  reports, and terminal assignments remain pending and fail closed. Artifact final reports and
  output are not Agent-journaled, so a pre-inbox disconnect remains unrecoverable. A separate
  bounded scan retries receipt persistence for already-committed finals using only key/digest and
  never repeats effects. The Controller performs bounded
  SQLite G2 recovery before listener bind and every 30 seconds, atomically marking overdue active
  assignments failed with `execution_outcome_unknown`; it never retries them. Postgres startup is
  rejected until that backend implements the recovery contract.
- Staged drift-check verification final results can atomically commit Assignment, Job, audit and
  inbox marker without claiming that a separate evidence report arrived. Persistent DriftEvidence
  is now journaled by the Agent and live on the authenticated v2 path. The Controller validates
  Controller-stored policy provenance and atomically commits the correlated drift row, required
  redacted audit, eligible remediation proposal/audit, and inbox marker before issuing its signed
  receipt. Exact retries replay the receipt without repeating effects. Either verification final or
  evidence can arrive first; a bounded pre-listener scan resolves only matching successful-final/fresh-
  compliant evidence pairs and the matching remediation origin. DriftCheck terminal `TaskResult` is a
  separate durable final-result report; its receipt commits the terminal effect, while the evidence
  receipt alone is never completion proof.
- Controller schema v23 persists a delivery namespace independent of signing keys and rotates its
  store epoch during actual backup restore. The Agent binds the local journal to the namespace and
  Agent ID and validates receipts against the current session epoch. It does not recover post-backup
  results already ACKed and removed from an Agent; cross-epoch reconciliation remains unimplemented.
- Controller incoming-report Application admission validates authenticated owner/namespace and
  encoded-body limit before repository staging. SQLite durably stages pending-effects task reports
  with duplicate/conflict/assignment-owner/capacity checks. Staging by itself never issues a receipt.
- SQLite atomically applies supported staged report effects and their inbox committed markers,
  preserving digest tombstones after output retention. Lifecycle, DriftEvidence, output, and
  supported Command/Runbook/DriftCheck final-result reports (including artifact-bearing Runbook
  finals) are live on the authenticated v2 session and emit persisted signed receipts after commit.
  Artifact bodies are size/checksum validated and put immutably before the SQLite transaction;
  exact retry is safe, but a crash can leave a file orphan. Postgres report runtime remains
  unsupported and fails closed.
- SQLite can now read bounded pending final-result reports after reopen and reject a changed
  body/digest without exposing the body. A bounded startup pass and periodic Controller worker
  reapply supported pending final effects, persist receipts only after commit, and queue receipts
  through an active session's single writer. A second bounded scan recovers receipt persistence for
  already-committed finals from key/digest without repeating their effects. Corrupt rows, owner
  mismatch, output gaps, unsupported effects, and terminal Assignments remain pending and fail closed.
- SQLite can atomically commit a staged command/runbook final's prepared artifact metadata,
  Assignment, Job aggregate, Job audit, and inbox marker. Failed metadata/marker/audit writes roll
  back DB effects; a pending inbox report survives reopen for idempotent file-put and DB retry.
  Prepared remediation execution status/Policy audit can join the same transaction; its persisted
  `succeeded_pending_verify` state is recovered into one verification Job after reopen.
  DriftEvidence effects and eligible proposal/audits also commit with the inbox marker atomically.
  Artifact-bearing Runbook final effects are now connected to the live v2 handler and bounded
  SQLite pending-inbox recovery. Agent-side artifact report replay, Postgres report recovery,
  remediation final-result follow-up, and file/DB orphan cleanup remain pending.
- Local artifact body `put` now preserves the first object for an ID/class across retries, rejects
  changed/corrupt prior bodies, and publishes a synced owner-only temporary file without clobbering
  an existing object. DB/file recovery and leftover temporary cleanup remain pending.
- Direct one-shot TaskAck/TaskRejected/TaskStarted/TaskResult transitions reject an authenticated
  Agent or Job that does not own the Assignment and record a Security audit. Persistent TaskAck,
  TaskStarted, and pre-execution TaskRejected use the v2 owner-bound journal/report-receipt path;
  artifact-bearing Runbook finals use a strict v2 Controller effect/receipt but are not durable in
  the Agent journal; direct one-shot delivery is still separate.
- A matching persistent TaskAck/TaskStarted/TaskRejected received after SQLite G2 marks its owner
  `failed/execution_outcome_unknown` now gets one terminal-preserving audit/inbox disposition and
  an exact signed `stored` receipt, allowing ordered Agent replay to continue without implying success.
- A matching no-artifact persistent DriftCheck final received after SQLite G2 marks its Assignment
  `failed/execution_outcome_unknown` gets the same terminal-preserving durable disposition; exact retry
  replays its signed receipt without repeating the effect or audit.
- Workspace tests pass locally; these changes are not a published release or a real Linux reboot gate.

## Included

- Rust workspace with layered crate boundaries.
- Single Rust `fleet` CLI binary.
- Controller initialization with Ed25519 identity and one-time admin token output.
- Enrollment token create/list/revoke API.
- Agent enrollment with controller fingerprint pinning.
- Authenticated outbound persistent WebSocket session.
- Heartbeat, facts, metrics, operational log upload, and task dispatch are separate intervals/flows.
- Controller-signed command task envelope.
- Agent-side signature, expiry, replay nonce, and target validation.
- Agent local file-backed replay nonce store rejects consumed task nonce after restart and fails closed if the store is unreadable or corrupt.
- High-risk command confirmation boundary.
- Approval request lifecycle with approve/reject/expire APIs and Web Admin queue.
- Selector preview, target snapshot storage, assignment state tracking, fanout concurrency, maxFailures, and partial-success aggregation.
- Command output storage separated from application logs.
- Facts, metrics, and drift snapshot storage with cursor paging API and agent/controller time fields.
- Agent inventory and label update API.
- Controller-served static `/admin` Web Admin UI.
- MVP runbook parser, `fleet apply` validation-only command, and signed controller-to-agent runbook dispatch API.
- Explicit retention cleanup command and controller-managed retention worker for bounded job output, facts, metrics, and agent log storage.
- Local file log tail with redaction, follow mode, max-duration guard, and journald shortcut skeleton.
- Local policy drift check engine for service running, package present, and strict 64-character lowercase file SHA-256 checks with signed drift job dispatch.
- Agent capability snapshot reporting, SQLite persistence, Agent API/Web Admin summary, and dispatch-time unsupported capability rejection.
- Web Admin UI can inspect agents, reported capabilities, facts, metrics, logs, drift latest/history, jobs, target assignments, audit events, enrollment tokens, approvals, runbook jobs, direct policy assignment, and selector target previews for command/runbook job creation.
- Audit export API and `fleet audit export` CLI with category filtering, cursor paging, JSONL output, and SecretRef marker redaction.
- npm package wrapper for Rust binary distribution.
- Standalone release tarball packaging with `SHA256SUMS`, checksum verification, and release checksum signature sign/verify scripts.
- Linux systemd install/start/status/log/uninstall commands with dry-run rendering.
- `fleet upgrade --dry-run` policy inspection for external package/artifact upgrades.
- `fleet demo` local loopback demo through the npm wrapper.
- Local MVP smoke script.
- Immediate dispatch and remote TLS loopback smoke scripts.
- Hardening audit script.

## Known Limits And Post-MVP Phase Mapping

Numbered Phase labels in this section belong to the historical roadmap, not the
active execution plan. Use the [capability map](../.docs/product/capabilities.md)
and [overall plan](../.docs/plans/plan.md) for current priorities and support boundaries.
This release note is not evidence that uncommitted checkout changes were published.

- Controller HTTP/WebSocket serving uses Axum.
- HTTPS is supported through built-in TLS or reverse proxy deployment. HTTP remains allowed for tests only and emits warnings.
- CLI login/profile storage exists at `.fleet/cli-profile.json` with owner-only permission checks. OIDC/SSO, API token lifecycle, project/team RBAC, and full multi-admin sessions are Phase 6 work.
- Agent command execution streams output chunks before process completion; Web Admin UI uses polling/storage.
- Web Admin UI covers agent inventory, command job creation, output, facts, metrics, drift, jobs, and audit.
- No Ansible compatibility layer exists. The documented subset import/report path is Phase 13 work and must not execute during import.
- `fleet apply` validates only and does not resolve `secretRefs`. Package/service/file primitive execution requires controller-signed runbook dispatch, high-risk confirmation, and an enrolled agent. Plain-variable `file.template` parser/render/runner mapping, explicit SecretProvider-compatible resolver injection, TaskResult artifact metadata reporting with optional non-secret body persistence, SQLite rendered artifact metadata storage, a local `ArtifactStore` body contract, Controller artifact retrieval API, Web Admin artifact metadata/retrieval surface, typed `SecretRef`, application `SecretProvider` contract, typed startup `SecretProviderSettings`, controller bootstrap provider factory, and agent runbook resolver handoff exist. Product provider source configuration, external provider adapters, and S3-compatible storage remain Post-MVP work.
- S3-compatible adapter decision is recorded: implementation is deferred until typed bootstrap artifact store settings, external secret reference credentials, feature-gated contract tests, and redaction tests exist.
- Systemd install/start commands are implemented for Linux root environments; reboot verification remains manual.
- Automatic self-upgrade, one-line installer, `.deb`, `.rpm`, Homebrew, Docker, and Windows service packaging are Phase 9 and Phase 12 work.
- Release checksum signatures use a committed public key and a fail-closed GitHub signing secret; tagged releases upload `SHA256SUMS.sig`, while manual dry-runs retain short-lived signed verification evidence. Key rotation policy remains Phase 9 work.
- Retention worker uses code-default MVP durations and has no runtime configuration endpoint or HA lease/leader election. Cleanup keeps audit events out of normal deletion and separates job output, facts, metrics, and agent log cutoffs. HA-safe lease coordination is Phase 10 work; runtime config patching remains prohibited.
- Controller signing key rotation/trust rollout and audited external restart boundaries exist (SEC-001).
  Agent certificate lifecycle foundations do not establish full mTLS client-certificate enforcement (EXT-001).
  In-process signer hot reload/self-restart is not the current path.
- Capability reporting, persistence, and basic dispatch rejection gate exist with a 24-hour stale snapshot guard. Platform-specific privilege/package/service probing and manual platform smoke are Phase 12 and Phase 15 work.
- Replay nonce protection is local and file-backed on each agent. Cross-controller/global replay correlation is not implemented; HA-safe coordination belongs to Phase 10.
- Approval request lifecycle and Web Admin approval queue exist. Product-grade multi-admin identity, sessions, and external auth are Phase 6 work.
- Assignment ack/start/reject protocol states are implemented; job cancel and command timeout now produce separate `canceled` and `expired` terminal states. Multi-agent fanout aggregation, capability-aware dispatch, queued-only dispatch claim, and send-failure release exist. Release does not requeue terminal assignments. Phase 15 must add long-running recovery smoke for reconnect, retry, timeout, and output replay cases before scale readiness is accepted.
- Scheduled drift entries are stored, queried, and consumed by a controller worker that creates signed due drift-check jobs. The worker is single-controller safe only; multi-controller lease/leader election is Phase 10 work.
- Policy-based remediation request domain/application proposal state machine, SQLite metadata persistence, persisted approval request creation, approved signed runbook job creation, task-event lifecycle reconciliation, Controller API surface, and thin CLI/Web Admin surface exist. A Controller-verified, signed, drifted policy check creates one idempotent `Proposed` request with its origin report and redacted audits in the same persistence transaction; compliant and unverified reports remain observations. A successful remediation result creates one correlated signed verification drift Job, assignment, and audit atomically, then attempts dispatch after commit; a disconnected agent remains queued. Before listener readiness, a single bounded startup scan reconciles correlation-free pending verification rows through the same create boundary; unverifiable legacy rows are audit-skipped without dispatch. A successful verification result and fresh compliant persisted evidence after remediation execution atomically resolve the remediation and only its origin drift, regardless of report/result delivery order; stale, drifted, unknown, failed, or mismatched evidence remains pending. The legacy manual running/result/verify API and CLI commands remain only as deprecated `409` compatibility endpoints; Web Admin displays persisted lifecycle state and provides no manual transition control. Execution is still approval-gated: there is no approval-bypassing auto-remediation worker. Phase 3 now has typed database backend settings, startup-only Postgres URL/SSL mode/connect timeout/pool parsing, a blocking Postgres client pool boundary, a minimum native TLS adapter for `sslmode=prefer/require`, a shared SQLite repository contract harness, a feature-gated Postgres migration skeleton with ignored integration gate, repository slices through RemediationRequest, `ControllerStore`/`ControllerStoreRef` boundaries, feature-gated Controller Postgres open/migration wiring, direct server runtime adapter dispatch, typed job+assignment transaction boundary, and queued-only dispatch claim/release contract. Custom CA/client certificate rotation, scheduled drift/retention lease, and HA claim semantics remain.
- Audit events are append-only at the controller API/application boundary and are excluded from normal retention cleanup. The SQLite MVP store is not a tamper-proof WORM audit store; tamper-evident hash chain, signed export manifest, and compliance report are Phase 11 work.
- Slack/Teams notification and Prometheus/OpenTelemetry export are Phase 8 work. Public HTTPS Git runbook/policy catalog sync, validation, explicit activation, protected API/CLI, and Admin metadata exploration are available. The current checkout also adds strict catalog-reference Job creation and immutable provenance in protected Job detail; Admin review and reference-only submission now connect to the shared approval/result view with immutable provenance. Scoped Node and synthetic native-browser checks cover this UI; the public Git-to-result journey now has scoped two-Agent Linux/native-browser acceptance, including fixed targets, approval gates and revision-invariant Job provenance. Private Git credentials and project scope remain separate work.
- Plugin/external adapter execution is not available. Signed manifest, disabled-by-default policy, and approval/capability/audit boundaries are Phase 14 work.
- 100-agent heartbeat and 1,000-output load gates are Phase 15 work.

## Demo Safety

HTTP controller URLs are allowed for setup checks, local development, lab tests, and short-lived validation only. Product, customer, production, shared, or long-running environments must use HTTPS.

Every HTTP path prints an insecure transport warning because traffic is not encrypted. A controller configured with an HTTP external URL also writes a Security audit event. HTTP transport provides no confidentiality or integrity guarantee and can expose tokens, commands, operational data, and traffic to man-in-the-middle attacks.

## Verification

Current readiness is checked with:

```bash
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
npm test --prefix npm/fleet
npm test --workspace @sponzey/fleet
npm run build --workspace web-admin
npm test --workspace web-admin
npm run typecheck --workspace web-admin
./scripts/npm_local_pack_smoke.sh
./scripts/npm_platform_local_install_smoke.sh
./scripts/npm_demo_smoke.sh
./scripts/smoke_mvp.sh
./scripts/smoke_immediate_dispatch.sh
./scripts/smoke_remote_tls_loopback.sh
./scripts/signature_verification_smoke.sh
./scripts/hardening_audit.sh
```

For a full local release gate:

```bash
./scripts/release_readiness_gate.sh
```

For destructive Linux checks, run on a Linux host with root privileges:

```bash
sudo ./scripts/release_readiness_gate.sh --include-manual
sudo reboot
sudo ./scripts/release_readiness_gate.sh --verify-manual-reboot
```

After npm registry publish, verify the installed wrapper with:

```bash
./scripts/release_readiness_gate.sh --include-registry
```
