# Sponzey Fleet Protocol

Sponzey Fleet agent-controller protocol은 JSON wire message를 사용한다. Rust domain object는 wire schema에 직접 노출하지 않고, `fleet-protocol`의 `WireMessage`와 `WirePayload`가 직렬화 경계가 된다.

## Envelope

모든 message는 공통 envelope를 가진다.

```json
{
  "protocol_version": 2,
  "message_id": "msg-1",
  "correlation_id": "corr-1",
  "agent_id": "agent-1",
  "timestamp_ms": 1,
  "payload": {
    "type": "heartbeat",
    "payload": {
      "agent_id": "agent-1",
      "status": "online"
    }
  }
}
```

필수 규칙:

- `protocol_version`은 현재 `2`다. 다른 버전은 payload 해석 전에 거부한다.
- v1과의 호환 fallback 또는 협상은 없다. Controller와 모든 Agent는 같은 릴리스의 v2를 사용해야 한다.
- version mismatch는 reject한다.
- unknown message type은 reject한다.
- malformed JSON은 reject한다.
- JSON wire message는 최대 8 MiB이며, `task_report` body는 base64 decode 후 최대 4 MiB다.
- `message_id`는 message 단위 식별자다.
- `correlation_id`는 request-response 또는 task-output 흐름을 묶는다.
- `agent_id`는 enrollment 이전 message에서는 없을 수 있다.
- `timestamp_ms`는 message를 만든 쪽의 시스템 시각이다. Agent가 보내는 facts, metrics, drift report message의 `timestamp_ms`는 controller 저장 시각과 API 응답의 `agent_system_time_ms` 기준이 된다.

## Auth/Session Payloads

인증과 session 유지용 payload:

- `enroll_request`
- `enroll_response`
- `agent_hello`
- `auth_challenge`
- `auth_response`
- `auth_accepted`
- `heartbeat`
- `task_report` and `report_receipt` (v2 reporting path)

예:

```json
{
  "type": "auth_challenge",
  "payload": {
    "nonce": "nonce-1"
  }
}
```

인증 성공 응답은 Controller의 영속 delivery identity를 포함한다.

```json
{
  "type": "auth_accepted",
  "payload": {
    "controller_namespace": "<64 lowercase hex characters>",
    "store_epoch": "<64 lowercase hex characters>"
  }
}
```

Agent는 응답의 Agent ID와 correlation ID가 현재 handshake와 일치하고 두 identity 값이
64자리 소문자 hex인지 확인한다. persistent Agent runtime은 Controller namespace와 Agent ID를
local journal owner에 바인딩한다. 현재 handshake의 epoch는 receipt 검증에 사용하며, receipt만으로
정확한 pending report 일치와 서명 검증을 건너뛸 수는 없다.

## WebSocket Gateway

MVP controller는 agent outbound 연결을 다음 endpoint에서 받는다.

```text
ws://127.0.0.1:7700/api/agents/ws
```

현재 handshake 흐름:

1. Agent sends `agent_hello` with `agent_id` and `fingerprint`.
2. Controller loads the enrolled agent public key and verifies the fingerprint.
3. Controller sends `auth_challenge` with nonce.
4. Agent signs the nonce with its local Ed25519 private key and sends `auth_response`.
5. Controller sends `auth_accepted` with its durable delivery namespace and store epoch. The persistent Agent binds the journal to the namespace and Agent ID, and uses the accepted epoch as the current receipt-verification boundary.
6. Controller registers the authenticated persistent session.
7. Controller drains at most one pending assignment for the agent immediately after session registration.
8. Agent sends periodic `heartbeat` liveness ticks on the same session.
   Each matching authenticated heartbeat refreshes stored inventory liveness using Controller
   receipt time, without clearing degraded health or emitting an unexpected-message audit.
   A mismatched payload Agent ID cannot refresh another Agent.
   Facts, metrics, and operational log chunks use separate agent-side intervals.
9. New command, drift-check, or runbook jobs are stored first, then dispatched immediately to active sessions.
10. Agent verifies the signed envelope. For persistent Command and no-artifact Runbook, nonce/target/expiry
    checks precede durable execution admission; `StartIntent` and output sequence progress commit before
    TaskAck/TaskStarted and host effects. After process restart or prior task-owner exit, an interrupted
    execution becomes a typed failed final report with its committed stream counts, never a rerun.
    Reconnect during a live task skips recovery; idle reconnect retries it. Artifact-producing Runbook,
    DriftCheck execution recovery, and direct one-shot execution remain on separate paths.
11. For persistent sessions, the CLI Agent commits `task_ack` and then `task_started` Lifecycle
    reports (stable report ids `task-ack` and `task-started`) to its local journal before sending
    either. TaskStarted is committed before Command child execution or Runbook/Drift execution.
    Lifecycle reports are ordered by stable report key, so TaskAck precedes TaskStarted, then
    TaskRejected; lifecycle reports precede Output and FinalResult reports. The Controller checks the authenticated Agent and stored
    Assignment owner, then atomically commits `dispatched -> accepted`, `accepted -> started`, or
    the pre-execution `dispatched -> rejected` transition, the
    Job aggregate, one Job audit event, and the inbox marker before returning a signed `stored`
    receipt. When the started Assignment belongs to a remediation runbook, its `job_created -> running`
    transition and Policy audit share that same transaction.
    The Agent replays pending reports after reconnect and removes each only after verifying its exact
    signed receipt in the current authenticated session. Persistent DriftCheck evidence uses a strict
    `drift_evidence` report; its terminal TaskResult is a separate strict `final_result` report on the
    same journal/receipt path. The evidence receipt confirms stored evidence only; the final-result
    effect is what transitions the Assignment/Job. Persistent Command and no-artifact Runbook
    stdout/stderr and no-artifact Command/Runbook final results use the same Agent journal/receipt path.
    Artifact-bearing Runbook finals use the authenticated Controller v2 effect/receipt path but are
    not Agent-journaled. Direct one-shot `agent heartbeat --once`, artifact-producing Runbook output
    replay, and Drift execution recovery remain outside their corresponding durable paths.

### Current WebSocket lifecycle

현재 lifecycle은 persistent outbound session이다.

- Agent가 Controller로 outbound WebSocket을 연다.
- 인증이 끝난 뒤 Agent가 heartbeat를 보낸다.
- v2만 지원하며 v1 Agent는 즉시 version mismatch로 거부된다. Controller와 모든 Agent는 함께 업그레이드해야 한다.
- Controller는 인증된 session을 runtime registry에 등록한다.
- session 등록 직후 해당 agent의 pending assignment를 최대 1개 drain한다.
- `POST /api/jobs/command`, `POST /api/jobs/runbook`, `POST /api/jobs/drift-check`는 job과 assignment를 DB에 저장한 뒤 active session으로 즉시 dispatch를 시도한다.
- connected session이 없거나 outbound queue가 가득 차면 assignment는 DB queued 상태로 남고 dispatch failure가 audit된다.
- queued assignment가 없더라도 Controller는 연결을 유지하고 heartbeat/facts/metrics/log/output/result payload를 같은 session에서 계속 처리한다.
- Controller는 Agent로 직접 접속하지 않는다. 현재 구조와 목표 구조 모두 Agent outbound 연결을 기준으로 한다.

Agent enrollment generates an Ed25519 key pair locally. The private key is stored in `agent_private.key`; the controller stores the public key and fingerprint. On Unix, `agent.conf` and `agent_private.key` must not be readable, writable, or executable by group/other.

`fleet agent start` runs as a persistent session loop by default. `--heartbeat-interval-seconds` controls liveness ticks only, not the connection cycle, facts upload, metrics upload, log upload, or task dispatch. Facts default to a lower-frequency static inventory interval controlled by `--facts-interval-seconds` (300 seconds). Metrics default to a chart-friendly interval controlled by `--metrics-interval-seconds` (30 seconds). Controller connection failures are retried indefinitely unless `--once` or `--max-reconnect-attempts` is set. For smoke tests and one-shot checks, pass `--once`.

Controller session implementation note:

- 인증이 끝난 Controller WebSocket handler는 read loop와 write loop를 분리한다.
- session당 WebSocket writer는 하나의 writer loop만 소유한다.
- Controller 내부 producer는 bounded outbound channel로 `task_assignment` 같은 `WireMessage`를 전달한다.
- outbound queue overflow는 write queue overflow로 구분되며, dispatch 계층에서는 DB queued assignment를 source of truth로 유지해야 한다.
- read loop는 기존 heartbeat, facts, metrics, log, `output_chunk`, task lifecycle, drift, security event와 v2 `task_report`를 처리한다. 일반 payload는 authenticated session agent id와 payload agent id를 비교하고, v2 report는 authenticated owner를 inbox admission에서 확인한다.
- agent id mismatch payload는 저장하지 않고 security audit 대상으로 처리한다.
- DB write failure는 message만 조용히 무시하지 않고 `store_error` close reason으로 session cleanup 대상이 된다.
- raw command output은 일반 product log로 흘리지 않고 job output storage에만 저장한다.
- rendered artifact body는 `task_result.artifacts[].content_bytes`가 있을 때만 Controller `ArtifactStore`에 저장한다. Metadata-only artifact payload는 legacy compatible path로 계속 허용한다.
- output chunk는 bounded runner output limit과 chunk sequence를 유지한다.
- 같은 `(job_id, agent_id, stream, sequence)` output chunk가 같은 body로 다시 오면 idempotent duplicate로 보고 무시한다.
- 같은 key의 output chunk가 다른 body로 오면 raw body를 audit/log에 남기지 않고 `websocket_output_chunk_conflict` security audit를 남긴 뒤 protocol error로 session cleanup 대상이 된다.
- controller connection drop만으로 `running` job을 즉시 `failed`로 바꾸지 않는다. 현재 dispatch의 expiry 검사는 queued assignment에만 적용되며, Agent가 돌아오지 않는 dispatched/accepted/started assignment를 일반적으로 수렴시키는 worker는 없다. Agent의 timeout result와 remediation verification recovery는 이 누락을 대신하지 않는다.
- Agent key revoke 성공 직후 controller는 active session이 있으면 `agent_revoked` close reason으로 writer loop에 close를 enqueue하고 registry에서 제거한다.
- Revoke는 추가 task 수신 차단과 session 종료를 보장한다. 특정 job을 중단하려면 revoke가 아니라 `POST /api/jobs/{job_id}/cancel`을 사용한다.
- Cancel API는 queued assignment를 DB에서 terminal `canceled`로 바꾸고, 이미 `dispatched`, `accepted`, `started` 상태인 active session에는 `task_cancel`을 보낸다.
- Agent는 `task_cancel`이 현재 실행 중인 task id와 일치하면 cancel flag를 설정하고, command runner는 child process를 kill한 뒤 `task_result.status = "canceled"`를 돌려보낸다.
- Darwin/Linux command runner는 실행별 process group을 소유하며 출력 callback 실패·cancel·timeout 때 정리한다.
  종료를 관찰할 때 leader를 먼저 reap하지 않아 group 정리 전 PID 재사용을 피한다. 출력은 poll로 제한된 크기만 읽으며,
  후손이 pipe를 유지해도 cancel/timeout 확인을 막는 reader join이나 무한 메모리 queue를 만들지 않는다.
  이 정리는 이미 일어난 host 변경을 되돌리거나 별도 session/group으로 이탈한 daemon을 제어하는 보장이 아니다.
- session lifecycle audit action은 `agent_session_started`, `agent_session_ended`, `agent_session_replaced`, `agent_session_revoked_closed`, `agent_session_auth_failed`를 사용한다.

## Controller Identity And Fingerprints

The controller identity endpoint exposes the controller signing identity, not
the TLS certificate identity.

- `controller_public_key` is the controller Ed25519 signing public key.
- `controller_fingerprint` and `controller_signing_fingerprint` are signing
  public key fingerprints. They are used by agents to detect controller signing
  key changes after enrollment.
- `tls_enabled` only reports whether the controller listener is using TLS server
  material.
- TLS certificate fingerprints must not be substituted for
  `controller_signing_fingerprint`.

The TLS server certificate proves the transport endpoint for HTTPS/WSS. The
controller signing key proves task envelopes. Future mTLS client certificates may
add transport authentication, but they do not replace agent key proof,
controller-signed task envelopes, expiry, nonce replay, or target validation.

Controller signing key rotation uses a dual-trust policy:

- before activation, the old signing key remains the signing key;
- after activation, the new signing key signs new task envelopes;
- the old signing key verifies only task envelopes signed before activation and
  only until the explicit old-key verification expiry;
- after old-key retirement, old-key signatures are rejected even if the task has
  not expired.

This policy is a domain state machine. Wire payloads and task verification must
not infer it from TLS certificate fingerprints or local certificate files.
The persisted rotation record stores only state, public fingerprints, and
validity timestamps. Private key material and private key paths remain outside
the protocol and rotation-state persistence model.
Request, validation, activation, retirement, and failure operations are
application use cases with security audit events. Protocol handlers and future
admin APIs must not duplicate transition logic or inspect private key material.
Validation requires a candidate signing keypair to sign/verify an explicit
challenge and the derived public fingerprint to match the pending new
fingerprint; private key material remains outside protocol payloads, persisted
rotation state, and audit values.
At controller bootstrap, the active signing keypair is validated and compared
with persisted rotation state before any task-signing path is exposed. A
mismatch is a startup failure, not a runtime config patch or handler-level
fallback.

Rotation readiness is exposed to operators through
`GET /api/controller/signing-rotation/status` and the
`fleet controller signing-rotation-status` CLI command. That surface is
read-only and returns state names, readiness names, fingerprint prefixes, and
dual-trust timestamps only. It is not an agent protocol message and must not
carry private key material, key paths, TLS certificate material, raw public key
bodies, task payload bodies, or process environment values.

Rotation mutation is exposed through admin REST endpoints under
`/api/controller/signing-rotation/*` and CLI commands under
`fleet controller signing-rotation`. These commands call application
request/validate/activate/retire/fail use cases and return the same
secret-free readiness vocabulary as the status endpoint. They are not
agent-controller wire messages. Candidate material validation uses explicit
controller-local file paths through the controller filesystem boundary; private
key bodies, raw public key bodies, TLS certificate material, task payload
bodies, and runtime environment patches are outside the protocol.

Agents verify controller-signed task envelopes through a controller signing
trust bundle. The bundle contains only public key material, public
fingerprints, a role (`current` or `previous`), `valid_from`, and optional
`valid_until`. Existing enrolled agents that only have a pinned controller
signing fingerprint use a backward-compatible single-entry `current` bundle.

`controller_signing_trust_bundle_update` is a task-data channel control message
for rotating controller signing trust during an authenticated agent session.
Its payload is:

```json
{
  "entries": [
    {
      "fingerprint": "public-signing-key-fingerprint",
      "public_key": "public-signing-key",
      "role": "current",
      "valid_from_ms": 1710000000000,
      "valid_until_ms": null
    }
  ]
}
```

Allowed roles are `current` and `previous`. `previous` entries require
`valid_until_ms`; duplicate fingerprints, missing current entry, invalid time
windows, and malformed public key fields are rejected before the bundle is
stored. Accepted bundles are stored in explicit in-memory agent session state
and are used only for subsequent task envelope verification. Accepted bundles
are also persisted to the agent config sidecar `controller_trust_bundle.json`
using the same public-only schema so restart keeps the rolled-out trust window.
The update does not mark any task accepted, started, or verified.

Trust-bundle rollout messages must preserve this boundary and must not include
private key material, key file paths, TLS certificate material, task payload
bodies, process environment changes, or runtime config patches.

Controller signing rotation status, mutation, and restart-plan APIs are REST/CLI
operator surfaces, not agent protocol messages. Restart-plan output is
read-only guidance derived from persisted rotation state and active runtime
signer summary; it must not trigger WebSocket control messages, controller
self-restart, key reload, or runtime config patching.

Controller signing trust bundle rollout is the REST/CLI surface that may send
`controller_signing_trust_bundle_update` to authenticated connected sessions.
It uses public-only bundle entries, requires the active controller signer to
match persisted selected rotation state, and reports disconnected targets as
skipped. Sending this control message must not create Job or Assignment state
and must not be interpreted as task acceptance or task execution.

The rollout retry surface uses the same protocol message and adds only
controller-side batch selection. `max_agent_count` limits how many target
sessions are attempted in one operator-triggered retry. Already-current agents
can be skipped only when the controller has explicit public ack state for the
same bundle fingerprint set. The unattended staged rollout worker continues
persisted public rollout state and must not persist request bodies, private key
material, certificate paths, WebSocket handles, or process environment values.

## Agent Client Certificate Lifecycle

Agent client certificate lifecycle now has a public-only wire schema foundation
on top of the domain state machine and application repository/use-case
contract. Runtime controller/agent handlers that mutate lifecycle state must
call the application use cases instead of mutating lifecycle snapshots in
WebSocket handlers. The current runtime boundary does not mutate lifecycle
state: the controller records lifecycle ack status in session runtime state and
Security audit, and the agent rejects lifecycle updates with a bounded
`certificate_lifecycle_runtime_not_implemented` acknowledgement until local
certificate application and mTLS enforcement exist. The controller also has an
internal dispatch helper that converts an application lifecycle record into a
public-only `agent_certificate_lifecycle_update` message for an already
authenticated connected session. The current public controller surfaces are
limited to read-only status and issuance request:
`GET /api/agents/{agent_id}/certificate-lifecycle/status`,
`fleet agents certificate-status <agent-id>`,
`POST /api/agents/{agent_id}/certificate-lifecycle/request-issuance`, and
`fleet agents request-certificate-issuance <agent-id>`. Status requires
`agent_read` and returns public state/prefix fields only. Issuance request
requires `agent_write`, stores public lifecycle state through the application
use case, writes Security audit, and reports dispatch status only. Dispatch
success is not agent acceptance or certificate installation.

The lifecycle states are:

- `not_issued`
- `issuance_requested`
- `issued`
- `renewal_requested`
- `dual_certificate_active`
- `revoked`
- `expired`
- `failed`

The protocol messages are:

- `agent_certificate_lifecycle_update`: controller-to-agent lifecycle action
  and public certificate metadata.
- `agent_certificate_lifecycle_ack`: agent-to-controller acknowledgement with
  accepted/rejected status, resulting lifecycle state, current public
  fingerprint, and bounded reason code.

Certificate issuance and renewal payloads may carry only public certificate
metadata needed by the domain/application contract: agent id, certificate
serial, certificate fingerprint, validity timestamps, lifecycle action,
bounded reason code, and correlation id. They must not carry private keys, PEM
bodies, certificate file paths, CA paths, task payload bodies, process
environment patches, WebSocket handles, or runtime config changes.

During `dual_certificate_active`, the current client certificate is accepted
only until the explicit grace deadline and the next certificate is accepted
according to its validity window. The current application/store contract covers
issuance request, issue, renewal request, renewal activation, rotation
completion, snapshot save/load, public metadata persistence, and Security audit
event creation. The current protocol contract covers message shape,
serialization, public-only metadata, ack status, controller-side ack audit, and
controller-side public update dispatch from application records. Agent-side
runtime certificate application currently returns explicit rejection when
unsupported. Listener-side mTLS verification, issue/renew/activate/revoke
public controller surfaces, agent-side certificate application, revocation
propagation, and renewal acknowledgement behavior remain future implementation
tasks.

Close reason policy:

- `normal_shutdown`: agent 또는 controller session loop가 정상 종료됐다.
- `handler_ended`: request handler가 끝나면서 registry guard가 정리됐다.
- `replaced_by_new_session`: 같은 agent id의 새 authenticated session이 이전 session을 대체했다.
- `agent_revoked`: agent key revoke로 active session이 닫혔다.
- `auth_failed`: authentication이 실패했다.
- `protocol_error`: malformed payload, invalid sequence, duplicate output body mismatch 같은 protocol 위반이다.
- `store_error`: controller가 session payload를 저장하지 못했다.
- `write_failure` / `write_queue_overflow`: WebSocket writer 또는 bounded outbound queue 문제다.

Security notes:

- HTTP/WebSocket controller URLs are test-only and emit insecure transport warnings.
- Product, customer, production, shared, and long-running environments must use HTTPS/WSS.
- Agent heartbeat checks the pinned controller fingerprint before opening the WebSocket.
- WebSocket authentication failures are recorded as security audit events.
- Enrollment tokens are not accepted on the task/heartbeat WebSocket channel.

## Task/Data Payloads

task 실행과 결과 전달용 payload:

- `task_assignment`
- `task_ack`
- `task_started`
- `task_rejected`
- `task_cancel`
- `output_chunk`
- `task_result`
- `security_event`
- `facts_snapshot`
- `metrics_snapshot`
- `capability_snapshot`
- `log_chunk`
- `drift_report`

인증/session payload와 task/data payload는 protocol layer에서 구분된다. agent는 authenticated session 이후에만 task/data channel message를 처리해야 한다.

Facts and metrics payloads include a lightweight system timestamp inside the JSON body so operators can identify when the agent produced the snapshot even after paging or exporting API responses.

- `facts_snapshot` is inventory data. It should describe relatively stable system characteristics such as OS, architecture, hostname, CPU logical count, total memory, memory module count when discoverable, disk device inventory, mount layout, root filesystem, root disk capacity, and network interface names. It must not carry current memory usage, disk usage, or CPU usage.
- `metrics_snapshot` is usage telemetry. It should describe values that change over time, such as CPU usage percent, memory used/available/used percent, disk used/available/used percent, process count, and service failure counts.

Facts snapshot:

```json
{
  "type": "facts_snapshot",
  "payload": {
    "agent_id": "agent-1",
    "body": "{\"system_time_ms\":1710000000000,\"os\":\"linux\",\"arch\":\"x86_64\",\"memory\":{\"total_kb\":16777216,\"module_count_known\":true,\"module_count\":2},\"disk\":{\"device_inventory_known\":true,\"device_count\":1,\"devices\":[{\"name\":\"nvme0n1\",\"kind\":\"disk\",\"size_kb\":104857600,\"removable\":false,\"rotational\":false}],\"mount_inventory_known\":true,\"mount_count\":1,\"mounts\":[{\"source\":\"/dev/nvme0n1p1\",\"mount_point\":\"/\",\"fs_type\":\"ext4\",\"read_only\":false}],\"root_capacity_known\":true,\"root_total_kb\":104857600}}"
  }
}
```

Metrics snapshot:

```json
{
  "type": "metrics_snapshot",
  "payload": {
    "agent_id": "agent-1",
    "body": "{\"system_time_ms\":1710000000000,\"cpu\":{\"logical_count\":4,\"usage_percent\":18.4},\"memory\":{\"usage_available\":true,\"total_kb\":16777216,\"used_kb\":4194304,\"available_kb\":12582912,\"used_percent\":25},\"disk\":{\"usage_available\":true,\"total_kb\":104857600,\"used_kb\":31457280,\"available_kb\":73400320,\"used_percent\":30}}"
  }
}
```

Drift report does not carry an arbitrary JSON body, so controller uses the agent message envelope `timestamp_ms` as both `checked_at_ms` and `agent_system_time_ms`.

### Drift report task correlation

When an agent executes a signed `drift_check` assignment, its `drift_report`
payload includes optional `job_id` and `task_id` values copied from that signed
task envelope. Both fields are omitted for uncorrelated observation reports;
the current v2 payload contract permits that omission without changing
`protocol_version`.

These values are correlation claims, not execution authority. The controller
must still authenticate the agent session and match the values to its persisted
assignment before using the report as remediation evidence. A missing,
mismatched, or unverified correlation must remain an observation-only report.

Capability snapshot:

```json
{
  "type": "capability_snapshot",
  "payload": {
    "agent_id": "agent-1",
    "privilege_level": "sudo_available",
    "package_manager": "apt",
    "service_manager": "systemd",
    "capabilities": [
      "persistent_session",
      "command_execution",
      "package_install"
    ],
    "reported_at_ms": 1710000000000
  }
}
```

Capability contract rules:

- Capability matching is a domain/application rule, not a controller HTTP handler or Web Admin rule.
- `fleet-protocol` owns only the wire shape: privilege level, optional package manager, optional service manager, reported capability names, and `reported_at_ms`.
- Domain capability snapshot states are `unknown`, `reported`, `stale`, `unsupported`, and `compatible`.
- Privilege levels are `unprivileged`, `sudo_available`, and `root`. `root` satisfies requirements that need `sudo_available`.
- Supported package manager values are currently `apt`, `dnf`, `yum`, `apk`, and `brew`.
- Supported service manager values are currently `systemd`, `launchd`, and `openrc`.
- Capability values are not overridden by YAML config, runtime env patching, or UI settings.
- Dispatch treats a stored snapshot older than the current 24-hour application default as stale and rejects before WebSocket write.
- Agent collection, controller persistence, dispatch rejection, API exposure, and Web Admin rendering now use this snapshot as the product capability boundary. Runtime session summaries are diagnostic metadata, not the dispatch gate source of truth.

Agent operational log chunk:

```json
{
  "type": "log_chunk",
  "payload": {
    "agent_id": "agent-1",
    "line": "level=info event=agent_heartbeat_completed agent_id=agent-1 status=online"
  }
}
```

The default agent start mode sends product-safe operational log chunks every
30 seconds. Operators can change the interval with
`--log-upload-interval-seconds` or disable it with `--disable-log-upload`.
These chunks are not raw file tails or journald streams. They are independent
from heartbeat, facts, metrics, and task assignment dispatch.

## Signed Task Envelope

`task_assignment`는 signed envelope와 실행할 task payload를 포함한다.

```json
{
  "type": "task_assignment",
  "payload": {
    "envelope": {
      "job_id": "job-1",
      "task_id": "task-1",
      "target_agent_id": "agent-1",
      "issued_at_ms": 1,
      "expires_at_ms": 60000,
      "nonce": "nonce-1",
      "payload_hash": "hash",
      "signature": "sig"
    },
    "task": {
      "kind": "command",
      "payload": {
        "program": "uptime",
        "args": [],
        "timeout_ms": 30000,
        "max_output_bytes": 1048576
      }
    }
  }
}
```

Runbook task payload:

```json
{
  "kind": "runbook_execution",
  "payload": {
    "runbook_document": "apiVersion: fleet.sponzey.dev/v1alpha1\nkind: Runbook\n...",
    "timeout_ms": 180000,
    "confirmed_high_risk": true
  }
}
```

Drift check task payload:

```json
{
  "kind": "drift_check",
  "payload": {
    "policy_document": "apiVersion: fleet.sponzey.dev/v1alpha1\nkind: Policy\n..."
  }
}
```

agent는 실행 전에 최소한 다음을 확인해야 한다.

- target agent id가 자기 id와 일치한다.
- signature가 비어 있지 않다.
- expiry가 지나지 않았다.
- nonce replay가 아니다.
- controller signing trust bundle에서 유효한 public key를 선택해 signature를
  검증한다.

검증에 실패하면 agent는 task를 실행하지 않고 `task_rejected`를 controller에 보낸다. Controller는 해당 assignment를 `rejected`로 저장하고 job audit event를 남긴다. 별도의 보안 이상 징후나 protocol mismatch는 `security_event`를 통해 Security audit event로 저장한다.

MVP agent는 agent data directory의 local file-backed nonce replay store를 사용해 restart 이후에도 consumed nonce를 거부한다. Replay store를 읽거나 기록할 수 없으면 task validation은 fail-closed로 종료되고 task execution으로 이어지지 않는다. 장시간 live streaming은 후속 hardening 범위다.

## Assignment Lifecycle, Output, and Result

### Active v2 output report and stored-report receipt

`task_report` and `report_receipt` are payloads in the active v2 `WireMessage` session envelope.
A report carries a stable Controller/Agent/Job/Task/report key, class (`lifecycle`,
`drift_evidence`, `output`, `final_result`), lowercase SHA-256 of its exact decoded body, and a nonempty base64 body limited
to 4 MiB. The whole JSON message is limited to 8 MiB. Encoding/decoding checks required identity
fields, matching outer Agent ID, body encoding, digest, and receipt shape. v1 is rejected before
payload parsing; there is no compatibility fallback.

The authenticated Controller WebSocket handles `lifecycle` TaskAck/TaskStarted/TaskRejected,
`drift_evidence`, `output`, and a limited `final_result` subset on SQLite. Supported lifecycle bodies are strict
`{"event":"task_ack"}`, `{"event":"task_started"}`, and
`{"event":"task_rejected","reason_code":"invalid_signature","reason":"..."}`, with stable report ids
`task-ack`, `task-started`, and `task-rejected`. It verifies the authenticated Agent and stored Assignment owner, then atomically
commits TaskAck's `dispatched -> accepted`, TaskStarted's `accepted -> started`, or TaskRejected's
`dispatched -> rejected` transition, the Job aggregate, one redacted Job audit, and the inbox marker.
TaskRejected stores the typed reason code plus redacted reason on the Assignment. Exact retries replay
the same receipt without another transition or audit; terminal rows and mismatched owners fail closed. Output reports use the strict `{stream, sequence, data}` body and
atomically commit the output chunk with the inbox marker. A final result requires strict
`{exit_code, status, reason, artifacts, output}` fields and an `output` summary containing
`stdout_chunks`, `stderr_chunks`, and `truncated`; there is no older-body fallback. Command,
no-artifact Runbook, and artifact-bearing persistent Runbook finals are supported. Artifact metadata
is validated before staging; an included body must match its declared size and SHA-256 and fit the
body limit. Metadata-only artifacts remain valid, but do not imply that a body is retrievable.
For persistent Command and no-artifact Runbook jobs, the Controller verifies each stored stream is exactly the contiguous sequence
`[0, count)` before it commits final effects or issues a receipt. Missing, gapped, or extra chunks
leave the final inbox report pending for retry. A truncated result cannot be reported as
succeeded. Its Job audit records only the two counts and truncation flag, never output bytes. This
barrier proves delivery of the Agent-journaled chunk prefix, not that every byte produced by task
execution was captured. The Controller atomically commits the Assignment status, Job aggregate,
artifact metadata, redacted Job audit and inbox marker. Included artifact bodies are first written
to the immutable local artifact store; an identical retry is safe if the later SQLite transaction
fails. Filesystem publication and SQLite are not one atomic transaction, so an unreferenced object
can remain after a failed/abandoned effect. Unsupported follow-up effects fail closed without a
receipt. For every supported class, the
Controller verifies the report key against the authenticated Agent and current Controller
namespace, stages the exact encoded body and digest, then signs and persists a `stored` receipt only
after the effect commits. It enqueues the stored receipt to the existing bounded, single-writer
session queue. A retry with the same key/body replays the exact persisted receipt without duplicating
effects. A changed body for the same key is audited as a conflict and receives no receipt. Owner
mismatch is also Security-audited and fails closed. Postgres report handling is currently unsupported
and fails closed.

Persistent DriftCheck uses a strict `drift_evidence` body with only `status`, `expected`, and `actual`;
policy identity, version, purpose, and ownership are read from Controller-stored Job/Assignment data.
The Agent commits the exact report to its local SQLite journal before send and retains it until the
current-session signed `stored` receipt is verified. The Controller commits correlated drift evidence,
its required redacted audit, an eligible remediation proposal and its audit when applicable, and the
inbox marker in one SQLite transaction. Exact retries replay the receipt; changed bytes, owner mismatch,
or provenance mismatch fail closed. This evidence receipt confirms only the evidence and required
effects were stored: it does not mark the Job/Assignment successful or replace the separate `TaskResult`.

The persistent CLI Agent uses this live path for TaskAck, TaskStarted, and TaskRejected on Command, Runbook, and
Drift assignments, DriftCheck evidence, Command/no-artifact Runbook stdout/stderr chunks, no-artifact
Command/Runbook finals, and artifact-bearing Runbook finals:
it commits each exact body and stable report key to its local
journal before send, then retries pending rows after reconnect. The WebSocket envelope receives a
fresh message/correlation identity per session; the report key and body remain stable. Persistent-task
summary counts advance only after the local journal confirms each output append; if an append result
is uncertain, the Agent does not guess the count or append a final report. The Agent
checks receipt session identity, current namespace and epoch, exact pending report identity/digest,
signing time and pinned/rotated Controller Ed25519 trust before submitting journal cleanup for
journaled reports. Artifact-producing Runbook output and final reports are intentionally ephemeral:
the final uses a strict v2 `FinalResult` report, but neither its bytes nor its receipt are retained
by the Agent journal. Therefore a disconnect before Controller inbox staging can lose that report;
the Controller receipt confirms a committed effect but does not create Agent-side replay. A pending
Controller inbox row remains available for an exact report retry, but automatic pending-row recovery
is not implemented. The direct one-shot `agent heartbeat --once` handler remains on its separate
legacy `TaskResult` path.
Persistent DriftCheck evidence and terminal TaskResult are now distinct journaled v2 reports: evidence
does not complete the Assignment, while its final-result report applies the terminal effect. Lifecycle
events other than TaskAck, TaskStarted, and TaskRejected, artifact/follow-up effects, rejected-receipt
disposition UX, and Drift execution recovery remain unsupported.

`fleet-protocol::receipt` now defines a signed receipt statement shape and canonical signing
preimage. Its domain-separated `fleet:report-receipt:v2:` prefix and byte-length-framed fields bind
the stable Controller namespace, Controller store epoch, Agent/Job/Task/report identity, lowercase
SHA-256 digest, signing time, disposition (`stored` or typed `rejected` reason), and signing-key fingerprint.
The signature is a separate lowercase Ed25519 hex field. A malformed field is rejected before
signing/verification. The active session codec validates receipt shape and outer Agent ownership;
the persistent Agent session additionally verifies Ed25519 against pinned/rotated Controller signing
trust, the accepted namespace/epoch and exact pending report before ACK cleanup. Only a committed
`stored` disposition can authorize cleanup. A `rejected` disposition fails closed and retains the
report; explicit conflict handling remains future work. Namespace/epoch persist in Controller
schema v23 and actual restore rotates the epoch. Namespace and Agent ID bind the local journal owner;
the current authenticated epoch is used for receipt verification. This does not recover output already
confirmed and deleted after a Controller backup snapshot. A still-pending exact journal report can be
replayed after restore: the Controller rechecks its authenticated owner and digest, avoids repeating a
committed effect, and issues a receipt bound to the current epoch. A prior-epoch receipt cannot clean
the Agent journal; a missing owner or assignment is not ACKed. This is not recovery for reports already
deleted by Agent ACK cleanup before the restored snapshot was taken.

The Controller Application layer now has a separate incoming-report admission contract: the
authenticated Agent ID and local namespace must match the report key and the encoded body must
fit a caller-supplied limit before repository staging. Its typed `pending effects`, duplicate,
conflict and capacity outcomes are not themselves signed storage ACKs. SQLite staging and TaskAck/
TaskStarted effect handling are connected for the live `lifecycle` class, correlated evidence and
eligible proposal effects for `drift_evidence`, output effects for `output`, and supported Command,
Runbook, and DriftCheck final-result effects for `final_result`. Artifact-bearing Runbook final reports
stage validated artifact bodies in the local immutable store and atomically commit artifact metadata,
Assignment/Job/audit effects, and the inbox marker in SQLite. Prepared remediation final-result
follow-up remains unconnected.
Persistent Command and no-artifact Runbook final reports
now verify exact contiguous stored output prefixes; this does not prove every task-execution byte was
captured. Persistent DriftCheck evidence and its terminal final result use separate durable reports;
artifact-producing Runbook output remains outside the Agent journal. A bounded SQLite recovery read
can retrieve pending final-result bytes after reopen, verifying digest and Assignment ownership.
Controller startup and the periodic worker use this read to apply supported effects; receipt
authority follows the committed transaction and signed receipt persistence. Optional artifact-body
puts occur before that DB transaction and are idempotent on exact retry. Output gaps, unsupported
effects, terminal Assignments, and corrupt rows fail closed and remain pending. There is no Agent
journal replay for an artifact-bearing Runbook report, so a pre-inbox disconnect remains unrecoverable.
File-only orphans can remain after a failed/abandoned effect.
Prepared remediation execution status and audit share the transaction, leaving a
durable `succeeded_pending_verify` recovery intent for the existing bounded verification worker.
Drift-check verification final Assignment/Job/audit/inbox effects now commit atomically as a
separate library path. The live `drift_evidence` report commits its correlated drift row, redacted audit,
eligible proposal effects, and inbox marker after exact bytes, authenticated Agent/Assignment, and
stored policy provenance checks. A final result and evidence can arrive in either order; duplicates
create no new effects. Neither report alone resolves remediation. If both effects are committed, a bounded Controller
startup scan now joins the persisted successful final and fresh compliant evidence through the
existing resolution use case. It does not recover still-pending inbox bodies or retry periodically;
prepared artifact effects for persistent Runbook finals are live, while remediation final-result
follow-up remains outside the v2 report handler.

The Controller now has a separate stored-receipt issuance helper. It accepts only `Committed` or
`AlreadyCommitted` inbox-effect outcomes, binds the resulting digest to the current durable
namespace/epoch and authenticated Agent ID supplied by its caller, checks the signing public/
private key pair and fingerprint, then signs the v2 statement. Pending/conflicting/not-staged
outcomes cannot produce a stored receipt. The authenticated TaskAck/TaskStarted/TaskRejected, DriftEvidence, output, and supported final-result
handlers call this helper only after their SQLite effect commits. The helper cannot itself authenticate its caller or
prove that a caller-provided outcome came from a committed DB result; rejected-disposition
persistence remains separate work.
An Application receipt port and SQLite schema v25 now persist signed bytes only after the exact inbox
row is committed. Same-signer duplicate reports replay identical bytes across Controller reopen. If
the active Controller signing key changed before Agent ACK cleanup, an exact committed report may
replace the receipt row with a newly signed current-key receipt without repeating its effect. The
Controller helper verifies the current candidate before persistence and verifies returned fields and
signature afterward. Pending, mismatched digest/owner/epoch, and stale-epoch candidates fail closed.
The Agent accepts the previous signer only during its configured trust grace. For SQLite TaskAck/TaskStarted/TaskRejected,
DriftEvidence, output, and supported final-result reports, the live WebSocket handler queues that receipt after
persistence. The persistent Agent consumes it only as permission to clean the exact acknowledged
journal row; an artifact-bearing Runbook report has no Agent journal row to clean and is not retained
for receipt-driven replay.

Controller schema v26 expands the SQLite inbox class check to include `drift_evidence`; it preserves
previous inbox and receipt rows while rebuilding the class-constrained inbox table with its receipt
foreign key intact.

### Current delivery limits

- Persistent TaskAck, TaskStarted, and TaskRejected for Command/Runbook/Drift assignments, DriftCheck evidence and terminal result, Command stdout/stderr, no-artifact Runbook stdout/stderr, and no-artifact Command/Runbook final results use the Agent journal and active v2 receipt path. Each report is committed locally before send and retained until a matching signed `stored` receipt is verified. TaskAck acceptance, TaskStarted start, and a pre-execution TaskRejected transition each commit with the Job aggregate, audit, and inbox marker; TaskRejected applies only to an owned `dispatched` Assignment and stores a redacted reason. DriftEvidence uses Controller-stored provenance and atomically commits the drift row, required audit, eligible remediation proposal effects and inbox marker. Its receipt does not mark the Job/Assignment successful. The separate DriftCheck final result applies the terminal status with its own exact receipt. Terminal Assignment state is never downgraded. Persistent Command and no-artifact Runbook finalization verifies exact per-stream `[0, count)` storage before its receipt and rejects a truncated success; this does not prove every task-execution byte was captured or guarantee exactly-once effects.
- Artifact-bearing persistent Runbook finals use the authenticated strict v2 `FinalResult` report. Controller size/checksum validation and owner checks precede an idempotent local body put; artifact metadata, Assignment/Job/audit effects, and the inbox marker then commit in one SQLite transaction, and the signed stored receipt is persisted afterward. A bounded SQLite startup pass and periodic worker retry up to 100 pending reports/8 MiB per effect scan, revalidate exact staged bytes and ownership, and queue committed receipts through an active session's single writer. It separately scans up to 100 committed final identities missing receipt bytes using only key/digest and persists those receipts without repeating effects. Output gaps, corruption, unsupported follow-up, and terminal Assignment state fail closed and remain pending. Postgres report handling/recovery is unsupported. The Agent does not journal artifact bodies or this final report, so disconnect before inbox staging can lose it. File-only orphans can remain across a failed/abandoned transaction; DB and filesystem are not atomic. This receipt is Controller commit confirmation, not end-to-end Agent replay or exactly-once execution.
- The direct one-shot `agent heartbeat --once` handler remains on the separate ephemeral `TaskResult` payload; those socket writes are not durable Controller receipts. DriftCheck evidence and terminal TaskResult are durable on persistent sessions, but Drift execution recovery and remediation final-result follow-up remain pending.
- Persistent Command and no-artifact Runbook execution records admission and start intent; a new process or idle runtime after prior task-owner exit journals `agent_interrupted_before_start` or `execution_outcome_unknown` as a failed final result without reexecution. The local execution record tracks committed stdout/stderr sequence counts in the same SQLite transaction as each output report, so output receipt cleanup cannot make a recovery final contradict Controller coverage. Final reports must match those counts. Reconnect during a live task skips recovery. Artifact-producing Runbook, direct one-shot, and Drift execution recovery remain outside this path.
- Agent journal schema v4 adds DriftEvidence while preserving v3 report rows and bytes; v3 persists stream counts. Upgrading a v2 journal with a `StartIntent` still active is rejected before changing its schema or stored reports; finish or reconcile that execution under the existing Agent first, then upgrade. This protects the final output-coverage contract and is separate from unsupported old wire-protocol compatibility.
- The active v2 session decoder ignores unknown fields on known payloads but rejects unknown message types. Ignoring a proposed capability field does not negotiate support for a new acknowledgement message.
- The legacy direct `TaskResult` path can commit the Assignment terminal status before artifact storage, Job aggregation, and audit complete. If artifact storage fails, reopening the store and replaying that result follows the terminal-assignment ignore path rather than repairing the missing effects. Persistent artifact-bearing Runbook finals now use the v2 inbox effect transaction; see `authenticated_artifact_final_result_commits_prepared_body_and_replays_receipt` and the [storage contract](storage.md).
- TaskRejected/TaskResult require the authenticated Agent and claimed Job to match the stored Assignment owner inside the transition transaction. A mismatch leaves the Assignment unchanged and is Security-audited. Persistent TaskAck, TaskStarted, and TaskRejected use the owner-bound durable report path; the durable report path also carries Command final results and no-artifact Runbook final results.
- A matching no-artifact persistent Command, Runbook, or DriftCheck final report that arrives after SQLite G2 recovery has marked its owned Assignment `failed/execution_outcome_unknown` receives a durable late disposition and signed `stored` receipt. The Controller records one redacted first-arrival audit and preserves the existing Assignment/Job terminal state; an exact retry replays the same receipt without repeating effects or audit. Command/Runbook reports require exact output coverage; DriftCheck reports require a no-artifact Job without remediation follow-up. Artifact-bearing Runbook reports and unrelated job classes remain fail-closed after a terminal Assignment. This is not an execution-success override or an exactly-once guarantee. One-shot final delivery, artifact-report Agent replay/automatic inbox recovery, Drift execution recovery, proof that every task-execution byte was captured, cross-epoch reconciliation for reports already ACK-cleaned before backup, and lossless backup recovery remain unsupported.
- A matching TaskAck/TaskStarted/TaskRejected that arrives after SQLite G2 has set its owned Assignment to `failed/execution_outcome_unknown` receives a late lifecycle disposition: the Controller atomically records one redacted Job audit and commits the inbox marker, without changing the Assignment, Job aggregate, or G2 reason, then persists and returns a signed `stored` receipt. Exact retry replays that receipt, so the Agent can clean the report and continue ordered replay. The receipt confirms durable report disposition, not acceptance, execution, or success. Owner mismatch and conflicting body remain fail-closed; the additional dispatched-cancellation exception is described below.
- A previously dispatched Assignment that the Controller has already marked `canceled` can receive a late final report from its authenticated owner. For no-artifact Command/Runbook Jobs without remediation follow-up, the Controller verifies exact body identity and stored output coverage, commits one `assignment_canceled_final_result_received` audit and the inbox disposition, then persists/replays a signed `stored` receipt. A valid `succeeded`, `failed`, `canceled`, or `timed_out` report can race cancellation; none changes the canonical canceled Assignment, its original reason/completion time, or the Job aggregate. Truncated success remains invalid. TaskAck/TaskStarted/TaskRejected racing the same dispatched cancellation use `assignment_canceled_lifecycle_report_received` and likewise apply no state transition. Undispatched canceled work, other terminal states/reasons, conflicting bodies, owner mismatches, and artifact/remediation/DriftCheck final effects are outside this exception. Stored means durable disposition, not permission to execute, execution success, or authority to rerun a task.

- TaskRejected is a pre-execution event and only transitions `dispatched -> rejected`; a report against another active Assignment state also fails closed and remains pending. Repeated admission of an already recorded Command reuses its existing durable result reports rather than producing a second TaskRejected. These guards prevent a replay refusal from replacing an uncertain execution result.

WebSocket write 성공은 agent가 task를 수락하거나 실행했다는 뜻이 아니다. Controller는 dispatch write 성공 시 assignment를 `dispatched`로만 저장한다. Persistent v2 session의 TaskAck, TaskStarted, TaskRejected는 위 `Lifecycle` report 경로를 사용하며, direct one-shot의 `task_ack`/`task_started`/`task_rejected` JSON은 별도의 control path 형식이다.

Agent lifecycle events:

```json
{
  "type": "task_ack",
  "payload": {
    "job_id": "job-1",
    "task_id": "task-1"
  }
}
```

```json
{
  "type": "task_started",
  "payload": {
    "job_id": "job-1",
    "task_id": "task-1"
  }
}
```

```json
{
  "type": "task_rejected",
  "payload": {
    "job_id": "job-1",
    "task_id": "task-1",
    "reason_code": "invalid_signature",
    "reason": "task envelope signature is invalid"
  }
}
```

Rejected reason codes:

- `agent_busy`
- `invalid_signature`
- `expired`
- `replay`
- `target_mismatch`
- `invalid_task`
- `capability_unsupported`
- `local_policy`
- `internal_error`

Controller-to-agent cancel message:

```json
{
  "type": "task_cancel",
  "payload": {
    "job_id": "job-1",
    "task_id": "task-1",
    "reason": "operator requested cancel"
  }
}
```

Agent는 `task_cancel.task_id`가 현재 실행 중인 task와 일치할 때만 cancel을 적용한다. 다른 task id의 cancel은 무시한다. Cancel된 command는 일반 failure가 아니라 `canceled` terminal result로 보고해야 한다.

command/runbook 실행 결과는 application log가 아니라 job output storage로 들어간다.

```json
{
  "type": "output_chunk",
  "payload": {
    "job_id": "job-1",
    "task_id": "task-1",
    "stream": "stdout",
    "sequence": 0,
    "data": "ok"
  }
}
```

```json
{
  "type": "task_result",
  "payload": {
    "job_id": "job-1",
    "task_id": "task-1",
    "exit_code": 0,
    "status": "succeeded",
    "reason": "",
    "artifacts": [
      {
        "artifact_id": "artifact-1",
        "step_id": "template:template",
        "destination": "/etc/app.conf",
        "checksum_sha256": "3f8a286ab667f1b60da3a12c138461dac343cab1eb3928c433a8062a61d417f8",
        "size_bytes": 5,
        "retention_class": "rendered_template",
        "content_bytes": [104, 101, 108, 108, 111]
      }
    ]
  }
}
```

`output_chunk`는 final result가 아니다. Controller는 output chunk를 job output storage에 저장하지만 assignment를 `succeeded` 또는 `failed`로 바꾸지 않는다.

Controller는 `task_result.status`가 있으면 이를 우선 사용한다. `succeeded`는 assignment `succeeded`와 job `success`, `failed`는 assignment `failed`와 job `failed`, `canceled`는 assignment/job `canceled`, `timed_out`은 assignment/job `expired`로 저장한다. 구버전 agent가 `status` 없이 `task_result`를 보내면 `exit_code == 0`은 success, 그 외는 failed로 fallback 처리한다. 이후 multi-agent fanout에서는 job aggregate 계산이 target별 assignment 결과를 기준으로 확장된다.

`task_result.artifacts`는 rendered artifact metadata를 전달한다. `content_bytes`는 optional이다. 구버전 agent처럼 `content_bytes`가 없으면 Controller는 metadata row만 저장하고 retrieval API에서는 body missing으로 처리한다. `content_bytes`가 있으면 Controller는 `size_bytes`, `checksum_sha256`, `retention_class`를 검증한 뒤 `ArtifactStore`에 저장한다. Checksum mismatch, size mismatch, max-size 초과, store failure는 rendered body를 저장하지 않고 protocol/store error로 처리한다. Product log와 audit에는 artifact id, size, checksum prefix, status만 허용하며 destination path, local store path, body bytes, rendered template body, secret value를 남기지 않는다.

이미 `canceled`, `expired`, `failed`, `succeeded`, `rejected` 같은 terminal assignment가 된 뒤에 늦은 `task_result`가 도착하면 Controller는 terminal 상태를 덮어쓰지 않고 `task_result_ignored` audit event만 남긴다. Disconnect나 duplicate session 때문에 늦은 success가 도착해도 canceled job을 success로 바꾸지 않는다.

## Security Event

```json
{
  "type": "security_event",
  "payload": {
    "agent_id": "agent-1",
    "action": "task_verification_failed",
    "detail": "invalid signature"
  }
}
```

`detail`에는 payload 원문이나 secret을 넣지 않는다. 실패 사유 중심의 짧은 문자열만 허용한다.
