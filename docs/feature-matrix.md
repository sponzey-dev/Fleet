# Sponzey Fleet Feature Matrix

검토일: 2026-10-23
기준 구현: `6683792` / v0.0.20 기반 + 미커밋 reporting/recovery 변경을 포함한 현재 checkout.
실제 코드·test·manifest가 최종 근거이며 이 문서는 이번 세션의 검증 통과/최신 배포를 뜻하지 않는다.

프로젝트 범위·우선순위·단계는 [문서 지도](../.docs/README.md),
[기능 지도](../.docs/product/capabilities.md), [전체 계획](../.docs/plans/plan.md)이 소유한다.
이 문서는 interface별 구현 세부와 현재 제한을 소유한다.

상태 표기:

- `Implemented`: 현재 동작하고 문서/테스트가 대체로 존재한다.
- `Partial`: 기본 흐름은 있으나 제품화에 필요한 상태 모델, UX, 테스트, 문서가 더 필요하다.
- `Planned`: 계획은 있으나 아직 구현되지 않았다.
- `Policy decision required`: 기술 구현 전에 제품 정책 결정이 필요하다.

## Capability Cross-reference

아래 ID는 전체 기능 지도와 연결하는 키이며 단계·출시 일정이 아니다.
명세 확정/구현/실제 검증을 구별하고, 기존 실행 task의 진행은 `.tasks/`에서 확인한다.

| 항목 | 현재 상태 | 관련 기능 ID | 선행 조건 |
| --- | --- | --- | --- |
| Template primitive / rendered artifact | Partial | RBK-001/RES-003/SEC-002 | Plain-variable `file.template` parser/render/runner path, explicit SecretProvider-compatible resolver injection, TaskResult artifact metadata reporting, optional body persistence into local `ArtifactStore`, SQLite metadata storage, checksum drift contract, local `ArtifactStore` body contract, Controller artifact retrieval API, Web Admin artifact metadata/retrieval surface, typed `SecretRef`, application `SecretProvider` trait, disabled/static fake provider redaction tests, typed startup `SecretProviderSettings`, controller bootstrap provider factory, and agent runbook resolver handoff exist. Secret-backed template artifact body bytes are omitted by default. External adapters remain. |
| Artifact metadata/store contract | Partial | EXT-003 | SQLite metadata table, controller metadata write path, filesystem-neutral `ArtifactStore` application contract, local filesystem implementation with checksum verification/path traversal rejection/delete contract, task result artifact body persistence, Controller artifact retrieval API, and Web Admin artifact metadata/retrieval surface exist. S3-compatible adapter remains. |
| Policy-based remediation lifecycle | Implemented | DRF-001 | Request state machine, SQLite metadata persistence, persisted approval request, approved signed runbook job creation, Controller task-event lifecycle reconciliation, and feature-gated Postgres repository/runtime adapter dispatch exist. Verified signed drifted reports atomically create one idempotent Proposed request with origin/audits. A successful remediation result atomically creates one correlated signed verification drift Job and queues it after commit when disconnected. Before listener readiness, a bounded startup scan reconciles correlation-free pending verification records and safely audits unverifiable legacy rows without dispatch. Successful verification plus fresh compliant evidence after remediation execution atomically resolves the remediation and only its origin drift, regardless of report/result delivery order. Legacy manual running/result/verify API and CLI commands are deprecated and return `409`; Web Admin displays persisted lifecycle state without manual transition controls. Approval-bypassing execution remains out of scope |
| Postgres store | Partial | EXT-002 | `DatabaseSettings`, typed Postgres URL/SSL mode/connect timeout/pool parsing, blocking Postgres client pool boundary, minimum native TLS adapter for `sslmode=prefer/require`, SQLite shared repository contract harness, feature-gated Postgres migration skeleton, repository slices through RemediationRequest, `ControllerStore`/`ControllerStoreRef` boundary, feature-gated Controller Postgres open/migration, direct server runtime adapter dispatch, typed job+assignment transaction boundary, and queued-only dispatch claim/release contract exist. A 2026-08-31 local PostgreSQL 18.3 disposable runtime run passed all 13 ignored repository tests, each in a fresh database. Custom CA/client certificate rotation, scheduled drift/retention lease, and HA claim semantics remain follow-up tasks. Current checkout startup rejects Postgres assignment/report recovery; repository/feature tests do not establish usable Controller runtime support. |
| S3-compatible artifact store | Planned | EXT-003/SEC-002 | Decision recorded; adapter implementation deferred until typed bootstrap `ArtifactStoreSettings`, external secret reference credential handling, feature-gated contract tests, and redaction tests are in place |
| mTLS / certificate and key rotation | Partial | SEC-001/SEC-002/EXT-001 | `ControllerTrustSettings`, `TlsServerIdentitySettings`, `ControllerSigningIdentitySettings`, and `AgentClientCertificateTrust` separate TLS server identity, controller signing identity, and future agent client cert trust at startup. `--agent-client-ca-cert`/`agent_client_ca_cert_path` is parsed as explicit future mTLS trust material but rejected before serving requests until listener enforcement exists. Agent certificate lifecycle domain state machine, snapshot/restore boundary, application repository/use-case contract, SQLite/Postgres-shaped public metadata persistence foundation, public-only lifecycle update/ack protocol schema, controller ack observation/audit, internal controller update dispatch helper, admin protected status and issuance request API/CLI surfaces, and agent explicit rejection ack exist; issue/renew/activate/revoke public controller surfaces, agent-side certificate application, listener enforcement, revocation propagation, and runtime trust checks remain. Controller signing key rotation domain state machine, dual-trust decision policy, rotation-state persistence contract, application operation/audit boundary, signing material validation boundary, filesystem staging/swap boundary, bootstrap runtime guard, explicit signer selection context, agent-side controller signing trust bundle verification, trust-bundle update/ack protocol and session foundation, agent trust sidecar restart survival, read-only rotation status API/CLI, mutation API/CLI, restart-plan API/CLI, audited external restart-action API/CLI, admin-triggered trust-bundle rollout API/CLI, bounded retry coordinator API/CLI, already-current ack skip, staged rollout domain state machine/persistence/worker, and Web Admin staged rollout surface exist. In-process hot reload/self-restart is not a current product path without a future ADR and reload state machine |
| Secret provider / OpenBao boundary | Partial | SEC-002: typed SecretRef·Application port·disabled/static test·runner resolver/body omission 기반만 구현됨. 실제 Agent Runbook 경로는 Disabled provider를 사용한다. D-007/014로 OpenBao KV v2·Agent 직접 조회·AppRole/준비별 단기 인증 계획을 확정했으며 adapter/bootstrap source·민감 file/lifecycle·실제 인수는 미구현이다. [명세](../.docs/domains/security/features/SEC-002-openbao-kv-v2.md) |
| OIDC and project/team RBAC | Planned | IAM-001/IAM-002 | Route permission matrix와 audit actor contract |
| Git runbook/policy catalog sync | Partial | CAT-001/CAT-002 | Public HTTPS source register, bounded async sync, durable source/revision/document metadata, explicit ready-revision activation, immutable Runbook/Policy provenance, protected API/CLI, and Runbooks/Policies Admin explorer exist. Admin three-list paging/selection, bounded canonical sync-operation status and explicit activation confirmation are implemented and covered by scoped API/Node/native-browser checks; strict catalog-reference Job creation API, atomic provenance/approval storage and protected immutable Job detail provenance are connected; Admin active-Runbook review, exact target snapshot, explicit reference-only submit, stable-ID reconciliation, shared approval/observation and immutable provenance display have scoped Node/native-browser verification; the public Git-to-approval-to-result journey has scoped two-Agent Linux/native-browser acceptance; private Git and project scope are separate. Catalog performance workflow/release wiring exists; actual pinned-runner evidence must be checked independently. |
| Slack/Teams notification and telemetry export | Planned | EXT-004 | Redacted summary payload contract |
| One-line installer and package expansion | Planned | EXT-005 | Signature verification and version pinning |
| Agent staged update policy | Planned | EXT-005 | Signed update artifact and rollback state machine |
| HA controller coordination | Planned | EXT-007 | Postgres transaction/lease semantics |
| Compliance audit hash chain and signed export | Planned | EXT-008 | SEC-001/SEC-002/EXT-001 signing/key policy |
| Windows/macOS agent support | Planned | EXT-006 | Platform capability adapter boundary |
| Ansible bridge import subset | Planned | EXT-009 | Fleet runbook schema validation |
| Plugin/external adapter boundary | Planned | EXT-010 | Signed manifest and disabled-by-default policy |
| Fleet scale/load gates | Planned | QUA-001 | P0/P1 production paths complete |

## Controller

| 기능 | 상태 | 현재 기준 |
| --- | --- | --- |
| 단일 `fleet` 바이너리의 controller subcommand | Implemented | `fleet controller init/start` |
| controller data directory 초기화 | Implemented | key, admin token hash, SQLite store 생성 |
| Web Admin static serving | Implemented | `/admin` |
| OpenAPI JSON과 Swagger UI | Implemented | `/openapi.json`, `/swagger-ui` |
| HTTP controller URL 허용 | Implemented | test-only warning과 audit 필요 |
| Built-in HTTPS | Implemented | `--tls-cert`, `--tls-key`; typed trust settings keep TLS server material separate from controller signing keys |
| Reverse proxy HTTPS | Implemented | `--external-url https://...` |
| Persistent agent session registry | Implemented | agent outbound WebSocket session |
| Immediate task dispatch | Implemented | active authenticated session으로 push |
| 세분화된 assignment ack/start/reject state | Implemented | Persistent session은 TaskAck/TaskStarted/TaskRejected를 owner-bound v2 Lifecycle report 및 signed receipt로 처리한다. accepted/started와 실행 전 dispatched→rejected 상태, Job aggregate, audit, inbox marker를 SQLite transaction으로 commit하고 exact duplicate에는 같은 receipt를 재생한다. TaskRejected reason은 redacted 값으로 Assignment에 저장한다. direct one-shot은 control event를 사용한다 |
| Job cancel API와 task cancel protocol | Implemented | `/api/jobs/{job_id}/cancel`, `task_cancel`, canceled terminal state |
| Timeout/cancel terminal 구분 | Implemented | command timeout은 expired, operator cancel은 canceled |
| Multi-agent fanout 상태 집계 | Implemented | selector target snapshot, assignment, concurrency, maxFailures, partial_success 계산 |
| Controller key rotation | Partial | SEC-001/SEC-002/EXT-001: domain signing key rotation state machine, dual-trust window decision policy, SQLite/Postgres-shaped persistence contract, application request/validate/activate/retire/fail operation use cases, key material sign/verify validation guard, filesystem staging/swap rollback boundary, bootstrap runtime guard, security audit boundary, explicit signer selection context, agent-side controller signing trust bundle verification, trust-bundle update/ack protocol and session foundation, agent trust sidecar restart survival, read-only status API/CLI, mutation API/CLI, restart-plan API/CLI, audited external restart-action API/CLI, admin-triggered trust-bundle rollout API/CLI, bounded retry coordinator API/CLI, already-current ack skip, staged rollout domain state machine/persistence/worker, and Web Admin staged rollout surface exist. In-process hot reload/self-restart is not a current product path without a future ADR and reload state machine |
| Backup/restore command | Implemented | Non-migrating inspection, private/noclobber JSON archive, real DB/key dry-run, local lease, independent human/delivery epoch rotation and atomic directory install. Owned native recovery/restore/rollback rehearsal passes; custom external DB and live/HA backup are outside this profile |
| Scheduled drift worker | Implemented | due schedule을 controller-signed drift-check job으로 생성하고 missed/skip audit 기록. EXT-007 전까지 HA-safe claim/lease는 없음 |
| Background retention worker | Implemented | controller-managed worker와 explicit cleanup command가 같은 application use case 사용. EXT-007 전까지 HA-safe retention lease는 없음 |
| Postgres store | Partial | EXT-002: typed database settings with startup-only Postgres URL/SSL mode/connect timeout/pool parsing, blocking Postgres client pool boundary, minimum native TLS adapter for `sslmode=prefer/require`, shared SQLite repository contract harness, feature-gated migration skeleton, repository slices through RemediationRequest, `ControllerStore`/`ControllerStoreRef` boundary, feature-gated Controller Postgres open/migration, direct Controller server runtime adapter dispatch, typed job+assignment transaction boundary, and queued-only dispatch claim/release contract exist. Custom CA/client certificate rotation, scheduled drift/retention lease, and HA claim semantics remain Current checkout startup rejects Postgres assignment/report recovery; repository/feature tests do not establish usable Controller runtime support. |

## Agent

| 기능 | 상태 | 현재 기준 |
| --- | --- | --- |
| Agent enrollment/init | Implemented | `fleet agent init`, alias `enroll` |
| Persistent outbound WebSocket session | Implemented | heartbeat와 task dispatch 분리 |
| Reconnect 지속 시도 | Implemented | `--once`, `--max-reconnect-attempts`로 변경 가능 |
| Controller fingerprint pinning | Implemented | enrollment 이후 controller identity 확인 |
| Signed task envelope 검증 | Implemented | signature, expiry, replay, target 검증 |
| Command task 실행 | Implemented | output chunk와 result 전송 |
| Command cancel/timeout process boundary | Implemented | Darwin/Linux는 출력 callback 오류·cancel·timeout에 새 process group을 정리하며, bounded poll로 inherited pipe 대기에도 취소/시간 제한을 확인. 이미 수행한 변경이나 group 이탈 daemon은 rollback하지 않음 |
| Crash-safe execution reporting | Partial | Persistent Command/no-artifact Runbook admission, start intent, restart failure reporting, per-stream output counts, journal replay/receipt, DriftCheck evidence/final reporting 및 SQLite owner-bound inbox transaction이 구현됨. Artifact-bearing Runbook final은 strict v2 report로 Controller가 checksum/size 검증, immutable body put, artifact metadata/Assignment/Job/audit/inbox 원자 commit 후 receipt를 저장한다. SQLite Controller는 pending final inbox를 시작 시 및 30초마다 최대 100건/8 MiB로 재처리하고, receipt는 효과 commit 뒤 persist하여 활성 session writer에 전달한다. 이미 효과가 commit됐으나 receipt가 없는 final도 최대 100건씩 key/digest만으로 찾아 효과 반복 없이 receipt를 저장한다. 손상·owner 불일치·출력 누락·미지원 효과·terminal Assignment는 pending/fail-closed한다. Artifact report는 Agent journal에 저장되지 않아 pre-inbox disconnect replay를 보장하지 않으며, 파일/DB orphan cleanup도 없다. Exact duplicate는 효과를 반복하지 않으며 terminal Assignment를 되돌리지 않는다. no-artifact Command/Runbook/DriftCheck final과 lifecycle late-G2 disposition은 owner/reason을 확인해 terminal state를 보존한다. Agent journal schema v3/v4 local migration은 기존 row/bytes를 보존하고 active v2 `StartIntent` 업그레이드를 거부한다. ACK-cleanup 된 보고의 과거 backup 복구, direct one-shot final, Drift execution admission/restart recovery, Postgres G2/report recovery와 exactly-once 실행은 미지원이다 |
| Persistent task output completeness barrier | Implemented | Active v2 persistent Command와 artifact가 없는 Runbook final은 Agent journal에 저장된 stdout/stderr chunk 수와 `truncated`를 필수 보고한다. Controller는 각 stream의 `[0, count)`가 모두 저장될 때까지 final effect/receipt를 보류하고, 잘린 출력은 성공으로 처리하지 않는다. Persistent DriftCheck terminal report는 빈 output summary를 사용하며 evidence report와 별도다. 이는 journal에 저장한 조각의 전달 확인이며 task 실행이 생성한 모든 byte의 capture 보장은 아니다. Artifact-producing Runbook 및 direct one-shot 출력은 이 계약 밖이다 |
| Runbook primitive 실행 | Partial | package/service/file.copy와 plain-variable/secret-ref file.template 실행 경로 존재. Secret-backed rendering uses explicit agent resolver handoff and omits artifact body bytes by default. `fleet apply` remains validation-only and does not resolve secrets. file.template은 TaskResult artifact metadata와 optional non-secret rendered body를 controller에 보고한다. Local `ArtifactStore` body persistence, Controller retrieval API, Web Admin artifact surface, typed `SecretRef`, and application `SecretProvider` contract exist |
| Drift check assignment 실행 | Implemented | signed drift job dispatch. File SHA-256 policy checks require 64-char lowercase hex and can use rendered template artifact checksum as expected value |
| Facts 수집 | Implemented | static inventory payload, memory/disk usage 제외, disk/partition/mount/network inventory 포함 |
| Metrics 수집 | Implemented | usage telemetry snapshot |
| Operational log upload | Implemented | 기본 30초, disable/interval 조정 가능 |
| Cancellation protocol | Implemented | `task_cancel`, process kill boundary, `canceled` terminal result |
| Capability declaration | Implemented | protocol snapshot, SQLite latest snapshot, Agent API/Web Admin summary, dispatch gate source of truth |
| Least privilege execution mode | Partial | unsupported/stale stored capability는 dispatch 전 rejected 처리. EXT-006에서 platform capability adapter, QUA-001에서 scale smoke |

## Web Admin

| 기능 | 상태 | 현재 기준 |
| --- | --- | --- |
| Admin token 입력 | Implemented | protected API Bearer token |
| Agent list/detail | Implemented | online/offline/revoked 표시 |
| Enrollment token 생성 | Implemented | Web Admin과 API |
| Command job 생성 | Implemented | high-risk/broad target은 approval request 생성 |
| Job output polling viewer | Implemented | raw output은 product log와 분리 |
| Long-running Job observation | Implemented | Run/Runbooks 공통 결과 panel에 단일 owner·pause/resume·route/auth 취소·늦은 응답 차단·last-update/오류 표시를 연결했다. Artifact 조회도 같은 view owner의 취소와 deadline을 사용한다. 부분 성공도 최종 출력 조회 뒤 관찰을 종료하며 대상별 결과는 보존한다. SQLite page API·strict cursor와 Admin bounded window/history·terminal drain을 연결했다. 표시 제외/보관 이력을 구분하고 재조회·화면 이탈 때 owner를 해제한다. 두 Linux Agent의 긴 Command·실제 browser/1440·1024·768 viewport·keyboard/focus/scroll·API 응답 본문/DOM 비용을 검증했다. 반복 전송은 줄지만 요청수와 JS 검증 비용은 증가하는 측정상 trade-off가 있으며, fleet 전체 부하/SLA나 Postgres runtime 지원을 뜻하지 않는다. catalog 실행 통합은 별도 범위다. |
| Facts inventory view | Implemented | grouped rendering and disk/mount table |
| Metrics chart | Implemented | range selector, recent samples, manual refresh |
| Drift latest/history 표시 | Implemented | latest and paged history |
| Audit list | Implemented | 최근 audit 조회 |
| Approval queue | Implemented | pending approvals, approve/reject, expire due |
| Target preview | Implemented | selector preview endpoint와 Web Admin command/runbook job 생성 전 preview, warning, selected/disabled/offline count 표시 |
| Runbook catalog/validate UI | Partial | Runbook job creation and result status exist. Runbooks/Policies share a public catalog explorer for source, revision, and body-free document metadata with explicit register/sync/activate actions; Runbooks additionally supports active-document review, explicit target preview and reference-only Job creation for shared approval/result observation. Context changes retire the review; uncertain submissions use the same Job ID. The public Git-to-result journey has scoped two-Agent Linux/native-browser acceptance. A dedicated authoring/validation UI remains separate. |
| Policy assignment API | Implemented | policy source 저장, direct agent assignment, schedule 저장/조회. Verified signed drifted evidence가 Proposed remediation request를 원자적으로 생성하며, TaskStarted/TaskResult가 persisted remediation lifecycle을 반영하고 success가 correlated signed verification Job을 생성한다. successful verification과 fresh-compliant evidence는 remediation과 origin drift를 원자적으로 resolve하며 startup recovery도 구현됐다. legacy manual lifecycle API는 `409` deprecated contract다 |
| Policy assignment UI | Implemented | policy save/list, selected-agent assignment, drift schedule와 persisted proposal/approval/running/pending verify/resolved lifecycle queue/detail을 표시한다. manual running/result/verify control은 제공하지 않는다 |

## CLI

| 기능 | 상태 | 현재 기준 |
| --- | --- | --- |
| `--help`, `--version` | Implemented | top-level CLI 지원 |
| `controller init/start` | Implemented | data dir 기반 |
| `agent init/start` | Implemented | enrolled agent 실행 |
| `enroll-token create/list/revoke` | Implemented | controller data dir 사용 |
| `run` | Implemented | controller command job 생성 |
| `facts`, `metrics` | Implemented | 조회 CLI |
| `logs` local file tail | Partial | local file tail 구현. Remote managed log source expansion은 EXT-004 telemetry/export boundary 이후 별도 task |
| `drift check` | Implemented | local policy check |
| `apply` | Partial | validation-only. Catalog activation is a separate explicit revision-pointer change; execution continues through the signed job path only. |
| `retention cleanup` | Implemented | explicit cleanup |
| `audit export` | Implemented | category filter, cursor paging, JSONL renderer |
| `login`/admin profile | Implemented | `.fleet/cli-profile.json`, owner-only permission check, remote operator commands |
| `upgrade` | Partial | dry-run upgrade policy inspection only. EXT-005에서 signed staged update policy |

## Packaging

| 기능 | 상태 | 현재 기준 |
| --- | --- | --- |
| npm wrapper `@sponzey/fleet` | Implemented | Rust binary launcher |
| Platform npm packages | Implemented | darwin/linux arm64/x64 |
| GitHub Actions npm publish | Implemented | matching tag workflow |
| Standalone release tarballs | Implemented | release workflow artifact packaging and checksum verification script |
| Linux glibc baseline check | Implemented | Ubuntu 22.04 build and check script |
| Linux systemd service commands | Implemented | install/start/status/logs/uninstall with dry-run support |
| Release signature verification | Implemented | committed release public key, fail-closed GitHub signing secret, detached checksum signature, and signed dry-run evidence artifact |
| Windows package | Planned | EXT-006 agent/service support 후 EXT-005 packaging track에서 publish gate 추가 |
| `.deb`, `.rpm`, Homebrew, Docker | Planned | EXT-005: package decision record, smoke command, signature/version pinning |
| One-line installer | Planned | EXT-005: dry-run, version pinning, checksum/signature verification |

## API and OpenAPI

| 기능 | 상태 | 현재 기준 |
| --- | --- | --- |
| OpenAPI 3.1 JSON | Implemented | `/openapi.json` |
| Swagger UI | Implemented | `/swagger-ui` |
| Enrollment token API | Implemented | create/list/revoke |
| Agent inventory API | Implemented | list/detail/labels/revoke-key |
| Facts/metrics/drift latest API | Implemented | agent/controller time fields 포함 |
| Facts/metrics/logs/drift paging API | Implemented | cursor paging |
| Job command/runbook/drift API | Implemented | high-risk confirmation |
| Job output API | Implemented | polling |
| Audit export API | Implemented | `/api/audit/export`, category filter, cursor paging, redacted values |
| Public/internal endpoint classification | Implemented | docs/api.md surface table |
| OpenAPI snapshot compatibility gate | Implemented | controller route contract test and Web Admin schema coverage |
| Generated SDK | Deferred | Web Admin dependency-free client is covered. A public SDK needs project RBAC and catalog API stabilization in a separate phase. |

## Security and Audit

| 기능 | 상태 | 현재 기준 |
| --- | --- | --- |
| Enrollment token hash storage | Implemented | raw token 1회 노출 |
| Admin token hash storage | Implemented | bootstrap token |
| Agent/controller key pairs | Implemented | Ed25519 identity |
| Controller fingerprint pinning | Implemented | agent enrollment 이후 |
| Signed task envelope | Implemented | command/runbook/drift |
| Replay nonce guard | Implemented | agent local file-backed nonce store, restart 이후 replay 거부, corruption fail-closed |
| High-risk confirmation | Compatibility | `confirmed_high_risk`는 approval 대체 아님 |
| Approval request workflow | Implemented | pending approval 생성, approve/reject/expire API, Web Admin queue |
| Personal administrator identity | Implemented | IAM-001: 단일 조직 로컬 계정·owner 전용 타인 관리·각 역할 본인 credential 관리, 고정8h session/30d PAT/15m 설정·reset, 공용token 원자 전환·last-owner guard·local recovery·restore human epoch 회수, 업무 commit 최신 권한·불변 audit actor, Admin/CLI 연결. 실제 두 사용자 HTTPS browser/API/CLI·Linux Agent 작업 중 회수·복구·bounded 인증 부하를 격리 환경에서 검증했다. 미배포 변경이며 전체 Fleet SLA·release acceptance를 뜻하지 않는다. |
| Federated identity and project isolation | Planned | OIDC/MFA와 project/team isolation은 IAM-001 인수에 포함하지 않음 |
| Audit events | Partial | 주요 이벤트와 category registry/export는 구현. EXT-008에서 tamper-evident chain/signed manifest |
| Audit export | Implemented | API/CLI category filter, cursor paging, SecretRef marker, update/delete API 없음 |
| Secret redaction | Partial | logs/output 경계 계속 보강 필요 |
