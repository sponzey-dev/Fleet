# Sponzey Fleet Storage and Migration Guide

작성일: 2026-07-07

이 문서는 Controller store의 현재 기준선과 이후 schema 변경 규칙을 정리한다.
목표는 job/assignment lifecycle, approval, policy 같은 다음 단계 schema 변경을
ad hoc으로 추가하지 않도록 하는 것이다.

프로젝트 전체 계획은 [plan.md](../.docs/plans/plan.md), 기능 ID는
[capabilities.md](../.docs/product/capabilities.md)가 소유한다. 아래 남은 Phase 번호는
과거 설계의 번호이며 활성 `.tasks/` phase나 구현 완료를 뜻하지 않는다.

## 현재 Storage 범위

현재 production-ready 기본 store는 SQLite다.

- 기본 controller DB는 data directory 아래 `controller/fleet.db`에 둔다.
- `fleet controller start --db sqlite://...`로 SQLite DB 경로를 bootstrap 시점에 명시할 수 있다.
- `postgres://...`와 `postgresql://...` URL은 typed `DatabaseSettings`에서
  Postgres backend로 분류된다. `fleet-controller --features postgres`에서는
  explicit typed `PostgresConnectionSettings`로 `PostgresStore`를 열고 migration을
  실행한 뒤 Controller runtime repository adapter 뒤로 전달한다. `postgres`
  feature가 꺼진 build는 Postgres backend를 bootstrap에서 거부한다. request
  handler, UI, runtime API에서 DB backend를 바꾸는 경로는 없다.
  다만 현재 checkout의 Controller startup은 Postgres Assignment/report recovery 미지원으로
  listener readiness 전에 거절한다. open/migration 배선과 repository 실DB 시험은 현재
  Postgres Controller 운영 가능성을 뜻하지 않는다. 후속 기능은 EXT-002다.
- Postgres connection settings는 startup-only 값이다. URL query의 `sslmode`는
  `disable`, `prefer`, `require`만 허용하고 기본값은 `disable`이다. URL query의
  `connect_timeout`은 초 단위 양의 정수만 허용하고 기본값은 10초다. URL query의
  `pool_max_connections`는 양의 정수만 허용하고 기본값은 4다. URL query의
  `pool_checkout_timeout`은 초 단위 양의 정수만 허용하고 기본값은 5초다. 현재
  `PostgresStore`는 blocking `postgres` client pool을 infrastructure 내부에서
  초기화하고 repository method는 pool checkout helper를 통해 client를 얻는다.
  Checkout failure는 URL, username, password, host를 포함하지 않는 high-level
  store error로 반환되어야 한다. `sslmode=disable`은 `NoTls`로 연결하고,
  `sslmode=require`는 native platform TLS adapter로 server TLS 연결을 시도한다.
  `sslmode=prefer`는 TLS 연결을 먼저 시도하고 실패하면 `NoTls` 연결을 한 번
  시도한다. 현재 범위는 server certificate 검증을 platform trust store에
  위임하는 최소 adapter이며 custom CA, client certificate/mTLS, certificate
  rotation은 Phase 5 작업이다.
- Postgres store는 feature-gated implementation slice다. `fleet-store --features
  postgres`는 explicit URL을 받는 `PostgresStore::connect`, schema migration entrypoint,
  ignored integration migration test, CatalogRepository와 Agent/AdminToken/ControllerIdentity/AgentIdentity
  repository trait implementation, EnrollmentToken repository trait implementation, Audit
  writer/query/export repository trait implementation, ApprovalRequest repository trait
  implementation, basic Job/TaskAssignment persistence repository implementation, Command/Runbook/Drift
  job repository implementation, DispatchAssignmentRepository pending assignment query와
  dispatch/reject/running/expired state transition, JobOutput/Facts/Metrics/AgentLog
  repository implementation, Drift/Policy/AgentCapability repository implementation,
  JobQuery/ArtifactMetadata/Retention repository implementation, RemediationRequest repository
  implementation을 제공한다. `fleet-controller --features postgres`는 direct
  `ControllerStore`/`ControllerStoreRef` dispatch를 통해 이 repository slice를
  server runtime handler에서 사용한다.
- runtime 중 DB URL이나 data directory를 바꾸는 방식은 허용하지 않는다.

현재 store는 `crates/fleet-store`의 `SqliteStore`가 담당한다.

현재 기본 data directory 구조:

```text
<data-dir>/
  controller/
    fleet.db
    controller_public.key
    controller_private.key
  agent/
    agent.conf
    agent_private.key
```

Controller backup/restore는 `controller/` 하위 파일만 대상으로 한다. `agent/`
하위 파일은 각 agent host의 local identity이므로 controller backup에 포함하지
않는다. 현재 job output, rendered artifact metadata, remediation request metadata,
facts, metrics, drift, audit, enrollment token hash는 SQLite `controller/fleet.db` 안에 저장된다.
`file.template` runner 결과는 agent `task_result` artifact metadata로 controller에
보고된다. `task_result.artifacts[].content_bytes`가 있으면 Controller는 checksum과
size를 검증한 뒤 body를 local `ArtifactStore`에 저장한다. Metadata-only legacy payload는
계속 허용되지만 retrieval API에서는 body missing으로 처리될 수 있다. Phase 4에는
filesystem-neutral `ArtifactStore` application contract와 local filesystem implementation이
있다. Controller bootstrap은 typed immutable `ArtifactStoreSettings`를 한 번 만들고,
MVP default backend인 local filesystem root를 `<data-dir>/controller/artifacts`로
고정한 뒤 `LocalArtifactStore`를 dependency로 주입한다. 이 local implementation은
artifact id 기반 object key만 허용하고 checksum verification, corrupt/missing result,
idempotent delete를 제공한다. 현재 local `put`은 같은 ID/class의 동일 body 재전송은 허용하지만
다른 body나 손상된 기존 object를 덮어쓰지 않는다. 새 body는 같은 디렉터리의 owner-only 임시
파일에 기록·동기화한 뒤 no-clobber link로 공개하고 디렉터리를 동기화한다. 이 파일 작업과
Controller DB metadata/Assignment transaction은 아직 하나의 원자 작업이 아니며, 충돌·중단
뒤 남는 임시 파일 또는 orphan object의 정리는 후속 복구 경계가 필요하다. Controller artifact retrieval API는 job id와 artifact
id만 받아 metadata 확인 후 verified body를 반환한다. Web Admin은 artifact metadata와
verified body retrieval action을 제공한다. Runtime API, Web Admin, request payload, process env는 artifact store backend 또는 root를 변경하지 않는다.
S3-compatible object storage는 아직 없다.

## S3-Compatible Artifact Store Decision

Decision: defer S3-compatible adapter implementation in the current Phase 4
slice.

Reason:

- Local `ArtifactStore` contract, body persistence, retrieval API, and Web
  Admin retrieval surface are now verified.
- Remote object storage introduces credential source, TLS trust, endpoint
  policy, retry/backoff, and object-store consistency decisions that must not
  be hidden inside request handlers or mutable global state.
- Phase 5 still owns SecretProvider-backed rendering and broader secret
  lifecycle work. Until that boundary exists, adding a concrete S3 SDK adapter
  would either hard-code startup secrets into a low-level adapter or invent a
  storage-specific secret path.

Required adapter design:

- Application and Domain crates must not depend on an S3 SDK, HTTP client, filesystem path, or environment variable lookup.
- The S3-compatible implementation must live in infrastructure behind
  `fleet_application::ArtifactStore`.
- Local filesystem remains the default artifact store backend.
- The local default is represented by typed immutable `ArtifactStoreSettings`
  and resolves to `<data-dir>/controller/artifacts` during Controller bootstrap.
- Backend selection must happen during Controller bootstrap only. No runtime configuration mutation is allowed.
- Web Admin and REST APIs must never accept artifact root, bucket name,
  endpoint URL, access key, secret key, session token, object key, or signed URL
  as request payload.
- Credentials must be startup secrets or secret references. Raw credentials must not be stored in SQLite/Postgres tables, application logs, audit values, Web Admin state, or job output.
- Object keys must be derived from artifact id and retention class only.
  Destination paths and local filesystem paths must never become remote object
  keys.
- `put` succeeds only after checksum verification. `get` returns bytes only
  through the `ArtifactStore` contract. `verify` returns `Verified`, `Missing`,
  or `Corrupt`. `delete` must be idempotent for missing objects.
- Retry/backoff, if added, must be bounded and explicit. Request handlers must
  not wait on unbounded remote object retries.

Logging policy:

- Product Log may include backend kind, artifact id, retention class,
  checksum prefix, size, and high-level status.
- Field Debug Log may include redacted endpoint host, retry count, and latency.
- Logs must not include access key, secret key, session token, signed URL,
  bucket credentials, object body, local path, destination path, or full HTTP
  request/response body.

Test strategy:

- Keep local `ArtifactStore` contract tests as the default workspace tests.
- Add any S3-compatible adapter behind an explicit feature flag.
- Use a fake/in-memory compatible client for fast contract tests.
- Mark real S3/MinIO integration tests ignored or feature-gated and require
  explicit endpoint/credential input at test startup only.
- Add redaction tests for adapter errors before enabling production use.

Implementation trigger:

- Introduce typed immutable `ArtifactStoreSettings` for `local` and `s3`.
- Define secret reference/startup secret handling for remote credentials.
- Add a feature-gated infrastructure adapter that passes the same
  put/get/verify/delete contract as `LocalArtifactStore`.
- Wire Controller bootstrap selection through explicit settings object or
  dependency injection only.
- Update release readiness gates with local default tests and optional ignored
  remote integration instructions.

## Migration 방식

현재 migration은 Rust 코드 기반이다.

- `SCHEMA_SQL`은 새 DB 또는 없는 table을 생성한다.
- `SqliteStore::migrate()`는 `SCHEMA_SQL`을 실행한 뒤 필요한 additive migration을 수행한다.
- 현재 additive migration은 `ensure_column` 방식으로 기존 table에 빠진 column을 추가한다.
- 현재 schema version은 `schema_migrations` table의 `fleet_store` row에 기록한다.
- 현재 binary보다 최신 schema의 DB를 직접 열면 migration/version 재기록 전에 거부한다.
- 현재 버전 상수는 `CURRENT_SCHEMA_VERSION`이다.

현재 기준:

```text
schema_migrations
  name = fleet_store
  version = CURRENT_SCHEMA_VERSION
```

현재 `CURRENT_SCHEMA_VERSION`은 28이다. v23은 기존 Controller row를 보존하면서
`controller_delivery_identity`에 random namespace·store epoch를 추가했고, v24는
`controller_report_inbox` pending-effects staging table을 추가했다. v25는 기존 inbox row를
보존하면서 `controller_report_receipts`에 서명된 저장 receipt의 영속 재응답 row를 추가했다.
v26은 기존 inbox report class 제한에 `drift_evidence`를 추가한다. SQLite는 기존 inbox와
receipt row/foreign key를 보존하며 class 제약 테이블을 다시 만든다; Postgres feature migration은
동일한 report class 제한을 확장한다. Live Controller report effect는 현재 SQLite 전용이다.

v27은 SQLite output-page projection·append/retention trigger를 추가한다. 해당 단계는
자신의 version 27만 기록하며, 후속 migration의 완료 번호를 대신 기록하지 않는다.
v28의 SQLite identity adapter는 아래 세 table과 별도 human authentication epoch를
하나의 immediate transaction으로 만들고 마지막에 version 28을 기록한다.
이미 v28인 DB에서 table이나 singleton metadata가 없거나 읽을 수 없으면 오류로 중단한다.
공용 token 상태를 자동 생성하여 복구하지 않는다. 기존 v27 Job/Approval/Agent identity,
audit·bootstrap token row/actor는 삭제하거나 새 사용자 ID로 치환하지 않는다.

| v28 identity table | 저장하는 값 / 경계 |
| --- | --- |
| `admin_auth_state` | `legacy_bootstrap`/`personal`/`local_setup_required`와 별도16-byte human epoch. Agent delivery namespace/epoch와 별개 |
| `admin_accounts` | 불변 user ID·canonical username·표시 이름·role/status·record/credential revision·validated fixed-profile salt/hash. raw password 없음 |
| `admin_credentials` | 목적·사용자/revision/epoch binding·SHA-256 digest·고정 created/expires·revoked/consumed terminal. immutable optional PAT label(256 UTF-8 bytes), raw session/PAT/setup/reset secret 없음 |

Application callback이 account/mode/credential/audit를 같은 `BEGIN IMMEDIATE` 경계에서
변경한다. 오류는 모두 rollback한다. commit에서도 personal mode의 로그인 가능한 owner를
최소 한 명 유지하며, Legacy로 되돌아가거나 Legacy 상태에 계정만 남기는 부분 전환을 거절한다.
owner 계산은 저장 row를 Domain으로 검증한다. 잘못된 profile·이름·verifier를 정상 값으로
정규화하거나 로그인 가능한 owner로 세지 않는다. credential identity/digest/purpose/binding/
lifetime은 update할 수 없고 terminal 상태를 되살릴 수 없다.
실제 두 SQLite connection의 동시 초기 owner 전환·마지막 owner 강등·설정 코드 claim은
각각 하나만 commit한다. KDF 중 역할/credential 회수가 먼저 commit하면 이후 계정 생성은
거절한다. Application 전체 계정 흐름과 reset audit fault도 실제 DB rollback 계약으로 검증한다.

공용 token lookup/insert는 같은 SQL statement의 auth mode 조건으로 제한한다.
personal/local-setup-required mode에서는 legacy row를 보존한 채 인증·새 발급을 거절한다.
Application의 restore-human-epoch use case는 SQLite와 실제 owned PG에서 account/verifier/credential rows와
기존 Agent/Job/Audit·delivery identity를 보존하며 mode/새 human epoch/Security audit만 원자적으로 변경한다.
구 session/PAT/setup/reset은 binding 불일치로 거절하고, 활성 owner가 없으면 local 설정 필요 상태를 택한다.
entropy/authority/audit 실패는 회전을 commit하지 않는다. 이전 epoch/revision의 lookup은 후속 bounded cleanup 대상이며
per-user 활성 quota와 달리 global lookup cap에는 정리 전 남은 row가 포함된다.
local recovery/actual restore의 human epoch 연결과 공식 binary rehearsal은 완료했다.
Application 로그인은 8h session 발급/고정 만료, KDF 밖 DB lock 해제와 commit 재검증, session8/global4096 admission을 검증했다.
Owner account metadata는 기존 user ID primary key의 오름차순·exclusive after를 사용하며 단일 SELECT가 최대101행(공개100+lookahead)만 읽는다.
새 schema/index/pragma는 추가하지 않았다. 모든 행을 Domain으로 검증한 뒤 proof 없는 summary로 변환하며, 불량 lookahead도 부분 page 대신 오류다.
Application은 조회 전후 현재 owner를 확인하고 GET에서 계정·credential·audit를 쓰거나 만료 정리를 하지 않는다. SQLite/실제 owned PostgreSQL 공통 계약으로 검증한다.
credential lookup은 영구 audit가 아닌 ephemeral 인증 row다. 같은 identity transaction에서 목적별 최대128개만 정리하고
남은 전체 physical rows를 cap에 센다. limit로 발급을 거절해도 bounded cleanup은 commit할 수 있으며 새 credential/audit는 만들지 않는다.
session/PAT 발급·설정/재설정·role/PW 회수·logout에 연결됐다. Controller bootstrap과 개인 login/logout/setup·owner 생성/변경/reset·본인 password 변경/PAT 발급 HTTP도 이를 소비한다.
owner mutation은 기존 account/credential/audit transaction을 사용하며 schema/index를 추가하지 않는다.
미래 시각에 생성된 target credential이 있으면 invalid ended_at를 만들지 않고 state conflict로 rollback한다.
PAT는16/전체8192, session은8/전체4096으로 같은 canonical transaction에서 admission을 검사한다.
metadata는 본인 PAT만 최대100(+내부 lookahead1) 조회하고 label·ID·고정 시각·서버 active 판정만 전달한다.
Controller의 실제 metadata GET/선택 회수도 이 port/use case를 소비한다. GET은 cleanup/renewal/audit를 하지 않는다.
타인/다른 목적 row는 decode 전에 SQL scope로 제외한다. 이미 회수된 row가 정리 대기 중이어도 DELETE 결과는 not_found이며,
선택 회수와 audit 오류는 원자 rollback한다. 정리 대기량에 따라 삭제 응답이 달라지지 않는다.
subject/kind를 SQL에서 먼저 좁혀 손상된 타인 row도 self-service에서 not_found이며, label은 v28 기존 nullable column을 사용해 schema version은 바꾸지 않았다. feature-gated v28
Postgres identity repository는 같은 semantic row/replacement 검증을 사용하고 auth singleton
row를 `FOR UPDATE`로 잠근 뒤 account/credential/audit를 commit한다. owner 계산은 streaming
read로 검증한다. owned loopback PostgreSQL18.3에서 기존 IAM8개+human restore2개+login/cleanup/metadata/revoke/concurrent6개+owner metadata1개(합17개)를
실제로 통과했고 기존 repository16개 기준선도 보존한다. schema27/실패 rollback·newer rejection·legacy actor 보존·동시 owner/claim·
KDF 중 회수도 확인했다. 시험 cluster는 종료하고 데이터/증거를 보존했다.
이는 Controller Postgres startup의 기존 report-recovery fail-closed 제한을 해제하지 않는다.

사람 인증 Command·DriftCheck·직접/카탈로그 Runbook 생성은 서명 준비 뒤 SQLite immediate/PG identity singleton lock 경계에서
현재 credential·계정·역할·epoch를 재검증하고 Job/assignment/approval/audit/selector/strategy를 함께 저장한다.
승인/거절도 같은 identity 직렬화 경계에서 pending approval·pending Job 상태·audit를 원자 저장한다.
PG는 선택한 approval row를 잠그고 조건부 pending 갱신을 사용한다. 오류·만료·회수 선행이면 rollback하며
dispatch는 commit 뒤에만 수행한다. schema/index/pragma 변경은 없다. 해당 공통 계약과 승인 저장 실패
rollback은 실제 owned PostgreSQL18.3에서 검증했다. 카탈로그의 identity·활성 revision/문서 binding·provenance도 같은 transaction으로 묶고 schema를 바꾸지 않았다.
명시적 취소·수동 만료·remediation 승인 요청/Job 생성도 아래의 동일한 identity 직렬화 경계를 사용한다.

명시적 사람 취소도 같은 identity transaction에서 typed assignment snapshot·Domain aggregate·audit를 원자 저장한다.
terminal assignment는 변경하지 않고 조건부 갱신·audit 실패는 전부 rollback한다. PG는 assignment→Job 순으로 잠근다.
Agent session queue는 이 transaction에 참여하지 않으며 commit 성공 뒤에만 시도한다. 취소 audit는 불변 사람 ID와
redacted 사유·전송 후보 수를 저장한다. 응답의 queue 수락 수는 Agent 수신 확인이나 durable 감사 결과가 아니다.

수동 승인 만료는 기존500 pending scan 안의 due 항목만 하나의 human-authorized batch로 저장한다.
approval·pending Job expiry·불변 요청자 audit가 함께 commit하며, 중간 approval/Job/audit fault는 전체 rollback한다.
이미 취소/terminal이거나 접수된 Job은 만료로 덮어쓰지 않는다. 자동 background scheduler를 추가하지 않는다.

remediation 승인 요청은 이전 metadata snapshot과 새 approval·Policy audit를 묶는다. 승인 후 Job 생성은 서명을 transaction 밖에서 준비하고, 현재 사람 권한·정확한 이전 remediation/approval·승인 만료를 같은 transaction에서 확인한다. Job·assignment·targets·승인·metadata·세 필수 audit 중 하나라도 실패하면 전체 rollback한다. PG는 identity singleton 뒤 대상 remediation/approval row를 잠근다. 이미 전달된 Job과 Agent identity/active session은 사람 credential 회수로 변경하지 않는다.

반복 실행 규칙:

- migration은 여러 번 실행해도 성공해야 한다.
- 이미 존재하는 table과 column은 유지해야 한다.
- 기존 row를 삭제하거나 재작성하지 않아야 한다.
- destructive migration은 별도 backup/restore 경로와 명시 operator 확인 없이는 허용하지 않는다.

## Empty DB 초기화와 Existing DB Migration 구분

Empty DB 초기화:

- data directory가 준비된 뒤 SQLite file을 연다.
- `SCHEMA_SQL`이 전체 table을 만든다.
- `schema_migrations`에 현재 version을 기록한다.

Existing DB migration:

- 기존 table과 row를 보존한다.
- 없는 table은 `CREATE TABLE IF NOT EXISTS`로 추가한다.
- 없는 column은 `ensure_column`으로 추가한다.
- 기존 column의 의미를 바꾸거나 삭제하지 않는다.
- backward fixture test로 기존 DB shape에서 현재 schema로 올라오는지 확인한다.

### Drift report provenance

Schema v16 adds nullable `job_id`, `task_id`, `policy_id`, `policy_version`,
and `purpose` columns to `drift_reports` in both SQLite and the feature-gated
Postgres migration. A report is automation-eligible only when all five values
form Controller-verified provenance for a stored drift assignment. The database
does not treat agent-provided wire values as verified by itself.

Existing rows keep all provenance columns `NULL` and are read as
`uncorrelated`; they remain visible but cannot become remediation evidence.
The partial unique index `drift_reports_correlated_task_unique_idx` rejects a
second row only when both `job_id` and `task_id` are present. It therefore
preserves multiple legacy or observation-only rows without inventing a
correlation.

The primary-key report id is carried only by the typed application/store read
record as a stable remediation-origin reference. It does not make a row
eligible: proposal code must still require a drifted report and matching
Controller-verified policy id and version.

Schema v17 adds nullable `drift_policy_id`, `drift_policy_version`, and
`drift_purpose` columns to `jobs`. Scheduled drift jobs write the policy
identity and purpose together with their stored policy document and signed task
assignments. Controller intake verifies a report's claimed job/task pair against
that persisted assignment before it writes report provenance. Manual raw-policy
drift jobs retain `NULL` typed fields, so their reports remain uncorrelated.

Schema v18 adds nullable `origin_drift_report_id` and `policy_version` to
`remediation_requests`. A verified drifted intake writes its drift report,
allocated typed origin id, remediation request, and redacted Drift/Policy audit
events in one SQLite/Postgres transaction. If any of those writes fails, the
transaction rolls back all of them. A duplicate `(job_id, task_id)` returns the
existing report/request without another audit. The partial unique index
`remediation_requests_active_policy_unique_idx` permits at most one active
origin-bearing request per `(agent_id, policy_id)`; a duplicate returns that
request without a second proposal audit. Its `origin_drift_report_id IS NOT
NULL` predicate preserves legacy nullable rows without treating them as
verified episodes.

Schema v19 adds `remediation_verification_jobs` as a one-to-one durable
correlation between a remediation request and its signed verification drift
Job. `remediation_id` is the primary key and `job_id` is unique, so retry or
duplicate execution results can find the existing verification Job without
adding nullable lifecycle fields to legacy remediation rows.

현재 migration fixture:

- `crates/fleet-store/fixtures/sqlite/schema_v8_jobs_only.sql`
- `crates/fleet-store/fixtures/sqlite/schema_v27_identity_baseline.sql`: IAM 변경 전 실제v27에서
  추출한 schema와 synthetic legacy token/actor·Agent identity·Job/Approval/Audit 행.
  dump load 동안만 FK를 끄고 load 후 켠 뒤 foreign-key check를 통과해야 한다.
- fixture는 `schema_migrations`의 `fleet_store` version을 명시해야 한다.
- fixture test는 env var로 path를 찾지 않고 Rust test에서 `include_str!`로 고정한다.
- fixture migration 성공은 column 존재 여부만이 아니라 `schema_migrations.version = CURRENT_SCHEMA_VERSION`과 legacy row 보존으로 확인한다.

Data directory 초기화 실패와 DB migration 실패는 구분한다.

- data directory가 없거나 권한이 없으면 controller init/start 경계에서 명확한 filesystem error를 보여준다.
- SQLite file은 열렸지만 schema 변경이 실패하면 store/migration error로 다룬다.
- 운영자는 data directory 삭제와 migration을 혼동하면 안 된다. 삭제는 reset이고, migration은 보존 upgrade다.

## Transaction Boundary

Application layer는 DB transaction object를 직접 받지 않는다. 다단계 저장 작업은
repository contract로 표현하고 SQLite/Postgres infrastructure adapter가 내부에서
transaction을 연다.

현재 명시된 boundary:

| Operation | Boundary | Failure behavior | HA note |
| --- | --- | --- | --- |
| catalog Job composite create | `CatalogRunbookJobCreationRepository::commit_catalog_runbook_job` | active/ready/document/body binding을 transaction 안에서 확인하고 Job·provenance·signed Assignment·targets·Approval·필수 audit·strategy/selector를 함께 commit 또는 rollback한다. Duplicate Job/changed selection은 새 effect가 없다. | SQLite 및 feature-gated Postgres adapter; dispatch/authorization은 별도 Application/interface 책임이다. |
| typed job + assignments create | `save_*_job_with_assignments` repository method | job insert 후 assignment insert가 실패하면 job과 이전 assignment가 함께 rollback되어야 한다. | 단일 store transaction 기준이다. |
| dispatch claim | `claim_assignment_for_dispatch` | `queued -> dispatched` 전이만 성공한다. non-queued, missing, terminal assignment는 상태를 바꾸지 않고 false/no-op로 처리한다. | multi-controller duplicate dispatch 방지는 Phase 10 lease/advisory lock 작업이다. |
| dispatch claim release | `release_assignment_dispatch_claim` | send failure 후 `dispatched -> queued`만 허용한다. rejected/succeeded/failed/canceled/expired 같은 terminal 상태는 requeue하지 않는다. | active WebSocket send 성공을 accepted/started로 간주하지 않는다. |
| remediation execution transition | `persist_remediation_execution_transition` | authenticated task event의 Agent/Job/Task owner를 transaction 안에서 확인하고 assignment transition, matching remediation lifecycle transition, Policy audit을 하나의 SQLite/Postgres transaction으로 commit한다. missing/terminal assignment와 late/duplicate remediation transition은 false/no-op이며, supplied remediation/audit write가 실패하면 assignment도 rollback한다. | WebSocket event 자체는 authority가 아니며 persisted task assignment owner와 remediation Job correlation만 canonical input이다. |
| remediation verification Job create/recovery | `save_remediation_verification_job` + `list_pending_remediation_verification_recovery` | successful remediation 뒤 signed drift Job, single-target assignment, v19 one-to-one correlation, Policy audit을 하나의 SQLite/Postgres transaction으로 commit한다. duplicate correlation은 existing Job id를 반환하고 새 assignment/audit을 만들지 않으며, Job 또는 assignment insert 실패는 모든 새 row를 rollback한다. Controller bootstrap은 listener bind 전 correlation 없는 `succeeded_pending_verify` row를 최대 100개만 조회해 같은 create use case로 수렴시킨다. policy/version/execution Job을 검증할 수 없는 legacy row는 dispatch하지 않고 identifier와 reason code만 담은 `remediation_verification_recovery_skipped` audit을 남긴다. | Controller는 commit 뒤에만 dispatch를 시도한다. disconnected agent는 queued assignment를 유지한다. recovery는 startup 한 번만 실행하며 periodic retry/HA claim은 제공하지 않는다. |
| remediation verification resolution | `resolve_remediation_verification_evidence` | successful verification assignment와 remediation execution completion 뒤의 compliant evidence가 모두 있을 때 remediation status, origin drift의 `resolved_at`/`resolution_job_id`, Policy audit을 하나의 SQLite/Postgres transaction으로 commit한다. evidence row는 typed id, agent, verification job/task, policy/version, `remediation_verification` purpose와 compliant status를 transaction 안에서 다시 확인한다. missing/mismatched/stale/noncompliant evidence와 missing origin은 no-op 또는 rollback이며 unrelated/latest drift를 갱신하지 않는다. | report와 final result의 delivery order는 Controller가 두 persisted records를 재조회해 수렴시킨다. verification task completion은 success guard이며 freshness timestamp가 아니다. |
| remediation verification resolution recovery | `list_pending_remediation_verification_resolutions` | Controller bootstrap은 listener bind 전에 최대 100개의 persisted candidate만 조회한다. 성공한 verification assignment, 같은 Agent의 성공 remediation assignment와 completion time, fresh compliant evidence, exact policy/version/purpose, unresolved origin이 모두 일치해야 하며 기존 resolution use case가 다시 검증하고 remediation/origin/audit을 원자 commit한다. | 한 번의 startup scan이며 periodic retry/HA claim은 없다. 배치 초과분은 다음 시작 때 재조회한다. 후보 조회만으로 상태를 바꾸지 않는다. |
| scheduled drift worker | `due_scheduled_drift_checks` + `record_scheduled_drift_check` | 현재는 단일 controller worker 기준으로 due list 조회 후 job 생성과 schedule update를 순차 수행한다. | HA-safe claim/lease는 아직 없으며 Phase 10 전까지 multi-controller 중복 실행 가능성을 지원 상태로 표현하지 않는다. |
| retention cleanup | `cleanup_retention` | dry-run은 count만 수행하고 삭제하지 않는다. 실제 cleanup은 output/facts/metrics/agent-log row만 artifact type별 cutoff로 삭제한다. Audit과 report inbox/receipt는 삭제 대상이 아니다. | HA-safe retention lease는 Phase 10 작업이다. |

현재 retention/capacity 범위는 서로 다르다.

| Replay/delivery state | Current bound | ACK / cleanup behavior | Unbounded part |
| --- | --- | --- | --- |
| Agent SQLite report journal | 미ACK reports와 execution metadata 합계에 4,096 report / 64 MiB 기본 한도. Final-result 예약 4 reports / 4 MiB 포함. | 검증된 exact receipt 뒤 report와 완료된 execution row를 삭제한다. report tombstone는 남기지 않는다. | 이 quota가 별도 nonce log를 제한하지 않는다. |
| Agent `task_nonces.log` | 별도 count/byte quota, TTL 또는 compaction 없음. | accepted nonce의 SHA-256 digest를 `v1:<64-hex-digest>` line에 append하고 재시작 시 전체 파일을 메모리에 읽는다. | 고유 nonce당 text 약 68 bytes 및 전체 HashSet 크기만큼 disk/RAM/startup 시간이 증가한다. |
| Controller inbox + receipt | pending inbox만 Agent당 최대 4,096 reports / 64 MiB, final-result reserve 4 / 4 MiB, 단일 body 4 MiB. | committed 뒤 원 body는 NULL이 되지만 key/class/digest/status/accounted_bytes tombstone와 최대 8 KiB receipt row는 남는다. | committed rows는 pending quota에서 제외되며 이 두 table의 TTL/전체 상한이 없다. |
| Controller task assignment | 별도 replay-tombstone quota 없음. | assignment nonce는 unique이며 현재 output retention 대상이 아니다. | 이 데이터의 수명/정리는 report retention과 별도로 정해야 한다. |

따라서 output retention은 raw output row만 제거하며 committed inbox tombstone와 receipt를 남겨 exact replay가 output을 부활시키지 못하게 한다. 회귀 test `output_retention_keeps_committed_report_tombstone_and_receipt_without_resurrecting_output`은 cleanup 후 tombstone/receipt의 유지, exact replay 재처리 무효과와 output row 미복원을 고정한다. 지금은 무기한 replay guard를 자르는 안전한 cutoff contract가 없으므로 TTL/purge/nonce compaction을 적용하지 않는다. 장기 운영에서의 committed row·nonce 파일 성장은 알려진 저장/성능 한계다. bounded retention 설계는 duplicate report 거부 기한, Controller restore/backup, Agent offline 최대 기간, nonce 재사용 방지와 operator 데이터 손실 승인을 먼저 정해야 한다. 수치화된 운영 최대치나 성능 SLA는 아직 없다.

검증 기준:

- `cargo test -p fleet-store transaction`
- `cargo test -p fleet-store sqlite_store_passes_typed_job_repository_contract_harness`
- `cargo test -p fleet-store sqlite_store_passes_dispatch_assignment_repository_contract_harness`
- `cargo test -p fleet-store --features postgres postgres_store_implements_typed_job_repository_traits`
- `cargo test -p fleet-store --features postgres postgres_store_implements_dispatch_assignment_repository_trait`

## Backup/Restore

공식 controller backup command:

```bash
fleet controller backup \
  --data-dir .fleet \
  --output ./fleet-controller.backup.json
```

공식 restore command:

```bash
fleet controller restore \
  --data-dir .fleet-restored \
  --input ./fleet-controller.backup.json
```

위험을 줄이기 위해 먼저 dry-run을 실행할 수 있다.

```bash
fleet controller restore \
  --data-dir .fleet-restored \
  --input ./fleet-controller.backup.json \
  --dry-run
```

Archive format:

- JSON file
- `format = fleet-controller-backup`
- `format_version = 1`
- `package_version`
- `created_at_ms`
- `source_data_dir`
- `schema_version`
- `sqlite_integrity_check`
- file list with relative path, size, SHA-256 checksum, hex-encoded content

Backup 대상:

- `controller/fleet.db`
- `controller/controller_public.key`
- `controller/controller_private.key`
- 앞으로 `controller/` 아래에 생기는 regular file

Backup 제외 대상:

- `agent/` local identity
- runtime socket, pid file, temporary file
- SQLite transient file `fleet.db-journal`, `fleet.db-wal`, `fleet.db-shm`

운영 중 backup 정책:

- backup과 actual restore는 Controller와 같은 OS data-dir lease를 획득한다. Controller와 이전 binary를 먼저 중지해야 한다.
  data-dir는 실행 OS user 소유의 0700 real directory여야 한다. dry-run은 target lease/file을 만들지 않는다.
- backup command는 SQLite `PRAGMA integrity_check`가 `ok`가 아니면 실패한다.
- backup은 원본을 read-only/immutable로 검사하며 auto-migration하지 않는다. 원본 schema version과 bytes를 그대로 보존한다.
  [SQLite immutable 계약](https://www.sqlite.org/uri.html)에 따라 모든 writer(구 binary 포함)를 먼저 중지해야 한다.
- journal/WAL/SHM이 남아 있거나 dangling symlink이면 running/dirty SQLite 상태일 수 있어 backup을 거부한다.
- archive에는 controller private key와 token hash가 포함되므로 secret처럼 보관해야 한다.
- archive는 새 0600 파일에 기록하며 기존 output(또는 symlink)을 덮어쓰지 않는다. 매번 새 파일명을 사용한다.

Restore 안전장치:

- archive format/version을 확인한다.
- archive schema version이 현재 binary의 `CURRENT_SCHEMA_VERSION`보다 크면 거부한다.
- 각 file checksum과 size를 확인한다.
- archive path는 `controller/` 아래 상대 경로만 허용한다.
- dry-run은 사용자 원본/target을 바꾸지 않고 private scratch에서 실제 SQLite integrity와 schema version을 검사한다.
  manifest와 DB version 불일치·newer schema·중복/SQLite transient entry·누락/불일치 signing pair를 거절한다.
  scratch는 종료 시 삭제하며 source/target migration이나 epoch 회전은 하지 않는다.
- archive Debug/error는 content와 private-key path를 포함하지 않는다.
- 기존 `controller/` directory가 비어 있지 않으면 `--force` 없이 restore하지 않는다.
- 실제 restore는 data-dir 아래 새 private staging에 풀고, 검증·migration·두 epoch 회전·파일 sync를 끝낸 뒤 교체한다.
  기존 target은 Darwin/Linux atomic directory exchange로 교체하고, 없는 target은 atomic no-replace rename으로 설치한다.
  지원하지 않는 filesystem/platform은 거절하며 두 rename fallback이나 임의 기존 staging 삭제를 하지 않는다.
- delivery namespace/Agent identity/signing keys는 보존하고 delivery store epoch와 독립 human epoch를 각각 새 값으로 기록한다.
  backup에 있던 account/password verifier·Job/Audit/history는 보존하지만 모든 기존 session/PAT/미사용 setup/reset code는 무효화한다.
  loginable owner가 없는 옛 backup은 local setup required가 되며 shared token을 다시 살리지 않는다.
- 교체 syscall 실패/검증/audit 실패까지는 기존 target이 보존된다. 교체 후 directory sync 실패는 이미 설치된 복원과 구분해
  경고하고 private rollback staging을 남긴다(Controller를 중지한 채 원 backup과 확인). cleanup 실패도 설치 완료·정리 대기로 경고한다.
  강제 종료로 남은 private staging은 자동 삭제하지 않는다. 다음 시작 전에 원 backup과 target을 확인하고 소유자가 수동 정리한다.
- actual restore 출력의 `schema_version`은 migration 후 version이며 `backup_schema_version`은 입력 archive version이다.

삭제와 backup/restore의 차이:

- data directory 삭제는 reset이다. controller identity, jobs, audit, telemetry, enrollment records가 사라진다.
- backup/restore는 보존 복구다. 같은 controller identity와 저장 데이터를 다시 사용할 수 있다.
- delivery namespace는 signing/TLS key rotation과 backup restore를 거쳐 유지하고, store epoch는 실제 restore마다 회전한다. 현재 v2 authenticated handshake는 두 값을 전달한다. persistent Agent journal은 namespace와 Agent ID를 owner로 저장하며, receipt 검증은 현재 session의 epoch를 요구한다. 여전히 Agent journal에 남은 exact report는 restore 후 replay될 수 있고, Controller는 restored DB의 owner-bound inbox effect를 중복 적용하지 않고 current-epoch receipt를 발급한다. old-epoch receipt는 local cleanup 권한이 없다.
- 과거 backup으로 돌아가면 backup 이후 Controller에만 있던 결과는 사라질 수 있다. Agent에 여전히 pending인 동일 report는 재전송할 수 있지만, 이미 ACK되어 Agent에서 삭제된 보고를 restore가 되살릴 수는 없다. 이 손실 구간은 외부 결과 archive/reconciliation 정책이 필요하며, unknown owner/assignment는 ACK하지 않는다.
- catalog source/revision/operation/document은 SQLite durable state이므로 Controller backup archive의
  `controller/fleet.db`에 포함된다. 재구성 가능한 Git checkout cache를 별도 backup file로 넣지 않는다.

### 실제 복원·rollback 운영 순서

1. 사용 중인 data-dir와 실행 OS user를 확인하고 Controller와 구 binary를 모두 중지한다.
   가능하면 진행 중인 작업을 마친 뒤 중지하며, Agent에서 이미 실행된 명령의 host side effect를 backup이 되돌리지는 않는다.
   이 JSON command profile은 기본 `<data-dir>/controller/fleet.db`용이다. 외부 custom SQLite 경로나 Postgres의 운영 backup 절차로 간주하지 않는다.
2. 현재 상태를 **새 이름의 safety backup**으로 보관하고 `restore --dry-run`으로 실제 DB/schema/signing pair를 확인한다.
   되돌아갈 입력 backup도 별도로 dry-run한다. 출력 파일이 이미 있으면 덮어쓰지 말고 새 파일명을 쓴다.
3. Controller가 중지된 상태에서 원하는 backup을 같은 data-dir에 `restore --force`한다.
   새 target이 생기기 전 실패하면 이전 target을 사용한다. 설치 후 sync/cleanup 경고가 있으면 자동 재시작하지 말고
   원 backup·완전한 target·private staging을 확인한다. 이름만 보고 기존 staging을 삭제하거나 수동 두 rename으로 교체하지 않는다.
4. 계정·역할·차단·비밀번호 검증 정보도 **backup 시점으로 돌아간다**. 기존 사람 token/code는 fresh epoch로 무효화되지만
   backup의 옛 비밀번호는 다시 유효할 수 있다. backup 이후의 보안 변경을 재적용하고, 필요하면 재시작 전에
   `controller admin recover-owner --data-dir <dir> --username <기존 이름>`으로 owner 비밀번호를 복구한다.
   사용할 owner가 없는 옛 backup은 `controller admin init-owner`로 준비한다. Agent signing key를 새로 만들지 않는다.
5. 정상 시작 후 개인 로그인·권한·Agent 재접속·Job/Audit 이력을 확인한다. 격리된 IAM HTTPS 인수는 이 순서와 옛 cookie/PAT/미사용 설정·reset 코드의 거절을 검증한다. 실제 운영 복구에서도 해당 환경의 확인을 생략하지 않는다.
   문제가 있으면 Controller를 다시 중지하고 **검증한 safety backup을 현재 IAM 지원 binary의 restore 명령으로** 적용한다.
   rollback도 두 epoch를 새로 만들며 이전 로그인/token을 재활성화하지 않는다. 구 binary/data directory를 임의로 섞지 않는다.

backup 이후의 Job/Audit/설정 변경은 그 backup에 없다. safety backup을 보존하고 필요한 기록을 별도로 대조해야 한다.
Agent가 아직 journal에 보관한 exact report만 replay 가능하며 이미 ACK·삭제한 결과나 외부 host 변경을 복원할 수는 없다.
반복 복원도 신규 epoch를 사용하므로 사람은 다시 로그인해야 한다. 이 절차는 HA/live backup 또는 자동 rollback을 제공하지 않는다.

## 현재 주요 Table

Core identity:

- `controller_identity`
- `controller_delivery_identity`
- `controller_report_inbox`
- `admin_tokens`
- `agents`
- `agent_identities`
- `enrollment_tokens`

Job and execution:

- `jobs`
- `job_targets`
- `task_assignments`
- `job_output_chunks`
- `approval_decisions`
- `approval_requests`

Telemetry and drift:

- `facts_snapshots`
- `metrics_snapshots`
- `drift_reports`
- `agent_log_chunks`
- `agent_capability_snapshots`

Policy:

- `policies`
- `policy_assignments`
- `policy_drift_schedules`
- `remediation_requests`

Catalog:

- `catalog_sources` — 공개 source URL/reference와 active revision pointer
- `catalog_revisions` — source/commit별 validation state와 document count 또는 failure code
- `catalog_sync_operations` — source별 하나의 진행 중 sync와 immutable terminal result
- `catalog_documents` — source/commit/path/checksum provenance와 validated 원문
- `job_catalog_runbook_provenance` — catalog Runbook Job의 immutable source/commit/path/checksum; referenced catalog document deletion을 제한한다.
- `policy_catalog_provenance` — catalog Policy의 immutable source/commit/path/checksum 및 source ownership; referenced catalog document deletion을 제한한다.

`CatalogRepository`는 SQLite와 feature-gated Postgres에서 같은 source/revision/operation/document
read/write 및 ready revision activation contract를 구현한다. 새 revision에서 같은 source의 unchanged
checksum document는 controller가 body를 다시 전달하지 않고 durable validated body를 복사해 provenance
row만 추가한다. `CatalogQueryRepository`는 이 durable state만 source id, source별 commit id,
source+commit별 path 오름차순의 exclusive cursor로 읽는다. application page 결과는 1~100 records로
제한하고 list에는 document body를 넣지 않으며, body는 이후 권한 검사를 거친 단건 detail 경로에서만
읽는다. 이 query는 Git fetch/refresh를 수행하지 않는다. 세 정렬 키는 각 table의 primary key 또는
`catalog_documents_source_commit_path_idx`로 index-backed이다. Postgres의 실제 서버 roundtrip은
disposable DB를 요구하는 ignored test로 분리한다.

Catalog Job의 새 `CatalogRunbookJobCreationRepository::commit_catalog_runbook_job` 경계는
Application이 준비한 Job, immutable provenance, signed Assignment와 target snapshot, pending Approval,
필수 audit, strategy와 selector snapshot을 한 transaction에서 저장한다. SQLite는 `BEGIN IMMEDIATE`,
feature-gated Postgres는 같은 source/revision/document row의 shared lock으로 active pointer·`Ready`·
Runbook kind·path·checksum·본문이 준비 시점과 일치하는지 commit 전에 다시 확인한다.
불일치는 `SelectionChanged`, 같은 Job ID는 `DuplicateJob`이며 생성 effect를 남기지 않는다.
Job/provenance/Assignment/target/Approval/audit 중 하나가 실패하면 모두 rollback한다.
SQLite 공통 write helper는 최종 COMMIT 실패도 rollback하며, 실패한 BEGIN은 caller의 기존
transaction을 변경하지 않는다.

Job의 `runbook_document`는 검증된 catalog 본문의 immutable 실행 snapshot이고,
`job_catalog_runbook_provenance`는 source id, commit, path, checksum을 보존한다. 생성 뒤 Agent labels나
source active pointer가 바뀌어도 기존 대상과 출처를 다시 계산하지 않는다. 참조 중인 catalog 문서의
삭제는 foreign key로 거부된다. 기존 `save_catalog_runbook_job_with_assignments` primitive는
Job/provenance/Assignment만 저장하므로 전체 생성 계약을 대신하지 않는다. 새 catalog 실행 HTTP
`POST /api/jobs/catalog-runbook`은 이 composite port를 사용하고 commit·approval 뒤에만 dispatch한다.
보호된 Job detail은 별도 read port로 Job 소유 provenance row를 읽으며 현재 source pointer와 join하거나
재계산하지 않는다. raw Job의 provenance 부재는 null이고, 저장소 오류를 null로 숨기지 않는다.
이 shared repository adapter 검증이 Postgres Controller runtime/recovery 지원을 뜻하지 않는다.

Catalog Policy publish도 active·`Ready` revision의 checksum 일치 Policy만 transaction 안에서
저장한다. 처음 publish는 policy id의 catalog source ownership을 만들고, 같은 source의 새 commit은
그 provenance를 갱신할 수 있다. 기존 manual policy 또는 다른 catalog source가 소유한 같은 id는
overwrite하지 않고 conflict로 끝난다. publish 자체는 Policy assignment, drift schedule, remediation을
생성하지 않는다.

Catalog의 1,000-document deterministic fixture와 local warm-run observation 방법은
[`catalog-performance.md`](catalog-performance.md)에 기록한다. 이 문서는 local 수치를 release
threshold로 취급하지 않으며, pinned runner에서 재현한 baseline만 release gate에 사용할 수 있다.

Audit:

- `audit_events`

`audit_events`는 controller API/application 경계에서 append-only로 다룬다.
운영 export는 `/api/audit/export` 또는 `fleet audit export`의 category
filter와 cursor paging을 사용한다. SQLite MVP 저장소는 물리적 WORM 보관소가
아니므로 장기 보존, 변조 방지, 규정 준수는 외부 백업/export 보관 정책으로
보완해야 한다.

Migration metadata:

- `schema_migrations`

## Repository Contract 기준

Application layer는 store 구현체가 아니라 repository trait을 통해 접근한다.

현재 주요 repository contract:

- `AgentRepository`
- `AgentInventoryRepository`
- `AgentIdentityRepository`
- `AdminTokenRepository`
- `ControllerIdentityRepository`
- `EnrollmentTokenRepository`
- `JobRepository`
- `CommandJobRepository`
- `RunbookJobRepository`
- `DriftCheckJobRepository`
- `TaskAssignmentRepository`
- `JobQueryRepository`
- `JobOutputRepository`
- `PolicyRepository`
- `CatalogRepository`
- `CatalogQueryRepository`
- `FactsRepository`
- `MetricsRepository`
- `DriftRepository`
- `AgentCapabilityRepository`
- `AuditRepository`
- `ApprovalRepository`

규칙:

- Domain layer는 SQLite, SQL, filesystem을 알면 안 된다.
- Application layer는 repository trait과 typed domain/application record만 사용한다.
- Infrastructure error는 repository boundary 밖으로 raw SQL 문맥을 과도하게 새지 않도록 한다.
- Store test는 trait contract를 통해 최소 roundtrip을 검증한다.
- 새 table을 추가할 때는 해당 application repository boundary를 먼저 정의한다.

## Agent Capability Snapshot Schema

`agent_capability_snapshots`는 agent가 보고한 최신 capability snapshot을 agent별로
하나만 보관한다. 이 table은 active WebSocket session summary가 아니라 dispatch
gate와 Agent API 응답이 사용하는 persistent source of truth다.

현재 column:

- `agent_id`: `agents.id`를 참조하는 primary key
- `privilege_level`: `unprivileged`, `sudo_available`, `root`
- `package_manager`: `apt`, `dnf`, `yum`, `apk`, `brew`, 또는 null
- `service_manager`: `systemd`, `launchd`, `openrc`, 또는 null
- `capabilities_json`: agent가 보고한 capability name array JSON
- `reported_at`: agent가 snapshot을 만든 system time epoch seconds
- `updated_at`: controller store upsert time epoch seconds

규칙:

- runtime 중 capability override 설정을 추가하지 않는다.
- Domain layer는 SQL schema를 알지 않고 `AgentCapabilitySnapshot`만 다룬다.
- Dispatch gate는 stored snapshot이 있는 경우 24시간 기본 TTL과 `RuntimePrimitive` 요구사항을 평가한다.
- Unsupported snapshot은 assignment를 WebSocket write 전에 `rejected` terminal 상태로 저장한다.
- raw collector output, command output, secret-bearing payload를 capability table이나 Product Log에 저장하지 않는다.

## Job/Assignment Schema

job과 assignment 상태는 분리한다.

현재:

- `jobs.status`는 coarse job status다.
- `task_assignments`는 signed task envelope 저장, pending dispatch queue, assignment lifecycle state 저장 역할을 한다.
- `job_targets`는 job과 target agent의 현재 단순 status를 저장한다.
- `job_output_chunks`는 stdout/stderr chunk를 저장한다.
- `rendered_artifacts`는 rendered template의 metadata만 저장한다. Rendered body는
  `ArtifactStore` object로 분리 저장되며, template body와 secret value는 DB table에
  저장하지 않는다.
- `approval_requests.job_id`는 일반 job approval에서는 existing job id를, remediation
  approval에서는 approve 이후 생성될 reserved job id를 저장한다. 따라서
  `approval_requests.job_id`는 `jobs(id)` FK를 두지 않는다. Remediation approval이
  job row 생성보다 먼저 존재할 수 있어야 하며, job 생성과 assignment 저장은 approve
  use case에서 한 번에 처리한다.

`task_assignments` lifecycle column:

- `status`: `queued`, `dispatched`, `accepted`, `started`, `succeeded`, `failed`, `rejected`, `canceled`, `expired`
- `dispatched_at`
- `accepted_at`
- `started_at`
- `completed_at`
- `last_error`

Post-MVP schema 변경 후보와 실행 phase:

- target snapshot source fields: Phase 2 remediation/result correlation에서 필요한 경우 추가한다.
- selector snapshot fields: Phase 2 remediation과 Phase 10 HA dispatch claim에서 필요한 경우 추가한다.
- final result payload: Phase 2 remediation result report와 Phase 11 compliance report에서 필요한 경우 추가한다.
- output chunk와 final result 분리: Phase 11 compliance report와 Phase 15 load gate 전에 repository contract로 고정한다.
- rendered artifact protocol link: 구현됨. runner 결과는 `task_result.artifacts`로 controller/store metadata에 연결하고, optional `content_bytes`가 있으면 local `ArtifactStore` body로 저장한다.
- artifact blob storage: Phase 4에서 local `ArtifactStore` contract, checksum verification, path traversal rejection, idempotent delete boundary, task result body persistence, Controller artifact retrieval API, Web Admin artifact metadata/retrieval surface가 추가됐다. S3-compatible adapter는 후속 task다.
- Postgres migration metadata: Phase 3에서 SQLite와 같은 repository contract로 추가한다.

권장 migration 순서:

1. 새 nullable column 또는 새 table을 추가한다.
2. 기존 row가 새 schema에서 읽히는지 fixture test를 추가한다.
3. application repository가 새 필드를 optional/default로 읽게 한다.
4. domain state machine test를 추가한다.
5. controller/agent protocol event를 연결한다.
6. 충분히 안정화된 뒤에만 NOT NULL 제약이나 stricter invariant를 검토한다.

## Output과 Result 저장 경계

`fleet-domain::delivery`에는 보고 전체 소유권(controller/agent/job/task/report)과 digest ACK 일치,
count/byte 한도 및 최종 결과 예약 공간 규칙이 있다. 저장 adapter는 용량 확인과 append를 같은
transaction으로 수행해야 한다. Persistent Agent runtime은 TaskAck, TaskStarted, TaskRejected,
DriftCheck evidence와 its separate terminal result, 그리고 Command/no-artifact Runbook stdout/stderr에
이 경계를 사용한다. No-artifact Command/Runbook final result도 같은 journal 경로에 있다.
DriftEvidence는 observation만 기록하며 TaskResult를 완료하지 않는다. Persistent DriftCheck의
terminal `final_result`는 별도 status/effect/receipt를 가진다. Artifact-bearing Runbook final은
Controller의 v2 effect/receipt 경로에 연결됐지만 Agent journal 저장·재전송은 아직 지원하지
않는다. TaskAck/TaskStarted/TaskRejected 이외 lifecycle report도 Agent durable path 밖이다.

### Agent journal and persistent report delivery

`fleet_application::delivery` owns report/execution repository contracts and queue/confirmation/admission/start use cases.
`fleet_store::agent_journal::SqliteAgentJournal` implements a separate local schema v4, not Controller
schema v26. It stores exact report bytes, ownership identifiers, class, SHA-256 digest and logical byte
accounting. Same key/body/class is a duplicate; changed content conflicts without overwriting the row.

Schema v2 adds `executions`; schema v3 adds durable stdout/stderr committed sequence counts and
migrates v1/v2 additively without rewriting report bytes or owner identity. Schema v4 adds the
`drift_evidence` report class and migrates v3 while preserving stored rows and bytes. One unfinished execution
is allowed. Admission records allocate the final report ID and store nonce/envelope hashes, timestamp,
maximum accounted final-result size, and per-stream committed chunk counts. Command text and raw nonces
are not stored in this record. Admission checks report usage **plus execution metadata** and keeps the
final reservation available; an unrelated final/rejection report cannot spend that reserve. A v2
journal with a `StartIntent` active cannot prove whether earlier output reports were already ACK-cleaned,
so the v3 migration fails closed without mutation until that task finishes under the existing Agent.

For persistent WebSocket Command and no-artifact Runbook, the runtime order is signature/target/expiry
verification and durable nonce consumption → admission commit → start-intent commit → TaskAck/TaskStarted
reports → host effects → final report and completion in one commit.
A consumed nonce stays consumed if admission fails. A duplicate admission is observation only, not
permission to execute. A new process, or an idle runtime after the prior task owner has ended, sees
admitted-only work as `agent_interrupted_before_start`, start-intent work as `execution_outcome_unknown`,
and completed work as report replay only. Neither interruption permits reexecution. Reconnection
while a task owner is still live must not run this recovery path; idle reconnect or next-task admission retries it.
Each output append validates the next sequence for that stream and updates the execution counts in the
same transaction. The counts survive per-output receipt cleanup; final-result append must match both
counts before it can complete the record. Recovery includes those counts and marks an outcome-unknown
output summary truncated, allowing Controller exact-prefix validation without claiming success. Final
ACK removes its completed execution metadata with that report; the existing durable nonce guard remains
responsible for replay rejection after this cleanup.

`fleet_agent::journal_worker` provides a generic single-owner thread for these blocking repository
operations. Submission and completion polling do not perform disk I/O. Count and logical-byte limits
cover queued/running requests **and retained replies**; replay reads reserve their requested maximum
response size. Oversized requests or a full budget are rejected before submission. Repository success,
not enqueue success, is the completion barrier. A timed-out/dropped ticket does not cancel a write:
the write may still commit, so retry must reuse its identity. Closing the owner refuses all clients,
drains accepted work and joins. An OS-stalled disk operation cannot safely be detached; shutdown waits
for that operation. The CLI owns this worker for the persistent session runtime and uses it to commit
TaskAck, TaskStarted, TaskRejected, and persistent Command/no-artifact Runbook output before sending reports and to acknowledge verified stored receipts.
Within a delivery tick, Lifecycle reports precede Output and FinalResult reports; exact report keys
provide deterministic ordering within a class. Receipt cleanup also filters any older bounded scan
snapshot that completes after its report has already been acknowledged, so deleted rows are not
reintroduced into the reconnect send queue.

- SQLite FULL synchronous commits precede append success. Exclusive locking rejects another opener;
  process exit releases SQLite locks without deleting reports. Replay reads are count- and byte-bounded.
- Matching controller/agent/job/task/report and digest are required for acknowledgement cleanup.
  A final-result ACK never deletes another report, including unACKed stdout/stderr.
- Capacity and insert share a transaction. Logical quota counts body, identity bytes, digest and fixed
  metadata; SQLite pages/rollback journal overhead require additional disk space. Disk-full failure
  does not evict committed reports or permit execution without a successful admission record.
- On Unix the directory and DB must belong to the effective user and exclude group/other permissions.
  New DB files use mode 0600; insecure modes, symlinks, multiply linked files, wrong identities,
  unsupported schemas and checksum corruption fail closed. Existing file permissions are not repaired.
- This schema has no TTL/purge operation. ACK deletion is logical cleanup, not guaranteed forensic
  erasure. There is no at-rest encryption. Controller backup does not include this Agent-local DB.
- The separate file-backed nonce replay guard stores one `v1:`-prefixed SHA-256 digest per accepted
  nonce and currently appends indefinitely. It is not covered by the Agent journal report/byte quota;
  startup loads all records into memory. There is no safe compaction/cutoff contract yet.

### Controller assignment execution-outcome recovery

The SQLite store exposes a bounded recovery adapter for active `dispatched`, `accepted`, and
`started` Assignments. Eligibility uses the persisted Controller `dispatched_at`, the Job's stored
execution timeout, and a Controller-supplied grace period; envelope expiry and connection loss do
not prove that execution stopped. The query returns at most 100 due candidates in exact due-time
order with a stable task-ID tie break, excluding queued, terminal, missing-dispatch-time, and
invalid-timeout rows.

For each candidate, SQLite conditionally compares its observed Assignment status, dispatch time,
Job identity, and stored timeout again inside `BEGIN IMMEDIATE`. A still-active row becomes
`failed` with only the typed `execution_outcome_unknown` reason. Assignment status, recomputed Job
aggregate, and redacted Job audit commit together. A concurrent terminal transition is preserved;
any failure in the transaction rolls all three effects back. Repeated scans do not create another
transition or audit, and recovery never replays a task.

The Controller executes one bounded pass before binding its listener and then runs another pass
every 30 seconds. Startup recovery errors prevent listener startup; periodic errors are recorded
and retried on the next interval. Store work runs on a blocking thread, and the Controller owns,
cancels, and joins the periodic worker during graceful shutdown. The recovery path currently
supports SQLite only. A Postgres-selected Controller build fails startup before binding because
Postgres has no implementation of this recovery contract; it must not be described as supporting
G2 recovery.

The persistent Command and no-artifact Runbook CLI paths connect admission/start-intent and
process-bootstrap recovery to the journal worker. Runbook output/final result uses commit-before-send,
replay and receipt cleanup. Persistent DriftCheck evidence and terminal result also use
commit-before-send/replay/receipt cleanup, but Drift execution admission/restart recovery, artifact-
producing Runbook output, and one-shot task execution remain outside this path. Controller-side
G2 Assignment recovery is runtime-enabled for SQLite only. A matching no-artifact persistent
Command or Runbook final result arriving after G2 marked the owned Assignment
`failed/execution_outcome_unknown` receives a durable inbox disposition and signed `stored` receipt.
The first disposition, a redacted audit of the reported terminal status and the committed inbox
marker are atomic; Assignment/Job state remains untouched. Exact retries replay the persisted receipt
without another audit. Other terminal reasons, artifact/remediation final-result effects and unrelated
task classes still fail closed. A matching no-artifact DriftCheck final result may use the same
terminal-preserving disposition; its evidence report remains a separate path and is not accepted as a
late final result. Tests cover close/reopen, abrupt child-process death after
admission/start/final commit, v1 migration, reservation pressure and injected SQLite transaction
failures; they do not establish real machine reboot or power-loss guarantees.

Persistent TaskAck/TaskStarted/TaskRejected can also arrive after SQLite G2 marks the owned
Assignment `failed/execution_outcome_unknown`. The lifecycle effect transaction verifies the exact
Agent/Job/Assignment owner and G2 reason, inserts one redacted Job audit, and marks the exact inbox
row committed without changing Assignment, Job aggregate, or G2 reason. The Controller then stores
and returns a signed `stored` receipt; exact replay reuses that receipt and lets the Agent continue its
ordered journal. This acknowledges durable receipt of the report only, not task acceptance, execution,
or success. Changed bodies and mismatched owners remain fail-closed. The dispatched-cancellation exception below does not relax other terminal-state guards.

For an already `canceled` Assignment with a persisted dispatch timestamp, the same SQLite transaction
can commit a terminal-preserving lifecycle disposition. A no-artifact Command/Runbook final without
remediation follow-up can also be dispositioned after its exact output prefix is verified. Any valid
final outcome can have raced Controller cancellation; Assignment status, original reason/completion
time, Job aggregate and output rows remain unchanged. Audit (`assignment_canceled_final_result_received`
or `assignment_canceled_lifecycle_report_received`) and inbox commit are atomic, and an audit/marker
failure leaves the report pending. Signed receipt persistence/recovery remains a subsequent step;
Agent cleanup still requires verification of that exact receipt. Exact retry/reopen repeats neither
transition nor audit. Undispatched cancellation, unrelated terminal states, conflicting body/owner,
output gaps and unsupported artifact/remediation/DriftCheck finals are rejected. This changes no table,
schema version, retention policy or live Postgres support.

The v2 signed receipt statement distinguishes a stable Controller namespace from a store epoch and
binds both to the exact report key/digest. The Controller now persists both; key rotation leaves
them unchanged and actual backup restore rotates the epoch in the temporary DB. The persistent Agent
binds its journal to namespace plus Agent ID and checks the current session epoch during receipt
verification. An Agent library verifier checks Ed25519 against pinned/rotated trust and the exact
local pending report, returning a candidate that the CLI acknowledges through the journal worker.
Current `ReportKey.controller` alone is not proof of Controller identity.

### Controller pending-effects inbox and receipt foundation

Controller schema v24 adds an additive report inbox. The SQLite adapter stages exact encoded task
report bytes under the stable Controller/Agent/Job/Task/report key, class and SHA-256 digest in one
`BEGIN IMMEDIATE` transaction. A fresh row requires an existing Assignment owned by that Agent and
Job. Same key/class/body is a pending duplicate after reopen; changed class/body is a typed
conflict. Per-Agent pending usage is capped at 4,096 reports/64 MiB logical bytes, with 4 reports/
4 MiB reserved from non-final reports so a final result is not starved. A single encoded body is
limited to 4 MiB. SQLite pages, WAL/rollback files and backup copies consume additional disk.
Pending rows are not ACKable: staging itself commits no Job/Assignment/output/artifact effect.
The SQLite output-effect adapter can now compare the exact staged bytes,
insert or verify an identical `job_output_chunks` row and mark the inbox row `committed` in one
transaction. On failure both effects roll back. It clears the committed raw inbox body but retains
the digest/status tombstone, so later output retention cannot make a replay recreate an old chunk.
The committed inbox `accounted_bytes` remains metadata but pending-capacity queries exclude that row.
`controller_report_receipts` retains one bounded receipt row per report (encoded bytes are at most
8 KiB) and the current retention worker has no deletion path for either table. Thus pending admission
quotas do not bound lifetime committed tombstones/receipts; replay safety currently depends on their
indefinite logical retention. A regression test applies output cleanup, then confirms the exact replay
returns `AlreadyCommitted`, retains the receipt, and does not recreate the deleted output chunk.
For persistent Command and no-artifact Runbook finals, the same SQLite transaction path requires an output summary and
checks that each Agent stream contains exactly indexes `[0, count)`. A missing, gapped, or extra
row leaves the final report pending and produces no final effect or receipt; replaying the missing
chunk allows the same final report to retry. A `truncated=true` final cannot succeed. The Job audit
stores only stdout/stderr chunk counts and the truncation flag, never the raw chunk bodies. This checks
delivery of locally journaled chunks and does not guarantee all task-execution output bytes were captured.
The SQLite recovery adapter can read at most 100 pending final-result reports or 8 MiB of bodies
per call in stable insertion order after reopen, checking Assignment ownership, body bounds and the
stored digest. Controller startup and a lifecycle-owned 30-second worker use this read to retry
supported final effects. A separate scan returns at most 100 already-committed final identities
whose receipt row is missing, using only key/digest; it can persist the receipt without reapplying
effects. Only a committed effect can persist a signed receipt, which is queued after the store lock is
released. Corrupt pending data stops the scan without exposing the body; an output gap, unsupported
follow-up, or terminal Assignment leaves that report pending and fail-closed.
A separate SQLite adapter atomically commits a staged command/runbook/drift-check final result's prepared
artifact metadata, Assignment, Job aggregate, Job audit, and inbox marker. File bodies, if present,
must first be put idempotently into the local ArtifactStore and their returned id/class/checksum/size
must match the metadata. A failed metadata or marker write rolls the entire DB effect back; the
pending inbox body survives reopen and can drive the same file put and DB retry. This leaves a
possible orphan file if the Controller dies between file put and DB commit, which a later cleanup
owner must reconcile. A prepared remediation execution transition can join the same DB commit:
the expected prior state, Agent/Job owner, resulting status and Policy audit are checked before
writing `succeeded_pending_verify` or a terminal remediation status. The existing bounded startup
recovery can turn `succeeded_pending_verify` into one correlated verification Job after restart;
an integrated test covers this library-to-recovery path. A drift-check final can commit its own
Assignment/Job/audit/marker without implying that a separate verification evidence report arrived
or that remediation resolved. The evidence may arrive before or after the final; the adapter does
not mutate that row. Already-terminal Assignment and marker-write failure leave the inbox pending
without overwriting terminal state or committing partial effects. Drift evidence resolution remains
outside the final-effect transaction. A separate verification-evidence adapter now compares exact
staged lifecycle-report bytes, Assignment owner and Controller-stored drift Job policy/version/
purpose before atomically inserting one correlated `drift_reports` row, redacted Drift audit and
inbox committed marker. Duplicate processing after reopen does not create another row/audit;
marker failure rolls all three writes back. Final and evidence can commit in either order.
Neither commit alone resolves remediation. When both effects are committed, the Controller's
bounded pre-listener recovery scan now joins the persisted successful final and fresh compliant
evidence through the existing resolution use case; reopen/replay tests verify origin-only resolution
and one audit. This scan does not replay still-pending inbox bodies, run periodically, or provide an
HA claim. The live v2 handler commits supported Command, Runbook, and DriftCheck final results
atomically with Assignment/Job/audit/inbox effects. Artifact-bearing Runbook bodies are first put
idempotently into the immutable local ArtifactStore; the returned body metadata is checked in the
SQLite transaction. A failed DB effect leaves the report pending for an exact retry, but no
background inbox-effect worker retries it. A crash between file put and DB commit can leave an
unreferenced artifact file. Prepared remediation final-result effects remain unconnected to that
handler; a separate live `drift_evidence` handler commits verification evidence, its required audit,
eligible proposal effects, and the inbox marker atomically.
The caller must parse the encoded report and supply the actual
artifact count, optional-body distinction and status; this library does not decode wire payloads or
independently inspect the object store. The live `final_result` handler supports validated artifact
metadata and prepared bodies for persistent Runbook reports, but does not connect remediation
final-result follow-up effects. The separate `drift_evidence` handler commits
correlated evidence, required audit, eligible remediation proposal/audit and inbox marker atomically.
The Postgres feature has matching schema shape but no
staging/effect adapter; live report handling is SQLite-only and fails closed on Postgres. Raw
pending bodies are sensitive, not Product/Field log content, and backup archives must be protected
accordingly.

Controller schema v25 adds a separate signed-receipt row keyed to the existing inbox report. The
SQLite receipt adapter checks the current Controller namespace/store epoch, Assignment owner,
committed inbox status and exact report digest in one immediate transaction before storing a
bounded receipt. A same-epoch/same-signer retry returns the original bytes after reopen even if the
caller generated a newer signature. After Controller signing-key rotation, an exact committed report
may replace the previous signer's bytes with the current signer's candidate; the Controller helper
signs/verifies the candidate before the repository call and verifies stored bytes again before send.
A different digest, pending row, stale epoch, or missing owner cannot authorize a receipt. After
explicit restore epoch rotation, the first valid new-epoch receipt replaces the old-epoch row. The
Controller-side helper parses returned bytes and rechecks statement ownership, disposition and
Ed25519 signature before they could be sent.
The authenticated live v2 session calls this helper for SQLite TaskAck/TaskStarted/TaskRejected,
DriftEvidence, output, and supported Command/Runbook/DriftCheck final-result reports, then queues the stored receipt through its single writer; the
Postgres feature has schema only. Signed receipt storage occurs after effect commit, so a crash between those steps
requires retry; it never turns a pending effect into an ACK. Controller/SQLite integration tests
commit an output effect, replace an old-signer receipt after key rotation, reopen/retry the current
receipt bytes, and confirm the report effect remains a single output chunk.

The live report branch accepts `drift_evidence` with strict `{status, expected, actual}` and takes
policy identity/version/purpose only from Controller-stored Job/Assignment provenance. Evidence,
required redacted audit, eligible remediation proposal/audit, and inbox marker commit atomically;
its receipt does not complete the Job/Assignment or replace the separate TaskResult. It also accepts
`output` with strict `{stream, sequence, data}`, a limited
`final_result` with strict `{exit_code, status, reason, artifacts, output}` and
`output` `{stdout_chunks, stderr_chunks, truncated}`. Persistent Command, no-artifact Runbook,
artifact-bearing Runbook, and DriftCheck finals are supported subject to their job/output contracts.
Artifact metadata and optional bodies are validated; a present body must match stored id/class/
checksum/size evidence. The Agent journals/replays no-artifact finals and DriftCheck results, but not
artifact-bearing Runbook output/final reports. SQLite retries staged pending final effects at startup
and every 30 seconds in batches bounded to 100 reports/8 MiB; exact staged bytes and owner are
revalidated. It also retries up to 100 committed final reports whose receipt persistence failed,
using only their identity/digest and never repeating the effect. Receipt delivery uses the active
session single writer after commit. A disconnect before inbox staging remains unrecoverable by the
Agent. Postgres report recovery is unsupported.
`artifacts` need not be empty. It also accepts
strict lifecycle bodies `{"event":"task_ack"}` / `{"event":"task_started"}` /
`{"event":"task_rejected","reason_code":"invalid_signature","reason":"..."}` under stable report
ids `task-ack` / `task-started` / `task-rejected`. It verifies each report against the authenticated Agent and current
Controller namespace. Each lifecycle effect additionally matches the stored Agent/Job/task owner and
commits the corresponding `dispatched -> accepted`, `accepted -> started`, or pre-execution
`dispatched -> rejected` Assignment transition, Job aggregate, one redacted audit, and inbox marker
in one SQLite transaction. TaskRejected also stores its reason code and redacted reason on the
Assignment. If the started Assignment is a remediation runbook, its `job_created -> running`
request transition and Policy audit commit in that same transaction. Exact duplicate effects do not
repeat transitions or audit; terminal, non-dispatched rejection, or mismatched-owner reports fail closed. After the effect commits, the
Controller persists the signed `stored` receipt and enqueues it on the session writer. Identical retry
replays the same signed bytes; a changed body gets no receipt. The persistent Agent journals TaskAck,
TaskStarted, TaskRejected, and DriftEvidence for Command, Runbook, and Drift tasks before sending and
deletes each only after the exact signed receipt verifies. It also uses this path end-to-end for Command/no-artifact Runbook stdout/stderr,
no-artifact Command/Runbook final results, and persistent DriftCheck terminal results. Command/Runbook
finalization verifies the exact stored sequence prefix and does not have an older final-body fallback;
DriftCheck terminal results carry an empty output summary. Artifact-producing Runbook stdout/stderr
and final reports remain non-durable in the Agent journal, although the final uses the authenticated
v2 `FinalResult` Controller effect/receipt path. The direct one-shot `agent heartbeat --once` handler
still uses the separate legacy `TaskResult` path. Drift evidence and its terminal result
are two distinct durable reports on persistent sessions.
Other lifecycle events, artifact/remediation final follow-up,
proof that all task-execution bytes were captured, reconciliation of reports already ACK-cleaned before
backup, lossless rollback, and Postgres runtime support remain future work. Still-pending exact reports
can be replayed against the restored owner-bound inbox and receive a current-epoch receipt without
repeating committed effects; unknown assignments remain fail-closed. The bounded Controller startup/periodic interrupted-execution recovery worker is implemented
for SQLite only; Postgres startup fails closed until it implements that contract.

`job_output_chunks`는 raw stdout/stderr chunk 저장소다.

- Product application log에 raw output을 남기지 않는다.
- duplicate `(job_id, agent_id, stream, chunk_index)`는 같은 body면 idempotent로 처리한다.
- 같은 key에 다른 body가 들어오면 protocol conflict로 본다.

### Bounded output read adapter (SQLite schema v27)

`fleet-application::output_read`와 SQLite `OutputPageRepository`는 기존 전체 배열 조회와
별도로 append ID 순서의 제한된 출력 page를 읽는다.
HTTP output-page route·opaque cursor codec·API client 및 Admin의 bounded live/history 소비를
연결했다. 실제 UI 비용 인수는 별도이며, wire v2와
기존 `/api/jobs/{job_id}/output` 응답은 바뀌지 않는다. 외부 계약은
[UI-001 출력 계약](../.docs/domains/execution/features/UI-001-output-paging-contract.md)을 따른다.

- 한 read transaction에서 canonical Job 상태, read projection과 출력 fragment를 읽는다.
  metadata query는 `LIMIT`을 적용하고 body는 `substr(CAST(body AS BLOB), ...)`로 나눠 가져온다.
  전체 body를 조회한 뒤 메모리에서 slice하지 않는다. UTF-8 code point 경계, NUL, 빈 row와
  i64 범위의 row/sequence/offset을 보존한다. 기본 128 fragments/65,536 source bytes,
  최대 256 fragments/262,144 source bytes다. source budget은 Agent ID·stream·data의 UTF-8 합계다.
- read cursor는 Job/optional Agent/stream, purpose-separated namespace+restore epoch digest,
  generation과 row/byte 위치를 갖는다. frozen high-water prefix를 drain한 다음 새 prefix를 읽으므로
  다른 Agent의 늦은 append를 사전순 cursor로 놓치지 않는다. epoch/generation 변경은 stale,
  다른 scope·잘못된 row/UTF-8 위치는 invalid이며 빈 성공으로 대체하지 않는다.
- `job_output_read_state(job_id, generation, history, last_row_id)`는 기술적 read projection이다.
  v26 이전 Job은 원문 row와 ID를 유지한 채 `unknown`, 이후 새 Job은 `tracked`로 시작한다.
  append는 같은 statement의 trigger로 high-water를 갱신한다. 실제 삭제는 generation을 증가시키고
  `pruned`로 바꾼다. dry-run·삭제 0건·rollback은 이력을 바꾸지 않는다. Job 삭제 시 projection도 종료된다.
  `tracked`는 저장 row 이력이며 모든 실행 byte의 capture를 보장하지 않는다.
- generation overflow, missing projection/trigger, 저장 row보다 낮은 high-water와 unreadable data는
  fail-closed다. request/reopen 중 projection을 초기화해 손실 이력을 지우지 않는다.
  공식 restore는 기존 store epoch를 회전시켜 cursor를 무효화한다. retention은 receipt/nonce나
  delivery epoch를 삭제·회전시키지 않는다.
- migration은 projection·trigger·`job_output_chunks_append_read_idx(job_id,id)`·v27 marker를
  같은 transaction으로 적용한다. 기존 canonical Job/Assignment/output는 변경하지 않는다.
  2,048 rows/두 Agent/1,024-byte row의 동일 local read 비교에서 임시 정렬을 제거하고 같은
  page를 반환함을 확인한 index다. 이 결과는 API/UI 비용 인수나 성능 SLA가 아니다.
- v27 DB는 v26 binary로 직접 열지 않는다. rollback은 변경 전 DB/identity 백업을 격리한
  경로에 복원한 뒤 해당 binary/schema로 검증하는 기존 절차를 따른다. backup 이후 이미 ACK된
  보고의 무손실 복원 한계는 그대로다. 이 migration의 rollback rehearsal는 실패 시 v26 marker와
  legacy row 보존, 재시도, 새 schema archive 거절 및 기존 backup/restore gate로 검증한다.
- Postgres는 공통 schema version marker만 v27로 전진하며 이 SQLite projection/page adapter를
  제공하지 않는다. 기존 repository contract·feature/실DB gate를 유지하고 Controller 운영 지원이나
  Postgres 증분 출력 지원으로 해석하지 않는다. v26 inbox class migration을 이후 버전마다 반복하지 않는다.

Final result는 output chunk와 다르다.

- success/failure/canceled/expired/rejected는 assignment final result로 저장해야 한다.
- exit code, duration, changed/skipped, primitive result는 final result에 가깝다.
- output chunk 수신만으로 job success를 판단하지 않는다.
- 이미 terminal 상태인 assignment는 늦은 result로 덮어쓰지 않는다. operator cancel 이후 늦은 success가 도착해도 job/assignment는 `canceled`로 남아야 한다.

현재 TaskResult 수신 전체는 하나의 transaction이 아니다. Assignment 상태 기록 뒤 artifact body/metadata,
Job aggregate와 audit을 처리하므로 artifact 저장 실패 시 terminal Assignment와 이전 Job 상태가 함께 남을 수 있다.
Controller의 `legacy_result_retry_after_artifact_failure_preserves_partial_commit` 테스트는 격리 SQLite를
다시 연 뒤 artifact store를 복구하고 동일 결과를 재전송해도 누락된 artifact/aggregate가 복구되지 않음을 고정한다.
이 한계는 terminal 상태 덮어쓰기를 허용하라는 뜻이 아니다. 향후 receipt와 후속 효과 복구를 설계할 때
terminal 보호와 별도로 해결해야 하며, 현재 backup/reopen 또는 재전송만으로 해결된다고 주장하지 않는다.

## Retention과 Audit

현재 retention cleanup path는 explicit CLI command와 controller-managed worker를
포함하며 다음 table을 대상으로 한다.

- `job_output_chunks`
- `facts_snapshots`
- `metrics_snapshots`
- `agent_log_chunks`

Audit retention은 별도 operator policy가 생기기 전까지 자동 삭제하지 않는다.

규칙:

- retention worker나 cleanup command는 `audit_events`를 기본 삭제 대상에 넣지 않는다.
- cleanup 실행 자체는 audit event로 남겨야 한다.
- logs, job output, metrics, facts는 retention 정책을 서로 구분한다.
- audit 장기 보관은 일반 retention worker가 아니라 명시적인 operator export/backup
  정책으로 처리한다.

## Test 기준

Storage 변경 시 최소 확인:

- empty DB initialization test
- migration repeatability test
- previous schema fixture migration test
- repository contract roundtrip test through application repository traits
- duplicate/constraint behavior test
- retention does not delete audit events test
- backup/restore rejects newer schema archive test
- `cargo test --workspace`
- `git diff --check`

빠른 store gate:

```bash
cargo test -p fleet-store migration_from_versioned_previous_fixture_adds_columns_without_losing_rows
cargo test -p fleet-store sqlite_catalog_repository_preserves_active_ready_revision_and_failed_attempt_after_reopen
cargo test -p fleet-store sqlite_catalog_sync_operation
cargo test -p fleet-store sqlite_catalog_document_repository_roundtrips_validated_body_after_reopen
cargo test -p fleet-store sqlite_catalog_query_repository_pages_durable_provenance_without_listing_bodies
cargo test -p fleet-store sqlite_catalog_document_cursor_reads_one_thousand_rows_in_ten_indexed_pages
cargo test -p fleet-store --features postgres postgres_store_implements_catalog_repository_trait
cargo test -p fleet-store sqlite_store_implements_application_repository_contracts
cargo test -p fleet-store sqlite_store_passes_shared_repository_contract_harness
cargo test -p fleet-store migration_state_transitions_follow_phase3_gate
cargo test -p fleet-application artifact_store_contract_is_storage_backend_neutral
cargo test -p fleet-store local_artifact_store
cargo test -p fleet-store --features postgres postgres_store_exposes_explicit_connection_entrypoints
cargo test -p fleet-store --features postgres postgres_store_selects_tls_adapter_for_sslmode_require
cargo test -p fleet-store --features postgres postgres_tls_adapter_failure_is_redacted
cargo test -p fleet-store --features postgres postgres_store_checkout_failure_is_redacted
cargo test -p fleet-store --features postgres postgres_store_implements_bootstrap_repository_traits
cargo test -p fleet-store --features postgres postgres_store_implements_enrollment_token_repository_trait
cargo test -p fleet-store --features postgres postgres_store_implements_audit_repository_traits
cargo test -p fleet-store --features postgres postgres_store_implements_approval_repository_trait
cargo test -p fleet-store --features postgres postgres_store_implements_job_assignment_repository_traits
cargo test -p fleet-store --features postgres postgres_store_implements_typed_job_repository_traits
cargo test -p fleet-store --features postgres postgres_store_implements_dispatch_assignment_repository_trait
cargo test -p fleet-store --features postgres postgres_store_implements_output_telemetry_repository_traits
cargo test -p fleet-store --features postgres postgres_store_implements_drift_policy_capability_repository_traits
cargo test -p fleet-store --features postgres postgres_store_implements_query_artifact_retention_repository_traits
cargo test -p fleet-store --features postgres postgres_store_implements_remediation_request_repository_trait
cargo test -p fleet-core database_settings
cargo test -p fleet-controller postgres_backend
cargo test -p fleet-cli controller_restore_refuses_incompatible_schema_version
cargo test -p fleet-cli controller_backup_restore_roundtrip_restores_database_and_keys
cargo test -p fleet-cli journaled_command_output_replays_after_reopen_and_stale_restore_epoch_receipt_cannot_clean_it
cargo test -p fleet-store sqlite_signed_receipt_rejects_pending_digest_epoch_and_reissues_for_current_signer
cargo test -p fleet-store sqlite_signed_receipt_reissues_exact_committed_report_after_signing_key_rotation
cargo test -p fleet-store output_retention_keeps_committed_report_tombstone_and_receipt_without_resurrecting_output
cargo test -p fleet-controller authenticated_output_report_reissues_after_signing_key_rotation_without_repeating_effect
```

Postgres가 있는 개발 환경에서만 실행하는 ignored gate:

```bash
FLEET_TEST_POSTGRES_URL=postgresql://... \
  cargo test -p fleet-store --features postgres \
  postgres_catalog_repository_roundtrips_source_operation_document_and_activation -- --ignored
FLEET_TEST_POSTGRES_URL=postgresql://... \
  cargo test -p fleet-store --features postgres postgres_migration_records_current_schema_version -- --ignored
FLEET_TEST_POSTGRES_URL=postgresql://... \
  cargo test -p fleet-store --features postgres postgres_bootstrap_repositories_roundtrip -- --ignored
FLEET_TEST_POSTGRES_URL=postgresql://... \
  cargo test -p fleet-store --features postgres postgres_enrollment_token_repository_roundtrip -- --ignored
FLEET_TEST_POSTGRES_URL=postgresql://... \
  cargo test -p fleet-store --features postgres postgres_audit_repository_roundtrip -- --ignored
FLEET_TEST_POSTGRES_URL=postgresql://... \
  cargo test -p fleet-store --features postgres postgres_approval_repository_roundtrip -- --ignored
FLEET_TEST_POSTGRES_URL=postgresql://... \
  cargo test -p fleet-store --features postgres postgres_job_assignment_repository_roundtrip -- --ignored
FLEET_TEST_POSTGRES_URL=postgresql://... \
  cargo test -p fleet-store --features postgres postgres_typed_job_repository_roundtrip -- --ignored
FLEET_TEST_POSTGRES_URL=postgresql://... \
  cargo test -p fleet-store --features postgres postgres_dispatch_assignment_repository_roundtrip -- --ignored
FLEET_TEST_POSTGRES_URL=postgresql://... \
  cargo test -p fleet-store --features postgres postgres_output_telemetry_repository_roundtrip -- --ignored
FLEET_TEST_POSTGRES_URL=postgresql://... \
  cargo test -p fleet-store --features postgres postgres_drift_policy_capability_repository_roundtrip -- --ignored
FLEET_TEST_POSTGRES_URL=postgresql://... \
  cargo test -p fleet-store --features postgres postgres_query_artifact_retention_repository_roundtrip -- --ignored
FLEET_TEST_POSTGRES_URL=postgresql://... \
  cargo test -p fleet-store --features postgres postgres_remediation_request_repository_roundtrip -- --ignored
```

이 URL은 test-only 입력이다. production code는 process env를 읽지 않고 explicit
argument 또는 bootstrap `DatabaseSettings`로만 DB 설정을 받는다.

각 ignored integration test는 **비어 있는 disposable database를 따로** 사용한다. 여러
repository contract fixture는 같은 test database 안의 다른 durable row를 의도적으로
관찰할 수 있으므로, `-- --ignored`로 전체 suite를 한 database에 병렬 실행해 parity 결과로
해석하지 않는다.

2026-08-31에는 loopback-only temporary PostgreSQL 18.3 cluster에서 위 13개 ignored test를
각각 새 database에 연결해 모두 통과했다. cluster와 data directory는 test 직후 제거했다.
이 결과는 feature-gated adapter의 local runtime parity 근거이며, production PostgreSQL,
custom CA/mTLS, HA lease/leader election 검증을 의미하지 않는다.

Fixture 갱신 절차:

1. `CURRENT_SCHEMA_VERSION`을 올리는 schema 변경 전에 새 previous-version fixture를 만든다.
2. fixture에는 기존 row와 `schema_migrations` row를 함께 넣는다.
3. 실패하는 fixture migration test를 먼저 작성한다.
4. migration 구현 후 legacy row 보존, 새 column/default, current schema version 기록을 검증한다.
5. backup/restore schema compatibility test가 newer archive를 계속 거부하는지 확인한다.
6. 문서의 fixture 파일명과 빠른 store gate 명령을 함께 갱신한다.

Schema/repository code가 바뀌면 추가 확인:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
git diff --check
```

## 아직 하지 않는 것

- Postgres implementation: Phase 3. `DatabaseSettings`, SQLite shared repository
  contract harness, feature-gated Postgres migration skeleton, and ignored integration
  migration test exist. Agent/AdminToken/ControllerIdentity/AgentIdentity bootstrap
  repository traits, EnrollmentToken repository trait, Audit repository trait, and ApprovalRequest
  repository trait exist behind the `postgres` feature. Basic Job/TaskAssignment persistence
  traits, command/runbook/drift typed job repository traits, and DispatchAssignmentRepository
  pending query/state transition also exist. JobOutput/Facts/Metrics/AgentLog,
  Drift/Policy/AgentCapability, JobQuery/ArtifactMetadata/Retention, and RemediationRequest
  repositories also exist. Controller runtime now has `ControllerStore` and `ControllerStoreRef`
  boundaries, feature-gated Postgres open/migration wiring, direct repository adapter dispatch,
  and queued-only dispatch claim/release contract in `fleet-controller --features postgres`.
  Current Controller startup is blocked by unsupported Postgres Assignment/report recovery.
  Recovery parity is required before runtime support. Further Postgres/HA work includes lease/claim semantics for scheduled drift, retention,
  and multi-controller workers. Custom CA, mTLS, and certificate rotation are Phase 5 work.
- S3-compatible artifact storage: Phase 4 local `ArtifactStore` contract와 checksum/path traversal/delete tests 통과 후 별도 task.
- destructive migration: backup/restore, operator confirmation, fixture migration test가 먼저 필요하다.
- runtime DB configuration mutation: 계속 금지한다.
- UI에서 DB schema 또는 runtime config를 직접 수정하는 기능: 계속 금지한다.
- HA lease/leader election: Phase 10.
- tamper-evident audit hash chain and signed manifest: Phase 11.
