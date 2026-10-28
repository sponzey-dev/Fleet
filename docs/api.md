# Sponzey Fleet Controller API

이 문서는 현재 구현된 Controller API 범위를 기록한다. API는 `fleet controller start`로 실행되는 Controller process가 제공한다.

구현 상태 표기는 [docs/feature-matrix.md](feature-matrix.md)를 기준으로 한다.
이 문서의 endpoint는 현재 구현된 API를 우선 설명하고, 아직 제품화 단계가
남은 부분은 Current Limits에 명시한다.

## Transport

HTTP와 HTTPS controller URL을 모두 허용한다. 단, HTTP는 설치 확인, 로컬
개발, 실험실 테스트, 짧은 검증 용도로만 사용해야 한다.

제품, 고객, 운영, 공동 사용, 장시간 실행 환경에서는 반드시 HTTPS를 사용해야
한다. HTTP는 암호화되지 않으므로 controller/agent 실행 경계에서 경고를
출력하고, controller external URL이 HTTP이면 Security audit에 기록한다.
HTTP 사용으로 발생하는 token 노출, command 탈취, 데이터 유출, 중간자 공격,
기타 위험이 있을 수 있다.

```bash
fleet controller start --host 127.0.0.1 --port 7700 --data-dir .fleet --external-url http://127.0.0.1:7700
```

SQLite DB 경로를 명시하려면 bootstrap 시점에 `--db sqlite://...`를 전달한다.
`postgres://...`와 `postgresql://...`는 typed database setting으로 분류되지만,
현재 Postgres adapter는 구현되지 않았다. 해당 URL로 controller를 시작하면
request handler가 열리기 전에 bootstrap 오류로 실패한다.

```bash
fleet controller start --host 127.0.0.1 --port 7700 --data-dir .fleet --db sqlite:///tmp/fleet.db --external-url http://127.0.0.1:7700
```

## Swagger / OpenAPI 지원 기준

Controller가 외부에 제공하는 HTTP API는 Swagger/OpenAPI 문서를 함께 제공한다.
운영자와 외부 자동화 도구가 같은 계약을 보고 연동할 수 있도록, REST API를
추가하거나 변경할 때는 코드, 테스트, `docs/api.md`, OpenAPI 문서를 함께
갱신한다.

제공 endpoint:

```http
GET /openapi.json
GET /swagger-ui
```

- `/openapi.json`은 OpenAPI 3.1 JSON 문서를 반환한다.
- `/swagger-ui`는 브라우저에서 확인할 수 있는 Swagger UI를 제공한다.
- Swagger UI는 Web Admin UI와 별개다. Web Admin UI는 `/admin`, API 문서는 `/swagger-ui`로 접근한다.
- WebSocket agent protocol은 REST OpenAPI 범위에 넣지 않고 `docs/protocol.md`에서 별도로 문서화한다.

OpenAPI 문서 범위:

- `/healthz`
- `/api/controller/identity`
- `/api/controller/signing-rotation/status`
- `/api/controller/signing-rotation/restart-plan`
- `/api/controller/signing-rotation/restart-action`
- `/api/controller/signing-rotation/request`
- `/api/controller/signing-rotation/validate`
- `/api/controller/signing-rotation/activate`
- `/api/controller/signing-rotation/retire`
- `/api/controller/signing-rotation/fail`
- `/api/controller/signing-rotation/rollout-trust-bundle`
- `/api/controller/signing-rotation/rollout-trust-bundle/staged`
- `/api/controller/signing-rotation/rollout-trust-bundle/retry`
- `/api/agents/enroll`
- `/api/enrollment-tokens`
- `/api/enrollment-tokens/{id}`
- `/api/agents`
- `/api/agents/{agent_id}`
- `/api/agents/{agent_id}/labels`
- `/api/agents/{agent_id}/revoke-key`
- `/api/agents/{agent_id}/facts`
- `/api/agents/{agent_id}/facts/latest`
- `/api/agents/{agent_id}/metrics`
- `/api/agents/{agent_id}/metrics/latest`
- `/api/agents/{agent_id}/logs`
- `/api/agents/{agent_id}/drift`
- `/api/agents/{agent_id}/drift/latest`
- `/api/catalog/sources`
- `POST /api/catalog/sources`
- `POST /api/catalog/sources/{source_id}/sync`
- `GET /api/catalog/sources/{source_id}/sync-operations/{operation_id}`
- `POST /api/catalog/sources/{source_id}/activate`
- `/api/catalog/sources/{source_id}/revisions`
- `/api/catalog/sources/{source_id}/revisions/{commit}/documents`
- `/api/catalog/sources/{source_id}/revisions/{commit}/document`
- `/api/policies`
- `/api/policies/{policy_id}/assignments`
- `/api/policies/{policy_id}/schedules`
- `/api/agents/{agent_id}/policies`
- `/api/drift/scheduled`
- `/api/jobs`
- `/api/jobs/{job_id}`
- `/api/selectors/preview`
- `/api/jobs/command`
- `/api/jobs/runbook`
- `POST /api/jobs/catalog-runbook`
- `/api/jobs/drift-check`
- `/api/jobs/{job_id}/cancel`
- `/api/jobs/{job_id}/output`
- `/api/jobs/{job_id}/output-page`
- `/api/jobs/{job_id}/artifacts/{artifact_id}`
- `/api/audit`
- `/api/audit/export`

인증 표기:

- 보호 API는 OpenAPI `bearerAuth` security scheme으로 admin token을 요구한다고 명시한다.
- Swagger UI에서 보호 API를 호출하려면 `Authorize`에 `fleet controller init`이 출력한 admin token을 넣는다.
- `/api/agents/enroll`은 admin token을 쓰지 않는다. enrollment token은 request body의 `token` 필드로 전달한다.
- `/healthz`, `/api/controller/identity`, `/openapi.json`, `/swagger-ui`는 문서와 readiness 접근을 위해 public endpoint로 둔다.

보안 문서화 규칙:

- OpenAPI example에는 실제 admin token, enrollment token, private key, secret, command output 원문을 넣지 않는다.
- token example은 `<admin-token>`, `<enrollment-token>`, `<redacted>` 같은 placeholder만 사용한다.
- enrollment token create 응답의 raw token은 "생성 직후 1회만 표시되는 민감값"으로 설명한다.
- HTTP transport는 테스트 전용이라는 경고를 Swagger description에도 포함한다.
- Swagger UI를 HTTP endpoint에서 사용할 수는 있지만, HTTP에서는 token과 요청 payload가 암호화되지 않는다. 운영/제품/공동 사용 환경에서는 HTTPS URL의 Swagger UI만 사용해야 한다.

변경 절차:

- 외부 API를 추가하면 OpenAPI path, request schema, response schema, error response를 같이 추가한다.
- 기존 request/response shape를 바꾸면 `info.version`과 package version의 영향도를 확인한다.
- Web Admin UI가 사용하는 API라면 `web-admin/api.schema.json`과 Web Admin smoke test도 함께 갱신한다.
- list API를 새로 추가할 때는 `limit`과 cursor 기반 paging을 우선 사용한다. offset paging은 snapshot이 계속 추가되는 운영 데이터에는 기본값으로 쓰지 않는다.

## API Surface 구분

현재 Controller가 제공하는 HTTP surface는 목적별로 나눈다.

| Surface | Endpoint 범위 | 인증 | 안정성 기준 |
| --- | --- | --- | --- |
| Public readiness/docs | `/healthz`, `/api/controller/identity`, `/openapi.json`, `/swagger-ui` | 없음 | 운영 도구가 의존할 수 있는 public surface |
| Agent protocol REST | `POST /api/agents/enroll` | enrollment token body | agent bootstrap 계약. WebSocket protocol은 별도 문서화 |
| Admin API | `/api/agents`, `/api/jobs`, `/api/approvals`, `/api/enrollment-tokens`, `/api/catalog/*`, `/api/controller/signing-rotation/*`, `/api/audit`, `/api/audit/export`, telemetry page API | admin bearer token | 외부 자동화 후보. OpenAPI와 contract test 대상 |
| Admin beta API | `/api/policies`, `/api/drift/scheduled`, `/api/selectors/preview`, label 변경, key revoke | admin bearer token | 구현되어 있지만 selector rollout과 UX가 더 바뀔 수 있음 |
| Internal static | `/admin`, `/admin/*`, `/favicon.ico` | 없음 | Web Admin asset serving. REST API 계약이 아님 |
| Agent WebSocket protocol | `/api/agents/ws` | agent identity proof | `docs/protocol.md` 범위. REST OpenAPI에 포함하지 않음. Persistent TaskAck/TaskStarted/TaskRejected, DriftCheck evidence와 별도 terminal result, Command/no-artifact Runbook output 및 no-artifact Command/Runbook final result는 SQLite report receipt path 사용; DriftEvidence receipt는 Job/Assignment 성공이 아니다. persistent Command/Runbook final은 output summary의 정확한 저장 구간도 확인한다. direct one-shot과 artifact-producing Runbook output/final report는 별도 경로 |

Public readiness/docs endpoint와 agent enrollment endpoint는 admin bearer token을 쓰지
않는다. 그 외 `/api/...` 운영 endpoint는 기본적으로 admin bearer token을 요구한다.
Web Admin UI가 쓰는 endpoint는 public API와 완전히 같지는 않지만, 누락을 막기 위해
`web-admin/api.schema.json`, `web-admin/scripts/test.js`, `docs/openapi.json`을 함께
검증한다.

## Common Contract

### Error Response

오류 응답은 가능한 한 다음 공통 모델을 따른다.

```json
{"error":"not_found"}
```

권한 부족처럼 추가 정보가 필요한 경우에는 `required_permission`을 포함한다.

```json
{"error":"forbidden","required_permission":"job_approve"}
```

상태 코드 기준:

- `400 Bad Request`: JSON parse 실패, request body validation 실패, query parameter 형식 오류.
- `401 Unauthorized`: admin token이 없거나 유효하지 않음.
- `403 Forbidden`: admin token은 유효하지만 role이 endpoint permission을 갖지 않음.
- `404 Not Found`: 특정 job, agent, approval, token 같은 명시적 resource가 없음.
- `409 Conflict`: enrollment 중복 agent, job id 중복, command/job 생성 충돌처럼 현재 상태와 충돌.

`latest` API의 데이터 없음은 resource not found와 다르게 처리한다.

- `GET /api/agents/{agent_id}/facts/latest`
- `GET /api/agents/{agent_id}/metrics/latest`
- `GET /api/agents/{agent_id}/drift/latest`

위 endpoint는 최신 snapshot/report가 없으면 `200 OK`와 JSON `null`을 반환한다. Web Admin은 이
값을 정상적인 "아직 수집 데이터 없음" 상태로 표시해야 한다. 반대로
`GET /api/agents/{agent_id}`처럼 특정 resource 자체를 조회하는 endpoint는 없으면
`404 {"error":"not_found"}`를 반환한다.

### Pagination

운영 중 계속 추가되는 데이터는 cursor 기반 paging을 사용한다.

Request query:

| Query | 기준 |
| --- | --- |
| `limit` | optional, `1..=500`, 기본값은 endpoint별 OpenAPI schema를 따른다. |
| `before` | optional opaque cursor. 이전 응답의 `next_cursor` 값을 그대로 넣는다. |

Response shape:

```json
{
  "items": [],
  "next_cursor": null
}
```

현재 이 paging contract를 쓰는 endpoint:

- `GET /api/agents/{agent_id}/facts`
- `GET /api/agents/{agent_id}/metrics`
- `GET /api/agents/{agent_id}/logs`
- `GET /api/agents/{agent_id}/drift`
- `GET /api/audit/export`

Catalog 목록은 같은 cursor 원칙을 쓰지만 오래된 immutable record를 ID/commit/path 오름차순으로
읽기 때문에 query와 응답 필드 이름이 `after`/`next_after`이고, `limit` 범위는 `1..=100`이다.
다음 endpoint에 적용한다.

- `GET /api/catalog/sources`
- `GET /api/catalog/sources/{source_id}/revisions`
- `GET /api/catalog/sources/{source_id}/revisions/{commit}/documents`

일반 snapshot 목록은 최신순이며 `next_cursor`를 사용한다. 위의 Catalog 세 목록은
ID/commit/path 오름차순이고 `next_after`가 `null`이면 다음 page가 없다. client는 반환받은
cursor를 그대로 다음 요청에 전달하며 분해하거나 생성하지 않는다.

### Catalog Read API

Catalog read API는 이미 Controller에 저장된 source, immutable revision, 검증된 document를
읽기만 한다. 조회 요청은 Git fetch, source sync, revision activation 또는 Policy/Runbook
실행을 시작하지 않는다. Admin은 각 목록을 한 page씩 유지하고 source/revision/document를 명시적으로
선택한다. 페이지를 바꿔도 선택했던 immutable metadata를 다른 항목으로 자동 교체하지 않는다.
route/auth/상위 선택이 바뀌면 진행 중 조회를 취소하며 늦은 성공·오류는 반영하지 않는다. 네 endpoint 모두 `Authorization: Bearer <admin-token>`을 요구하며,
현재 `policy_read` 권한을 사용한다.

```http
GET /api/catalog/sources?limit=50&after=<cursor>
GET /api/catalog/sources/{source_id}/revisions?limit=50&after=<cursor>
GET /api/catalog/sources/{source_id}/revisions/{commit}/documents?limit=50&after=<cursor>
GET /api/catalog/sources/{source_id}/revisions/{commit}/document?path=runbooks%2Frestart-web.yaml
```

세 목록 응답은 다음 모양이다.

```json
{
  "items": [],
  "next_after": null
}
```

- source item은 `id`, public `url`, `reference`, `active_commit`만 반환한다.
- revision item은 `commit`, durable `state`, `document_count`, sanitized `failure`만 반환한다.
- document 목록 item은 `kind`, repository-relative `path`, `checksum`만 반환한다. **`body`는
  목록에 절대 포함되지 않는다.**
- 하나의 document body가 필요할 때만 `document?path=...` detail endpoint를 사용한다. detail은
  `kind`, `path`, `checksum`, `body`를 반환한다. query `path`는 URL query 값으로 percent-encode해야
  하며, 해당 document가 없으면 `404 {"error":"not_found"}`를 반환한다.
- `limit`이 `1..=100` 밖이거나 `after`/`path`의 percent encoding이 잘못되면 `400`이다. 목록의
  존재하지 않는 source/revision은 빈 page이고, 그 source/revision 아래의 명시적 document detail이
  없으면 `404`이다.

Catalog source mutation은 owner/admin의 `policy_write` 권한만 허용한다. `POST /api/catalog/sources`는
`source_id`, public HTTPS `url`, `reference`를 받고 source와 redacted audit event를 만든다.
`POST /api/catalog/sources/{source_id}/sync`는 `{ "operation_id": "..." }`로 durable operation을
만든 뒤 bounded worker에 전달하고 `202`를 즉시 반환한다. 등록 및 sync 요청은 credential을 받거나
HTTP handler에서 Git fetch를 실행하지 않는다.
202 body의 `id`는 실제 canonical operation ID다. 같은 source에 진행 중인 operation이 있으면 요청한
ID 대신 기존 ID가 반환될 수 있다. 202는 완료나 활성화를 뜻하지 않는다.
`GET /api/catalog/sources/{source_id}/sync-operations/{operation_id}`는 `policy_read` 권한으로
해당 source에 속한 operation만 조회한다. 응답은 `id`, `source_id`, nullable `commit`,
`state`(`in_progress`/`completed`/`failed`/`cancelled`), nullable `failure`다. `completed`에는 commit이
있고, `failed`의 failure는 `fetch_rejected`, `fetch_failed`, `validation_failed`, `limit_exceeded`,
`cancelled` 중 하나이며 다른 state의 failure는 null이다. 기존 ready revision으로 새 operation의
완료를 판정하지 않는다. 조회는 fetch·activation·audit mutation을 수행하지 않는다.
모든 상태 조회 응답은 `Cache-Control: no-store`다. 잘못된 ID나 query는 400, 미인증은 401,
권한 없음은 403, operation 부재 또는 source 불일치는 동일한 404다. query parameter는 받지 않는다.
저장소 오류는 내부 SQL·URL·원인을 담지 않는 500 `catalog_sync_status_unavailable`로 반환한다.
Admin 상태 관찰은 10초 요청 deadline과 최대 3분 관찰 기한을 소유하며, transient GET만 최대 3회/제한된 backoff로 재시도한다. 화면 이탈·인증·선택 변경은 관찰을 정리하고, 변경 POST의 응답을 잃으면 결과 불명으로 표시하며 자동 재전송하지 않는다.
Activation은 `POST /api/catalog/sources/{source_id}/activate` body의 immutable `commit`을 받아 ready revision만 active pointer로 전환한다. sync 완료는 activation을 자동으로 수행하지 않는다. Admin은 선택한 source와 ready commit을 확인 창에서 명시적으로 확인한다. 이는 CAS/분산 잠금이 아니며 다른 관리자의 동시 변경을 막지 않는다.

### Catalog Runbook Job API

`POST /api/jobs/catalog-runbook`는 `job_create`와 `policy_read` 권한을 모두 요구한다.
source를 sync/activate할 권한과 Job을 생성할 권한은 별도다. actor는 인증된 token에서 정하고
request의 actor/confirmed_by/approval/nonce 또는 raw `runbook_document` 필드를 받지 않는다.
unknown field와 DTO field의 중복 지정도 거절한다. 기존 `POST /api/jobs/runbook`은 유지한다.

```json
{
  "job_id": "catalog-job-1",
  "source_id": "public-catalog",
  "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "path": "runbooks/sample.yaml",
  "checksum": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "target_agent_ids": ["agent-web-01"],
  "timeout_seconds": 30,
  "expires_in_seconds": 300,
  "confirmed_high_risk": true,
  "strategy": {"concurrency": 1, "maxFailures": 1}
}
```

필수 필드는 `job_id/source_id/commit/path/checksum`이다. commit은 소문자 hex40/64자,
checksum은 소문자 SHA256 hex64자다. 본문은 서버 durable catalog에서만 읽는다.
nonempty `target_agent_ids`, `selector`, `matchLabels` 중 하나만 사용한다. 모두 없으면
저장된 Runbook의 target selector를 쓴다. selector는 disabled Agent를 제외하고 offline Agent는
포함한다. explicit ID의 unknown/disabled/duplicate는 저장 전에 거절한다. 보고된 Runbook 및
package/service/file capability가 incompatible하거나 24시간보다 오래되면 저장 전에 거절한다.
미보고/unknown capability는 기존 dispatch 정책처럼 허용하며 Agent의 실행 검증을 대신하지 않는다.

옵션 기본값은 timeout30초, expiration300초, concurrency1, maxFailures없음,
confirmed_high_risk=false다. 기간은 양수이며 platform/persisted millisecond 범위 안이어야 한다.
concurrency/maxFailures는 제공하면 양의u32다. confirmation은 acknowledgement이며 승인을 대신하지 않는다.
Job/provenance/Assignment/target snapshot/Approval/audit/strategy/selector는 하나의 transaction으로
저장한다. active/ready/path/checksum/body를 commit 안에서 다시 확인하며 commit 전에는 dispatch하지 않는다.
성공201은 기존 CreateJobResponse(`job_id/target_count/assignment_count/status/approval_request_id`)다.
Runbook 승인 대기에서는 active session이 있어도 전송하지 않고 기존 approval 경로를 사용한다.

| HTTP | 코드·의미 |
| --- | --- |
| 400 | `invalid_catalog_job` 또는 `invalid_catalog_targets`: DTO/reference/options/문서/대상 선택 오류 |
| 401 | `unauthorized` |
| 403 | `forbidden`, `required_permission`: job_create 또는 policy_read 부족 |
| 404 | `catalog_reference_not_found`: source/revision/document 부재 |
| 409 | `catalog_selection_changed`: active/ready/checksum/immutable binding 변경; 선택을 다시 확인 |
| 409 | `job_already_exists`: 같은 Job ID의 기존 상태를 변경하거나 다시 dispatch하지 않음 |
| 409 | `catalog_target_unavailable`, `catalog_target_unsupported`, `catalog_target_capabilities_stale` |
| 500 | `catalog_job_creation_unavailable`: 저장/서명/조립 실패의 분류된 응답, 내부 오류 없음 |

POST의 모든 응답은 `Cache-Control: no-store`다. client는 제출용 Job ID를 한 번 정해 유지한다.
응답을 잃었으면 같은 ID의 `GET /api/jobs/{job_id}`로 생성 여부를 확인하고 POST를 자동 재시도하거나
새 ID로 조용히 바꾸지 않는다. `409`는 새 실행 성공이 아니다.

`GET /api/jobs/{job_id}`는 기존 `job_read` 권한과 summary 필드를 유지하며
`catalog_provenance: null | {source_id,commit,path,checksum}`를 추가한다. raw Job은 null이다.
Job 소유 snapshot을 읽으므로 이후 source activation/labels 변경으로 다시 계산하지 않는다.
Job 목록 shape와 raw Job 생성 API에는 이 필드를 추가하지 않는다. 본문/secret/output도 포함하지 않는다.
생성 audit의 `catalog_runbook_job_created`는 같은 immutable 출처와 인증 actor를 보존한다.

`POST /api/jobs/catalog-runbook`의 확정 거절 응답은 선택적으로
`Fleet-Catalog-Rejection` header를 반환합니다. 값은 `catalog_selection_changed`,
`catalog_target_unavailable`, `catalog_target_unsupported`, `catalog_target_capabilities_stale` 중
하나이며 이 경우 Job이 생성되지 않았으므로 명시적인 새 검토를 할 수 있습니다.
중복 ID(`job_already_exists`)나 header가 없거나 알 수 없는 응답은 원래 Job ID로 확인합니다.
Admin은 오류 본문을 읽거나 보관하지 않으며 이 구분으로 자동 재전송하거나 새 Job을 만들지 않습니다.

### Job and Assignment

Job API는 job aggregate 상태와 target별 assignment 상태를 함께 반환한다.

- `JobSummary.status`: 전체 job aggregate 상태.
- `dispatch_state`: controller 관점의 dispatch 진행 상태.
- `assignment_summary`: target assignment 상태별 count.
- `target_agents[].assignment_status`: target별 실제 assignment 상태.
- `target_agents[].connected`: 현재 persistent agent session 연결 여부.

Client는 job 결과를 `status` 하나만 보고 판단하지 말고, target별 상태와 output endpoint를 함께
확인해야 한다. output은 `/api/jobs/{job_id}/output`에 누적 저장되고, empty output은 실패를
의미하지 않는다.



## Compatibility and Deprecation

현재 API schema version은 `mvp-1`이다. OpenAPI `info.version`, npm/package version,
문서 version은 release 작업에서 함께 확인한다.

호환성 기준:

- Public readiness/docs endpoint와 Admin API 안정 후보는 patch release에서 breaking change를 하지 않는다.
- Admin beta API는 동작하지만 request/response shape가 바뀔 수 있다. 변경 시 OpenAPI, Web Admin schema, release note를 같이 갱신한다.
- Internal static asset과 agent WebSocket frame은 REST API 호환성 정책 대상이 아니다. WebSocket protocol은 `docs/protocol.md`와 protocol compatibility test 기준을 따른다.
- 응답 필드는 가능한 한 additive change를 우선한다. 기존 필드의 의미 변경, enum 값 삭제, required field 추가는 breaking change로 본다.

Deprecation 기준:

- 기존 field나 endpoint를 제거해야 하면 최소 한 minor release 동안 문서와 OpenAPI에 deprecated 상태로 남긴다.
- 대체 field/endpoint가 있으면 같은 문서 섹션에 migration 예시를 둔다.
- 제거 시점은 release note에 명시한다.
- 보안상 즉시 제거해야 하는 경우에도 compatibility 예외와 위험 사유를 release note에 남긴다.

SDK 기준:

- TypeScript generated SDK는 아직 별도 package로 배포하지 않는다. 현재 Web Admin의 dependency-free `api-client.js`와 `web-admin/api.schema.json`이 최소 client contract smoke 역할을 한다.
- Rust client crate는 아직 만들지 않는다. CLI가 controller API 호출을 더 많이 공유하게 되면 `fleet-client` 같은 library crate로 분리한다.
- generated SDK를 도입하면 생성물 자체보다 OpenAPI snapshot, endpoint coverage, client smoke test를 release gate에 먼저 연결한다.

## Health

```http
GET /healthz
```

응답:

```json
{"status":"ok"}
```

Health endpoint는 인증 없이 접근 가능하다. 이 endpoint는 process가 요청을 받을 수 있는지 확인하기 위한 최소 readiness surface다.

## Controller Identity

```http
GET /api/controller/identity
```

응답:

```json
{
  "controller_public_key": "<ed25519-public-key-hex>",
  "controller_fingerprint": "<sha256-public-key-fingerprint-hex>",
  "controller_signing_public_key": "<ed25519-public-key-hex>",
  "controller_signing_fingerprint": "<sha256-public-key-fingerprint-hex>",
  "tls_endpoint": {
    "external_url": "https://fleet.example.com",
    "tls_enabled": true
  }
}
```

Agent는 시작 시 저장된 controller fingerprint와 이 응답을 비교한다. 값이 달라지면 explicit re-enroll 없이 연결하지 않는다.

## Controller Signing Rotation Status

```http
GET /api/controller/signing-rotation/status
Authorization: Bearer <admin-token>
```

이 endpoint는 controller signing key rotation의 read-only readiness surface다. 조회는
persisted rotation state를 전이하지 않고, private key material, key file path, TLS
certificate material, raw public key body, task payload body를 반환하지 않는다.

응답:

```json
{
  "controller_id": "default-controller",
  "persisted_record_present": true,
  "persisted_state": "dual_trust_active",
  "readiness": "dual_trust_active_agents_migrating",
  "active_signing_fingerprint_prefix": "new-fp-12345678",
  "selected_signing_fingerprint_prefix": "new-fp-12345678",
  "old_fingerprint_prefix": "old-fp-12345678",
  "new_fingerprint_prefix": "new-fp-12345678",
  "requested_at_ms": 1710000000000,
  "validated_at_ms": 1710000001000,
  "activated_at_ms": 1710000002000,
  "old_key_verifies_until_ms": 1710003600000,
  "retired_at_ms": null,
  "failed_at_ms": null,
  "bootstrap_guard": "active_matches_selected",
  "agent_trust_rollout": "agents_migrating"
}
```

Readiness 값:

- `steady_ready`
- `rotation_requested_not_validated`
- `new_material_validated_waiting_activation`
- `dual_trust_active_agents_migrating`
- `old_key_retirement_available`
- `terminal_failed`
- `terminal_canceled`
- `terminal_retired`

CLI:

```bash
fleet controller signing-rotation-status --controller-url https://fleet.example.com --admin-token <admin-token>
fleet controller signing-rotation-status --controller-url https://fleet.example.com --admin-token <admin-token> --json
```

CLI는 controller API만 호출한다. CLI가 controller store, signing key files, process
environment, 또는 runtime config를 직접 읽어 readiness를 추론해서는 안 된다.

## Controller Signing Rotation Restart Plan

`GET /api/controller/signing-rotation/restart-plan`은 admin bearer token을 요구하는
read-only endpoint다. 이 endpoint는 signing rotation status에서 restart/reload
operator plan을 파생해 반환한다. Controller process를 직접 재시작하거나, key file을
swap하거나, runtime config를 patch하거나, in-process key reload를 수행하지 않는다.

```http
GET /api/controller/signing-rotation/restart-plan
Authorization: Bearer <admin-token>
```

```json
{
  "controller_id": "default-controller",
  "restart_required": true,
  "reload_supported": false,
  "recommended_action": "restart_controller_process",
  "readiness": "dual_trust_active_agents_migrating",
  "bootstrap_guard": "active_mismatch_selected",
  "agent_trust_rollout": "agents_migrating",
  "active_signing_fingerprint_prefix": "old-fp-12345678",
  "selected_signing_fingerprint_prefix": "new-fp-12345678",
  "blocked_reason": "active signer does not match persisted selected signer; restart controller with validated signing material and verify status before retiring old key",
  "verification_commands": [
    "fleet controller signing-rotation-status --controller-url <controller-url>",
    "fleet controller signing-rotation restart-plan --controller-url <controller-url>"
  ],
  "safety_notes": [
    "this version does not support in-process controller signing key reload",
    "restart the controller process through the service manager after validated material is in place",
    "verify bootstrap_guard is active_matches_selected before retiring the old key"
  ]
}
```

CLI:

```bash
fleet controller signing-rotation restart-plan \
  --controller-url https://fleet.example.com \
  --admin-token <admin-token>

fleet controller signing-rotation restart-plan \
  --controller-url https://fleet.example.com \
  --admin-token <admin-token> \
  --json
```

`restart_required=true`는 persisted selected signing fingerprint와 active runtime
signer가 다르다는 뜻이다. Operator는 service manager나 기존 controller service
운영 절차로 controller process를 재시작한 뒤 status/restart-plan command로
`bootstrap_guard=active_matches_selected`를 확인해야 한다.

## Controller Signing Rotation Restart Action

`POST /api/controller/signing-rotation/restart-action`은 admin bearer token과
`signing_rotation_write` permission을 요구하는 mutation endpoint다. 이 endpoint는
operator가 external service-manager restart를 수행하겠다는 intent를 audit에 남기고,
실제 실행할 local service command와 verification command를 반환한다. HTTP handler는
controller process를 종료하거나 재시작하지 않고, key file reload, key swap, runtime
config patch, process env 변경도 수행하지 않는다.

```http
POST /api/controller/signing-rotation/restart-action
Authorization: Bearer <admin-token>
```

```json
{
  "confirm_external_restart": true,
  "reason": "approved maintenance window"
}
```

- `confirm_external_restart=true`가 없으면 요청은 거부된다.
- `restart_required=false`인 상태에서는 요청이 거부되고 audit event를 쓰지 않는다.
- Response와 audit에는 key body, key path, TLS material, admin token, task payload를
  포함하지 않는다. Reason은 redaction path를 통과한다.

```json
{
  "controller_id": "default-controller",
  "action": "external_service_manager_restart",
  "action_status": "audit_recorded_external_restart_required",
  "restart_required": true,
  "reload_supported": false,
  "readiness": "dual_trust_active_agents_migrating",
  "bootstrap_guard": "active_mismatch_selected",
  "active_signing_fingerprint_prefix": "old-fp-12345678",
  "selected_signing_fingerprint_prefix": "new-fp-12345678",
  "service_command": "fleet controller restart-service --dry-run",
  "verification_commands": [
    "fleet controller signing-rotation-status --controller-url <controller-url>",
    "fleet controller signing-rotation restart-plan --controller-url <controller-url>"
  ],
  "safety_notes": [
    "controller restart is executed outside the HTTP handler through an explicit service-manager command",
    "this action records operator intent only and does not reload keys or mutate runtime config",
    "after service restart, verify bootstrap_guard is active_matches_selected"
  ]
}
```

CLI:

```bash
fleet controller signing-rotation restart-action \
  --controller-url https://fleet.example.com \
  --admin-token <admin-token> \
  --confirm-external-restart \
  --reason "approved maintenance window"

fleet controller restart-service --dry-run
sudo fleet controller restart-service
```

## Controller Signing Rotation Mutations

Controller signing rotation mutation API는 admin bearer token과
`signing_rotation_write` permission을 요구한다. 현재 bootstrap `owner`와 `admin`
role은 허용되고, `operator`와 `viewer`는 거부된다.

모든 mutation 성공 응답은 `GET /api/controller/signing-rotation/status`와 같은
secret-free readiness shape를 반환한다. API와 CLI는 private key body, raw public
key body, PEM body, TLS certificate material, task payload body, process environment
값을 받거나 반환하지 않는다. Unknown field는 `400 invalid_signing_rotation_request`로
거부된다.

### Request

```http
POST /api/controller/signing-rotation/request
Authorization: Bearer <admin-token>
```

```json
{
  "new_fingerprint": "<candidate-signing-fingerprint>",
  "old_key_verifies_for_seconds": 3600,
  "reason": "scheduled signing key rotation"
}
```

`old_key_verifies_for_seconds`와 `old_key_verifies_until_ms` 중 정확히 하나만 보낸다.
이 route는 application use case를 통해 `steady -> rotation_requested`를 수행한다.

### Validate

```http
POST /api/controller/signing-rotation/validate
Authorization: Bearer <admin-token>
```

```json
{
  "candidate_public_key_path": "/var/lib/fleet/controller/candidate_public.key",
  "candidate_private_key_path": "/var/lib/fleet/controller/candidate_private.key",
  "reason": "candidate keypair validated on controller host"
}
```

이 route는 controller host의 명시적 candidate file path를 사용해 keypair challenge
검증을 수행한 뒤, fingerprint가 requested state와 일치할 때만
`rotation_requested -> new_material_validated`를 수행한다. 응답에는 candidate path나
key body를 넣지 않는다.

### Activate / Retire / Fail

```http
POST /api/controller/signing-rotation/activate
POST /api/controller/signing-rotation/retire
POST /api/controller/signing-rotation/fail
Authorization: Bearer <admin-token>
```

```json
{"reason":"operator requested state change"}
```

- `activate`는 `new_material_validated -> dual_trust_active`만 수행한다. key file swap,
  restart, reload를 암묵적으로 수행하지 않는다.
- `retire`는 old-key verification window guard가 지난 뒤에만
  `dual_trust_active -> old_key_retired`를 수행한다.
- `fail`은 non-terminal rotation state를 `rotation_failed`로 전이한다. reason은
  redaction path를 통과하며 rotation state, response, audit value에 raw secret을
  저장하지 않는다.

CLI:

```bash
fleet controller signing-rotation request \
  --controller-url https://fleet.example.com \
  --admin-token <admin-token> \
  --new-fingerprint <candidate-signing-fingerprint> \
  --old-key-verifies-for-seconds 3600

fleet controller signing-rotation validate \
  --controller-url https://fleet.example.com \
  --admin-token <admin-token> \
  --candidate-public-key-path /var/lib/fleet/controller/candidate_public.key \
  --candidate-private-key-path /var/lib/fleet/controller/candidate_private.key

fleet controller signing-rotation activate --controller-url https://fleet.example.com --admin-token <admin-token>
fleet controller signing-rotation retire --controller-url https://fleet.example.com --admin-token <admin-token>
fleet controller signing-rotation fail --controller-url https://fleet.example.com --admin-token <admin-token> --reason "candidate validation failed"
```

Audited restart action이 현재 지원되는 rotation restart 경로다. HTTP handler
self-restart와 in-process signing key hot reload는 별도 ADR, reload state machine,
rollback/audit model이 있기 전까지 제품 경로로 제공하지 않는다. Mutation response,
status command, restart-plan command의 `bootstrap_guard`를 확인해 active runtime
signing key와 persisted selected key가 일치하는지 검증한다.

## Controller Signing Trust Bundle Rollout

`POST /api/controller/signing-rotation/rollout-trust-bundle`은 admin bearer token과
`signing_rotation_write` permission을 요구한다. 이 endpoint는 `dual_trust_active`
또는 retired state에서 active runtime signer가 persisted selected signer와 일치할
때만 authenticated connected agent sessions에
`controller_signing_trust_bundle_update` protocol message를 보낸다.

```http
POST /api/controller/signing-rotation/rollout-trust-bundle
Authorization: Bearer <admin-token>
```

```json
{
  "previous_public_key_path": "/var/lib/fleet/controller/controller_public.key.bak",
  "agent_ids": ["agent-1", "agent-2"],
  "max_agent_count": 50
}
```

- `previous_public_key_path`는 dual-trust rollout에서만 필요하며 controller-local
  public key file path다. Private key path/body는 받지 않는다.
- `agent_ids`를 비우면 현재 authenticated connected sessions 전체가 대상이다.
  명시한 agent가 연결되어 있지 않으면 `skipped_not_connected`로 보고된다.
- Agent가 같은 current controller signing fingerprint를 이미 accepted ack로 보고한
  active session이면 재전송하지 않고 `skipped_already_current`로 보고된다.
- `max_agent_count`는 optional bounded batch limit이다. 생략하면 target set 전체를
  시도하고, `0`은 거부된다.
- Response, audit, Product Log에는 public key body, private key body/path, TLS
  material, task payload body, admin token, local key path를 포함하지 않는다.
- 이 endpoint는 Job/Assignment state를 만들거나 변경하지 않는다. Trust bundle
  delivery success는 task acceptance/start/success와 별개의 control message 결과다.
- Agent는 적용 성공/실패 후 `controller_signing_trust_bundle_ack`를 보낸다.
  Controller는 ack를 connection-scoped session registry runtime state로만 기록하고
  audit에는 accepted flag, entries count, current fingerprint prefix, bounded reason
  code만 남긴다. Public key body, private key, local path, raw payload는 ack에
  포함하지 않는다.

```json
{
  "controller_id": "default-controller",
  "persisted_state": "dual_trust_active",
  "attempted_count": 2,
  "updated_count": 1,
  "skipped_count": 1,
  "failed_count": 0,
  "entries_count": 2,
  "current_fingerprint_prefix": "new-fp-12345678",
  "previous_fingerprint_prefix": "old-fp-12345678",
  "agent_results": [
    {"agent_id": "agent-1", "status": "sent"},
    {"agent_id": "agent-2", "status": "skipped_not_connected"},
    {"agent_id": "agent-3", "status": "skipped_already_current"}
  ]
}
```

`POST /api/controller/signing-rotation/rollout-trust-bundle/staged`는 domain
staged rollout state machine을 사용하는 단일 coordinator tick이다. 이 endpoint는
admin bearer token과 `signing_rotation_write` permission을 요구하고, 현재
session registry의 connection/ack 상태를 `ControllerSigningStagedRolloutTarget`
observation으로 변환한 뒤 domain planner가 선택한 batch만 전송한다.

```http
POST /api/controller/signing-rotation/rollout-trust-bundle/staged
Authorization: Bearer <admin-token>
```

```json
{
  "previous_public_key_path": "/var/lib/fleet/controller/controller_public.key.bak",
  "agent_ids": ["agent-1", "agent-2", "agent-3"],
  "batch_size": 10,
  "max_failures": 1,
  "ack_timeout_seconds": 30
}
```

- `batch_size`, `max_failures`, `ack_timeout_seconds`는 hidden default 없이
  request에서 명시적으로 받는다. `batch_size == 0` 또는
  `ack_timeout_seconds == 0`은 domain invalid config로 거부된다.
- `agent_ids`를 비우면 현재 authenticated connected sessions snapshot을 대상
  후보로 사용한다. 명시한 agent가 연결되어 있지 않으면 unavailable/skipped로
  집계되며 WebSocket handle은 domain/storage에 저장하지 않는다.
- Accepted current fingerprint ack가 session registry에 있는 agent는
  `already_current_count`로 집계하고 재전송하지 않는다.
- 이 endpoint는 하나의 synchronous tick을 수행한다. 같은 controller signing
  fingerprint, previous fingerprint, target set, config에 대해 저장된 staged
  rollout state가 있으면 load/save하여 다음 tick을 이어간다. `waiting_for_ack`
  상태에서는 accepted-current observation과 ack timeout을 먼저 반영하고, 아직
  in-flight ack를 기다리는 중이면 같은 agent에게 재전송하지 않는다. Controller는
  같은 persisted state를 이어가는 periodic worker도 시작한다. Worker는 dual-trust
  payload를 만들 때 persisted staged state에 key body/path를 저장하지 않고,
  bootstrap에서 받은 controller signing public key path의 sibling
  `controller_public.key.bak`만 previous public key source로 사용한다. Web Admin은
  controller signing status 조회와 staged tick 실행 surface만 제공한다. HTTP handler
  self-restart와 in-process signing key hot reload는 현재 지원 경로가 아니며,
  audited external restart-action과 service-manager command를 사용한다.
- Response와 Security audit에는 rollout state, count, fingerprint prefix만
  포함한다. Public key body, private key body/path, local key path, token,
  raw payload body는 기록하지 않는다.

```json
{
  "controller_id": "default-controller",
  "persisted_state": "dual_trust_active",
  "rollout_state": "waiting_for_ack",
  "target_count": 3,
  "planned_count": 1,
  "attempted_count": 1,
  "updated_count": 1,
  "skipped_count": 1,
  "failed_count": 0,
  "already_current_count": 1,
  "unavailable_count": 0,
  "pending_count": 1,
  "entries_count": 2,
  "current_fingerprint_prefix": "new-fp-12345678",
  "previous_fingerprint_prefix": "old-fp-12345678",
  "agent_results": [
    {"agent_id": "agent-2", "status": "sent"}
  ]
}
```

Staged coordinator CLI:

```bash
fleet controller signing-rotation staged-trust-bundle \
  --controller-url https://fleet.example.com \
  --admin-token <admin-token> \
  --previous-public-key-path /var/lib/fleet/controller/controller_public.key.bak \
  --agent-id agent-1 \
  --batch-size 10 \
  --max-failures 1 \
  --ack-timeout-seconds 30
```

Manual rollout CLI:

```bash
fleet controller signing-rotation rollout-trust-bundle \
  --controller-url https://fleet.example.com \
  --admin-token <admin-token> \
  --previous-public-key-path /var/lib/fleet/controller/controller_public.key.bak \
  --agent-id agent-1
```

`POST /api/controller/signing-rotation/rollout-trust-bundle/retry`는 같은 request와
response schema를 사용하되, operator가 `max_agent_count`와 `agent_ids`로 retry
batch를 명시하는 bounded retry coordinator surface다.

```bash
fleet controller signing-rotation retry-trust-bundle \
  --controller-url https://fleet.example.com \
  --admin-token <admin-token> \
  --previous-public-key-path /var/lib/fleet/controller/controller_public.key.bak \
  --max-agent-count 25
```

Retry coordinator는 현재 session registry에서 관측 가능한 연결/queue 상태만
사용한다. Agent-side "already current" acknowledgement state는 authenticated
session runtime state로만 사용하며 DB/domain object에 저장하지 않는다. Unattended
background scheduler는 별도 hardening task다.

## 개인 인증 HTTP 기반

local 첫 owner 전환 뒤 `personal` mode에서는 아래 HTTP 경로와 기존 보호 API의 cookie/PAT 인증을 제공한다.
단일 조직의 로컬 계정과 개인 인증 경로다. owner 계정 관리·본인 password/PAT API는 연결됐으며 Command·DriftCheck·직접/카탈로그 Runbook 생성·승인/거절·명시적 취소·수동 만료·remediation 승인 요청/Job 생성의 최신 권한 guard도 연결됐다.
개인 Admin 로그인·계정/본인 credential 화면은 연결됐다. 개인 token CLI 입력/profile도 연결됐다. 실제 두 사용자 HTTPS browser/API/CLI·Linux Agent 작업 중 접근 회수·복구와 인증 부하를 격리 환경에서 검증했다.
전환 전 `legacy` mode의 공용 token과 개인 credential 사이에 자동 fallback은 없다.
`fleet login --controller-url <origin>`은 숨김 TTY에서 개인 token을 받고, 자동화는 `--token-stdin`으로 한 줄과 EOF를 전달한다. 개인 PAT는 필수 `GET /api/auth/session`200을 확인한 뒤 기존 `controller_url`/`admin_token` profile 형식으로 저장한다. 원격 password 로그인/저장은 없다. profile은 Unix 본인 소유600·원자 교체·server origin 범위이며, 다른 주소만 override하면 저장 credential을 보내지 않는다. 보호 요청은10초 기한·redirect 거절이며401은 무효/만료/회수 재인증,403은 권한 부족으로 표시한다. 기존 명시적 `--admin-token` 인자는 legacy 호환이며 새 개인 token의 권장 입력이 아니다.
사설 CA는 login의 `--tls-ca-cert`로 공개 PEM 파일만 지정한다. profile의 선택적 `tls_ca_cert`에 canonical path를 기록하며 기존2필드 profile은 그대로 읽는다. 명령 bootstrap에서16KiB 이하 regular file을 한 번 읽고 유효한 인증서 집합을 확인한다. 특수 파일·private-key PEM은 거절하고 기본 roots/hostname 검증과 Origin 범위를 유지한다. 시스템/browser trust 변경이나 TLS 검증 우회 옵션은 없다. 이는 CLI local profile 계약이며 REST DTO는 바꾸지 않는다.
정적 Admin client는 인증 generation 변경·logout 때 이전 요청과 선택을 종료하고 늦은 응답을 버린다.401은 재인증,403은 권한 부족으로 구분하며 필수 auth/계정404를 숨기지 않는다. 응답 불명 Job은 ID로 명시적 조회만 하고 다른 인증 generation으로 자동 재전송하지 않는다. Settings는 My account·owner 전용 People·Controller 탭으로 나뉜다. 입력한 비밀번호는 submit 직후 비우고, 일회성 값은 일반 상태나 HTML 속성에 저장하지 않으며 닫기·logout·페이지 이탈 때 지운다.

| Method / 경로 | 입력·인증 | 결과 |
| --- | --- | --- |
| GET `/api/auth/status` | public | `mode`: `legacy`, `personal`, `local_setup_required`; `local_setup_required` boolean. 개인 정보 없음 |
| POST `/api/auth/login` | 정확한 Origin, JSON `username`·`password` | `user`, 고정 UTC Unix seconds `expires_at`, `csrf_token`; session secret은 Set-Cookie로만 전달 |
| GET `/api/auth/session` | 현재 cookie 또는 개인 PAT | 현재 `user`·고정 `expires_at`; cookie만 `csrf_token`, PAT는 null. 조회로 기한 연장 없음 |
| POST `/api/auth/logout` | cookie, Origin, `X-Fleet-CSRF`; body 없거나 빈 JSON object | 현재 session만 회수하고 204·cookie 만료. 이미 만료/회수됐다면 401·cookie 만료. PAT logout은 403 |
| POST `/api/auth/setup` | Origin, JSON `code`·`new_password` | 유효한 일회성 설정/reset 코드 소비·204. 자동 로그인하지 않음 |
| POST `/api/auth/password` | 현재 개인 cookie/PAT·`current_password`, `new_password`만 | 204·본인 session/PAT/미사용 code 전체 회수. cookie caller는 cookie 만료·새 로그인 필요 |
| POST `/api/auth/tokens` | 현재 개인 cookie/PAT·`current_password`, 선택적 `label` | 201 `token: {id, expires_at, secret}`; 고정30일 PAT secret을 이 응답에서만 표시 |
| GET `/api/auth/tokens` | 현재 개인 cookie/PAT; 선택적 `limit`·`after` | 본인 PAT의 `items: [{id,label,created_at,expires_at,active}]`, `next_cursor`만. 원문·hash·binding 없음 |
| DELETE `/api/auth/tokens/{token_id}` | 현재 개인 cookie/PAT; body/query 없음, current_password 불필요 | 본인 선택 PAT만 회수·204. 타인/없는 ID/다른 목적/이미 회수한 ID는 같은404 |
| GET `/api/admin/users` | 현재 owner cookie 또는 PAT; 선택적 `limit`·`after` | bounded `items` metadata·`next_cursor` |
| GET `/api/admin/users/{user_id}` | 현재 owner cookie 또는 PAT | 해당 계정의 `user` metadata; 없는 ID는404 |
| POST `/api/admin/users` | 현재 owner·같은 요청의 `current_password`; `username`, `display_name`, `role` | 201 `user`와 한 번만 표시하는 `setup: {id, expires_at, code}`; pending 계정 |
| PATCH `/api/admin/users/{user_id}` | 현재 owner·`current_password`; `display_name`, `role`, `disable:true` 중 하나 이상 | 200 `user`; username/id/status/actor 변경과 `disable:false`는 거절 |
| POST `/api/admin/users/{user_id}/password-reset` | 현재 owner·`current_password`만 | 201 한 번만 표시하는 `reset: {id, expires_at, code}`; 새 비밀번호는 이 요청에서 받지 않음 |

`user`는 `id`, `username`, `display_name`, `role`, `status`, `record_revision`의 metadata만 포함한다.
password verifier, credential digest·binding, raw session/token/code는 이 projection에 없다.
계정 조회는 owner만 가능하며 admin/operator/viewer는 본인 ID 조회도403이다. 본인 로그인 정보는 `/api/auth/session`을 사용한다.
목록은 ID 오름차순·기본25/최대100이며 `after`는 이전 응답의 불투명 위치다. query는 collection의 `limit`/`after`만
허용하고 중복·알 수 없는 field·빈/불량 cursor·다른 owner/목적/version은400으로 거절한다. detail에는 query를 받지 않는다.
GET body는 받지 않으며 계정·credential·audit를 변경하거나 만료 연장/정리하지 않는다. pending/disabled 계정도 owner에게 보인다.
조회 전후 현재 owner 권한을 재검증하고, 불량 저장 행은 부분 응답 대신 안전한503으로 처리한다.
owner mutation은 같은 요청에서 현재 비밀번호를 증명하고 account·credential·audit의 원자 transaction 안에서
현재 actor·target revision·마지막 로그인 가능한 owner를 다시 검증한다. 로그인과 같은 CPU admission과
현재 actor의 canonical username 실패 한도를 공유한다. target 이름을 바꿔 비밀번호 추측 한도를 우회할 수 없다.
Cookie mutation은 Origin/CSRF를, PAT mutation은 단독 bearer와 현재 비밀번호를 요구한다.
표시 이름만 변경하거나 같은 role을 요청하면 기존 credential은 유지한다. role/차단/reset은 해당 사람의 모든
session/PAT/미사용 code를 회수한다. 자기 credential이 폐기되는 성공 응답은 cookie도 지우며 타인 변경은 caller를 유지한다.
마지막 owner 제거는409 `last_owner`, 중복 이름은409 `user_exists`, revision/clock 충돌은409 `state_conflict`다.
실패 시 부분 계정 변경·발급·audit가 남지 않는다. audit 오류는 안전한503이다. 기존 Agent 작업은 이 인증 회수로 취소하지 않는다.
setup/reset code의 고정 기한은15분이다. 차단 계정은 owner reset 후 새 code claim으로 복구하며 자동 로그인하지 않는다.
mutation에는 query를 받지 않고 알 수 없는/중복 field와 명시적 null도 거절한다. 네트워크 결과가 불명확하면 POST를 자동 재시도하지 않는다.
본인 password/PAT 발급은 모든 활성 role에서 허용한다. 본인 ID는 현재 credential에서만 정하며
body의 user_id/username/actor/role/expiry 같은 임의 대상·권한·기한 입력은 거절한다. PAT 권한은 현재 사람의 role을 따른다.
PAT label은 선택 입력이며 지정 시 비공백·제어 문자 없는 최대256 UTF-8 bytes다. null/빈 값은 거절하며 trim하지 않는다.
PAT는 본인16개/전체 lookup8192행 한도이며 초과는429 `token_limit`, CPU/실패 한도는429 `authentication_busy`다.
한도 거절에 새 token/audit는 없고 bounded 만료 lookup 정리는 허용한다. PAT 발급은 현 web session을 바꾸지 않으며
password 변경은 본인의 모든 credential을 회수하되 타인의 credential과 이미 승인된 Agent 작업은 유지한다.
본인 PAT 조회는 기본25/최대100이며 account 목록과 구분되는 subject/purpose/version-scoped 불투명 cursor를 쓴다.
서버가 현재 binding·epoch·계정·상태·시각으로 `active`를 판정한다. 만료/미래 생성 행도 남아 있으면 false로 표시하며 GET이 정리·연장하지 않는다.
owner/purpose 조건은 SQL에서 semantic decode 전에 적용한다. 손상된 타인 행은 조회에서 제외되고 회수는 같은404이며,
본인 손상 행은 lookahead라도 부분 page 대신 안전한503이다. 선택 회수·audit는 원자적이며 audit 실패는 credential을 유지한다.
본인 요청에 사용한 PAT 자체도 회수할 수 있다. 다른 PAT/web session/사람은 유지하며 cookie는 지우지 않는다.
이미 회수된 lookup 행이 bounded cleanup을 기다려도 재차 DELETE는 같은404다. 표시 이름/role 변경은 audit의 불변 user ID를 바꾸지 않는다.
auth body는 최대 16 KiB이고 UTF-8 JSON의 알려진 field만 허용한다. 중복 JSON field도 거절한다.
일회성 code와 비밀번호는 POST body로만 전달하며 auth 경로의 query는 거절한다.

canonical origin은 bootstrap `--external-url`에서만 만든다. personal/local-setup-required 시작에
유효 origin이 없으면 fail-closed하며 요청 Host나 forwarded header를 신뢰하지 않는다.
HTTPS cookie는 `__Host-fleet_session`, Secure·HttpOnly·SameSite=Strict·Path=/·host-only·Max-Age=28800이다.
짧은 HTTP lab에서는 기존 insecure warning/audit와 `fleet_session`을 사용한다.
login/설정 claim은 정확한 Origin과 `application/json`을 요구한다(UTF-8 charset parameter 허용).
그 밖의 cookie mutation은 같은 Origin과 해당 session의 `X-Fleet-CSRF`를 요구한다.
쿠키/Authorization 동시 입력·중복 credential header는 400 `ambiguous_authentication`으로 거절한다.
Web session을 bearer로, PAT를 cookie로, 설정/reset 코드를 로그인 credential로 바꾸어 사용하지 않는다.

auth와 사람 인증을 요구하는 보호 API 응답은 `Cache-Control: no-store`다. 401은 잘못된 비밀번호·없는/비활성 계정·만료/회수에 공통이다.
403은 Origin/CSRF/용도·권한 거절, 429는 `authentication_busy` 또는 `session_limit`,
503은 worker/store 일시 실패 또는 총 30초 인증 deadline이다. 원문 crypto/SQL 오류를 반환하지 않는다.
기한은 웹 8시간·PAT 30일·설정/reset 15분 고정이며 별도 idle expiry는 없다.
KDF의 native worker는 bootstrap에서 생성·종료하고 HTTP admission도 worker+pending 범위로 제한한다.
KDF/entropy 동안 공용 store mutex나 DB transaction을 보유하지 않는다.

## Legacy Admin Token

`fleet controller init`은 최초 실행 시 admin token을 1회 출력한다.

```bash
fleet controller init --data-dir .fleet
```

출력 예:

```text
controller initialized at .fleet
controller fingerprint: <sha256-public-key-fingerprint-hex>
admin token: admin-...
```

`controller init`은 controller Ed25519 key pair를 생성한다. public key는 `controller_public.key`, private key는 `controller_private.key`에 저장한다. Unix에서는 private key 파일이 group/other에 열려 있으면 init/start path에서 거부한다.

admin token 원문은 DB에 저장하지 않는다. Controller는 token hash만 저장한다. 이미 초기화된 controller에서 다시 `init`을 실행하면 controller key와 admin token을 새로 만들지 않는다.

MVP에서 Controller와 CLI가 새로 생성하는 token, job, assignment nonce, message id는 사람이 읽을 수 있는 prefix와 ULID를 조합한 형태를 사용한다. 예: `admin-...`, `enroll-...`, `et-...`, `job-cli-...`, `nonce-...`, `msg-...`.

전환 전 legacy mode의 보호 API는 다음 header를 요구한다. personal mode에는 적용되지 않는다.

```http
Authorization: Bearer <admin-token>
```

Admin token 인증은 boolean 통과/실패가 아니라 controller 내부의 admin request
context로 변환된다.

```text
actor_id = bootstrap-admin
role = owner
```

현재 `controller init`이 만든 bootstrap admin token은 `bootstrap-admin` actor와
`owner` role로 매핑된다. 이후 제품형 admin identity, CLI login, OIDC/SSO가
추가되더라도 API handler는 같은 방식으로 authenticated actor와 role을 받아야
한다. UI나 request body에 담긴 `actor`, `created_by`, `confirmed_by` 값은 권한
판단 근거가 아니다. Controller는 인증된 admin actor를 audit actor로 사용한다.

현재 최소 role 후보는 다음과 같다.

| Role | 권한 방향 |
| --- | --- |
| `owner` | 전체 권한. bootstrap admin token의 현재 role이다. |
| `admin` | 현재 최소 모델에서는 전체 권한. 이후 조직/사용자 모델에서 세분화 가능하다. |
| `operator` | job 생성/승인/취소와 audit 조회는 가능하지만 enrollment token 생성과 agent revoke는 불가하다. |
| `viewer` | agent/job/approval/audit 조회 중심. job 실행, 승인, revoke, token 생성은 불가하다. |

권한 실패 응답은 인증 실패와 구분한다.

```http
401 Unauthorized
{"error":"unauthorized"}
```

`401`은 admin token이 없거나 유효하지 않을 때 반환한다.

```http
403 Forbidden
{"error":"forbidden","required_permission":"job_approve"}
```

`403`은 token은 유효하지만 해당 actor role이 endpoint에 필요한 permission을
가지지 않을 때 반환한다. Web Admin UI는 이 응답을 표시할 뿐이며 권한을 결정하지
않는다. 자세한 matrix는 [docs/security.md](security.md)를 기준으로 한다.

## Enrollment Token API

### Create

```http
POST /api/enrollment-tokens
Authorization: Bearer <admin-token>
```

요청 body는 비워도 되며, 비어 있으면 `max_uses=1`, `expires_in_seconds=3600`, empty labels를 기본값으로 사용한다.

```json
{
  "labels": "role=web,env=prod",
  "max_uses": 1,
  "expires_in_seconds": 3600
}
```

응답은 raw enrollment token을 1회 포함한다.

```json
{"id":"et-...","token":"enroll-...","expires_in_seconds":3600}
```

raw enrollment token은 DB에 저장하지 않는다. DB에는 token hash와 metadata만 저장한다.
생성 이벤트는 enrollment audit에 남기되 raw token은 기록하지 않고 token id reference만 남긴다. Audit actor는 request body가 아니라 인증된 admin actor를 사용한다.

### List

```http
GET /api/enrollment-tokens
Authorization: Bearer <admin-token>
```

응답:

```json
[
  {
    "id": "et-...",
    "default_labels": "",
    "max_uses": 1,
    "used_count": 0,
    "remaining_uses": 1,
    "revoked": false,
    "expires_at_epoch": 1710003600
  }
]
```

### Revoke

```http
DELETE /api/enrollment-tokens/{id}
Authorization: Bearer <admin-token>
```

성공 시 `204 No Content`를 반환한다.
폐기 이벤트도 enrollment audit에 남긴다.

## Agent Enrollment API

Agent는 enrollment token을 사용해 controller에 자기 identity를 등록한다. 이 endpoint는 admin token을 사용하지 않는다.

```http
POST /api/agents/enroll
Content-Type: application/json
```

요청:

```json
{
  "token": "enroll-...",
  "agent_id": "agent-web-01",
  "name": "web-01",
  "public_key": "<ed25519-public-key-hex>",
  "fingerprint": "<sha256-public-key-fingerprint-hex>",
  "labels": [
    {"key": "role", "value": "web"}
  ]
}
```

응답:

```json
{
  "agent_id": "agent-web-01",
  "controller_public_key": "<ed25519-public-key-hex>",
  "controller_fingerprint": "<sha256-public-key-fingerprint-hex>"
}
```

Controller는 raw enrollment token을 hash로 검증하고, 성공 시 token use count를 증가시킨다. 만료, 폐기, max uses 초과 token은 거부한다. 등록 시 public key와 fingerprint가 일치하지 않으면 거부한다. Enrollment token에 default labels가 있으면 agent labels에 적용하고, agent가 명시한 같은 key의 label은 default를 override한다.

## Command Job API

Command job API는 admin token 인증 후 command job과 controller-signed task assignment를 생성한다. Controller는 job과 assignment를 DB에 저장한 뒤 active authenticated agent session이 있으면 즉시 `task_assignment`를 dispatch한다. 등록된 agent가 disconnected 상태이면 assignment는 queued 상태로 남고, agent가 reconnect하여 session registry에 등록되는 즉시 pending queue drain 대상으로 처리된다. Persistent v2 session에서 Agent는 TaskAck, TaskStarted, 실행 전 TaskRejected를 stable report ID `task-ack`/`task-started`/`task-rejected`의 `Lifecycle` class v2 `task_report`로 journal에 먼저 저장해 보낸다. Controller는 Agent/Job/Assignment owner를 확인하고 `dispatched -> accepted`, `accepted -> started`, `dispatched -> rejected` 상태 전이와 각 Job aggregate/audit/inbox marker를 한 transaction으로 commit한 뒤 signed `stored` receipt를 돌려준다. 거절 사유는 redacted 값으로 Assignment에 저장한다. 재전송은 같은 receipt를 재사용하며 중복 audit를 만들거나 terminal 상태를 되돌리지 않는다. Persistent v2의 Command 출력과 지원되는 no-artifact final report는 commit-before-send 및 receipt 경로를 사용한다. Artifact-producing Runbook의 출력/최종 결과와 직접 one-shot의 `task_result`는 별도 경로다. 별도 output subscribe API는 아직 후속 범위다.

Job과 task assignment는 항상 DB에 먼저 저장된다. WebSocket send는 저장 이후에만 시도할 수 있으며, DB transaction과 WebSocket send는 하나의 원자적 작업으로 취급하지 않는다. 따라서 queued assignment가 source of truth이고, active session dispatch 실패 시 assignment는 queued 상태로 남아 재시도 대상이 된다.

Assignment 상태 모델은 `queued -> dispatched -> accepted -> started -> succeeded/failed/canceled/expired`와 실행 전 `dispatched -> rejected`를 사용한다. Agent가 검증, capability, local policy, busy 상태 등으로 실행을 거부하면 `rejected` terminal 상태가 된다. Operator cancel은 `canceled`, command timeout은 `expired`로 저장하며 둘 다 일반 `failed`와 구분한다. WebSocket write 성공은 `dispatched`까지만 의미하며, persistent TaskAck report 또는 별도 direct ACK가 `accepted`를 기록한다. Persistent TaskStarted report 또는 direct one-shot event가 `started`를 기록한다. Persistent TaskRejected는 이유를 가린 채 journal에 저장되고 exact signed receipt까지 보존되며, 아직 dispatched 상태인 Assignment만 `rejected`로 전이한다. 각 persistent transition은 owner 확인 후 Assignment/Job/audit/inbox marker를 함께 저장한다. G2가 `failed/execution_outcome_unknown`으로 terminal 처리한 뒤 exact owner의 TaskAck/TaskStarted/TaskRejected가 도착하면 audit/inbox disposition과 signed receipt만 추가하고 Assignment/Job/G2 사유는 바꾸지 않는다. G2 이후 matching no-artifact persistent Command/Runbook/DriftCheck final report도 terminal 상태를 유지한 채 signed receipt로 정리하며, 다른 terminal 상태나 사유는 fail-closed한다. receipt는 report/effect 저장 확인이지 실행 성공 증거가 아니다. `output_chunk`는 output 저장 event일 뿐 성공으로 처리하지 않는다. Persistent v2 `final_result`(DriftCheck terminal result 포함)가 persistent assignment 결과를 확정하며, direct one-shot은 별도 `task_result` event를 사용한다.
Persistent Command와 no-artifact Runbook의 내부 v2 final report에는 필수 `output` summary가 있으며, Controller는 stdout/stderr 각각의 `[0, count)` 조각이 저장되기 전에는 final 결과나 receipt를 확정하지 않는다. `truncated=true` 결과는 성공으로 처리하지 않는다. summary가 없는 구형 final body에는 호환 fallback이 없으므로 Controller와 Agent를 함께 업그레이드해야 한다. 이 확인은 Agent가 journal에 기록한 조각의 전달을 보장할 뿐, task 실행이 만든 모든 출력 byte를 수집했다는 보장은 아니다.

`output_chunk`는 output storage event일 뿐 성공으로 처리하지 않는다. Persistent session 결과는 `final_result` report로, direct one-shot 결과는 별도 `task_result`로 확정된다.

Agent가 running 중 disconnect되면 Controller는 task result 없이 즉시 실패를 확정하지 않는다. SQLite Controller는 persisted `dispatched_at` + Job 실행 timeout + 5분 grace가 지난 뒤에도 `dispatched`/`accepted`/`started`인 Assignment를 listener bind 전과 30초 주기의 bounded recovery에서 `failed` + `execution_outcome_unknown`으로 수렴시킨다. 이 상태는 Agent process가 실패했다는 증명이 아니라 Controller가 결과를 확인하지 못했다는 뜻이며 자동 재실행하지 않는다. Agent local command는 task timeout과 runner output limit을 계속 적용받는다. 이미 terminal 상태인 assignment에 늦은 result가 도착하면 Controller는 terminal 상태를 덮어쓰지 않는다. Recovery 계약이 없는 Postgres 구성은 Controller가 listener를 열기 전에 startup failure를 반환한다.

Dispatch 대상 선택 정책:

- disabled/revoked agent에는 dispatch하지 않는다.
- disconnected agent의 assignment는 queued 상태로 둔다.
- expired assignment는 agent로 보내지 않고 expired 처리 대상이 된다.
- 같은 `(job_id, agent_id, stream, chunk_index)` output chunk가 같은 body로 다시 오면 idempotent duplicate로 처리한다.
- 같은 key의 output chunk가 다른 body로 오면 conflicting duplicate이며 raw output body 없이 `websocket_output_chunk_conflict` security audit를 남기고 protocol error로 session cleanup 대상이 된다.

```http
POST /api/jobs/command
Authorization: Bearer <admin-token>
Content-Type: application/json
```

요청:

```json
{
  "job_id": "job-1",
  "target_agent_ids": [],
  "selector": "role=web",
  "strategy": {
    "concurrency": 2,
    "maxFailures": 1
  },
  "program": "uptime",
  "args": [],
  "timeout_seconds": 30,
  "confirmed_high_risk": true,
  "confirmed_by": "operator@example.com",
  "expires_in_seconds": 300,
  "nonce_prefix": "nonce-job-1"
}
```

응답:

```json
{
  "job_id": "job-1",
  "target_count": 1,
  "assignment_count": 1,
  "status": "queued",
  "approval_request_id": null
}
```

`target_agent_ids`를 명시하면 해당 agent를 대상으로 한다. `target_agent_ids`가 비어 있고 `selector` 또는 `matchLabels`가 있으면 controller가 inventory에서 matching agent를 찾아 target을 만든다. 하나의 job은 target snapshot에 포함된 각 agent마다 assignment를 하나씩 만든다.

지원하는 selector:

- `agent:<name-or-id>`: agent display name 또는 agent id가 일치하는 agent를 선택한다.
- `label:key=value`: 단일 label 일치 조건이다.
- `key=value,key2=value2`: 여러 label이 모두 일치해야 한다.
- `matchLabels`: JSON object 기반 label selector다. 예: `"matchLabels": {"role": "web", "env": "prod"}`.

`selector` string과 `matchLabels` object는 동시에 사용할 수 없다. 둘 다 보내면 400으로 거부한다.
Group selector와 query selector는 이번 범위에서 지원하지 않으며, 향후 정책/권한 모델과 함께 설계할 planned 기능이다.

`strategy`는 multi-agent fanout 실행 정책이다.

- `strategy.concurrency`는 동시에 dispatch할 수 있는 assignment 수다. 생략하면 `1`이며, 순차 실행을 뜻한다.
- `strategy.maxFailures`는 terminal failure 계열 assignment 수가 기준에 도달했을 때 남은 queued assignment를 `canceled`로 전환하는 한계값이다. 생략하면 failure 개수로 fanout을 중단하지 않는다.
- `concurrency=0` 또는 `maxFailures=0`은 400으로 거부한다.
- active authenticated agent session이 있으면 concurrency 한도 안에서 즉시 dispatch한다.
- active session이 없는 target assignment는 queued 상태로 남고, reconnect 후 dispatch 대상이 된다.

Command risk는 domain classifier가 판정한다. `uptime`, `hostname`, `whoami` 같은 safe probe는 `status=queued`로 생성되고 approval 없이 dispatch될 수 있다. shell, `sudo`, `su`, reboot/shutdown, user/group 변경, package/service/file mutation 계열, unknown command는 high-risk로 보고 `status=pending_approval`과 `approval_request_id`를 반환한다. 여러 agent를 동시에 대상으로 하는 broad target도 command 자체가 safe여도 approval이 필요하다.

`confirmed_high_risk`는 과거 클라이언트 호환을 위한 operator acknowledgement 필드다. 이 값이 `true`여도 approval을 대신하지 않는다. High-risk 또는 broad-target job은 approval request가 `approved` 상태가 되기 전까지 dispatch되지 않는다. Controller는 private signing key로 task envelope signature를 만들고, job과 task assignment를 SQLite에 저장한 뒤 `job_created` audit event를 남긴다. Approval이 필요한 경우 `approval_requested` audit event도 남긴다. Dispatch 시 `job_started`, result 수신 시 `job_completed`, `job_failed`, `job_canceled`, `job_timed_out` audit event를 남긴다.

CLI에서 controller API로 job을 생성하려면 admin token을 명시 인자로 전달한다. token은 command payload나 job output에 섞지 않는다.

```bash
fleet run \
  --controller-url http://127.0.0.1:7700 \
  --admin-token <admin-token> \
  --selector role=web \
  --confirm-risk \
  uptime
```

## Selector Preview API

Selector preview API는 job 생성 전 동일한 selector 정책으로 어떤 agent가 대상이 되는지 보여준다. 이 API는 read-only이며, inventory 정보를 노출하므로 admin token 인증이 필요하다. Preview 자체는 audit event를 남기지 않는다. 실제 실행 audit는 job 생성과 dispatch/result 단계에서 남긴다.

```http
POST /api/selectors/preview
Authorization: Bearer <admin-token>
Content-Type: application/json
```

요청 예시:

```json
{
  "matchLabels": {
    "role": "web",
    "env": "prod"
  }
}
```

응답 예시:

```json
{
  "matched_count": 2,
  "selected_count": 1,
  "disabled_count": 1,
  "offline_count": 0,
  "warnings": [
    {
      "code": "disabled_agents_excluded",
      "message": "1 disabled or revoked agent(s) match the selector but will be excluded"
    }
  ],
  "agents": [
    {
      "agent_id": "agent-web-01",
      "name": "web-01",
      "status": "online",
      "labels": [{ "key": "role", "value": "web" }],
      "selected_for_dispatch": true
    },
    {
      "agent_id": "agent-web-02",
      "name": "web-02",
      "status": "disabled",
      "labels": [{ "key": "role", "value": "web" }],
      "selected_for_dispatch": false
    }
  ]
}
```

Preview 정책:

- disabled/revoked agent는 `matched_count`에는 포함하지만 dispatch 대상에서는 제외한다.
- offline agent는 dispatch target으로 선택될 수 있으며, reconnect 전까지 assignment가 queued 상태로 남는다.
- 활성 session이 있는 agent는 오래된 저장 상태와 관계없이 preview에서 `online`으로 표시하며
  `offline_count`와 해당 warning에서도 제외한다. 이 관찰 값은 Agent record나 heartbeat 시각을 갱신하지 않는다.
  disabled/revoked 제외는 session보다 우선한다. 그 외 `pending`·`busy`·`degraded` 상태도 그대로 표시한다.
- `warnings`는 선택 결과를 막지 않는 운영상 주의사항이다.
- Web Admin UI의 Run과 Runbooks panel은 job 생성 전 같은 preview API를 호출해 `matched_count`, `selected_count`, `disabled_count`, `offline_count`, warning, agent row를 표시한다.
- Web Admin UI는 preview 응답의 `selected_count`가 0이면 command/runbook job 생성을 중단한다. Selector 해석, disabled/revoked 제외, offline 허용 판단은 UI가 재구현하지 않고 controller 응답을 기준으로 한다.

Job 생성 후 target snapshot:

- Controller는 job 생성 시점의 selector source를 `selector_kind`, `selector_source`로 저장한다.
- Controller는 assignment 저장 시점의 target agent id, 표시명, 상태, labels snapshot을 저장한다.
- Job 생성 뒤 agent labels나 status가 바뀌어도 기존 job의 target snapshot은 바뀌지 않는다.
- 실제 assignment 생성과 dispatch 대상의 source of truth는 job 생성 시 저장된 assignment와 target snapshot이다.

## Runbook Job API

Runbook job API는 admin token 인증 후 runbook 문서를 validation하고, controller-signed task assignment를 생성한다. 실제 package/service/file/check/snapshot primitive 실행은 agent가 signed envelope를 검증한 뒤 수행한다. `fleet apply`는 local validation-only 명령이며, privileged execution path가 아니다.

```http
POST /api/jobs/runbook
Authorization: Bearer <admin-token>
Content-Type: application/json
```

요청:

```json
{
  "job_id": "job-nginx-runbook-1",
  "target_agent_ids": [],
  "strategy": {
    "concurrency": 1,
    "maxFailures": 1
  },
  "runbook_document": "apiVersion: fleet.sponzey.dev/v1alpha1\nkind: Runbook\nname: nginx-basic\nmatchLabels:\n  role: web\nsteps:\n  - id: nginx-package\n    package:\n      name: nginx\n      state: present\n  - id: http-listener\n    port.check:\n      host: 127.0.0.1\n      port: 8080\n",
  "timeout_seconds": 180,
  "confirmed_high_risk": true,
  "confirmed_by": "operator@example.com",
  "expires_in_seconds": 300,
  "nonce_prefix": "nonce-nginx-runbook"
}
```

응답:

```json
{
  "job_id": "job-nginx-runbook-1",
  "target_count": 1,
  "assignment_count": 1,
  "status": "pending_approval",
  "approval_request_id": "approval-01..."
}
```

규칙:

- invalid runbook은 task assignment 생성 전에 거부한다.
- runbook execution task는 high-risk로 분류한다.
- `confirmed_high_risk`는 호환용 acknowledgement이며 approval을 대신하지 않는다.
- runbook job은 `pending_approval`로 생성되고 approval request가 approve되기 전까지 dispatch되지 않는다.
- request의 `target_agent_ids`, `selector`, `matchLabels`가 있으면 그 값이 runbook 문서 selector보다 우선한다.
- request target 지정이 모두 비어 있으면 runbook 문서의 `selector` 또는 `matchLabels`로 target snapshot을 만든다.
- selector resolution은 disabled/revoked agent를 제외한다.
- `strategy.concurrency`와 `strategy.maxFailures`는 command job과 같은 fanout 정책을 사용한다.
- runbook 문서의 `checkMode`는 read-only check step만 실행하고 mutation step은 skip한다.
- runbook 문서의 `dryRun`은 모든 primitive 실행을 skip한다.
- agent는 signed envelope 검증, expiry 검증, replay 검증 이후에만 실행한다.
- step output은 job output chunk로 저장하고 Product application log와 분리한다.

## Drift Check Job API

Drift check job API는 admin token 인증 후 policy 문서를 signed drift check
assignment로 만든다. Agent는 signed envelope를 검증한 뒤 drift check engine을
실행하고, 결과를 drift report storage와 job assignment result로 보고한다.

```http
POST /api/jobs/drift-check
Authorization: Bearer <admin-token>
Content-Type: application/json
```

요청:

```json
{
  "job_id": "job-drift-1",
  "target_agent_ids": [],
  "selector": "role=web",
  "strategy": {
    "concurrency": 2,
    "maxFailures": 1
  },
  "policy_document": "apiVersion: fleet.sponzey.dev/v1alpha1\nkind: Policy\nmetadata:\n  name: nginx-running\nspec:\n  targets:\n    selector: role=web\n  checks: []\n",
  "timeout_seconds": 30,
  "created_by": "operator@example.com",
  "expires_in_seconds": 300,
  "nonce_prefix": "nonce-drift-1"
}
```

응답:

```json
{
  "job_id": "job-drift-1",
  "target_count": 1,
  "assignment_count": 1,
  "status": "queued",
  "approval_request_id": null
}
```

규칙:

- invalid policy는 task assignment 생성 전에 거부한다.
- selector resolution은 disabled agent를 제외한다.
- `strategy.concurrency`와 `strategy.maxFailures`는 command/runbook job과 같은 fanout 정책을 사용한다.
- 단일 target drift check는 approval 없이 queued 될 수 있다.
- 여러 target에 대한 broad drift check는 `pending_approval`과 `approval_request_id`를 반환하고 approve 전까지 dispatch되지 않는다.
- drift report body는 drift report API로 조회하고, raw command output은 job summary에 포함하지 않는다.

### Approval Requests

Approval API는 high-risk 또는 broad-target job이 dispatch되기 전에 운영자가 승인/거절/만료 처리할 수 있는 lifecycle을 제공한다. 모든 endpoint는 admin token 인증이 필요하다. Approve/reject actor는 request body가 아니라 인증된 admin actor에서 결정된다.

Approval status:

- `pending`: 승인 대기 중이다. 이 상태의 job은 `pending_approval`이고 dispatch되지 않는다.
- `approved`: 승인자가 승인했다. 연결된 job은 `queued`로 전환되고 active agent session이 있으면 즉시 dispatch 대상이 된다.
- `rejected`: 승인자가 거절했다. 연결된 job은 `failed`로 전환되고 dispatch되지 않는다.
- `expired`: approval expiry가 지나 만료 처리됐다. 연결된 Job이 아직 pending_approval이면 expired로 전환되어 dispatch되지 않는다. 이미 취소/terminal이거나 접수된 Job 상태는 보존한다.
- `canceled`: future policy 또는 operator workflow에서 사용할 reserved terminal 상태다.

List pending approvals:

```http
GET /api/approvals?status=pending
Authorization: Bearer <admin-token>
```

응답:

```json
[
  {
    "id": "approval-01...",
    "job_id": "job-1",
    "requester": "operator@example.com",
    "approver": null,
    "reason": "high-risk command requires manual approval",
    "status": "pending",
    "expires_at_ms": 1710000300000,
    "created_at_ms": 1710000000000,
    "decided_at_ms": null
  }
]
```

Approve:

```http
POST /api/approvals/{approval_id}/approve
Authorization: Bearer <admin-token>
Content-Type: application/json
```

```json
{
  "reason": "approved maintenance window"
}
```

호환성 때문에 legacy `actor` field를 보내도 request parse는 허용하지만 controller는
그 값을 무시한다. approver와 approval audit actor는 cookie/PAT 또는 전환 전 공용 token으로
서버가 인증한 불변 actor ID를 사용한다. 자기승인도 기존 정책대로 허용한다.

Command·DriftCheck·직접/카탈로그 Runbook 생성과 승인/거절은 현재 credential·계정·역할·human epoch를 동일 업무 transaction에서
다시 검증한다. 회수가 먼저 commit되면 401, 현재 권한 부족은 403이다. 이미 저장한 작업/결정은
이후 사람의 logout·차단으로 취소하지 않는다. 승인/거절의 approval·pending Job 상태·audit는
함께 commit하거나 rollback한다. 없는 승인은 404, 잘못된 상태 전이는 400이며,
commit 전 만료·경합은 409 state_conflict, 저장소/요청 기한 실패는 민감한 진단 없이 503이다.
이 네 생성 API에서 duplicate Job ID는 409 job_already_exists이며 새 생성 효과를 남기지 않는다.
요청 기한/인증 저장소 오류는 503이며 서명 준비/업무 저장소 오류는 안전한 500이다.
카탈로그의 활성 revision·문서 checksum·불변 provenance 검증도 같은 transaction에 유지한다.
명시적 Job 취소·수동 승인 만료·remediation 승인 요청과 Job 생성도 같은 최신 권한·원자 저장 경계를 사용한다.

Reject:

```http
POST /api/approvals/{approval_id}/reject
Authorization: Bearer <admin-token>
Content-Type: application/json
```

```json
{
  "reason": "outside maintenance window"
}
```

Expire due requests:

수동 만료는 기존 최대500 pending scan을 유지한다. 현재 요청자의 JobApprove 권한을 같은 batch transaction에서
재검증하고 approval·아직 pending_approval인 Job·요청자 UID의 audit를 함께 저장한다. 중간 오류는 batch 전체를
되돌리며, 이미 canceled/terminal이거나 접수된 Job은 덮어쓰지 않는다. 회수된 credential은401, 권한 부족403,
상태 경합409, 저장소/기한 오류503이다. 반복 요청으로 이미 만료된 항목을 다시 변경하지 않는다.

```http
POST /api/approvals/expire
Authorization: Bearer <admin-token>
```

응답:

```json
{
  "expired_count": 1,
  "approvals": [
    {
      "id": "approval-01...",
      "job_id": "job-1",
      "requester": "operator@example.com",
      "approver": null,
      "reason": "high-risk command requires manual approval",
      "status": "expired",
      "expires_at_ms": 1710000300000,
      "created_at_ms": 1710000000000,
      "decided_at_ms": 1710000310000
    }
  ]
}
```

Audit 정책:

- `approval_requested`: approval request 생성 시 남긴다.
- `approval_approved`: approve 처리 시 approver actor와 reason을 남긴다.
- `approval_rejected`: reject 처리 시 approver actor와 reason을 남긴다.
- `approval_expired`: expiry 처리 시 controller actor로 남긴다.

Web Admin approval queue 요구사항:

- pending approval 목록은 `GET /api/approvals?status=pending`을 source of truth로 사용한다.
- UI는 high-risk 판단, broad-target 판단, job 상태 전이를 자체 계산하지 않는다.
- approve/reject 버튼은 reason만 보내고, 성공 후 job list와 approval list를 다시 읽는다. 화면에 표시되는 approver는 API 응답과 audit을 기준으로 한다.
- `approval_request_id`가 있는 job 생성 응답은 "queued"가 아니라 "approval required"로 표시해야 한다.
- expired/rejected/approved terminal approval은 pending queue에서 제거하고 audit에서 확인할 수 있게 연결한다.

### Remediation Requests

Remediation API는 drifted policy에서 생성된 remediation request를 approval, signed runbook job, result verification으로 연결한다. 승인 요청과 실행 생성은 현재 사람의 cookie/PAT 인증(legacy mode에서는 공용 token)과 `job_approve` 권한이 필요하다. 조회는 remediation metadata만 반환하고 raw runbook document, rendered artifact body, command output, token, secret 값을 반환하지 않는다.

Remediation status:

- `proposed`: drifted policy가 remediation 후보를 만들었지만 approval request는 아직 없다.
- `pending_approval`: approval request가 생성되었고 job id는 예약되어 있지만 job row와 task assignment는 아직 생성되지 않았다.
- `approved`: approval decision이 승인되었고 signed job creation 직전 상태다.
- `job_created`: signed runbook job과 assignment metadata가 저장되었다. active agent session이 있으면 저장 이후 dispatch 대상이 된다.
- `running`: linked job이 실행을 시작했다.
- `succeeded_pending_verify`: remediation execution은 성공했지만 persisted successful verification Job과 fresh correlated compliant evidence 검증 전이다.
- `resolved`: persisted successful verification Job과 remediation execution 뒤의 fresh compliant evidence가 remediation과 origin drift를 함께 resolve했다.
- `failed`, `rejected`, `expired`, `canceled`: terminal 상태다.

List remediation metadata:

```http
GET /api/remediations?agent_id=agent-web-01&policy_id=nginx-running&limit=50
Authorization: Bearer <admin-token>
```

응답:

```json
[
  {
    "id": "remediation-nginx-running-agent-web-01",
    "policy_id": "nginx-running",
    "policy_name": "nginx-running",
    "agent_id": "agent-web-01",
    "runbook_ref": "runbooks/nginx-remediate.yml",
    "status": "proposed",
    "approval_required": true,
    "risk_summary": "drifted policy requires approved remediation",
    "job_id": null,
    "lifecycle_source": "persisted",
    "legacy_state": "legacy_unverified",
    "created_at_ms": 1710000000000,
    "updated_at_ms": 1710000000000
  }
]
```

Create remediation approval request:

```http
POST /api/remediations/{remediation_id}/approval-request
Authorization: Bearer <admin-token>
Content-Type: application/json
```

```json
{
  "approval_id": "approval-remediation-01",
  "job_id": "job-remediation-01",
  "reason": "drift remediation requires approval",
  "expires_in_seconds": 600
}
```

Approve and create signed remediation job:

```http
POST /api/remediations/{remediation_id}/approve
Authorization: Bearer <admin-token>
Content-Type: application/json
```

```json
{
  "approval_id": "approval-remediation-01",
  "job_id": "job-remediation-01",
  "runbook_document": "apiVersion: fleet.sponzey.dev/v1alpha1\nkind: Runbook\nmetadata:\n  name: nginx-remediate\nspec:\n  tasks: []\n",
  "timeout_seconds": 30,
  "expires_in_seconds": 600,
  "nonce_prefix": "nonce-remediation-01",
  "reason": "approved remediation window"
}
```

승인 요청은 remediation 상태·새 approval·요청자 UID audit를 한 transaction에 저장한다. 실행 생성은 서명 준비 후 현재 JobApprove 권한, 기존 remediation/approval snapshot과 만료를 다시 검사하고 Job·assignment·targets·승인 결정·remediation 상태·필수 audit를 함께 commit한다. 서명 중 로그아웃·권한 회수는401/403, 상태 경합·만료는409 state_conflict, 저장 실패는503이며 부분 효과를 남기지 않는다. 서명 실패는 민감한 진단 없는500이다. 요청자와 승인자의 불변 UID를 각각 보존하며 자기승인도 허용한다.

응답은 remediation metadata, approval metadata, job id, assignment count만 포함한다. `runbook_document` 원문은 response와 audit value에 포함하지 않는다.

Deprecated manual running/result/verify endpoints:

```http
POST /api/remediations/{remediation_id}/running
Authorization: Bearer <admin-token>

{"job_id":"job-remediation-01"}
```

```http
POST /api/remediations/{remediation_id}/result
Authorization: Bearer <admin-token>

{"job_id":"job-remediation-01","status":"succeeded"}
```

```http
POST /api/remediations/{remediation_id}/verify
Authorization: Bearer <admin-token>

{
  "agent_id": "agent-web-01",
  "policy_id": "nginx-running",
  "policy_name": "nginx-running",
  "job_id": "job-remediation-01"
}
```

Read model and validation rules:

- approval request 생성은 job row를 만들지 않는다. approval request의 `job_id`는 reserved id다.
- approve endpoint는 approval을 승인한 뒤 signed runbook job과 assignment를 store에 저장한다.
- WebSocket dispatch는 job/assignment 저장 이후에만 가능하다.
- 수동 `running`, `result`, `verify` endpoint와 동명 CLI command는 호환성 기간 동안 남지만 항상 `409 Conflict`를 반환하며 lifecycle state를 변경하지 않는다.
- authenticated agent task event가 execution lifecycle을 기록한다. successful verification TaskResult와 remediation execution 뒤의 fresh compliant persisted evidence만 application transaction을 통해 remediation과 origin drift를 `resolved`로 바꾼다.
- list/detail 응답의 `lifecycle_source`는 항상 `persisted`다. `verification_job_id`, `verification_assignment_status`, `verification_evidence_status`는 존재하는 correlated row만 표시한다. `verification_assignment_status=failed`는 remediation을 성공으로 표시하지 않는다.
- `origin_drift_report_id`가 없는 historical row는 `legacy_state=legacy_unverified`로 표시하며 자동으로 verified로 승격하지 않는다. recovery가 막힌 row의 `legacy_blocked` reason은 audit에서 확인한다.
- Web Admin은 수동 lifecycle 버튼을 제공하지 않고 persisted remediation metadata를 표시한다. CLI의 deprecated command는 요청 전 warning을 출력한 뒤 같은 `409` compatibility response를 전달한다.

CLI surface:

```bash
fleet remediations list --agent-id agent-web-01 --policy-id nginx-running
fleet remediations get remediation-nginx-running-agent-web-01
fleet remediations request-approval remediation-nginx-running-agent-web-01 --approval-id approval-remediation-01 --job-id job-remediation-01
fleet remediations approve remediation-nginx-running-agent-web-01 --approval-id approval-remediation-01 --job-id job-remediation-01 --runbook runbooks/nginx-remediate.yml
fleet remediations running remediation-nginx-running-agent-web-01 --job-id job-remediation-01
fleet remediations result remediation-nginx-running-agent-web-01 --job-id job-remediation-01 --status succeeded
fleet remediations verify remediation-nginx-running-agent-web-01 --agent-id agent-web-01 --policy-id nginx-running --policy-name nginx-running --job-id job-remediation-01
```

CLI와 Web Admin은 persisted remediation lifecycle metadata만 표시한다. Web Admin의 approved runbook YAML 입력은 approve request body로만 사용하고 list/detail/result surface에 다시 렌더링하지 않는다.

### List Jobs

Web Admin UI와 CLI 확인용으로 최근 job summary를 조회한다.

```http
GET /api/jobs
Authorization: Bearer <admin-token>
```

응답:

```json
[
  {
    "id": "job-1",
    "status": "queued",
    "dispatch_state": "queued",
    "risk": "high",
    "command_program": "uptime",
    "command_args": ["-a"],
    "selector_kind": "selector",
    "selector_source": "label:role=web",
    "strategy": {
      "concurrency": 1,
      "maxFailures": null
    },
    "target_count": 1,
    "target_agent_ids": ["agent-web-01"],
    "target_agents": [
      {
        "agent_id": "agent-web-01",
        "name": "web-01",
        "status": "offline",
        "snapshot_status": "online",
        "labels": [{ "key": "role", "value": "web" }],
        "task_id": "task-job-1-agent-web-01",
        "assignment_status": "queued",
        "last_error": "",
        "connected": false,
        "revoked": false
      }
    ],
    "assignment_summary": {
      "queued": 1,
      "dispatched": 0,
      "accepted": 0,
      "started": 0,
      "succeeded": 0,
      "failed": 0,
      "rejected": 0,
      "canceled": 0,
      "expired": 0,
      "skipped": 0,
      "unknown": 0
    },
    "rendered_artifacts": [
      {
        "artifact_id": "artifact-template-1",
        "task_id": "task-job-1-agent-web-01",
        "agent_id": "agent-web-01",
        "retention_class": "rendered_template",
        "checksum_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "size_bytes": 13
      }
    ],
    "target_connected": false,
    "created_at_ms": 1710000000000,
    "updated_at_ms": 1710000000000,
    "expires_at_ms": 1710000060000,
    "last_error": ""
  }
]
```

이 API는 저장된 summary와 controller가 알고 있는 target connection 상태만 보여준다.
authorization 판단이나 job 상태 전이는 controller application/domain 경계에서 처리한다.
raw command output은 포함하지 않는다. `rendered_artifacts`는 metadata only 목록이며
rendered body, local filesystem path, destination path를 포함하지 않는다.

`status`는 domain job 상태이고, `dispatch_state`는 운영자가 보기 위한 dispatch 상태다.
예를 들어 `status=queued`라도 target agent가 persistent session으로 이미 연결되어
있으면 `dispatch_state=created`로 보일 수 있다. `dispatch_state=delivered`는
controller가 active authenticated agent session으로 task assignment를 보냈다는 뜻이다.

### Job and Assignment State Terms

Job은 운영자가 생성하고 추적하는 실행 단위다. Assignment는 특정 agent에
배정된 실행 단위다. 단일 agent 실행은 target이 하나인 multi-agent job의 특수한
경우로 본다.

Job status:

- `draft`: 아직 dispatch 대상이 아닌 생성 직후 상태다. target assignment가 없거나
  approval이 필요 없는 job이 queue되기 전 상태다.
- `pending_approval`: high-risk job이 approval 또는 명시적 확인을 기다리는 상태다.
- `queued`: job과 assignment가 저장되었고 dispatch 대기 중인 상태다.
- `running`: 하나 이상의 assignment가 dispatched, accepted, started 중 하나이거나
  실행 결과를 기다리는 상태다.
- `partial_success`: 일부 assignment는 성공했고 일부 target은 failed, rejected,
  canceled, expired 중 하나로 끝난 terminal aggregate 상태다.
- `success`: 모든 assignment가 성공한 terminal aggregate 상태다.
- `failed`: 성공한 assignment가 없고 하나 이상의 assignment가 failed, rejected,
  expired로 끝난 terminal aggregate 상태다. 전체 rejected도 job aggregate로는
  `failed`이며, rejected 여부는 assignment/audit에서 구분한다.
- `canceled`: 모든 assignment가 canceled로 끝난 terminal aggregate 상태다.
- `expired`: 모든 assignment가 expired로 끝난 terminal aggregate 상태다.

Assignment status:

- `queued`: DB가 source of truth로 assignment를 저장했지만 아직 active session으로
  전달하지 않은 상태다.
- `dispatched`: controller가 authenticated persistent session으로 signed task
  envelope를 보낸 상태다.
- `accepted`: agent가 task envelope 검증 후 실행 대상으로 받아들인 상태다.
- `started`: agent가 실제 primitive 실행을 시작한 상태다.
- `succeeded`: agent-side 실행이 성공한 terminal 상태다.
- `failed`: agent-side 실행이 실패한 terminal 상태다.
- `rejected`: agent가 signature, expiry, replay, target mismatch, capability,
  local policy 등의 이유로 실행을 거부한 terminal 상태다.
- `canceled`: controller 또는 operator 취소가 반영된 terminal 상태다.
- `expired`: 실행 deadline 또는 assignment expiry가 지나 terminal 처리된 상태다.

`output_received`는 assignment status가 아니라 event다. output chunk는
`/api/jobs/{job_id}/output`에 저장하고, assignment 상태는 `started`를 유지한다.

Aggregate 규칙:

- 모든 assignment가 `succeeded`이면 job은 `success`다.
- 일부 `succeeded`와 일부 terminal failure/cancel/expire/reject가 섞이면
  `partial_success`다.
- 성공 없이 `failed`, `rejected`, `expired`가 있으면 job은 `failed`다.
- 모든 target이 `canceled`이면 job은 `canceled`다.
- 일부 target만 cancel되고 성공 target이 있으면 `partial_success`다.
- `maxFailures`가 설정되고 failure count가 기준에 도달하면 남은 queued assignment를
  더 dispatch하지 않고 job aggregate는 `failed` 또는 `partial_success`로 계산한다.
- maxFailures 도달로 실행되지 않은 queued assignment는 `canceled`로 전환하며,
  Security audit에 `job_max_failures_reached`를 남긴다.

OpenAPI response model 기준:

- `JobSummary.status`는 위 Job status 값을 반환한다.
- `JobSummary.strategy`는 job 생성 시 저장된 fanout 정책을 반환한다.
- `target_agents[].status`는 snapshot status와 controller가 아는 현재 연결 여부를 섞어 만든 운영 표시용 상태이며 Assignment status가 아니다.
- `target_agents[].snapshot_status`와 `target_agents[].labels`는 job 생성 시점의 target snapshot이다.
- `target_agents[].assignment_status`는 target별 assignment 상태다. 아직 assignment가
  없거나 legacy summary인 경우 `null`일 수 있다.
- `target_agents[].task_id`는 target에 배정된 task id다. 없으면 `null`이다.
- `target_agents[].last_error`는 target assignment의 redacted error summary다. raw
  stdout/stderr는 포함하지 않는다.
- `assignment_summary`는 target별 assignment status를 controller가 집계한 count다.
  `skipped`는 `maxFailures` 도달로 dispatch되지 않고 cancel된 queued assignment를
  뜻한다.
- `rendered_artifacts`는 해당 job의 rendered artifact metadata다. Artifact body는
  `/api/jobs/{job_id}/artifacts/{artifact_id}`로만 조회한다.
- Web Admin은 job status, dispatch state, target별 assignment summary를 함께
  보여줄 수 있다.

### Get Job Detail

특정 job의 현재 상태, target agent 연결 상태, 만료 시각을 조회한다. Web Admin UI는
이 응답과 output polling 결과를 함께 사용해서 queued/offline/running/completed/no-output
상태를 구분한다.

```http
GET /api/jobs/{job_id}
Authorization: Bearer <admin-token>
```

응답:

```json
{
  "id": "job-1",
  "status": "running",
  "dispatch_state": "delivered",
  "risk": "high",
  "command_program": "uptime",
  "command_args": ["-a"],
  "selector_kind": "selector",
  "selector_source": "label:role=web",
  "strategy": {
    "concurrency": 2,
    "maxFailures": 1
  },
  "target_count": 1,
  "target_agent_ids": ["agent-web-01"],
  "target_agents": [
    {
      "agent_id": "agent-web-01",
      "name": "web-01",
      "status": "online",
      "snapshot_status": "online",
      "labels": [{ "key": "role", "value": "web" }],
      "task_id": "task-job-1-agent-web-01",
      "assignment_status": "started",
      "last_error": "",
      "connected": true,
      "revoked": false
    }
  ],
  "assignment_summary": {
    "queued": 0,
    "dispatched": 0,
    "accepted": 0,
    "started": 1,
    "succeeded": 0,
    "failed": 0,
    "rejected": 0,
    "canceled": 0,
    "expired": 0,
    "skipped": 0,
    "unknown": 0
  },
  "target_connected": true,
  "created_at_ms": 1710000000000,
  "updated_at_ms": 1710000000000,
  "expires_at_ms": 1710000060000,
  "last_error": ""
}
```

규칙:

- raw stdout/stderr는 이 API에 포함하지 않는다.
- output은 `/api/jobs/{job_id}/output`에서만 조회한다.
- `target_connected`는 target 중 하나 이상이 현재 authenticated persistent session에 붙어 있으면 `true`다.
- rejected/expired/failed 상태에서는 `last_error`가 비어 있을 수 있으므로, 운영자는 audit과 output을 함께 확인해야 한다.

A persistent report racing an earlier Controller cancellation does not change the API's canonical
canceled Assignment or its original reason. For a previously dispatched Assignment, exact-owner
lifecycle reports and supported no-artifact Command/Runbook finals can receive a terminal-preserving
storage disposition and signed receipt; finals still require exact stored output coverage and no
remediation effects. A late Agent success is a recorded report, not an API success override. This
introduces no new REST fields or permission and never authorizes automatic re-execution.

### Cancel Job

Operator가 job을 취소한다. Body는 비워도 되며, reason을 넣으면 audit과 assignment `last_error`에 redaction 후 남긴다.

```http
POST /api/jobs/{job_id}/cancel
Authorization: Bearer <admin-token>
Content-Type: application/json
```

요청:

```json
{
  "reason": "operator requested cancel"
}
```

응답:

```json
{
  "job_id": "job-1",
  "status": "canceled",
  "task_id": "task-1",
  "agent_id": "agent-web-01",
  "assignment_status": "canceled",
  "canceled_count": 3,
  "cancel_delivered_count": 1,
  "cancel_delivered": true
}
```

정책:

- 현재 사람의 JobCancel 권한·credential·epoch를 같은 취소 transaction에서 앞뒤 검증한다. 회수 선행은 401, 권한 부족은 403이며 변경 효과가 없다.
- assignment 선택·Job aggregate·불변 사용자 actor의 감사 기록은 함께 commit/rollback한다. 저장소/기한 오류는 안전한 503, 상태 경합은 409 state_conflict다.
- Agent queue 전송은 commit 뒤에만 시도한다. cancel_delivered=true/count는 queue 수락이며 Agent 수신/종료 확인이 아니다.
- 감사 기록은 가려진 사유·canceled_count·cancel_dispatch_candidate_count를 저장한다. 전달 성공 수는 아직 모르는 commit 시점에 기록하지 않는다.
- `queued` assignment는 DB에서 바로 `canceled` terminal 상태가 된다.
- `dispatched`, `accepted`, `started` assignment는 DB에서 `canceled`로 바뀌고, active session이 있으면 Controller가 agent로 `task_cancel` message를 보낸다.
- `cancel_delivered=false`는 active session이 없거나 outbound queue에 cancel message를 넣지 못했다는 뜻이다. 이 경우에도 DB의 job/assignment cancel 상태는 source of truth다.
- Agent가 이미 실행 중인 command를 취소하면 child process를 kill하고 `task_result.status="canceled"`를 보낸다.
- Timeout은 cancel과 다르다. command timeout은 `task_result.status="timed_out"`로 보고되고 Controller는 assignment/job을 `expired`로 저장한다.
- 이미 terminal 상태인 assignment는 늦은 success/failure result로 덮어쓰지 않는다.

### Poll Output

MVP는 실시간 subscribe 대신 polling 방식 output 조회 API를 제공한다.

```http
GET /api/jobs/{job_id}/output
Authorization: Bearer <admin-token>
```

응답:

```json
[
  {
    "job_id": "job-1",
    "agent_id": "agent-web-01",
    "stream": "stdout",
    "sequence": 0,
    "data": "ok"
  }
]
```

이 API는 job output storage를 조회한다. command stdout/stderr는 Product application log에 자동 기록하지 않는다.

### Bounded Output Page

기존 전체 배열 API와 별도로 SQLite의 저장 출력을 제한된 크기로 읽는다.

```http
GET /api/jobs/{job_id}/output-page?limit=128&max_bytes=65536
Authorization: Bearer <admin-token>
```

매 요청 기존 `job_read` permission을 검사한다. 현재 owner/admin/operator/viewer는 모두 이
읽기 권한을 갖는다. cursor는 인증이나 무결성 증명이 아니며 actor/role query는 받지 않는다.
optional `agent_id`, `stream=stdout|stderr`, `after`를 지원한다. 중복·알 수 없는 query,
빈 필터, 부호·소수·공백·overflow 정수는 400으로 거절한다. `limit`은1–256,
`max_bytes`는4,096–262,144이고 clamp하지 않는다.

응답은 `{items, next_after, has_more, caught_up, history, job_status}`다. `items`는 저장 append
순서의 UTF-8 fragment이며 `chunk_key`, `sequence`, `offset_bytes`, `total_bytes`는 i64 범위의
10진 **문자열**이다. 큰 row는 code point 경계로 나누고 NUL·Unicode·빈 row를 보존한다.
예산은 fragment별 Agent ID·stream·data UTF-8 합계이며 uncompressed JSON은2MiB 이하,
모든 응답은 `Cache-Control: no-store`다. `job_status`는 같은 read snapshot의 canonical 상태다.

`after`는 `op1.` base64url/no-padding cursor다. decoded ASCII JSON은 최대2,048 bytes이며
알 수 없는/중복/누락 field, 다른 type/version·scope·invalid offset/fence는 거절한다.
Job·Agent·stream 필터를 바꾸면 처음부터 다시 읽는다. 보관 삭제나 공식 restore로 기존
cursor가 무효화되면409 `output_cursor_stale`이며, 새 context와 이전 내용을 섞지 않는다.
Job 없음은404, metadata가 예산에 들어가지 않으면413 `output_metadata_too_large`, read 상태
확인 불가는500 `output_read_unavailable`이다. 실패를 빈 성공이나 기존 전체 fetch로 숨기지 않는다.

`has_more`는 frozen prefix 안의 잔여 fragment이고 `caught_up`은 그 prefix를 읽은 뒤 현재
저장 high-water와 일치한다는 뜻이다. terminal Job도 마지막 prefix와 새 prefix를 확인해야 한다.
`history=tracked|unknown|pruned`는 저장 row 이력이며 capture 전체성·작업 성공의 증거가 아니다.
정확한 cursor/재조립/terminal drain 계약은 [UI-001 출력 계약](../.docs/domains/execution/features/UI-001-output-paging-contract.md)을 따른다.
Admin 결과 화면은 이 page API를 고정 사용한다. 실패 시 기존 전체 조회로 되돌아가지 않는다.
Live window와 stored history를 구분하며 terminal prefix 뒤 fresh detail/open cursor를 확인한다.
Postgres page adapter와 실제 Linux/브라우저 최종 인수·비용 검증은 미완료다.

### Get Rendered Artifact Body

Rendered artifact body retrieval은 metadata와 blob storage를 분리한다. 요청은 job id와
artifact id만 받으며 local filesystem path, destination path, rendered template body를
request payload로 받지 않는다.

```http
GET /api/jobs/{job_id}/artifacts/{artifact_id}
Authorization: Bearer <admin-token>
```

응답:

```json
{
  "job_id": "job-1",
  "artifact_id": "artifact-template-1",
  "task_id": "task-1",
  "agent_id": "agent-web-01",
  "retention_class": "rendered_template",
  "checksum_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "size_bytes": 13,
  "content_bytes": [114, 101, 110, 100, 101, 114, 101, 100]
}
```

정책:

- Authorization은 job read 권한을 사용한다.
- Controller는 agent `task_result.artifacts[].content_bytes`가 있는 rendered artifact만 local `ArtifactStore` body로 저장한다. Metadata-only legacy payload는 metadata row만 남기며 body retrieval에서는 missing일 수 있다.
- Artifact body ingest는 `size_bytes`, SHA-256 checksum, retention class, max body size를 검증한 뒤 저장한다.
- Controller는 metadata repository에서 job 소속 artifact인지 먼저 확인한 뒤 `ArtifactStore`에서 body를 읽고 checksum을 검증한다.
- Missing artifact body는 `404 Not Found`를 반환한다.
- Checksum mismatch는 body를 반환하지 않고 `409 Conflict`와 `artifact_corrupt`를 반환한다.
- Product application log와 audit에는 local absolute path, destination path, artifact body bytes, rendered template body, secret value를 남기지 않는다.

## Agent Inventory API

### List

```http
GET /api/agents
Authorization: Bearer <admin-token>
```

응답:

```json
[
  {
    "id": "agent-web-01",
    "name": "web-01",
    "status": "online",
    "connected": true,
    "revoked": false,
    "fingerprint": "<agent-fingerprint>",
    "labels": [
      {"key": "role", "value": "web"}
    ],
    "last_seen_at_ms": 1710000000000,
    "last_seen_age_seconds": 12,
    "hostname": "web-01",
    "os": "linux",
    "arch": "x86_64"
  }
]
```

`hostname`, `os`, `arch`는 최신 facts snapshot에서 추출한 얇은 inventory summary다. facts가 아직 없으면 `null`이다. `last_seen_age_seconds`는 response 생성 시점 기준의 health 판단 보조값이며, `last_seen_at_ms`가 없으면 `null`이다.

Session summary 필드:

- `connected`: controller session registry에 active authenticated persistent session이 있으면 `true`다.
- `status`: 저장된 agent 상태와 현재 session 상태를 조합한 운영자용 상태다.
- `last_seen_at_ms`: Controller가 인증된 Agent의 초기 연결 또는 heartbeat를 수신해 저장한 시각이다. 후속 heartbeat도 갱신하며 Agent가 보낸 timestamp·status를 신뢰하지 않는다. 일반 task/output payload의 session liveness는 별도 runtime registry가 관리한다.
- `last_seen_age_seconds`: 응답 생성 시점 기준으로 계산한 age다.
- 상세 queue depth, connection id, close reason history는 Product API 응답에 포함하지 않고 audit와 Field Debug 로그에서 확인한다.

Inventory 상태 정책:

- active authenticated persistent session이 있으면 `"connected": true`, `"status": "online"`이다.
- session은 없지만 `last_seen_at_ms`가 최근 threshold 이내이면 `"connected": false`, `"status": "reconnecting"`이다.
- threshold를 넘으면 `"connected": false`, `"status": "offline"`이다.
- Agent key가 revoke되어 더 이상 heartbeat를 받아들이면 안 되는 agent는 `"connected": false`, `"status": "offline"`, `"revoked": true`를 함께 반환한다.

내부 저장 상태는 disabled/revoked로 분리될 수 있지만, 운영 화면에서는 연결 불가 상태와 revoke 상태가 동시에 드러나야 한다.

### Detail

```http
GET /api/agents/{agent_id}
Authorization: Bearer <admin-token>
```

응답은 list item과 같은 shape의 단일 object다. 존재하지 않는 agent는 `404`를 반환한다. Agent public key 원문은 이 API에 노출하지 않는다.

### Revoke Agent Key

```http
POST /api/agents/{agent_id}/revoke-key
Authorization: Bearer <admin-token>
```

Agent key를 revoke하고 agent를 disabled 상태로 전환한다. 응답은 갱신된 agent detail object이며, 운영 화면에서는 `"connected": false`, `"status": "offline"`, `"revoked": true`가 함께 표시된다. revoke 성공 직후 active session이 있으면 controller는 해당 session을 `agent_revoked` close reason으로 종료한다. 이후 같은 key를 사용하는 WebSocket 인증과 heartbeat online 전환은 허용되지 않는다. 존재하지 않는 agent는 `404`를 반환한다. 성공 시 `agent_key_revoked` audit event를 남기고, active session을 닫은 경우 `agent_session_revoked_closed` audit event도 남긴다.

이미 agent 로컬 OS process로 실행 중인 task를 즉시 kill하는 것은 revoke API의 보장 범위가 아니다. revoke는 key/session 차단 API이며 추가 task 수신 차단과 session 종료를 보장한다. 특정 job을 중단하려면 `/api/jobs/{job_id}/cancel`을 사용한다.

### Update Labels

```http
PATCH /api/agents/{agent_id}/labels
Authorization: Bearer <admin-token>
Content-Type: application/json
```

요청:

```json
{
  "labels": [
    {"key": "role", "value": "api"},
    {"key": "env", "value": "prod"}
  ]
}
```

응답은 갱신된 agent detail object다. Label key/value는 domain validation을 통과해야 한다. 성공 시 `agent_labels_updated` audit event를 남기며, audit에는 label 원문 전체 대신 label count 중심 metadata를 기록한다.

### Latest Facts

```http
GET /api/agents/{agent_id}/facts/latest
Authorization: Bearer <admin-token>
```

응답:

```json
{
  "agent_id": "agent-web-01",
  "collected_at_ms": 1710000000000,
  "agent_system_time_ms": 1710000000000,
  "body": {
    "system_time_ms": 1710000000000,
    "os": "linux",
    "arch": "x86_64",
    "family": "unix",
    "cpu": {
      "logical_count": 4
    },
    "memory": {
      "total_kb": 16384256,
      "module_count_known": true,
      "module_count": 2,
      "module_count_source": "linux_dmi_type17"
    },
    "network": {
      "interfaces": ["lo", "eth0"]
    },
    "disk": {
      "device_inventory_known": true,
      "device_count": 1,
      "devices": [
        {
          "name": "nvme0n1",
          "kind": "disk",
          "size_kb": 52428800,
          "removable": false,
          "rotational": false
        }
      ],
      "mount_inventory_known": true,
      "mount_count": 2,
      "mounts": [
        {
          "source": "/dev/nvme0n1p1",
          "mount_point": "/",
          "fs_type": "ext4",
          "read_only": false
        },
        {
          "source": "/dev/nvme0n1p2",
          "mount_point": "/data",
          "fs_type": "xfs",
          "read_only": false
        }
      ],
      "root_mount_known": true,
      "root_source": "/dev/nvme0n1p1",
      "root_fs_type": "ext4",
      "root_capacity_known": true,
      "root_filesystem": "/dev/root",
      "root_total_kb": 52428800
    },
    "degraded": {
      "status": false,
      "signals": []
    }
  }
}
```

Agent facts snapshot은 persistent session에서 전송되지만 heartbeat마다 전송되지 않는다. 기본 agent start 설정에서는 initial session snapshot 이후 `--facts-interval-seconds` 기준으로 전송되며 기본값은 300초다. `collected_at_ms`는 controller가 저장한 snapshot 시각이며, 신규 agent message에서는 agent가 보낸 message timestamp를 기준으로 한다. `agent_system_time_ms`는 해당 snapshot을 만든 agent 시스템 기준 시각이다. Facts/metrics payload 내부의 `body.system_time_ms`도 동일한 agent 시스템 시각을 담는다. Facts는 OS, architecture, platform family, hostname, CPU logical count, memory total/module count, Linux `/sys/block` 기반 disk/partition inventory, Linux `/proc/mounts` 기반 mount layout, Linux `/proc/net/dev` 기반 network interface, root disk capacity 같은 비교적 변하지 않는 inventory만 담는다. 현재 메모리 사용량, 디스크 사용량, CPU 사용률은 facts가 아니라 metrics에 담는다. Facts payload의 `degraded.status=true`는 controller에서 agent 상태 `degraded`로 반영된다.

### Facts Snapshot Pages

```http
GET /api/agents/{agent_id}/facts?limit=50&before=<cursor>
Authorization: Bearer <admin-token>
```

응답:

```json
{
  "items": [
    {
      "agent_id": "agent-web-01",
      "collected_at_ms": 1710000000000,
      "agent_system_time_ms": 1710000000000,
      "body": {"system_time_ms": 1710000000000, "os": "linux"},
      "cursor": "1710000000:42"
    }
  ],
  "next_cursor": "1710000000:42"
}
```

`limit` 기본값은 50이고 최대 500이다. `before`는 이전 응답의
`next_cursor` 값을 그대로 넣는다. Cursor는 opaque value로 취급하고
클라이언트에서 분해하거나 직접 만들지 않는다. 응답은 최신 snapshot부터
내림차순으로 반환한다. 다음 페이지가 있으면 `next_cursor`를 반환하고,
더 가져올 row가 없으면 `next_cursor`는 `null`이다.

### Latest Metrics

```http
GET /api/agents/{agent_id}/metrics/latest
Authorization: Bearer <admin-token>
```

응답:

```json
{
  "agent_id": "agent-web-01",
  "collected_at_ms": 1710000000000,
  "agent_system_time_ms": 1710000000000,
  "body": {
    "system_time_ms": 1710000000000,
    "cpu": {
      "logical_count": 4,
      "usage_percent": 18.4
    },
    "memory": {
      "usage_available": true,
      "total_kb": 16384256,
      "used_kb": 8260800,
      "available_kb": 8123456,
      "used_percent": 50
    },
    "process": {
      "pid": 1234,
      "count": 92
    },
    "service": {
      "status_available": true,
      "failed_units_count": 0,
      "failed_units": []
    },
    "disk": {
      "usage_available": true,
      "total_kb": 52428800,
      "used_kb": 18432000,
      "available_kb": 33996800,
      "used_percent": 35
    }
  }
}
```

Metrics snapshot도 persistent session에서 전송되지만 heartbeat 주기와는 독립적이다. 기본 agent start 설정에서는 initial session snapshot 이후 `--metrics-interval-seconds` 기준으로 전송되며 기본값은 30초다. `collected_at_ms`는 저장된 snapshot 시각이고, `agent_system_time_ms`는 agent가 metrics를 만든 시스템 시각이다. Metrics는 CPU 사용률, 메모리 사용량/사용률, 디스크 사용량/사용률, process count, service failure count처럼 시간에 따라 변하는 사용량 telemetry를 담는다. MVP는 lightweight snapshot만 저장하며 time-series observability platform으로 확장하지 않는다. `service.status_available=false`는 systemd가 없거나 조회가 불가능한 환경을 의미하며, collector 실패로 process를 중단하지 않는다. Retention cleanup은 controller-managed worker와 `fleet retention cleanup` explicit command가 같은 application use case를 사용한다.

### Metrics Snapshot Pages

```http
GET /api/agents/{agent_id}/metrics?limit=50&before=<cursor>
Authorization: Bearer <admin-token>
```

응답:

```json
{
  "items": [
    {
      "agent_id": "agent-web-01",
      "collected_at_ms": 1710000000000,
      "agent_system_time_ms": 1710000000000,
      "body": {"system_time_ms": 1710000000000, "cpu": {"logical_count": 4}},
      "cursor": "1710000000:42"
    }
  ],
  "next_cursor": "1710000000:42"
}
```

Paging 규칙은 facts snapshot pages와 동일하다. `before`는 이전 응답의
`next_cursor`를 그대로 사용한다.

### Agent Operational Log Pages

```http
GET /api/agents/{agent_id}/logs?limit=50&before=<cursor>
Authorization: Bearer <admin-token>
```

응답:

```json
{
  "items": [
    {
      "agent_id": "agent-web-01",
      "collected_at_ms": 1710000000000,
      "line": "level=info event=agent_heartbeat_completed",
      "cursor": "1710000000:42"
    }
  ],
  "next_cursor": "1710000000:42"
}
```

이 API는 agent가 주기적으로 올리는 product-safe operational log stream을
조회한다. Secret-like 값은 agent/controller 경계에서 redact된 뒤
`agent_log_chunks`에 저장된다. 이 stream은 command stdout/stderr, runbook
primitive output, task final result와 분리한다. Command stdout/stderr는
`GET /api/jobs/{job_id}/output`으로 조회해야 하며 product application log에도
자동으로 남기지 않는다.

Paging 규칙은 facts/metrics snapshot pages와 동일하다. `before`는 이전
응답의 `next_cursor`를 그대로 사용한다. Agent operational log chunk는
agent message timestamp를 별도 payload로 갖지 않으므로 `collected_at_ms`는
controller가 저장한 시각이다.

### Latest Drift Report

```http
GET /api/agents/{agent_id}/drift/latest
Authorization: Bearer <admin-token>
```

응답:

```json
{
  "agent_id": "agent-web-01",
  "checked_at_ms": 1710000000000,
  "agent_system_time_ms": 1710000000000,
  "policy_name": "nginx-running",
  "status": "drifted",
  "severity": "warning",
  "acknowledged": false,
  "acknowledged_by": null,
  "acknowledged_at_ms": null,
  "resolved": false,
  "resolution_job_id": null,
  "resolved_at_ms": null,
  "expected": "service nginx running",
  "actual": "stopped"
}
```

Agent가 WebSocket task-data channel로 보낸 drift report는 `drift_reports`에 저장되고 `drift_report_received` audit event를 남긴다. `checked_at_ms`와 `agent_system_time_ms`는 agent가 drift report message를 보낸 시스템 시각을 기준으로 한다. Local `fleet drift check --policy`는 service running, package present, file SHA-256 check engine을 사용한다. Controller는 `/api/jobs/drift-check`로 signed drift check assignment를 생성할 수 있으며, agent는 signed envelope 검증 이후 drift check를 수행한다.

### Drift Report Pages

```http
GET /api/agents/{agent_id}/drift?limit=50&before=<cursor>
Authorization: Bearer <admin-token>
```

응답:

```json
{
  "items": [
    {
      "agent_id": "agent-web-01",
      "checked_at_ms": 1710000000000,
      "agent_system_time_ms": 1710000000000,
      "policy_name": "nginx-running",
      "status": "drifted",
      "severity": "warning",
      "acknowledged": false,
      "acknowledged_by": null,
      "acknowledged_at_ms": null,
      "resolved": false,
      "resolution_job_id": null,
      "resolved_at_ms": null,
      "expected": "service nginx running",
      "actual": "stopped",
      "cursor": "1710000000:42"
    }
  ],
  "next_cursor": "1710000000:42"
}
```

Paging 규칙은 facts/metrics snapshot pages와 동일하다.

### Policy Assignment and Scheduled Drift

Policy API는 저장된 policy source와 agent 배정을 관리한다. 자세한 운영 모델은
[docs/policy.md](policy.md)를 기준으로 한다.

```http
GET /api/policies
Authorization: Bearer <admin-token>
```

응답:

```json
[
  {
    "id": "nginx-running",
    "name": "nginx-running",
    "version": 1,
    "source": "apiVersion: fleet.sponzey.dev/v1alpha1\nkind: Policy\n...",
    "created_at_ms": 1710000000000,
    "updated_at_ms": 1710000000000
  }
]
```

```http
POST /api/policies
Authorization: Bearer <admin-token>

{"source":"apiVersion: fleet.sponzey.dev/v1alpha1\nkind: Policy\n..."}
```

Controller는 source를 저장하기 전에 domain policy parser로 검증한다. remediation
section이 있으면 MVP에서는 `approvalRequired: true`가 필요하다.

```http
POST /api/policies/{policy_id}/assignments
Authorization: Bearer <admin-token>

{"agent_id":"agent-web-01"}
```

응답:

```json
{
  "policy_id": "nginx-running",
  "agent_id": "agent-web-01",
  "assigned_at_ms": 1710000000000
}
```

Agent inventory 응답에는 `assigned_policy_ids`가 포함된다. agent별 배정만
조회하려면 다음 endpoint를 사용한다.

```http
GET /api/agents/{agent_id}/policies
Authorization: Bearer <admin-token>
```

Scheduled drift 설정:

```http
POST /api/policies/{policy_id}/schedules
Authorization: Bearer <admin-token>

{"agent_id":"agent-web-01","interval_seconds":300}
```

응답:

```json
{
  "policy_id": "nginx-running",
  "agent_id": "agent-web-01",
  "interval_seconds": 300,
  "next_due_at_ms": 1710000300000,
  "last_checked_at_ms": null
}
```

Due schedule 조회:

```http
GET /api/drift/scheduled
Authorization: Bearer <admin-token>
```

Controller scheduled drift worker는 due schedule을 읽어 controller-signed
drift-check job과 assignment를 생성한다. Worker는 bootstrap에서 주입된 store와
identity dependency만 사용하며, 실행 중 runtime env를 다시 읽거나 변경하지 않는다.
Missed schedule, missing policy/agent, disabled agent skip은 audit event로 남긴다.

### Audit Events

```http
GET /api/audit
Authorization: Bearer <admin-token>
```

응답:

```json
[
  {
    "category": "security",
    "action": "invalid_signature",
    "actor": "system",
    "target": "agent-web-01",
    "value_kind": "redacted",
    "value": "redacted",
    "occurred_at_ms": 1710000000000
  }
]
```

Audit API는 최근 50개 event를 최신순으로 반환한다. `SecretRef` 값은 원문을 반환하지 않고 `secret_ref` marker로만 노출한다.

감사 export:

```http
GET /api/audit/export?category=security&limit=100&before=<cursor>
Authorization: Bearer <admin-token>
```

응답:

```json
{
  "items": [
    {
      "category": "security",
      "action": "insecure_http_transport_enabled",
      "actor": "system",
      "target": "controller",
      "value_kind": "redacted",
      "value": "redacted",
      "occurred_at_ms": 1710000000000,
      "cursor": "1710000000:42"
    }
  ],
  "next_cursor": "1710000000:41"
}
```

`/api/audit/export`는 최신순 cursor paging을 제공한다. `limit`은 `1..=500`
범위로 처리하며, `before`는 이전 응답의 `next_cursor` 값을 그대로 전달한다.
`category`는 생략할 수 있고, 지정하면 아래 registry 중 하나만 허용한다.
모르는 category는 `400 Bad Request`로 거부한다.

Audit category registry:

| Category | 포함 이벤트 기준 |
| --- | --- |
| `agent` | agent online/offline, session start/end, key revoke, label update |
| `enrollment` | enrollment token create/revoke, agent enrollment |
| `job` | job created/started/completed/failed/canceled/timed out, assignment dispatch/result |
| `approval` | approval requested/approved/rejected/expired |
| `drift` | drift report received, scheduled drift due/missed/skip |
| `policy` | policy save, assignment, schedule 변경 |
| `security` | insecure HTTP transport, auth failure, invalid signature, replay/target mismatch, conflicting output chunk, retention cleanup security event |

CLI export:

```bash
fleet audit export --category security --limit 100 > audit-security.jsonl
```

CLI는 controller 응답의 `items`를 한 줄에 하나의 JSON object로 출력한다. Raw
secret, token, private key, command output 원문은 audit export 응답에 포함하지
않는다. `SecretRef`는 `value_kind: "secret_ref"`와 `value: "secret_ref"`로만
표시한다.

Audit mutation 정책:

- Controller는 audit event update/delete API를 제공하지 않는다.
- Retention cleanup은 facts/metrics/logs/job output처럼 bounded artifact만
  지우며 audit table은 일반 retention 대상이 아니다.
- 현재 SQLite 저장소는 application/API 경계에서 append-only로 다루지만,
  물리적으로 tamper-proof WORM 저장소를 제공하지 않는다. 운영 장기 보존이나
  규정 준수가 필요하면 외부 백업, export 보관, 파일시스템/스토리지 권한,
  서명된 release/backup 운영 절차를 별도로 적용해야 한다.

## Current Limits

- Controller HTTP/WebSocket layer는 Axum 기반으로 제공한다.
- Controller accept loop는 명시적 shutdown signal 경계를 갖지만, process signal integration은 CLI/runtime 후속 작업이다.
- controller key pair rotation은 아직 구현하지 않았다.
- CLI login/profile 저장 방식은 구현되어 있다. 기본 profile은 `.fleet/cli-profile.json`이며 protected remote command는 insecure permission을 거부한다.
- Persistent WebSocket session 이후 queued command assignment dispatch, ack/start/reject/result 상태 저장, cancel/timeout terminal 구분, completed output/result 수신은 동작한다. Web Admin UI는 command job 생성, polling 기반 output viewer, target별 assignment table을 제공한다. CLI live renderer와 true streaming subscribe는 후속 task 범위다.
- Approval request lifecycle API와 최소 admin role/permission check는 구현되어 있다. Web Admin approval queue 화면은 pending approvals 조회, approve/reject, expire due action을 제공한다. CLI login/profile과 최소 remote approval commands는 구현되어 있다. OIDC/SSO, full multi-admin lifecycle은 후속 task 범위다.
- Facts/metrics/drift page API는 cursor paging을 제공한다. Generated SDK 배포는 후속 task 범위다.
- Policy source 저장, direct agent assignment, schedule 저장/조회 API, scheduled drift background worker, Web Admin policy list/assignment/schedule 화면은 구현되어 있다. Selector 기반 assignment rollout worker는 후속 task 범위다.
