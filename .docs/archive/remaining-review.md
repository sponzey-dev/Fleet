> 이 문서는 2026-09-23의 보완 사항 검토를 보존한 이력입니다. 현재 진행 상태를 소유하지 않습니다.
> R1–R7은 [기능 지도](../product/capabilities.md)와 [전체 계획](../plans/plan.md)에 연결했습니다.
> 이후 구현된 내용과 미실행 검증은 현재 코드·계약·실행 기록을 확인하세요.

# Fleet 제품 보완 사항

검토 기준: 2026-09-23, `v0.0.20` / `6683792`.
상태: 아래 항목은 구현 완료 목록이 아니라, 코드·테스트·제품 목표를 대조한 후속 작업 후보다.

## 문서의 범위와 사용법

- 제품 목표는 [PROJECT.md](../../PROJECT.md), 현재 지원 계약은 코드·테스트와

  [기능표](../../docs/feature-matrix.md)를 함께 확인한다. 이 문서는 그 차이와 보완 기준을 기록한다.
- **실행 결과 신뢰성은 이 문서의 작업 목록에서 제외한다.** 결과 전달·장애 복구 계획은

  [.tasks/plan.md](../../.tasks/plan.md)에서 별도로 관리한다.
- `.tasks/`는 현재 Git ignore 대상이다. 이 문서의 plan/archive 링크는 로컬 workspace용이며,

  계획을 저장소에 함께 배포하려면 별도 추적 정책을 정해야 한다. 이번 작업은 ignore 규칙을 바꾸지 않는다.
- 각 항목의 제안은 개발 승인이나 확정된 출시 약속이 아니다. 개별 계획을 시작할 때 범위,

  public contract, 보안·호환성 영향과 완료 기준을 확정한다.
- P1은 일상 운영 흐름 또는 팀 사용 전 우선 보완, P2는 확대 운영·유지보수 전 보완이다.

  실행 결과 신뢰성 작업과의 상대적 우선순위는 별도 활성 계획이 결정한다.
- 기본 원격 실행, 승인, 서명, 대상 snapshot, 취소·timeout, 감사, drift/remediation,

  공개 Git 카탈로그 기반이 없는 제품은 아니다. 이미 있는 계약을 유지하면서 부족한 경계를 완성한다.

## R1. 장시간 작업 관찰과 결과 화면 — P1

### 확인한 현재 상태

- [web-admin/app.js](../../web-admin/app.js)의 `JOB_OUTPUT_POLL_ATTEMPTS = 45`,

  `JOB_OUTPUT_POLL_INTERVAL_MS = 1000`, `pollJobOutput`은 제한된 횟수만 조회한다.
  요청 소요 시간에 따라 실제 시간은 달라지며, 마지막 추가 조회 후 자동 추적이 끝난다.
- 매 회 `getJob`과 `getJobOutput`을 호출하고 출력 전체를 다시 렌더링한다.

  [API client](../../web-admin/api-client.js)의 `getJobOutput`은 증분 cursor를 전달하지 않는다.
- Agent의 output chunk 전달 기능이 없다는 의미는 아니다. 이 항목은 Admin에서 오래 실행되는

  작업을 지속 관찰하는 UX와 조회 비용의 문제이며, 전달 신뢰성 계획과 구분한다.

### 사용자 영향과 개선 범위

- 긴 패키지 설치·설정 작업에서 자동 갱신이 끝난 화면을 실행 정지로 오해할 수 있다.
- 출력이 있는 경우에도 추적 중단 여부, 마지막 갱신 시각, 재개 방법을 명확히 보여준다.
- 화면 이탈·복귀, 조회 오류·재인증, 작업 전환 시 기존 조회의 취소와 재연결을 정의한다.
- 진행 작업을 다시 열어 관찰할 수 있게 하고, 가능하면 cursor 기반 증분 조회로 중복 전송을 줄인다.

  새 API가 필요하면 먼저 응답·cursor·정렬·보존 만료 계약을 정한다. SSE/WebSocket 도입은 필수가 아니다.
- 자동 스크롤은 사용자가 이전 출력을 읽을 때 중단하고, 대상별 출력과 terminal 결과를 구분한다.

### 완료 기준과 검증

- 45초를 넘는 실행을 완료까지 추적하거나, 명시적인 일시정지·재개 상태로 설명한다.
- 화면 재진입 후 서버 상태에서 복원하며 browser가 success/failure를 자체 판정하지 않는다.
- 출력 중복·누락, 대상 전환 응답 race, 네트워크 오류, 빈 출력, approval 대기, 취소·timeout을 검증한다.
- polling owner와 cancellation을 테스트하고 요청 수·전송 바이트를 변경 전후 비교한다.
- Admin test/typecheck/build, API 계약 변경 시 OpenAPI/schema/client coverage, 키보드·실제 브라우저 검증을 수행한다.
- 제외: 결과 ACK·Agent 영속 대기열, UI 전면 재설계, Grafana 대체.

## R2. Git 카탈로그에서 실행까지의 연결 — P1

### 확인한 현재 상태

- 공개 HTTPS source 등록, sync, revision 활성화, provenance와 목록 조회가 있다.
- `renderCatalogDocuments`는 문서 메타데이터를 표시하지만 실행할 문서를 선택하는 흐름과 연결되지 않는다.
- `buildRunbookJobRequest`는 사용자가 붙여 넣은 `runbook_document`를 요구한다.

  [기능표](../../docs/feature-matrix.md)의 `Runbook catalog/validate UI`도 이 연결을 후속 범위로 명시한다.
- `loadCatalogSources`, `loadCatalogRevisions`, `loadCatalogDocuments`는 첫 응답의 `items`만 저장한다.

  API client는 페이지 입력을 받지만 현재 화면은 `next_cursor`를 이어서 사용하지 않는다.
- sync/activate 조작에 Source ID, operation ID, commit 입력이 노출된다. 비동기 sync 요청의 접수와

  실제 완료를 사용자에게 구분하고 상태 재조회 흐름을 확인할 필요가 있다.

### 사용자 영향과 개선 범위

- Git에 Runbook을 등록해도 실행 시 다시 복사·붙여 넣어야 하며, 선택한 버전의 근거가 흐려질 수 있다.
- source → ready/active revision → 문서 → 대상 미리보기 → 승인 → 실행 결과의 흐름을 연결한다.
- 서버가 보관한 immutable source/commit/path/checksum을 사용한다. 브라우저가 본문을 복사해

  raw 실행으로 우회하여 catalog provenance를 잃는 방식은 사용하지 않는다.
- source/revision/document 각각에 pagination, 선택 유지, loading/empty/error/forbidden을 제공한다.
- sync 요청 접수와 완료·실패·취소를 구분하고, 중복 클릭 및 작업 중 화면 이탈을 처리한다.
- Policy는 activation의 publish 의미와 기존 정책 소유권 충돌을 보여준다.

  활성화가 자동 실행이나 승인 생략으로 바뀌어서는 안 된다.

### 완료 기준과 검증

- 본문 붙여 넣기 없이 활성 catalog Runbook을 선택하여 기존 승인·서명 경로로 실행한다.
- 실행 직전 revision 변경은 명확한 충돌/재확인으로 처리하고 다른 버전을 조용히 실행하지 않는다.
- 두 페이지 이상 fixture에서 끝까지 조회 가능하며 문서 중복·누락이 없다.
- failed sync가 기존 active revision을 바꾸지 않으며 오류·권한 제한이 화면에서 구분된다.
- provenance, target snapshot, approval, raw API 호환의 application/controller 회귀 테스트를 유지한다.
- Admin test/typecheck/build 및 1440·1024·768 폭과 키보드 조작을 실제 확인한다.
- 제외: private Git 인증, webhook/주기 sync, Git write-back, catalog 자동 실행.

## R3. 팀 운영용 관리자 계정과 접근 회수 — P1, 다중 사용자 운영 전

### 확인한 현재 상태

- [보안 모델](../../docs/security.md)의 Current Scope는 bootstrap 관리자 토큰 중심이다.
- owner/admin/operator/viewer 권한 검사, 저장된 token hash 기반 인증, authenticated actor 감사가 있다.

  권한 검사가 전혀 없는 것으로 표현해서는 안 된다.
- OIDC/SSO, 사용자 관리, 다중 관리자 세션, project/team scope는 제품 흐름으로 완성되지 않았다.

### 사용자 영향과 개선 범위

- 초기 토큰을 여러 사람이 공유하는 방식으로는 실제 요청자·승인자와 접근 회수 대상을 분리하기 어렵다.
- 사람별 identity와 로그인·로그아웃·만료·회수, 최소 권한, 감사 actor를 연결해야 한다.
- 우선 단일 조직의 사용자 lifecycle을 완성할지, OIDC를 첫 로그인 수단으로 사용할지 별도 결정한다.

  project/team 격리는 data ownership·목록 필터·대상 선택까지 영향을 주므로 별도 경계로 나눈다.
- 승인자 분리 정책은 현재 role matrix만으로 충족한다고 가정하지 말고 제품 요구를 명시한다.
- bootstrap 복구 절차와 일반 운영 계정을 구분하며, token을 URL·장기 browser storage에 저장하지 않는다.

### 완료 기준과 검증

- 서로 다른 두 운영자의 요청·승인·감사가 고유 actor로 남는다.
- 권한 없는 대상 조회·실행·승인은 UI뿐 아니라 API에서 거부된다.
- 만료·회수된 세션/credential의 재사용, 역할 변경, 로그아웃, bootstrap 복구를 검증한다.
- project scope를 포함한다면 다른 project의 ID를 직접 요청하는 경우에도 격리가 유지된다.
- security/checklist, permission matrix, API/schema 및 사용자 안내를 함께 갱신한다.
- 제외: 첫 작업에 SAML/LDAP/OIDC와 모든 enterprise 기능을 동시에 구현하는 것.

## R4. 실제 비밀값 공급자와 안전한 템플릿 실행 — P1, secret 사용 자동화 전

### 확인한 현재 상태

- typed `SecretRef`, application `SecretProvider`, runner resolver, redaction test가 있다.
- [controller](../../crates/fleet-controller/src/lib.rs)의 `build_controller_secret_provider`는

  Disabled 또는 주입된 StaticTest provider를 구성한다. 이것은 실제 Vault 연동 완료가 아니다.
- secret-backed artifact body를 기본적으로 생략하는 기존 정책이 있다.

### 사용자 영향과 개선 범위

- DB 비밀번호·API key를 사용하는 Runbook을 제품 경로로 운영하기 어렵다.

  해결책으로 raw 비밀값을 Runbook·Git·CLI 인자·로그에 넣어서는 안 된다.
- 첫 production provider 하나와 credential bootstrap, Controller/Agent 중 조회 주체,

  reference 권한·전달 경계를 결정한다. Vault/OpenBao는 후보이지 이 문서에서 확정한 선택은 아니다.
- 조회 실패·권한 거부·만료·값 교체를 typed failure로 처리하고 임의 빈 문자열 fallback을 금지한다.
- lease/rotation이 필요한 공급자는 작업 실행 중 만료와 재시도의 의미를 함께 정한다.

### 완료 기준과 검증

- 격리된 provider integration에서 실제 reference를 해석하여 템플릿을 적용하고 실패는 명시적으로 종료한다.
- token/secret/body가 Product/Field 로그, audit, 오류, artifact 응답에 노출되지 않는 fixture를 검증한다.
- 기존 disabled/static tests 및 secret-backed body 비저장 정책을 유지한다.
- security/storage, bootstrap 설정, README EN/KO를 같은 변경에서 동기화한다.
- 제외: 임의 provider 플러그인 시스템, 모든 backend 동시 지원, UI의 runtime 비밀값 설정 편집.

## R5. Fleet 전체 규모 검증과 측정 기반 최적화 — P2, 확대 운영 전

### 확인한 현재 상태

- [PROJECT.md](../../PROJECT.md)의 성공 기준은 Agent 100대 동시 heartbeat와

  command job 1,000개의 출력 스트리밍 안정성을 포함한다. 동시 job 1,000개로 임의 해석하지 않는다.
- [기능표](../../docs/feature-matrix.md)의 `100-agent / 1,000-output scale gates`는 Planned다.
- [.github/workflows/catalog-performance.yml](../../.github/workflows/catalog-performance.yml)은

  카탈로그 warm sample/baseline을 검증한다. 이 게이트는 Agent 실행 부하 검증을 대체하지 않는다.
- Controller store는 `Arc<Mutex<ControllerStore>>`를 사용한다. 실제 병목 여부는 측정 전 단정하지 않는다.

### 개선 범위와 완료 기준

- CPU/메모리/OS/store/빌드 모드, 연결 수, 동시 실행 수, 작업 시간, 출력 bytes·chunk 크기,

  heartbeat 간격, warm-up/측정 시간을 고정한 대표 workload를 먼저 정의한다.
- heartbeat 지연, task dispatch·결과 조회 지연, 처리량, 메모리·queue 크기, DB lock/transaction

  대기, 오류율을 측정하고 허용치를 최적화 전에 승인한다.
- 100 Agent/총 1,000 command job 시나리오와 장시간 soak를 구분하고 재현 가능한 보고서를 남긴다.
- DB batch/index, blocking I/O 격리, queue 조정은 측정된 병목에만 적용한다.

  통과를 위해 baseline을 자동 완화하거나 queue를 무한정 늘리지 않는다.
- 카탈로그 deterministic/timing gate와 새 Fleet 부하 gate를 독립적으로 유지한다.
- real workload와 synthetic test 한계를 표시하고 근거 없이 최대 지원 대수를 광고하지 않는다.
- 제외: HA 도입, 성능 측정 없는 전면 비동기 DB 교체, 전체 TSDB 구현.

## R6. 책임 경계 중심의 점진적 리팩토링 — P2, 관련 기능 변경과 함께

### 확인한 현재 상태

- [fleet-agent 인덱스](../../crates/fleet-agent/src/source.md)는 process-local state만 소유한다고 명시한다.

  실제 socket/task adapter와 bootstrap은 [fleet-cli](../../crates/fleet-cli/src/source.md)에 많이 남아 있다.
- Controller의 HTTP/session/catalog worker 조합, application use case, store backend 구현도

  큰 `lib.rs`에 집중돼 있다. 테스트 포함 파일 길이를 production 코드 크기로 오해하지 않는다.

### 개선 범위와 완료 기준

- 독립 lifecycle·보안 경계·side-effect owner가 있는 부분부터 characterization test 후 분리한다.

  새 기능에 직접 필요한 분리는 해당 기능 계획에서 수행하고, 나머지 이동만 이 후속 항목으로 남긴다.
- CLI는 parse/bootstrap/composition, agent library는 실행 lifecycle, application은 use case/port,

  infrastructure는 socket·process·store I/O를 맡는 방향을 유지한다.
- controller auth/session/dispatch/catalog와 store backend별 테스트 경계를 작은 단위로 개선한다.
- 리팩토링 단위에서 API/wire/schema/사용자 동작 변경을 섞지 않고 기존 회귀 테스트를 유지한다.
- `cargo metadata --no-deps`, `cargo tree -p fleet-domain`, fmt/clippy/관련 테스트로 의존 방향을 확인한다.
- 가장 가까운 `source.md`와 필요한 rustdoc/JSDoc만 동기화한다. 모든 파일·symbol에 주석을 강제하지 않는다.
- 제외: 대규모 일괄 파일 이동, 새 framework, 추측성 trait/crate, 파일 길이만을 이유로 한 구조 변경.

## R7. 문서의 현재 상태·계획·검증 근거 일치 — P1, 독립 문서 작업

### 확인한 불일치

- 기능표의 catalog 설명에는 pinned release-runner threshold가 남았다고 쓰여 있지만,

  현재 catalog performance workflow와 npm release의 호출 연결은 존재한다.
  구성 존재와 실제 실행 성공을 구분하여 해당 task/run evidence까지 대조해야 한다.
- 이전 계획은 완료라고 표시하면서 일부 phase 제목·본문에는 public interface/검증 대기가 남아 있다.

  이전 기록은 [phase010](../../.tasks/phase010/)에 보존하며 새 목표의 완료 상태로 재사용하지 않는다.
- `docs/security.md`의 OIDC "Phase 6" 참조는 현재 활성 계획의 phase 번호와 같은 뜻이 아니다.

  새 계획 수립 뒤에도 과거 단계 번호를 그대로 참조하면 잘못된 완료 판단을 만들 수 있다.
- `AGENTS.md`의 "현재 source.md가 없다"는 설명과 이미 존재하는 여러 source index가 다르다.

### 개선 범위와 완료 기준

- current/partial/planned, implementation/local test/manual test/external release를 구분한다.
- 이미 구현된 기능을 Planned로 두거나, trait/state foundation만으로 제품 지원 완료라 쓰지 않는다.
- 장기 roadmap 번호는 문서 내 안정된 항목으로 연결하고 활성 `.tasks/plan.md`의 phase와 혼용하지 않는다.
- archive 이동으로 달라지는 링크도 확인한다. 과거 증거를 삭제하거나 당시 실패를 성공으로 고치지 않는다.
- feature matrix/security/protocol/storage/release gate 및 README EN/KO의 실제 사용자 명령을 대조한다.
- 경로·링크·명령 검증과 `git diff --check`를 통과하고 미실행 수동 검증은 남겨 둔다.

## 후순위 확장: 현재 기능 결함과 구분

다음은 기능표에 명시된 미완성·장기 항목이다. 위 작업에 자동 포함하지 않는다.

| 분야                     | 현재 경계와 다음 판단                                                                                                                           |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| 외부 알림·telemetry export | Slack/Teams 및 export는 Planned. 운영자가 화면을 보고 있지 않을 때 필요한 알림부터 별도 요구를 정한다. Prometheus/Grafana 전체 대체는 목표가 아니다.                             |
| mTLS                   | certificate lifecycle foundation과 TLS 서버 인증을 full client-certificate enforcement로 혼동하지 않는다. 현재 unsupported mTLS 설정의 fail-closed를 유지한다. |
| Postgres·HA            | feature-gated partial path가 있다. 실제 store 운영 성숙도와 lease/leader coordination은 별개이며 SQLite 단일 Controller 완성을 막는 선행조건으로 만들지 않는다.           |
| S3 artifact            | local store contract는 있다. 외부 credential·권한·retention을 승인한 후 adapter 하나를 추가한다.                                                          |
| Private Git            | 공개 카탈로그 흐름과 실제 SecretProvider를 우선한다. raw credential을 catalog API에 덧붙이지 않는다.                                                            |
| 플랫폼·설치·update          | Darwin binary 배포와 Linux 수준 운영 기능의 동등성은 다르다. Windows service, 추가 package, signed staged update/rollback은 별도 계획이다.                       |
| 감사 변조 탐지               | append-only API와 tamper-evident hash chain/signed export는 다르다. 규정 준수 요구가 확인되면 독립 범위로 정한다.                                              |

## 권장 분할과 검증 기록

- 사용자 흐름: R1과 R2를 각각 작은 계획으로 나눈다. 출력 관찰 개선과 catalog 실행 연결을 구분한다.
- 팀 운영: R3의 개인 identity lifecycle부터 시작하고 project isolation은 승인된 후 확장한다.
- secret 자동화: R4에서 provider 하나만 대상으로 잡는다.
- 확대 운영: R5의 baseline을 먼저 만들고 R6는 측정·변경 경계에 맞춰 수행한다.
- R7은 독립 문서 정합성 작업으로 처리한다. 이 문서를 작성했다고 위 항목들이 수정된 것은 아니다.

이번 검토 세션에서 확인한 자동 검증은 `cargo test -p fleet-agent` 2개,
`cargo test -p fleet-cli failed_outbound_write_keeps_front_report_for_reconnect` 1개,
`npm test --workspace web-admin`, `npm run typecheck --workspace web-admin` 통과다.
이는 위 후속 기능의 인수 시험을 대신하지 않는다. 전체 release gate, 실제 VM 장애 주입,
100 Agent 부하 및 현재 브라우저 시각 검증은 이번 검토에서 실행하지 않았다.
