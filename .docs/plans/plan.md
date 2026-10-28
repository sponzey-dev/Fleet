# Fleet 전체 프로젝트 계획

기준일: 2026-10-27. 재정립한 [제품 정의](../product/overview.md)를 실제 개발 상태에 맞춰
검증 가능한 사용자 결과의 순서로 완성한다. **전체 우선순위는 사용자 확정,
P-01–04는 제한된 기능 인수 증거가 있고 P-05 이후는 후속 범위**다.
기능 목록은 [capabilities](../product/capabilities.md), 중요 선택은 [decisions](../decisions/decisions.md),
구조/리팩토링은 [system](../architecture/system.md), 수치/측정은 [quality targets](../architecture/quality-targets.md)가 소유한다.

## 1. 계획의 기준선과 역할

현재 checkout은 `6683792` / tag `v0.0.20` 기반이며 manifest도 0.0.20이다.
이미 구현된 연결·승인·명령·Runbook·policy/remediation·catalog 기반을 처음부터 다시 개발하지 않는다.
대규모 미커밋 report/recovery 변경이 있으므로 작업 재개 때 source+diff digest와 현재 gate 결과를 고정한다.
이 문서는 최신 release/npm 상태나 모든 dirty 변경의 완료를 선언하지 않는다.

P-01–03의 실행 계획·기록 78개는 사용자 결정에 따라
[phase011](../../.tasks/phase011/)로 이동 보관했다. 기존 phase002–phase010은 유지했다.
Linux 3 scenario·장시간 관찰/증분 출력·catalog 승인/실행의 완료 증거는
[보관 state](../../.tasks/phase011/state.md)와
[최종 acceptance](../../target/output-read-rehearsal/catalog-final-acceptance.json)에 연결된다.
과거 task056과 초기 계획의 미실행 서술은 당시 기준선으로 보존하며 현재 미완료로 재표시하지 않는다.
이 문서는 프로젝트 순서·경계·단계 진입/종료만 소유한다. 실제 실행 상태·증거·task 분해는 `.tasks/`가 소유한다.
`.tasks/`는 Git ignored이므로 파일이 없는 환경에서 완료 기록을 추정하지 않는다.

P-04의 로컬 계정·실제 HTTPS/Linux 인수·최종 회귀는
[phase012 완료 기록](../../.tasks/phase012/state.md)에 보관했다.
현재 실행 계획은2026-10-28의 [D-007/D-014](../decisions/decisions.md#d-007)에 따라
[OpenBao KV v2 비밀 템플릿 실행](../../.tasks/plan.md)으로 구체화했다.
Agent 직접 조회·AppRole/준비별 단기 인증을 확정했으며 구현·인수는 아직 실행하지 않았다.
신뢰성 전 경로·실SecretProvider·전체 Fleet 성능·release가 완료된 것은 아니다.

## 2. 확정된 진행 순서와 분할

[D-005](../decisions/decisions.md#d-005): ① 남은 신뢰성 장애 검증 → ② 장시간 결과 화면 →
③ catalog 실행 연결 → ④ 개인 계정·실제 SecretProvider → ⑤ 전체 부하 검증·측정 최적화.
경계별 리팩토링은 각 기능과 함께 수행하고 HA·Windows·자동 update는 후속 확장으로 분리한다.

| 단계 | 완성할 사용자 결과 / 기능 ID | 선행조건 | 단계 크기 / 다음 진입 기준 |
| --- | --- | --- | --- |
| P-00 | 현재 정의·기능·계약·계획을 혼동 없이 찾음 / DOC-001 | README 정의·AGENTS·현재 코드 조사 | 이번 문서 작업. 문서 링크/소유권 검증이지 제품 완료 아님 |
| P-01 | 실제 Linux 장애 뒤 결과·불확실성을 설명 / RES-002, RES-001 회귀 | 격리 환경·exact binary·승인·rollback | 기존 task056 마무리. Linux 3 scenario 필수 통과 |
| P-02 | 긴 Job을 다시 열어 끝까지 관찰 / UI-001 | P-01의 지원 결과 경계·EXE-001 | lifecycle/복귀와 증분 비용 개선을 두 수직 단위로 분리 |
| P-03 | Git 문서에서 검토·승인·실행·결과까지 / CAT-002 | CAT-001, EXE-001, P-02 공통 결과 viewer | pagination/선택, immutable Job 생성, 승인/관찰 회귀 |
| P-04 | 사람별 요청자·승인자·접근 회수를 추적 / IAM-001 | local 방식·D-013 정책 확정, I-00 contract/기술 측정 | 단일 조직 identity lifecycle 인수 검증. project isolation은 별도 |
| P-05 | 실제 secret reference로 안전하게 자동화 / SEC-002 | D-007 확정: OpenBao KV v2·Agent/AppRole·준비별 token | 현재 계획. 안전한 민감 plan/file·admission/metadata 경계부터 실제 provider/실패·교체 인수 |
| P-06 | 실제 대표 부하에서 한계·개선 효과를 설명 / QUA-001, ARC-001 | workload/harness/baseline, D-008 허용치 | 측정 → 병목 한 개씩 변경 → 동일 부하/soak 회귀 |
| P-07 | 목표 사용 범위와 운영·복구·배포 한계를 증거로 인수 / RES-003/004, OPS/REL 회귀 | D-009 출시 지원 경계, 적용 선행 단계 | 잔여 보고·보존 성장 위험과 운영 runbook, release rehearsal |
| P-08 | 실제 요구가 확인된 확장 하나씩 제공 / IAM-002, EXT-* | 확장별 결정·인수 계약 | 요약 roadmap만 유지. 전체 확장 일괄 착수 아님 |

위 번호는 기존 PROJECT/`.tasks/phaseNNN`의 phase 번호와 무관하다.
P-01–03의 완료 판정은 해당 source/environment의 보관 증거를 따른다.
후속 변경으로 관련 경계가 바뀌면 영향 범위 회귀를 수행한다. 새 사용자 요청으로 순서가 바뀌면 결정 기록을 갱신한다.
납기·person-day·다음 version·상업 edition은 미정이며 임의로 숫자를 부여하지 않는다.

## 3. 단계별 착수와 완료 계약

### P-00 — 기준과 이력 분리

- 결과/사례: DOC-001, 제품 GOAL-01–06 ↔ 기능 ID ↔ 계획 ↔ 인수 사례를 추적할 수 있다.
- 준비: README/AGENTS/주요 계약/현재 diff/활성 task를 대조한다.
- 산출물: 필수 `.docs/` 문서, 근접 3개 기능 명세, 결정 ledger, archive/이전 경로 안내,
  EN/KO README·AGENTS·세부표의 진입 링크. API/schema·실행 task 경로는 유지한다.
- 검증: local Markdown path/anchor, 기능·결정·사례 ID 연결, 구 계획 참조와 지원 표현,
  설치 예제 보존, `git diff --check`.
- 종료: 문서가 서로 다른 current/partial/planned를 주장하지 않고 미확정은 명시돼야 한다.
  이 단계에서 runtime build/test/VM/publish를 수행할 필요가 없고, 과거 pass를 이번 결과로 기록하지 않는다.

<a id="p-01"></a>
### P-01 — 지원 경로의 실제 Linux 장애 검증

- 상태: 지원 범위의 실제 Linux 세 사례 완료. 상세 실행 증거는 phase011에 보관했다.
- 기능 결과: GOAL-03 / RES-002. [상세 범위·RES-AC-00–04](../domains/execution/features/RES-002-linux-recovery.md)를 먼저 적용한다.
- 재실행 준비: 기존 usable image/VM과 현재 전용 자원 owner부터 조사한다.
  exact source/binary, OS/service/data identity, snapshot/rollback, hidden credential 입력,
  empty 전용 data dir와 실행 직전 승인 조건을 확보한다. 준비되지 않으면 NOT READY다.
- 최소 작업: 기존 script/installer/unit checker 재사용 → 승인된 persistent test Command 실행 →
  Controller restart → Agent SIGKILL/restart → host reboot 후 검증을 각각 별도 수행한다.
  실패가 드러나면 재현 test → 최소 수정 → 관련 회귀 순서로 처리한다.
- 관찰: Job/Assignment 상태·reason, stdout start/finish marker와 실제 marker 횟수,
  새 Agent PID/restart counter, terminal 보존·보고 중복 효과 없음. source digest와 사례별 증거를 남긴다.
- 합격: 세 interruption 사례와 적용 자동 회귀가 실제 PASS. 실패·미실행은 미완료 유지.
  local checker/compile 성공만으로 OS 경계가 입증된 것으로 보지 않는다.
- 제외/후속: artifact pre-inbox·Drift execution·one-shot·Postgres recovery 확대는 RES-003,
  무상한 저장 성장·cutoff는 RES-004다. 이들을 숨기지 않고 위험 목록으로 유지한다.
- 다음: 지원 경계·남은 한계를 확정해 P-02가 표시할 상태와 reason의 기준으로 쓴다.

<a id="p-02"></a>
### P-02 — 장시간 실행 관찰

- 상태: lifecycle·증분 출력·실제 장시간 관찰 인수 완료. 현재 구현을 기존 45회 한도로 설명하지 않는다.
- 기능 결과: GOAL-03 / UI-001. [UI-AC-01–07](../domains/execution/features/UI-001-job-observation.md#acceptance).
- 최초 구현 기준은 45회 poll/전체 조회였다. 후속 변경은 현재 lifecycle/cursor 동작을 characterization하고 fake clock·deferred API fixture,
  실제 장시간 harmless Command와 browser 관찰 환경을 준비한다.
- 단위 A: cancel 가능한 단일 polling owner, Job 재진입, tracking/pause/error/last-updated,
  stale-response 방지, 대상별 canonical status/reason. 현 API로 먼저 정확성을 완성한다.
- 단위 B: 필요 시 cursor 계약 확정 → Controller/application/store 조회 경계 → OpenAPI/Admin schema/client →
  증분 render·dedup/resync 순서. full-fetch fixture를 대조 기준으로 둔다.
- 검증: 긴 Job·빈 출력·잘못된 명령·승인 대기·cancel/timeout, auth/network 실패,
  A→B 전환 race, scroll/focus, 1440/1024/768. bytes/요청 수·append 비용 before/after 기록.
- 합격: UI 사례·Admin test/typecheck/build·변경 API gate가 PASS. 단위 A만 끝나면 A만 인수한다.
- 제외: 결과 전달 protocol 변경, full monitoring, frontend framework 교체, 전면 UI 재디자인.

<a id="p-03"></a>
### P-03 — catalog에서 실행까지

- 상태: CAT-AC-01–08과 실제 public Git→승인→두 Linux Agent 실행 인수 완료. private Git은 제외한다.
- 기능 결과: GOAL-04 / CAT-002. [CAT-AC-01–08](../domains/catalog/features/CAT-002-catalog-execution.md#acceptance).
- 준비: 최소 두 페이지 source/revision/document fixture, ready/active/failed/syncing 상태,
  existing immutable provenance·Job 생성 use case와 UI 매핑을 조사한다.
  조사 결과 Application catalog 실행 유스케이스는 있으나 protected HTTP/CLI/Admin 실행 배선은 없다.
  Job/provenance/Assignment transaction과 이후 Approval/audit 분리 호출의 fault를 먼저 검증한다.
  목록의 기존 cursor 계약은 `after/next_after`이며 다른 telemetry의 `next_cursor`와 구분한다.
- 단위 A: pagination·선택 상태·sync 접수/완료·error/forbidden와 중복 동작 취소.
- 단위 B: active 문서 선택 → immutable reference → target preview → 기존 approval/signing Job 생성 →
  UI-001 결과 화면. active revision 변경/선택 변조의 최소 conflict 계약은 먼저 API/test로 고정한다.
- 검증: pasted raw body 우회 없음, stale commit·checksum·권한·unsupported kind·target 거절,
  approval 거절/만료·label snapshot·provenance/audit·실제 browser. 기존 raw API 회귀 유지.
- 합격: 문서 선택만으로 기존 안전한 실행 경로가 연결되고 CAT 사례·Rust/Admin/schema gate PASS.
  sync/activation 버튼만 존재하는 것은 완료가 아니다.
- 제외: private Git, webhook/자동 sync/activation/dispatch, Git write-back, 새 workflow editor.

<a id="p-04"></a>
### P-04 — 개인 identity와 접근 회수

사용자 답변으로 **Fleet 자체 아이디·비밀번호, 단일 조직 개인 계정만** 확정했고 제한된 기능 인수를 검증했다. 최종 회귀·자원 감사의 근거는 현재 task 목록을 따른다.
[IAM-001 상세 인수 계약](../domains/identity/features/IAM-001-local-accounts.md)과
[보관 실행 계획](../../.tasks/phase012/plan.md)과 [D-013](../decisions/decisions.md#d-013)의 확정 정책을 따른다.
웹 session 8시간·PAT 30일·일회성 코드 15분, owner 계정 관리·본인 credential 관리,
기존 자기승인 허용·변경 시 회수, local 전환/복구와 restore credential 무효화를 인수한다.

- 기능 결과: GOAL-06 / IAM-001. 서로 다른 운영자의 요청·승인·audit actor를 구분하고 접근을 회수한다.
- 준비: 확정 정책의 account/session/credential owner·permission/오류/전환 table을 고정하고
  KDF·resource cap·입력/발급/정리 한도는 보안 하한과 격리 측정으로 선택한다. 전체 Fleet SLA는 포함하지 않는다.
- 최소 범위: 단일 조직 사람 identity → authenticated context → 권한 검사 → session 종료/회수 → audit.
  기존 owner/admin/operator/viewer permission boundary를 교체·우회하지 않는다.
- 인수 사례: `IAM-AC-01` 두 actor의 요청/승인/audit 구분; `IAM-AC-02` 직접 API 권한 우회 거절;
  `IAM-AC-03` 만료/회수/역할 변경 뒤 credential 재사용 거절; `IAM-AC-04` bootstrap 복구와 secret 비노출.
- 검증 준비: 두 명 이상의 synthetic identity, expiry clock·revocation fixture, 실제 HTTPS 로컬 계정 연동.
  API/security/checklist/schema/client/README를 함께 검증한다.
- 합격: 확정 정책을 기대/실제 사례로 입증, token 장기 browser 저장 없음. role enum만 있는 것은 완료 아님.
- 제외: IAM-002 project/team isolation, SAML/LDAP/all IdP 동시 지원, billing/유료 edition.

<a id="p-05"></a>
### P-05 — 실제 SecretProvider 한 개

[D-007](../decisions/decisions.md#d-007)로 OpenBao KV v2 한 개·Agent 직접 조회·AppRole/준비별 단기 인증을 확정했다.
[D-015](../decisions/decisions.md#d-015)에 따라 dryRun/checkMode/apply는 provider 접근0이며,
실제 실행도 조회 후 token 회수 성공을 확인한 뒤 파일 적용으로 넘어간다. 회수 실패는 준비 실패다.
상세 인수는 [SEC-002](../domains/security/features/SEC-002-openbao-kv-v2.md),
단계/검증은 [현재 개발 계획](../../.tasks/plan.md)을 따른다. 아직 실제 provider 구현/인수는 없다.

- 기능 결과: GOAL-06 / SEC-002. 승인된 reference만 해석해 template/작업을 실행한다.
- 준비: 현재 typed SecretRef/port/resolver/Disabled/StaticTest·body omission의 characterization,
  선택 provider의 disposable instance 또는 동등한 격리 integration 환경, fake secret sentinel.
- 최소 범위: Agent bootstrap-only typed 설정/factory·permission/reference mapping → AppRole/KV resolver →
  민감 plan/private atomic file·실행 admission/metadata-only 보고 → 실패·만료·다음 작업의 값 교체·비노출 검증.
  Controller는 참조만 보관하고 raw secret을 조회/중계하지 않는다.
  secret body 포함 final의 staging 전 거절·metadata-only late-G2/취소 disposition과 receipt도 이 좁은 경로의 필수 검증이다.
- 예정 사례: `SEC-AC-01` 실제 reference로 기대 파일 적용; `SEC-AC-02` forbidden/missing/expired/timeout/revoke 실패 시
  빈값 fallback·해당 Agent 준비 단계의 host 효과0; `SEC-AC-03` preview 접근0·credential 교체/token 수명;
  `SEC-AC-04` Fleet logs/audit/errors/wire/artifact에 sentinel 원문 없음과 private temp/crash 정리.
  이미 시작한 host 단계의 실패는 실제 완료 효과를 보존하고 fanout Job의 기존 partial_success 집계를 유지한다.
  전용 private credential 파일·OpenBao HTTPS payload·process 메모리는 목적별 보유/정리 경계로 구별한다.
- 합격: 선택 provider integration와 기존 disabled/static tests, runner/controller/Agent 경계,
  security/storage/config/README gate PASS. port만 존재하는 것으로 완료 아님.
- 제외: 범용 provider plugin, 모든 backend, dynamic DB secret/lease renewal, browser runtime secret editor,
  raw secret Git/CLI 인자 저장·이미 적용한 파일의 자동 원복/작업 재실행.

<a id="p-06"></a>
### P-06 — 전체 부하 검증과 측정 기반 최적화

- 기능 결과: GOAL-06 / QUA-001, 필요한 ARC-001. [QUA-AC-01–04](../architecture/quality-targets.md).
- 준비: hardware/OS/store/build/network, Agent/동시 작업/총 작업/출력 크기·기간을 고정한 harness.
  기존 catalog deterministic/timing gate를 재사용하되 fleet gate의 대체로 쓰지 않는다.
- 단위 A: baseline + redacted metrics + 대표 workload/soak. 이전 100 Agent/총 1000 Job 후보는
  사용 환경과 함께 재확인한다. 합격 latency/RSS/error/regression은 D-008에서 최적화 전에 결정한다.
- 단위 B: 측정 병목 하나씩 lock/DB/blocking I/O/queue/render 개선, 동일 조건 재시험.
  필요 시 독립 adapter lifecycle seam만 tidy한다. 근거 없이 batch/concurrency/cache/pragma를 바꾸지 않는다.
- 관찰/합격: 허용치 충족 + state/report correctness 불변 + before/after 재현 가능.
  부하 수치를 낮추거나 baseline을 자동 갱신해 통과시키면 실패. 미합의 수치면 성능 인수 미완료.
- 제외: 성능을 이유로 HA·full async DB 교체·broker 도입·대규모 module 재작성.

<a id="p-07"></a>
### P-07 — 지원 범위·운영 위험·release 인수

이 단계는 모든 장기 확장을 완성하는 단계가 아니다. 목표 사용 환경에 필요한 위험을 닫거나
제한·미지원으로 명시하는 단계다. 중간 단계별 release 여부/버전은 사용자가 별도 결정한다.

- 결과: RES-003/004와 OPS-001/REL-001의 운영 계약을 실제 지원 범위와 일치시킨다.
- 준비: D-009로 artifact pre-inbox, Drift execution recovery, direct one-shot, Postgres startup/recovery,
  ACK cleanup 후 과거 backup 한계, journal/inbox/receipt/nonce 성장의 출시 영향과 우선순위를 판단한다.
  미지원 경로 차단/명시 제한 또는 경로별 구현 중 선택하고 계획을 갱신한다.
- 단위 A: 지원 task/report matrix 및 crash-point fixture. artifact body/journal quota·file/DB orphan,
  evidence와 final receipt의 독립성, 중단 실행 정책을 해당 경로 착수 전에 상세화한다.
- 단위 B: storage growth 측정, disk-full/기동 비용/retention 영향, operator 관찰·용량 계획·복구 절차.
  안전한 replay cutoff 결정 없이 tombstone/nonce TTL/purge를 추가하지 않는다.
- 단위 C: HTTPS 설치·systemd·backup/restore/이전 schema·signing rollout·release archive/npm wrapper
  rehearsal, 정확한 version/source/platform digest·rollback. release는 실제 요청 시 별도 실행한다.
- 예정 사례: `OPS-AC-01` previous-data restore/migration 보존·newer-schema 거절;
  `OPS-AC-02` disk-full/보존 증가에도 성공 위조·무단 삭제·무한 작업 없음;
  `OPS-AC-03` 새 binary 검증/교체·참조 확인·이전 중복물 정리와 승인된 rollback 예외 추적;
  `OPS-AC-04` clean install/upgrade·HTTPS·service lifecycle 및 registry install 구분;
  `OPS-AC-05` 지원/거절 경로를 public docs·API·wire·runtime에서 일관되게 확인.
- 합격: 필수 사례·manual/external gate의 실제 증거, 남은 제한·승인된 예외·중단 기준을 명시한다.
  blocker를 단지 README warning으로 옮겨 닫지 않는다. 미실행인 필수 gate가 있으면 출시 인수 미완료.
- 자원: [resource lifecycle](../architecture/system.md)의 검증 후 교체·이전 파일 정리 원칙 적용.
  실제 VM/root/데이터/계정/registry 변경은 대상과 별도 실행 권한을 확인한다.

<a id="p-08"></a>
### P-08 — 요구 기반 확장 roadmap

| 작업 묶음 / 기능 | 먼저 확인할 사용자 가치·결정 | 선행 검증·인수 방향 |
| --- | --- | --- |
| project/team 격리 / IAM-002 | 단일 조직으로 충분한가, 실제 데이터 owner/scope는? | IAM-001 후 list/query/direct ID/target/catalog/audit 격리 matrix |
| mTLS / EXT-001 | client certificate 운영·발급·회수 책임 | SEC-001 후 listener enforcement·Agent 적용·renew/revoke/reconnect negative tests |
| Postgres / EXT-002 | SQLite로 부족한 관측 근거·운영 요구 | report/G2 recovery 동등 계약부터. migration/restore/실DB·pool/TLS·single Controller soak |
| S3와 private Git / EXT-003·CAT 확장 | 외부 데이터/credential·권한·retention | SEC-002/IAM, 실패·중복·orphan·redaction과 provenance 유지 |
| 알림/export / EXT-004 | 운영자가 놓치면 안 되는 첫 사건·destination | redacted summary, bounded retry/dedup/forbidden·destination failure |
| installer/update / EXT-005 | 필요한 channel/OS/package 하나 | signature/version pinning/승격 전 검증·staged failure/rollback |
| cross-platform / EXT-006 | 첫 macOS/Windows 역할·primitive | platform capability별 지원표와 실제 OS enroll/run/cancel/service gate |
| HA / EXT-007 | single Controller downtime/성능 한계를 측정했는가? | EXT-002, leader/lease/fencing·claim/recovery·two-controller crash/partition |
| compliance / EXT-008 | 실제 규정·증거·보존 요구 | sequence/hash-chain tamper detection·signed export·restore와 보존. WORM 오표현 금지 |
| import/plugin / EXT-009/010 | 단순 YAML/외부 API로 충족되지 않는 실제 사례 | 비지원 항목 보고·import 시 실행 없음, signed manifest/least privilege·cancel/audit |

각 확장은 overview·기능·정책·선택 이유·인수 계약을 먼저 갱신한 뒤 작은 실행 계획으로 나눈다.
편의상 도입할 상용 서비스·edition·과금·multi-tenant SaaS는 이 표에서 확정하지 않는다.

## 4. 공통 작업·검증·종료 규칙

작업마다 ‘현재 순간/언어·실행 단위/지배적 위험/방법론/증거·종료’를 기록한다.
행동 변경은 재현/characterization → 예상 이유의 RED → 최소 구현 → GREEN → tidy 순서로 수행한다.
필요한 tidy만 행동 보존 단위로 분리한다. 문서-only는 link/명령/상태·EN/KO/diff 검증으로 충분하다.

검증은 변경한 경계부터: domain/application 순수 규칙 → store/runner/protocol contract →
Controller/CLI integration → Admin API/view → 실제 Linux/browser/DB → release/registry 순서로 넓힌다.
실행 명령은 [AGENTS 7.4](../../AGENTS.md#74-검증-명령-선택)와 [release gate](../../docs/release-gate.md)를 따른다.
Postgres feature test와 실DB, smoke script unit와 실제 reboot, workflow 존재와 실제 publish를 구별한다.

모든 실행 기록에는 기능/사례 ID, 환경/source 기준, expected/actual, PASS/FAIL/NOT RUN, 증거 경로,
남은 limitation을 남긴다. raw token/key/command output을 공개 log에 첨부하지 않는다.
필수 실패·미실행은 다음 단계에 결과를 제공한 것으로 처리하지 않으며, 독립 준비만 진행할 수 있다.
API/wire/schema/permission/storage 변경은 각 소유 문서·schema/client/source index를 함께 갱신한다.

## 5. 이전 보완 사항의 추적

| 이전 항목 | 새 기준 |
| --- | --- |
| REMAINING R1 | UI-001 / P-02 |
| R2 | CAT-002 / P-03 |
| R3 | IAM-001 P-04, project scope는 IAM-002 P-08 |
| R4 | SEC-002 / P-05 |
| R5 | QUA-001 / P-06 |
| R6 | ARC-001 / 각 기능의 boundary tidy |
| R7 | DOC-001 / P-00 및 매 단계 동기화 |
| 기존 결과 신뢰성 계획 | RES-001/002 P-01, residual RES-003/004 P-07. task056의 실제 진행은 유지 |
| 초기 PROJECT roadmap/상업 제안 | 구현된 부분은 기반 회귀, 미지원/확장은 P-08, edition/일정은 D-010 미정 |

P-04는 완료 기록을 보관했고 현재 다음 범위는 P-05의 OpenBao KV v2다.
D-007/D-014를 따른 S-00 contract·격리 조건부터 시작하며, 전체 부하 허용치 D-008과 출시 경계 D-009는 각 후속 단계에서 결정한다.
