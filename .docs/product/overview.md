# 제품 범위와 성공 기준

이 문서는 [README 정의](../../README.md)의 상세 목표·사용자·제품 범위를 소유한다.
기능별 상태는 [기능 지도](capabilities.md), 순서는 [전체 계획](../plans/plan.md), 선택 근거는
[결정 기록](../decisions/decisions.md)에 둔다. 기준일: 2026-10-27.

## 문제와 사용자

Fleet는 여러 Linux 서버를 운영하는 사람이 반복 명령·설정·점검을 대상 확인, 승인,
서명, 결과와 감사의 한 흐름으로 다루는 self-hosted OSS 서버 운영 자동화 플랫폼이다.
Agent가 Controller로 outbound 연결하므로 매번 서버에 inbound SSH 접속할 필요는 없지만,
Agent에서 Controller까지의 네트워크 연결은 필요하다.

첫 사용자는 단일 운영 책임자 또는 소규모 운영팀이다. 고객별 데이터 격리나 다중 조직 SaaS를
현재 제품의 전제로 삼지 않는다. 개인 identity가 완성되기 전 bootstrap token 공유를
팀 계정 관리의 대체 수단으로 권장하지 않는다.

## 사용자 결과

| 목표 ID | 사용자가 얻는 결과 | 관찰할 증거 |
| --- | --- | --- |
| GOAL-01 | 연결 가능한 서버를 등록하고 실제 대상·상태를 확인한다 | Agent identity/labels, authenticated session, inventory API/UI |
| GOAL-02 | 검토한 대상에만 승인된 작업을 전달한다 | target snapshot, 승인 전 dispatch 없음, signed envelope 검증과 audit |
| GOAL-03 | 서버별 실행 결과와 불확실성을 구별한다 | Assignment terminal/reason, stdout/stderr, receipt와 복구 시험 |
| GOAL-04 | 반복 작업을 Git의 특정 문서·버전으로 재현한다 | immutable catalog provenance → Job → 결과/audit |
| GOAL-05 | drift를 승인된 수정과 새 검증으로 닫는다 | origin drift → remediation → verification Job → fresh evidence |
| GOAL-06 | 사용자·secret·자원 한계를 통제하며 운영 범위를 넓힌다 | 고유 actor/회수, provider 거절·redaction, 재현 가능한 부하 보고 |

## 대표 여정과 인수 계약

기존 흐름은 재구현하지 않고 회귀 기준으로 유지한다. 아래는 예정된 인수 검증이며
이 문서 작성 세션에서 시험을 새로 실행한 결과가 아니다.

| 사례 ID | 조건과 행동 | 기대 결과 / 불합격 | 검증 방법 |
| --- | --- | --- | --- |
| JOURNEY-01 | 격리 Linux Agent를 한 번 사용 가능한 enrollment token으로 등록하고 연결 | identity와 labels 확인. 재사용/만료 token 거절, token 재노출 없음 | enroll/session contract + HTTPS smoke, API와 Admin 대조 |
| JOURNEY-02 | labels가 다른 Agent 두 대 중 한 대를 preview하고 Job 생성, 이후 labels 변경 | 생성한 snapshot만 유지. 다른 Agent 실행 또는 무승인 dispatch면 실패 | application/store target snapshot·approval tests + 두 Agent 흐름 |
| JOURNEY-03 | 존재하는 명령/잘못된 명령/timeout/cancel을 각각 요청 | per-Agent terminal과 reason/output 구분. UI가 성공 추정하거나 무기한 running이면 실패 | runner/CLI/Controller tests + [RES-002](../domains/execution/features/RES-002-linux-recovery.md) |
| JOURNEY-04 | active catalog 문서를 선택하고 검토·승인·실행 | 붙여 넣기 없이 immutable provenance가 결과까지 연결. 다른 revision 실행/승인 우회면 실패 | [CAT-002 인수 사례](../domains/catalog/features/CAT-002-catalog-execution.md#acceptance) |
| JOURNEY-05 | 격리된 service/file 상태를 policy와 다르게 바꾸고 remediation 승인 | fresh signed verification으로 원래 drift만 resolve. 오래된/다른 대상 evidence로 resolve하면 실패 | existing policy/remediation integration + disposable Linux smoke |

## 현재 기반과 앞으로 완성할 범위

조사한 checkout은 `main`의 `6683792`/`v0.0.20` 기반이며 manifest는 `0.0.20`이다.
보고·복구 관련 큰 uncommitted diff를 포함한다. 최신 배포 버전, npm 수록 내용 또는
전체 미커밋 변경의 인수 완료를 뜻하지 않는다. 재개 시 commit+diff digest를 다시 고정한다.

현재 핵심 루프는 구현돼 있다. 단일 Controller/SQLite, Linux systemd, enrollment와 session,
명령·Runbook·승인·취소·timeout, facts/metrics/log, policy/remediation, public Git catalog,
정적 Admin, backup/retention과 서명 배포 기반을 유지한다. 자세한 한계는
[현재 기능표](../../docs/feature-matrix.md)와 protocol/storage/security 계약이 소유한다.

기존 신뢰성 경로의 Linux 장애 검증, 장시간 결과 관찰, catalog에서 실행까지의 연결은
[완료 증거](../../.tasks/phase011/state.md)를 보관했다.
[개인별 로컬 관리자 계정](../domains/identity/features/IAM-001-local-accounts.md)은
[D-012](../decisions/decisions.md#d-012)의 범위에서 실제 HTTPS 두 사용자·Linux 작업 중 회수·복구·bounded 인증 부하를 검증했다.
개인 계정의 상세 인수·최종 회귀는 [phase012](../../.tasks/phase012/task-list.md)에 보관했다.
다음 기능 범위는 [OpenBao KV v2](../domains/security/features/SEC-002-openbao-kv-v2.md)의 Agent 직접 조회·AppRole 단기 인증이다.
아직 미구현이며 이후 측정 기반 확장을 수행한다. 전체 순서는
[D-005](../decisions/decisions.md#d-005)를 유지한다.
각 단계는 별도로 인수하며 달력 일정·버전 번호·유료 edition 약속은 정하지 않았다.

### 결과 신뢰성에서 약속하지 않는 것

로컬 journal commit 이후 지원 보고의 재전달·멱등 수신과 실행 exactly-once는 다르다.
저장 전 crash, 디스크 소실, 모든 stdout/stderr byte capture, ACK 정리 뒤 과거 backup으로
돌린 데이터 복구, 중단된 Runbook step resume를 보장하지 않는다.
artifact Runbook의 Agent pre-inbox replay, direct one-shot, Drift execution recovery,
Postgres recovery는 같은 지원 범위가 아니다. 이를 포함한 출시 정책은 RES-003과 D-009에서 다룬다.
불확실한 실행은 성공으로 추정하거나 자동 재실행하지 않는다.

### 후속 확장과 비목표

full mTLS, Postgres runtime 성숙화, S3, 알림/export, 추가 installer, staged update,
Windows/macOS 운영 동등성, HA, tamper-evident audit는 독립 확장이다.
서명 키 rotation 기반과 TLS 서버 인증만으로 full mTLS를 완료라 하지 않는다.
Postgres repository 시험만으로 현재 Controller 운영 지원을 주장하지 않는다.

full monitoring/TSDB, CI/CD, EDR, VPN, Kubernetes 필수 구조, Ansible 전체 호환,
무승인 자동 remediation, plugin marketplace는 이 계획의 기본 제품 범위가 아니다.
Ansible subset/plugin 후보는 필요성 확인 후 후속 명세로 다룬다.
기존 OSS 기능을 Team/Enterprise 이름으로 옮기거나 과금 경계를 새로 정하지 않는다.

## 품질·성공 지표와 제약

필수 성공은 위 여정에서 정상/거절/장애 결과를 설명할 수 있는지로 판정한다.
수치 목표·측정 설계는 [quality-targets.md](../architecture/quality-targets.md)가 소유한다.
초기 문서의 5/10/30분 설치, demo 성공률, 100 Agent/1,000 Job은 검증되지 않은 설계 후보다.
1000 Job은 총 작업 수이지 동시 1000 작업 또는 1000 output chunk로 바꿔 해석하지 않는다.

예산·납기·운영비·지원 SLA는 미합의다. 외부 서비스/인프라를 구매하거나 production 데이터를
사용하는 것은 계획 수립의 실행 권한에 포함되지 않는다. 배포·commit·publish도 별도 요청 대상이다.
프로젝트 라이선스는 `AGPL-3.0-only`, npm 이름은 `@sponzey/fleet`, 실행명은 `fleet`로 유지한다.
