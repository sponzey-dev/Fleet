# 기능 지도

제품 수준의 안정적인 기능 ID·역할·의존성·상세화 상태를 소유한다.
기준일 2026-10-27, 조사한 dirty checkout 기준. 구현 세부는 [현재 기능표](../../docs/feature-matrix.md)와
실제 source/test가 우선한다. 이 표의 구현 상태는 출시 또는 이번 세션의 테스트 통과 선언이 아니다.
단계·착수/완료 기준은 [전체 계획](../plans/plan.md)이 소유한다.

우선순위: `기반 유지`는 재개발하지 않는 회귀 범위, `P1`은 확정한 근접 순서,
`조건부`는 해당 사용/출시 전 결정, `후속`은 요구 확인 전 자동 착수하지 않는 확장이다.
명세의 ‘확정’은 계약이 존재한다는 뜻이며 구현·검증 완료와 별개다.

## 기반과 근접 보완

| ID / 도메인 | 사용자·역할 / 기능 결과 | 우선순위·선행 | 명세 위치 / 확정 상태 | 구현 상태 | 검증 근거 / 남은 검증 |
| --- | --- | --- | --- | --- | --- |
| AGT-001 / 연결 | 운영자가 enroll/revoke하고 Agent가 outbound session 유지 | 기반 유지 | [protocol](../../docs/protocol.md), [security](../../docs/security.md) / 기존 계약 | 구현 | CLI/Controller session tests, TLS smoke; P-01 OS 경계는 별도 |
| INV-001 / 대상 | 운영자가 identity/labels/capability를 보고 target snapshot 확정 | 기반 유지; AGT-001 | [API](../../docs/api.md), [security](../../docs/security.md) / 기존 계약 | 구현 | application/controller targeting tests, Admin preview; JOURNEY-02 |
| OBS-001 / 가시성 | 운영자가 facts·metrics snapshot·Agent log 구분 조회 | 기반 유지; AGT-001 | [logs](../../docs/logs.md), [API](../../docs/api.md) / 기존 계약 | 구현, Linux 중심 | CLI collectors/Controller/Admin tests. full TSDB·platform parity 아님 |
| EXE-001 / 실행 | 요청자가 명령을 제출하고 승인 권한자가 허용, 서버별 취소/timeout/결과 | 기반 유지; INV-001 | [protocol](../../docs/protocol.md), [runbooks](../../docs/runbooks.md), [security](../../docs/security.md) / 기존 계약 | 구현 | domain/runner/controller/CLI tests; 결과 지원 범위는 RES-001 |
| RBK-001 / Runbook | 운영자가 package/service/file.copy/file.template 작업을 반복 실행 | 기반 유지; EXE-001 | [runbooks](../../docs/runbooks.md) / 기존 계약 | 부분: `fleet apply`는 validation-only, secret/provider 한계 | runner/CLI runbook tests, nginx manual smoke; SEC-002/RES-003 구분 |
| DRF-001 / 정책 | 운영자가 drift → 승인된 remediation → fresh verification을 추적 | 기반 유지; RBK-001 | [policy](../../docs/policy.md), [protocol](../../docs/protocol.md) / 기존 계약 | 구현, single Controller | application/store/controller order·mismatch tests; JOURNEY-05 |
| CAT-001 / catalog | 관리자가 public HTTPS source sync/validation/명시 activation | 기반 유지; authorization | [API](../../docs/api.md), [catalog performance](../../docs/catalog-performance.md) / 기존 계약 | 구현, private Git 제외 | catalog fetch/application/store tests, 기존 performance workflow |
| OPS-001 / 운영 | 운영자가 SQLite backup/restore·retention·systemd 사용 | 기반 유지 | [storage](../../docs/storage.md), [retention](../../docs/retention.md), [service](../../docs/service-install.md) / 기존 계약 | 구현, 보고 저장소 성장 한계 | schema/backup fixtures, 수동 OS gate는 P-01/07 |
| SEC-001 / trust | 관리자가 signing identity·신뢰 rollout·외부 restart 절차 관리 | 기반 유지 | [security](../../docs/security.md) / 기존 계약 | 부분: rotation 기반 존재, full mTLS/hot reload 아님 | domain/store/controller trust tests; EXT-001과 분리 |
| REL-001 / 배포 | 운영자가 검증된 `fleet` binary를 npm/standalone으로 설치 | 기반 유지 | [release gate](../../docs/release-gate.md) / 기존 계약 | 구현, 실제 tag/registry와 별도 | wrapper/platform/signature checks; 이번 세션 publish 안 함 |
| RES-001 / 보고 | Agent가 지원 report를 journal에 보존하고 signed receipt 뒤 정확히 정리 | 기반 회귀; EXE-001 | [protocol](../../docs/protocol.md), [storage](../../docs/storage.md) / 현재 지원 계약 | 부분: Command/no-artifact Runbook·Drift 보고 등 경로별 차이 | RES-002 실제 시험 완료. RES-003/004 잔여 경계 유지 |
| RES-002 / 장애 검증 | 운영자가 restart/kill/reboot 뒤 결과·불확실성·중복 없음 확인 | 기반 회귀; RES-001 | [상세 명세](../domains/execution/features/RES-002-linux-recovery.md) / 확정 | 지원 경로 실제 Linux 3 scenario 완료 | [phase011 state](../../.tasks/phase011/state.md), 원본 task056 보존 |
| UI-001 / 실행 관찰 | 운영자가 장시간 작업을 다시 열고 대상별 출력·상태를 끝까지 관찰 | 기반 회귀; EXE-001, RES-001 | [상세 명세](../domains/execution/features/UI-001-job-observation.md) / 확정 | lifecycle·재진입·대상별 증분 출력/페이지 구현 | UI-AC-01–07 완료 증거와 측정/제약은 phase011. 전체 SLA 아님 |
| CAT-002 / catalog 실행 | 운영자가 active 문서를 선택해 기존 승인·서명 실행 경로 사용 | 기반 회귀; CAT-001, EXE-001, UI-001 | [상세 명세](../domains/catalog/features/CAT-002-catalog-execution.md) / 확정 | HTTP/CLI/Admin 연결·원자적 생성·불변 provenance 구현 | CAT-AC-01–08 및 실제 public Git→두 Linux Agent 인수 완료. private Git 제외 |
| IAM-001 / 개인 identity | 사람별 로그인·권한·만료·회수·audit actor | 구현·기능 인수 검증; D-006/013 | [로컬 계정 명세](../domains/identity/features/IAM-001-local-accounts.md), [P-04](../plans/plan.md#p-04) / local 방식·단일 조직 | Domain/Application/store·owner/self HTTP·업무 commit guard·Admin/개인 CLI·local 전환/복구 연결 | IAM-AC-01–04의 실제 HTTPS 두 사용자·Linux 작업/회수·restore·bounded 인증 부하 증거는 [phase012](../../.tasks/phase012/task-list.md). 미배포·전체 SLA/출시/OIDC/project 격리 제외 |
| IAM-002 / project 격리 | 다른 project의 inventory/job/catalog 직접 ID 접근 차단 | 조건부; IAM-001, scope 결정 | [P-08](../plans/plan.md#p-08) / 미확정 | 미구현 | cross-project matrix 필요; 첫 identity 작업에 자동 포함 안 함 |
| SEC-002 / secret | 승인된 reference를 실제 provider에서 해석해 안전하게 실행 | 다음 P-05; D-007/014 확정 | [OpenBao KV v2 명세](../domains/security/features/SEC-002-openbao-kv-v2.md), [P-05](../plans/plan.md#p-05) / Agent 직접 조회·AppRole/준비별 단기 인증 | typed port/disabled/static test 기반. 실제 Agent는 Disabled이며 OpenBao adapter 미구현 | SEC-AC-01–04 계획 확정·미실행. 민감 plan/file·admission/metadata 보고·실제 HTTPS/OpenBao/Linux 검증 필요 |
| QUA-001 / 성능 | 확대 운영 전에 대표 부하·병목·회귀를 측정 | P1 후속 순서; D-008 | [품질 기준](../architecture/quality-targets.md), [P-06](../plans/plan.md#p-06) / 측정 절차 준비, 수치 미확정 | catalog gate만 존재, 전체 fleet gate 미완성 | QUA-AC-* 예정, 실측 없이 동시성/캐시/DB 교체 금지 |
| ARC-001 / 구조 | 변경 경계에서 runtime/adapter owner를 분리해 회귀 없이 확장 | 각 기능과 함께; characterization | [system](../architecture/system.md#refactoring), AGENTS / 기존 방식 확정 | Agent 추출 일부, CLI runtime 잔존 | dependency/characterization + 관련 gate. 대규모 일괄 이동 아님 |
| RES-003 / 보고 확대 | artifact pre-inbox/Drift 실행/one-shot의 지원 경계 결정·보완 | 조건부 출시 전; D-009 | [protocol](../../docs/protocol.md), [P-07](../plans/plan.md#p-07) / 경로 선택 미확정 | 경로별 부분/미지원 | 지원 매트릭스·각 crash point 인수 필요 |
| RES-004 / 보존 증가 | journal/inbox/receipt/nonce 성장·용량 부족을 명시적으로 처리 | 조건부 장기 운영 전; D-009 | [storage](../../docs/storage.md), [P-07](../plans/plan.md#p-07) / purge 계약 미확정 | journal bounded 기반, 일부 tombstone/nonce 무상한 | 보존/안전한 cutoff·storage-full·복구 시험 필요 |
| DOC-001 / 정합성 | 운영자가 현재 지원·미검증·후속 범위를 구별 | 전 단계 | [문서 지도](../README.md) / 구조 확정 | 완료 증거와 다음 IAM 계획의 현재 진입점 동기화 | 이번 계획 작업은 문서 검증만 수행. 과거 제품 gate와 구분 |

## 확장 지도

아래는 기능 목적과 선행조건만 정의한다. 일정·지원 SLA·구현 승인·상업 edition 확정이 아니다.
상세 인수 계약과 사용자 선택을 준비하기 전에는 구현에 들어가지 않는다.

| ID | 목적 / 현재 상태 | 선행조건 / 명세 위치 |
| --- | --- | --- |
| EXT-001 | full mTLS client-certificate enforcement / lifecycle 기반만 부분 존재 | SEC-001, certificate issue/renew/revoke·listener·Agent 적용; [security](../../docs/security.md) |
| EXT-002 | Postgres 단일 Controller 운영 지원 / adapter·실DB repository tests 존재, recovery 때문에 현재 startup 거절 | RES-001/003/004 동등 계약, migration/restore/soak·TLS; [storage](../../docs/storage.md) |
| EXT-003 | S3-compatible artifact adapter / local store만 구현 | SEC-002, credential·retention·orphan lifecycle; [storage](../../docs/storage.md) |
| EXT-004 | 작업 실패 등 외부 알림과 최소 telemetry export / 미구현 | IAM/SEC, redacted payload·bounded retry·중복/실패 정책; [P-08](../plans/plan.md#p-08) |
| EXT-005 | 추가 installer/package·signed staged update / archive 서명 존재, self-update 미완성 | REL-001, 버전 pinning·target 검증·rollback; [service](../../docs/service-install.md) |
| EXT-006 | macOS service/collector 동등성, Windows Agent/service / macOS binary만으로 동등 지원 아님 | capability별 adapter/권한/process cancel·실OS gate; [system](../architecture/system.md) |
| EXT-007 | HA Controller / 미지원 | EXT-002, leader/lease·fencing·claim·worker ownership, two-controller failure tests |
| EXT-008 | tamper-evident audit chain/signed export / API append-only는 존재 | SEC-001, canonical sequence/retention·복구 검증, 규정 요구 결정 |
| EXT-009 | Ansible subset import / 미구현 | RBK-001 안정 schema, 비지원 보고, import 시 실행 없음; full compatibility 제외 |
| EXT-010 | 외부 adapter/plugin / 미구현 | signed manifest·권한·capability·timeout/cancel·audit, disabled default, 사용자 요구 확인 |

Private Git은 CAT-001/002와 SEC-002/IAM을 완성하고 credential·scope를 별도 결정한 뒤 상세화한다.
‘확장성’이라는 이유로 범용 plugin framework나 새 broker를 먼저 만들지 않는다.
