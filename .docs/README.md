# Fleet 문서 지도

기준일: 2026-10-27. 이 지도는 재정립한 제품 정의를 전체 계획·기능·계약에 연결한다.
문서 작성은 기능 구현이나 검증 통과를 뜻하지 않는다.

## 처음 읽을 때

1. [루트 README](../README.md) 또는 [한국어 안내](../README.ko.md)에서 제품과 사용 흐름을 읽는다.
2. 작업자는 [AGENTS.md](../AGENTS.md)의 적용 규칙을 확인한다.
3. [제품 범위와 성공 기준](product/overview.md), [기능 지도](product/capabilities.md)를 읽는다.
4. [시스템과 소유권](architecture/system.md)을 확인하고 [전체 계획](plans/plan.md)에서 다음 범위를 찾는다.
5. 해당 기능 명세 → 현재 계약 → 관련 source/test → 실행 task 순서로 좁힌다.

## 사실별 기준 위치

| 사실 / 작업 | 먼저 읽을 기준 | 함께 확인할 근거 |
| --- | --- | --- |
| 외부 소개·설치·실행 | 루트 README EN/KO | 실제 CLI·npm manifest |
| 목표·출시 범위·제외 범위 | [product/overview.md](product/overview.md) | [결정 기록](decisions/decisions.md) |
| 제품 기능·우선순위·상세화 상태 | [product/capabilities.md](product/capabilities.md) | 현재 구현 세부표는 [docs/feature-matrix.md](../docs/feature-matrix.md), 최종 사실은 source/test |
| 구조·dependency·state owner | [architecture/system.md](architecture/system.md) | Cargo manifests, 각 `source.md`, AGENTS |
| 품질 목표·측정 조건 | [architecture/quality-targets.md](architecture/quality-targets.md) | 아직 합의하지 않은 수치는 목표로 강제하지 않음 |
| 인증·권한·secret·서명·audit 변경 | [docs/security.md](../docs/security.md), [checklist](../docs/security-checklist.md) | API permission matrix, domain/application tests |
| 데이터·migration·보관·복구 변경 | [docs/storage.md](../docs/storage.md), [retention](../docs/retention.md) | migration fixtures와 실제 store tests |
| HTTP API 변경 | [docs/api.md](../docs/api.md), [OpenAPI](../docs/openapi.json) | [Admin schema](../web-admin/api.schema.json), client coverage |
| wire·receipt·실행 복구 변경 | [docs/protocol.md](../docs/protocol.md) | `fleet-protocol`, Agent/Controller/Store contract tests |
| 전체 순서·착수·완료 기준 | [plans/plan.md](plans/plan.md) | 기능·사례 ID와 결정 기록 |
| 현재 실행 계획 | [.tasks/plan.md](../.tasks/plan.md), [SEC-002](domains/security/features/SEC-002-openbao-kv-v2.md) | OpenBao KV v2 한 개·Agent 직접 조회·AppRole/준비별 단기 인증. 계획 확정·실제 provider 미구현/인수 미실행. 구현 요청 시 새 task 목록을 생성 |
| 완료 task·실제 시험 결과 | [phase011](../.tasks/phase011/task-list.md), [phase012](../.tasks/phase012/task-list.md) | P-01–03/legacy task056 및 P-04 개인 계정 인수/정리 보관. .tasks는 Git ignored 로컬 기록이며 배포 checkout에 없을 수 있음 |
| 서비스·장애·release 작업 | [service install](../docs/service-install.md), [release gate](../docs/release-gate.md) | 기존 scripts, 정확한 환경·소스 기준·시험 증거 |

API/schema와 실행 기록은 도구가 사용하는 기존 경로를 유지한다. `.docs/plans/plan.md`는
프로젝트 수준의 순서를 소유하고 `.tasks/`의 task checkbox나 검증 결과를 복제해 관리하지 않는다.
실행 기록이 없는 checkout에서는 ‘미확인’으로 두고 재검증한다.

## 이번에 정리한 위치

| 이전 위치 / 내용 | 현재 기준 / 처리 |
| --- | --- |
| `PROJECT.md` 제품·기능·설계·Phase 0–15 | `product/overview.md`, `product/capabilities.md`, `architecture/system.md`, `plans/plan.md`로 재작성. 원문은 [초기 제안](archive/project-proposal.md), 기존 경로는 안내만 유지 |
| `REMAINING.md` R1–R7 | 기능 ID와 단계에 흡수. [이전 검토](archive/remaining-review.md)를 보존하고 기존 경로는 새 기준으로 안내 |
| `docs/architecture.md` | [architecture/system.md](architecture/system.md)로 통합, 기존 경로는 안내 |
| `docs/feature-matrix.md` 과거 실행 phase 표 | 안정적인 기능 ID로 교체. 구현 세부표는 그 경로에 유지하고 전체 일정 소유권은 제거 |
| `docs/security.md`, `storage.md`, `release-gate.md` 등의 과거 Phase 참조 | 현재 계약은 유지. 과거 번호임을 표시하고 새 기능/계획으로 연결. 아래 대응표 참조 |
| .tasks root의 이전 계획·실행 기록 78개 | 사용자 D-012에 따라 phase011로 이동. 기존 phase002–phase010은 유지. 과거 phase 번호는 전체 계획 단계와 무관 |
| `RESEARCH.md` | 초기 시장 조사, 현재 요구·지원 계약이 아님. 이번 재계획에서 외부 시장 수치를 재검증하지 않음 |

과거 번호 대응: template/artifact 1·4 → RBK-001/RES-003/EXT-003;
remediation 2 → DRF-001; Postgres 3 → EXT-002; 보안 5 → SEC-001/SEC-002/EXT-001;
identity 6 → IAM-001/IAM-002; Git catalog → CAT-001/CAT-002;
알림 8 → EXT-004; 배포/update 9 → EXT-005; HA 10 → EXT-007;
감사 11 → EXT-008; 플랫폼 12 → EXT-006; Ansible 13 → EXT-009;
plugin 14 → EXT-010; scale 15 → QUA-001.

현재 문서의 진입 링크는 갱신했다. 과거 archive와 실행 task의 당시 서술은 이력으로 유지한다.
외부 위키·북마크의 존재/갱신은 확인하지 않았으며 기존 경로 안내로 연결한다.

## 상세화 수준과 남은 결정

확정된 기반은 단일 Controller·SQLite·Linux, 정적 Web Admin, `fleet` 단일 binary,
AGPL-3.0-only, v2 paired cutover다. 사용자 확정 순서는 [D-005](decisions/decisions.md#d-005)다.

[Linux 복구 검증](domains/execution/features/RES-002-linux-recovery.md),
[장시간 관찰](domains/execution/features/UI-001-job-observation.md),
[catalog 실행 연결](domains/catalog/features/CAT-002-catalog-execution.md)은 완료 증거를 phase011에 보관했다.
[개인별 로컬 관리자 계정](domains/identity/features/IAM-001-local-accounts.md)은 D-012/013 기준의
제한된 실제 HTTPS/Linux 인수·최종 정리를 완료했고 phase012에41개 파일을 이동 보관했다.
현재 다음 범위는 [SEC-002 OpenBao KV v2](domains/security/features/SEC-002-openbao-kv-v2.md)다.
[D-007/014](decisions/decisions.md#d-007)로 backend·Agent 직접 조회·AppRole/준비별 단기 인증을 확정했다.
구현은 S-00의 안전 contract·기술 한도·격리 시험 조건부터 진행하며 아직 provider 연결/인수는 실행하지 않았다.
전체 부하 허용치와 미지원 결과 경로의 출시 정책은
[D-008–D-009](decisions/decisions.md#pending-decisions)에서 해당 단계 전에 결정한다.
