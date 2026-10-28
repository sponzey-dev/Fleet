# 품질 목표와 검증 조건

목표 수치·측정 조건의 기준 위치다. 기준일 2026-10-23. 실제 시험 결과는 실행 기록이 소유한다.
선택 근거는 [D-002/003/008/009](../decisions/decisions.md), 단계는 [전체 계획](../plans/plan.md)을 참조한다.

## 확정된 불변 조건

| ID | 기준 / 적용 범위 | 검증 방법 / 실패 기준 |
| --- | --- | --- |
| Q-SEC | 승인·서명·target·expiry·nonce·identity guard를 복구/UX 때문에 우회하지 않는다 | negative contract tests. 한 guard라도 우회하거나 secret이 log/audit에 노출되면 실패 |
| Q-STATE | terminal Assignment를 late success로 되돌리지 않고 불확실 실행을 자동 재실행하지 않는다 | state/replay/cancel/timeout/G2 tests, marker 확인. 중복 host effect 또는 terminal downgrade면 실패 |
| Q-REPORT | 지원 경로는 journal commit-before-send, Controller effect commit-before-receipt, exact verified receipt cleanup | drop/reconnect/reopen·duplicate/conflicting body·output coverage tests. gap인데 success 또는 ACK로 다른 report 삭제면 실패 |
| Q-DATA | v2 hard cut에도 local migration·legacy row·backup restore 안전성을 유지한다 | previous schema fixture, repeat migration, newer archive rejection, restore epoch·rollback rehearsal |
| Q-RESOURCE | queue/worker/process는 명시 owner·bounded 동작·cancel/shutdown을 갖는다 | full queue, disconnect, storage-full, stalled process, shutdown tests. 무한 자원/대기나 owner 누락이면 실패 |
| Q-UI | stale 응답이 다른 Job/Agent 화면을 덮지 않고 API truth와 관찰 상태를 구분한다 | fake-clock race tests + 실제 브라우저. terminal 추정·재인증 busy loop·token storage면 실패 |
| Q-SCOPE | Linux/SQLite/current path와 미지원 경로·manual 미실행을 분명히 표시한다 | docs/feature/source/release evidence 대조. build/test 존재만으로 운영 완료라 쓰면 실패 |

기존 코드의 batch/timeout/quota 값은 계약/구현 기준이며 이 문서에서 새 성능 SLA로 바꾸지 않는다.
report tombstone/nonce의 무상한 증가 등 이미 존재하는 위반 위험은 RES-004에서 명시 처리한다.

## 성능 검증 절차 — QUA-001

1. exact commit+diff, release/debug build, OS/arch, CPU/RAM/disk/filesystem, SQLite 설정, network/TLS,
   heartbeat interval, Agents·동시 실행·총 Jobs, Job 길이/output bytes/chunk, catalog size를 기록한다.
2. idle 연결, heartbeat+facts/metrics, command fanout+output, API/Admin 읽기, 장시간 soak를 분리한다.
   정상 부하와 reconnect burst/slow consumer/storage pressure 같은 failure load도 구분한다.
3. warm-up·측정 기간·반복 횟수·seed와 clean-data/기존-data 조건을 고정한 reproducible harness를 준비한다.
4. heartbeat 지연/끊김, dispatch·terminal·query latency 분포, 처리량, CPU/RSS, queue high-water,
   store lock/transaction 대기, DB/journal/inbox/nonce 증가·error rate를 수집한다. stdout/secret payload는 지표로 수집하지 않는다.
5. baseline을 먼저 남기고 사용자와 D-008의 허용 지연·메모리·오류·회귀 범위를 확정한 뒤 최적화한다.
   같은 조건의 before/after, correctness regression와 soak를 함께 판정한다. 기준 자동 완화는 금지한다.

| 사례 ID | 예정된 행동 | 통과 기준 / 증거 |
| --- | --- | --- |
| QUA-AC-01 | 동일 fixture/config/seed로 baseline 반복 | 환경·raw redacted metric·측정 스크립트·재현 명령 확보. 환경이 다르거나 누락되면 비교 불가 |
| QUA-AC-02 | 승인된 representative load/soak 실행 | D-008 수치 만족 + Q-STATE/Q-REPORT 위반 없음. 미합의 수치 또는 미실행이면 성능 인수 미완료 |
| QUA-AC-03 | 측정 병목 하나를 변경하고 동일 부하 재실행 | before/after와 허용 회귀·정확성 만족. throughput만 높이고 오류/유실/중복 발생하면 실패 |
| QUA-AC-04 | cursor/증분 출력 도입 시 고정 output fixture로 비교 | 전송 bytes·요청 수·UI append 비용 비교 및 gap/duplicate 없음. full-fetch보다 개선 주장만 있으면 실패 |

## 아직 목표로 강제하지 않는 수치

초기 100 Agent 동시 heartbeat / 총 1000 Command Job은 workload 후보로 유지한다.
동시 실행 수, 출력량, duration, 지연/메모리 허용치는 아직 확정하지 않았다.
`docs/release-gate.md`의 과거 ‘1000 output chunks’는 다른 작은 fixture이며 이 목표를 대체하지 않는다.
기존 catalog deterministic/timing gate는 별도이다. workflow 파일 존재와 실제 pinned-runner pass도 구분한다.

설치 5/10/30분, demo 95%, 설치 이슈 10% 등 초기 제안은 표본·환경이 없어 SLA/출시 gate가 아니다.
recovery RTO/RPO도 미합의다. 지원 보고의 durability 경계와 실제 복구 시간 측정을 먼저 확보한다.
