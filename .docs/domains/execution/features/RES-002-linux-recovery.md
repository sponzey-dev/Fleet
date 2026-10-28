# RES-002 — 지원 실행 경로의 Linux 장애 검증

목적: 지원 중인 결과 전달 계약이 실제 Linux systemd/process/reboot 경계에서도 성립하는지 확인한다.
GOAL-03, [Q-STATE/Q-REPORT](../../../architecture/quality-targets.md), D-002/005를 따른다.
지원 범위의 실제 세 사례는 완료했다. 상세 결과는
[보관 목록](../../../../.tasks/phase011/task-list.md)과
[진행 문서](../../../../.tasks/phase011/task0001-0001.md)가 소유한다.
[task056](../../../../.tasks/phase011/task056.md)은 재개 전의 원본 기록으로 보존한다.

## 범위·주체·준비

- 수행자: disposable Linux VM 소유 운영자. Controller/Agent는 승인된 test Command를 처리한다.
- 재사용: [manual recovery script](../../../../scripts/manual_task_recovery_smoke.py),
  [unit checker](../../../../scripts/test_manual_task_recovery_smoke.py),
  [systemd installer](../../../../scripts/manual_systemd_reboot_smoke.sh), [release gate](../../../../docs/release-gate.md).
- 입력: exact commit+dirty diff digest로 만든 `fleet`, OS/arch, SSH/VM identity, 전용 data dir,
  service ExecStart, bootstrap credential, unique Job/Assignment와 harmless marker.
- 전제: isolated VM, 운영 데이터/기존 Fleet service 없음, snapshot/복구 경계, time/disk 여유,
  hidden token 입력, test-only HTTP warning 또는 적절한 TLS.
- 과거 QEMU guest가 지금 존재한다고 가정하지 않는다. 먼저 [자원 목록](../../../architecture/system.md)을 재확인한다.
- root install/data write·Agent kill·host reboot는 대상·영향을 밝히고 현재 task의 실행 직전 승인 조건을 따른다.

포함은 persistent Command의 Controller restart, Agent SIGKILL/restart, host reboot다.
artifact·one-shot·Drift execution admission 확대, Runbook step resume, production restore,
registry publish나 파일 정리는 이 단위에 포함하지 않는다. 통과해도 다른 경로의 인수 완료가 아니다.

## 규칙·관찰·실패 처리

실제 승인 API를 거쳐 생성한 단일 대상 작업이 started이고 marker가 저장된 뒤 장애를 주입한다.
stdout marker, private filesystem marker, Job/Assignment terminal/reason을 모두 확인한다.
script의 unique marker 한 번은 이 제한된 시험의 중복 방지 증거이지 외부 side effect exactly-once 보장이 아니다.
재시도는 보고 재전달이며 명령 재실행이 아니다. 자동 재실행으로 시험을 통과시키지 않는다.

Controller-only restart 동안 Agent 실행이 살아 있으면 저장 보고가 재전달되어 정상 결과로 수렴한다.
Agent process 또는 host가 작업 중 죽으면 성공 추정 없이 `failed/execution_outcome_unknown`으로 수렴한다.
script가 기대하는 Job `success`/Assignment `succeeded` 명칭을 혼동하지 않는다.
cancel/expired 등 기존 terminal은 늦은 결과로 바뀌지 않아야 한다.

연결/설치/preflight가 실패하면 중단 원인을 기록하고 미실행 사례는 NOT RUN으로 남긴다.
실패 중 marker·DB·journal을 지우거나 새 Job으로 덮어쓰지 않는다. 복구와 재시험은 원인 수정 및
정확한 이전 증거 보존 후 수행한다. token/raw output은 Product 로그·공개 증거에 넣지 않는다.

<a id="acceptance"></a>
## 예정된 인수 사례

| ID | 조건·행동 | 기대 결과·불변 상태 | 확인 방법 / 실패 조건 |
| --- | --- | --- | --- |
| RES-AC-00 | 환경·binary/source·empty data·unit 확인, preflight | 정확한 disposable 대상, rollback 확보, 승인 조건 충족 | metadata/hash/preflight. 대상 불명·기존 데이터면 실행 금지 |
| RES-AC-01 | started Command 중 Controller만 restart | Job success/Assignment succeeded, started/finished output·marker 각각 한 번 | script controller-restart + API/marker. 누락/중복/unknown이면 실패 |
| RES-AC-02 | started Command 중 Agent SIGKILL, systemd 자동 restart | failed, `execution_outcome_unknown`, start marker 한 번, finish 없음, 자동 재실행 없음 | script agent-restart, NRestarts·새 active/running PID, API/marker. 단순 is-active만으로 통과 불가 |
| RES-AC-03 | started Command marker sync 뒤 host reboot, 복귀 후 verify | failed/unknown, start 한 번, finish 없음, 서비스 재시작·상태 보존 | prepare-reboot/수동 reboot/verify-reboot. 부팅만 성공이면 미완료 |
| RES-AC-04 | 위 scenario 뒤 재연결·late/duplicate 보고와 관련 자동 회귀 실행 | terminal 보존, exact report 중복 효과/후속 audit·Job 생성 없음, 지원 output coverage 유지 | 기존 Store/Controller replay/late tests와 script 결과 대조. UI만 확인하면 불충분 |

증거에는 scenario별 source digest, platform/service identity, Job/Assignment ID, 기대/실제 상태·사유,
marker counts, 결과 PASS/FAIL/NOT RUN, redacted 실행 기록을 남긴다. receipt cleanup 세부는 자동
Store/Agent contract 증거로 연결하고 script가 직접 검사했다고 과장하지 않는다.

## 착수·완료

착수: RES-AC-00 준비와 runtime 지원 계약이 식별돼야 한다. 환경 조사는 즉시 가능하지만
root interruption은 위 승인 조건을 별도로 충족해야 한다.
완료: RES-AC-00–04의 필수 결과와 적용 자동 gate가 실제 통과하고 task/state/현재 문서가 일치한다.
실제 Linux 세 사례가 하나라도 FAIL/NOT RUN이면 P-01은 미완료다.
검증한 binary 승격·임시 자원 정리는 별도 명시 범위로 수행하고 미정리 예외를 남긴다.
