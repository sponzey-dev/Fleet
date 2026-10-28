# UI-001 — 장시간 Job 관찰과 복귀

목적: GOAL-03의 실행 결과를 오래 실행되는 Job에서도 오해 없이 관찰하게 한다.
대상은 Run/Runbooks의 기존 결과 화면이며 전체 Admin 재디자인이나 report protocol 교체가 아니다.
현재 구현 근거: [app.js](../../../../web-admin/app.js)의 공통 결과 panel과
[단일 관찰 owner](../../../../web-admin/job-observer.js),
[bounded 출력 reader](../../../../web-admin/job-output-reader.js)와 보호된 page를 읽는
[API client](../../../../web-admin/api-client.js), [API 계약](../../../../docs/api.md).
일정 순서는 [D-005](../../../decisions/decisions.md#d-005), 품질은 Q-UI/Q-SEC를 따른다.

## 주체·입력·책임

인증된 운영자가 Job을 선택하거나 다시 열고, Agent/stream을 선택해 출력과 결과를 읽는다.
입력은 Job ID, target Assignment, 서버 Job/결과/output 응답이다.
API permission이 접근을 결정하며 browser actor/role은 권한 근거가 아니다.
UI local state는 관찰 lifecycle만 소유한다. canonical Job/Assignment는 서버가 소유한다.
token은 memory-only로 유지하며 URL/query/localStorage에 넣지 않는다.

## 최소 처리 범위

1. Job 선택마다 하나의 polling owner를 만들고 Job 변경/화면 이탈/로그아웃 때 요청·timer를 취소한다.
2. fixed 45회 후 조용히 멈추지 않는다. 추적 중·마지막 갱신·일시정지·재개·오류를 출력 유무와 무관하게 표시한다.
3. 서버 terminal이 확인되면 마지막 출력 확인 후 종료한다. output 존재/접속 끊김을 terminal로 추정하지 않는다.
4. 같은 Job을 다시 열면 서버 상태부터 읽는다. 이전 Job의 늦은 응답은 selection generation으로 무시한다.
5. 일시 network failure는 bounded backoff와 취소 가능한 재조회, auth/forbidden은 자동 loop 중지와 명확한 안내로 처리한다.
6. Agent별 status/reason·stdout/stderr를 구분하고 위를 읽는 사용자의 scroll을 빼앗지 않는다.
7. 기능 수직 단위를 나눈다: 먼저 현 API로 정확한 lifecycle/복귀를 완성하고, 다음에 증분 조회 비용을 개선한다.
   cursor는 착수 시 정렬·stream sequence·retention 만료 계약을 정의하고 API/OpenAPI/schema/client test를 함께 바꾼다.
   SSE/WebSocket 신규 도입은 이 기능의 필수조건이 아니다.

### 관찰 상태 — Job 상태와 다름

| local 상태 | 전이 계기 | UI effect / 금지 |
| --- | --- | --- |
| idle/loading | Job 열기 | 서버 조회 시작. 기존 화면의 terminal 재사용 금지 |
| following | 유효한 nonterminal 응답 | 갱신 시각 표시·다음 bounded 요청. 45회 한도 silent stop 금지 |
| paused/error | 사용자 pause, 연결 실패 또는 auth/permission 거절 | 이유·재개/재인증 표시, 실패를 Job failed로 쓰지 않음 |
| completed | 서버 terminal 및 최종 조회 | 결과·reason 표시, timer 정리. 미수신 output을 성공 추정하지 않음 |
| disposed | 다른 Job/route/로그아웃 | abort/timer 정리, 늦은 응답으로 DOM 갱신 금지 |

## 출력 계약과 복구

동일 chunk는 stream/sequence의 서버 계약으로 중복 append를 막고, gap/retention expiry는
명시적으로 표시하거나 서버 snapshot으로 재동기화한다. UI가 sequence gap을 메워 가짜 출력을 만들지 않는다.
증분 cursor가 준비되기 전 full-fetch 경로는 정확성 기준으로 유지할 수 있지만 비용 개선 완료라 하지 않는다.
기존 Agent/sequence 정렬 뒤 cursor만 붙이면 앞 Agent의 늦은 append를 놓칠 수 있으므로,
기존 output row id 등으로 append order·scope·보존/restore 후 유효성을 먼저 정한다.
구체적인 다음 단계의 route·cursor·한도·보관/terminal 경계는
[증분 출력 착수 계약](UI-001-output-paging-contract.md)에 정의한다. 이는 구현 예정 기준이며
현재 whole-array API나 Agent wire를 바꿨다는 뜻은 아니다.
terminal 상태와 output 조회 시점이 다를 수 있어 마지막 저장 범위까지 drain한 뒤 관찰을 끝낸다.
DOM/memory 표시 범위는 bounded로 정하고, 앞부분을 화면에서 제외하면 이전 출력 조회·보존 안내를 제공한다.
empty output도 정상이며 missing executable의 실패·stderr/no-output terminal과 혼동하지 않는다.
API 오류·페이지 복귀가 새 Job 제출이나 승인 재요청을 발생시켜서는 안 된다.

<a id="acceptance"></a>
## 예정된 인수 사례

| ID | 조건·행동 | 기대 결과·실패 기준 | 방법·증거 |
| --- | --- | --- | --- |
| UI-AC-01 | fake clock으로 45회보다 긴 nonterminal, 이후 terminal 응답 | 계속 추적하거나 사용자가 명시적으로 pause. terminal 후 timer 없음 | Node lifecycle test, 실제 >45초 harmless Linux Command 브라우저 확인 |
| UI-AC-02 | 출력 있는/없는 상태에서 network error, pause/resume, 재인증 | 갱신/중단 상태와 재개 방법이 항상 보임. busy loop/Job state 추정이면 실패 | API test double, request count·timer/abort assertion |
| UI-AC-03 | Job A 요청 지연 중 B로 전환하고 A 응답 도착 | B의 status/output/target 보존, A effect 없음 | fake deferred response race, route 복귀 브라우저 확인 |
| UI-AC-04 | 두 Agent, empty/error/cancel/expired/approval 대기 | target별 canonical 결과·reason 일치. aggregate만으로 덮으면 실패 | fixture와 실제 API 비교, Run/Runbooks 공통 조회 경로 |
| UI-AC-05 | 두 Agent/stream late append·페이지 재전송·gap·보관/restore·한글 경계·terminal read race | 중복/누락 은폐 없음, 재동기화·보존 안내, 마지막 저장 범위 drain | cursor API/Store/client/coverage contract + deterministic chunks |
| UI-AC-06 | 동일 대용량 output을 before/after 조회 | 요청/bytes/append 비용 측정, QUA-AC-04 연결 | 고정 fixture 측정 보고. 비교 없는 성능 완료 선언 금지 |
| UI-AC-07 | 1440/1024/768 폭, 키보드, 긴 이름·긴 output·사용자 scroll | 기존 sidebar 구조, label/control 정렬·읽기 유지, focus/scroll 존중 | 실제 browser 수동 관찰과 redacted screenshots |

착수: P-01 결과 경계와 기존 상태/API characterization, UI local lifecycle 테스트 seam 준비.
증분 API는 다음 sub-slice에서 contract를 확정한다.
완료: UI-AC-01–07 및 Admin test/typecheck/build·변경 API gate 통과, 문서/EN·KO 사용자 흐름 일치.
첫 sub-slice만 통과하면 관찰 lifecycle만 완료로 기록하며 비용 개선은 별도 남긴다.
