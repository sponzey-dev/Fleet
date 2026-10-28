# CAT-002 — 활성 catalog 문서에서 실행까지

목적: GOAL-04의 Git 문서를 복사·붙여 넣지 않고 검토·승인·실행·결과로 연결한다.
CAT-001 public HTTPS sync/validation/activation, 기존 Runbook Job use case를 재사용한다.
`CreateCatalogRunbookJob` Application composite persistence와 additive Controller HTTP 생성·Job detail
provenance 조회가 연결된다. Admin의 preview·제출·approval·관찰 통합과 실제 Linux 인수는 별도로
검증해야 하며 API 존재만으로 전체 사용자 흐름 완료를 뜻하지 않는다. CLI 전용 catalog 실행 명령은 없다.
목록 응답의 다음 cursor는 `next_after`, 요청은 `after`다.
계약 소유자는 [API](../../../../docs/api.md), [runbooks](../../../../docs/runbooks.md),
[security](../../../../docs/security.md)이며 선택 순서는 [D-005](../../../decisions/decisions.md#d-005)다.

## 주체·입력·소유권

운영자는 접근 가능한 source → ready/active revision → Runbook document를 선택한다.
source sync/activation은 기존 owner/admin 권한, Job 생성/승인은 현재 route permission을 따른다.
입력은 source identity, immutable commit/path/checksum, target selection·기존 job options다.
서버가 저장된 문서를 해석·검증하고 immutable provenance를 생성한다.
UI가 본문을 가져와 raw `runbook_document`로 보내 catalog 출처를 가장하지 않는다.

## 처리 규칙·실패·부작용

- source/revision/document 목록은 cursor 끝까지 탐색 가능하며 선택 유지/변경 시 loading·empty·error·forbidden을 구분한다.
- sync 요청의 접수와 실제 ready/failed/canceled 결과를 구별하고 중복 click·화면 이탈을 처리한다.
- ready와 active를 구별한다. activation 자체는 Job 생성·dispatch가 아니며 기존 active를 failed sync로 바꾸지 않는다.
- active 문서를 명시적으로 선택하고 기존 target preview와 경고 후 Job을 생성한다.
  승인 필요 작업은 기존 queue/상태를 따르고 서명·snapshot·audit를 재사용한다.
- 선택 뒤 active revision이 바뀌면 확인했던 immutable 문서를 다른 버전으로 조용히 대체하지 않는다.
  stale selection 검출과 재확인을 제공한다. request/response 필드는 기존 server contract를 조사한 뒤
  필요한 최소 conflict 계약을 API·schema·client·tests에서 함께 확정한다.
- Runbook validation·unsupported capability·권한·checksum/path mismatch는 거절하며 Job 일부 생성이나 dispatch가 없어야 한다.
- Policy는 activation의 publish 의미와 기존 policy ownership 충돌을 보여주되 이 작업에서 자동 execution으로 바꾸지 않는다.
- 생성한 Job의 결과를 UI-001 공통 관찰 경로에서 연다. provenance가 Job/audit에서 조회 가능해야 한다.
- Job/provenance/Assignment/target snapshot/Approval/필수 audit/strategy/selector는 composite repository
  command의 한 transaction에서 저장한다. active·ready·document binding을 commit 전에 재확인한다.
  새 실행 인터페이스는 이 경계를 사용하고 commit 및 approval 뒤에만 dispatch한다. 중간 실패를
  일부 Job만 남기는 성공으로 처리하거나 기존 부분 저장 primitive로 대체하지 않는다.

제외: private Git credential, webhook/주기 sync, Git write-back, 자동 activation/실행,
범용 workflow editor, 새로운 Job/approval state machine. 원래 raw Runbook API는 승인된 별도
compatibility 변경 없이 삭제하지 않는다. 이는 v1 wire fallback을 되살리는 것과 무관하다.

<a id="acceptance"></a>
## 예정된 인수 사례

| ID | 조건·행동 | 기대 결과·불합격 조건 | 확인 방법·증거 |
| --- | --- | --- | --- |
| CAT-AC-01 | public HTTPS fixture ready revision 활성화, 문서 선택·preview·제출 | pasted body 없이 immutable source/commit/path/checksum Job, 승인 후에만 dispatch | application/controller provenance contract + browser E2E, Job/audit |
| CAT-AC-02 | 각 목록을 두 페이지 이상 두고 탐색·전환 | 끝까지 누락/중복 없는 목록, 선택 race 없음 | paged API double·Admin tests·키보드 browser |
| CAT-AC-03 | 문서 선택 후 다른 revision 활성화 또는 선택 checksum 변조 | 명시 conflict/재확인 또는 typed rejection, 다른 문서 실행 없음 | Controller/application transaction test + browser 재선택 |
| CAT-AC-04 | sync 실패·진행 중 화면 이탈·중복 sync | active pointer 보존, 접수/완료 구분, 중복 Job 없음 | catalog lifecycle tests + API/state 관찰 |
| CAT-AC-05 | viewer·권한 없음·미지원 문서·다른 document kind·invalid target | 현재 permission/validation 거절, write/dispatch 없음 | route matrix/OpenAPI/client coverage + negative fixtures |
| CAT-AC-06 | 실행 필요 approval 거절/만료, labels 변경, 두 Agent 결과 | approval·snapshot·provenance·per-target 결과 보존 | 기존 Job/approval tests 회귀 + UI-001 연결 |
| CAT-AC-07 | 1440/1024/768, 긴 source/path·error, 키보드 | alignment/overflow/focus와 loading/empty/error 구분 가능 | Admin tests/typecheck/build + 실제 browser screenshots |
| CAT-AC-08 | Job/provenance/Assignment/Approval/audit 생성 중 fault 및 같은 Job ID 재요청 | 필요한 생성 상태가 함께 commit되거나 rollback. partial Job/Approval·누락 audit·중복 dispatch 없음 | Application/SQLite fault injection·reopen·protected API integration |

착수: public catalog contract/metadata paging/Job provenance 기존 흐름을 characterization하고
stale-selection 최소 계약과 UI/API mapping을 확정한다. 신규 server primitive는 필요를 입증할 때만 만든다.
완료: CAT-AC-01–08, API/schema/client gate, 관련 Rust/Admin tests와 사용자 안내가 통과·동기화된다.
catalog fetch timing gate는 별도 유지하며 UI 성공으로 그 gate 통과를 대신하지 않는다.
