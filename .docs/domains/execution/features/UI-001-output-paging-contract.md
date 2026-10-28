# UI-001 — 증분 출력 착수 계약

상태: **Application/SQLite·보호 API/client·Admin bounded view 구현 및 해당 Linux/브라우저 인수 검증**.
기존 전체 배열 REST는 유지한다. Admin은 새 page API만 소비하고 bounded window/history와
terminal prefix/fresh detail 확인을 사용한다. 해당 Linux/브라우저 경로와 동일 출력 비용을 검증했으며,
전송량 감소를 전체 CPU 속도 개선이나 fleet 규모의 SLA로 일반화하지 않는다.
[UI-001](UI-001-job-observation.md)의 출력 하위 계약이며 Node/Store/route 시험과 브라우저
fixture만으로 UI-AC-06·실제 Linux 인수를 완료하지 않는다. wire v2는 유지한다.

## 읽기 범위와 크기

`GET /api/jobs/{job_id}/output-page`를 별도 추가한다. 기존 `job_read` permission을 매번
검증하며 cursor 자체는 인증·권한·승인 또는 사용자가 모든 출력을 읽었다는 증명이 아니다.
actor나 role을 query/body에서 받지 않는다. 운영 transport는 HTTPS이며 기존 HTTP 시험 정책을 따른다.

| Query | 계약 |
| --- | --- |
| `after` | 첫 요청에서는 생략. 이후 서버가 반환한 opaque cursor를 그대로 전달한다. decoded ASCII 최대 2,048 bytes. |
| `agent_id` | 생략하면 Job의 모든 Agent. 있으면 해당 Agent의 저장 출력만 필터링한다. |
| `stream` | 생략 또는 `stdout`/`stderr`. Agent 필터와 독립이다. |
| `limit` | fragment 수. 기본 128, 허용 1–256. |
| `max_bytes` | 아래 source payload 합계. 기본 65,536, 허용 4,096–262,144 bytes. |

정수는 부호·소수점·공백·overflow 없는 10진수로 검증하고 clamp하지 않는다. 중복/알 수 없는
query key, 빈 필터와 지원하지 않는 stream은 400이다. 필터를 바꾸면 이전 cursor를 폐기한다.
유효하지만 저장 출력이 없는 Agent/stream 필터는 빈 조회이며 Job 실패를 뜻하지 않는다.

source payload 예산은 각 fragment의 UTF-8 `agent_id + stream + data` byte 합계다.
chunk key·sequence·offset 등은 고정된 정수 범위, cursor는 별도 길이 제한을 갖는다.
Controller는 JSON escaping 이후 **uncompressed JSON body 2 MiB** 상한도 검사한다.
이 수치는 요청·메모리의 공학적 경계이며 latency/처리량 SLA나 task 실행의 output limit이 아니다.
기존 Runner의 capture limit, report quota와 보존 기간을 바꾸지 않는다.

## 응답과 원문 보존

```json
{
  "items": [
    {
      "chunk_key": "42",
      "agent_id": "agent-a",
      "stream": "stdout",
      "sequence": "3",
      "offset_bytes": "0",
      "total_bytes": "12",
      "data": "hello world\n",
      "chunk_complete": true
    }
  ],
  "next_after": "op1.<opaque>",
  "has_more": false,
  "caught_up": true,
  "history": "tracked",
  "job_status": "running"
}
```

- `items`는 저장 append row ID 순서다. Agent/sequence 사전순으로 cursor를 만들지 않는다.
  `chunk_key`는 현재 read context 안의 row ID 10진 문자열이다. raw row ID로 다른 Job을 읽을 수 없다.
- `sequence`, `offset_bytes`, `total_bytes`도 10진 문자열이다. JavaScript Number의 53-bit 정밀도로
  식별자나 위치를 반올림하지 않는다. Controller DTO와 Application의 숫자 값은 명시적으로 변환한다.
- 큰 단일 row는 UTF-8 code point 경계에서 fragment로 나눈다. offset/total은 문자 수가 아닌
  원문 byte 위치다. NUL·줄바꿈·emoji·결합 문자를 제거하거나 replacement 문자로 바꾸지 않는다.
  grapheme이 fragment 경계에 걸릴 수는 있지만 byte 재조립 결과는 원문과 같아야 한다.
- `chunk_complete`는 그 row의 끝까지 왔다는 뜻이다. Job 성공, capture 전체성 또는 모든 stream의
  최종 수신을 뜻하지 않는다. 실제 길이가 0인 row도 한 번 반환하고 cursor가 전진한다.
- 동일 context의 `(chunk_key, offset_bytes)`와 같은 data는 재요청 중복이다. 다른 data는 conflict로
  정지하며 덮어쓰지 않는다. 같은 stream의 sequence 1이 0보다 먼저 저장돼도 최종 stream 표시는
  `(agent_id, stream, sequence, offset)`로 재조립한다. append cursor와 표시 순서를 혼동하지 않는다.
- `next_after`는 빈 page나 현재 끝에서도 반환한다. `has_more`는 고정한 prefix 안의 잔여 fragment,
  `caught_up`은 그 prefix를 모두 읽었고 이번 snapshot의 현재 high-water와 일치한다는 뜻이다.
  출력이 더 이상 생기지 않을 것이라는 약속은 아니다. `job_status`는 같은 DB read snapshot의
  canonical Job 상태이며 UI가 출력 존재로 추정한 상태가 아니다.

metadata 하나가 요청 예산에 들어가지 않으면 해당 row를 건너뛰지 않는다. 앞서 읽은 prefix만
반환했다면 `has_more=true`로 남기고, 다음 요청에서도 진입 불가능하면 명시적인 413으로 정지한다.
원문 body가 큰 경우는 이 오류로 대체하지 않고 분할한다. legacy row와 기존 배열 조회는 보존한다.

## Opaque cursor

외부 형식은 `op1.` + padding 없는 base64url UTF-8 JSON이다. 내부 필드는 엄격히 검증하며
알 수 없는 field/version, 각 필드에 지정된 JSON type과 다른 값, 범위 밖 값은 거절한다.

| 내부 필드 | 값 |
| --- | --- |
| `s` | Job ID·optional Agent·stream을 type/length framing한 SHA-256 scope digest |
| `e` | Controller delivery namespace·restore store epoch를 별도 purpose로 framing한 SHA-256 digest |
| `g` | Job별 output read generation, 0–i64::MAX의 최소 10진 문자열 |
| `r` | 마지막 읽은 append row ID, 같은 범위의 10진 문자열. 시작 sentinel은 `"0"`. |
| `o` | 그 row에서 소비한 UTF-8 byte offset, 같은 범위의 10진 문자열 |
| `f` | 진행 중인 frozen high-water 10진 문자열 또는 JSON null |

digest purpose는 각각 `fleet.output-read.scope.v1`, `fleet.output-read.store.v1`로 분리한다.
None/Some 및 각 field의 byte 길이를 포함해 문자열 이어 붙이기의 모호성을 없앤다.
digest는 lowercase hex64 문자열이다. scope 입력은 purpose literal 뒤에 Job/Agent/stream의
`j`/`a`/`s` ASCII tag, presence byte(0/1), Some인 경우 u64 big-endian byte 길이와 UTF-8
원문을 순서대로 연결한다. Job은 항상 Some이고 stream 값은 `stdout`/`stderr`다.
store 입력은 별도 purpose literal 뒤에 namespace·store epoch 각각의 u64 big-endian 길이와
UTF-8 값을 순서대로 연결한다. 두 digest의 목적과 field 경계를 섞지 않는다.
cursor에는 token, signing key, raw output이나 artifact body를 담지 않는다. 새 signing identity나
receipt key를 만들지 않는다. cursor는 신뢰할 수 없는 읽기 위치이며 DB 범위와 permission을
매 요청 다시 확인한다. opaque라는 이유로 integrity/authorization 보장을 주장하지 않는다.

scope가 다르면 400, 현재 store/restore digest 또는 generation이 다르면 409이다.
offset이 row를 넘거나 UTF-8 중간을 가리키거나 fence가 현재 저장 범위를 넘으면 400이다.
row ID의 수치 gap은 다른 Job·삭제·실패한 insert로도 생기므로 그 자체로 유실을 추정하지 않는다.

## 보관과 복구 metadata

Job별 technical read projection에 `generation`, `history`, `last_row_id`를 둔다.
canonical Job/Assignment 상태의 write owner는 기존 Application use case이고,
이 projection은 Store의 같은 write transaction/trigger 경계에서만 유지한다.

| 상황 | projection / 읽기 효과 |
| --- | --- |
| 이전 schema의 Job | row/body를 바꾸지 않고 generation 0, history `unknown`, 현재 MAX(id)로 초기화 |
| metadata 추적 이후 새 Job | generation 0, history `tracked`, high-water 0 |
| output append | 같은 commit에서 high-water 증가. 정상 duplicate는 새 row가 없어 projection 불변 |
| 실제 output 삭제 | 같은 statement/transaction에서 그 Job의 generation 증가·history `pruned`. 기존 cursor는 무효 |
| dry-run / 삭제 0건 / 실패 rollback | generation/history/원문 불변 |
| reopen | namespace/epoch와 projection 유지, 기존 cursor 유지 |
| 공식 restore | 기존 restore epoch 회전으로 이전 cursor 무효. report trust는 기존 restore 계약대로 유지 |
| Job 삭제 | Job 및 projection 소유권 함께 종료, 새 읽기는 404 |

SQLite는 모든 기존 output writer/retention 경로를 포괄하는 append/delete 및 Job insert trigger를
우선 사용한다. 삭제와 generation 갱신을 따로 commit하지 않는다. 보관을 위해 report receipt epoch를
회전시키거나 tombstone/nonce를 purge하지 않는다. generation overflow/corrupt metadata는 fail-closed다.
read projection이 없는 기존 Job을 runtime 요청 중 자동 재초기화하지 않는다.

`tracked`는 추적 시작 이후 **저장 row 이력**이 유지됐다는 뜻이며 모든 실행 byte가 capture됐다는
뜻이 아니다. `unknown`은 migration 이전 보관 이력을 증명할 수 없음, `pruned`는 실제 저장 출력이
삭제됐음을 뜻한다. 어느 상태도 canonical Job 상태를 바꾸지 않는다. 빈 page를 보고 이 세 경우를
모두 ‘출력 없이 성공’으로 표시해서는 안 된다.

SQLite 물리 schema/migration은 v27의 `job_output_read_state`와 append/delete·Job insert
trigger로 구현한다. Postgres page adapter는 현재 제공하지 않는다.
previous-schema fixture·legacy row 불변·반복 migration·backup/newer-schema 거절·rollback을 검증한다.
shared Postgres 영향은 feature/실DB gate로 별도 확인하며 현재 Controller 지원 범위를 확대하지 않는다.
rehearsal의 시험용 table/trigger를 production migration이라고 간주하지 않는다.

## Snapshot과 terminal drain

1. 하나의 read transaction에서 canonical Job 상태·generation·high-water와 bounded fragment를 읽는다.
   handler가 SQL/state 규칙을 소유하거나 transaction/lock을 network await까지 유지하지 않는다.
2. 시작 또는 이전 prefix 종료 시 현재 high-water를 fence로 잡는다. page가 남으면 같은 fence를
   cursor에 유지한다. 그 사이 들어온 더 큰 append ID는 다음 prefix에서 읽는다.
3. `has_more=false`에서 cursor의 fence를 null로 바꾼다. 이전 fence 뒤로 이미 새 row가 들어왔다면
   `caught_up=false`이므로 반드시 다음 snapshot을 읽는다. terminal만으로 이 단계를 건너뛰지 않는다.
4. 마지막 prefix를 drain하고 canonical terminal이 확인되면 Job detail을 새로 읽고 열린 cursor로
   한 번 더 확인한다. 새 prefix가 있으면 계속 drain한다. 현재 snapshot까지 확인한 시각을 표시한다.
5. 최종 조회 이후 도착하는 late G2 출력까지 영원히 없다고 약속하지 않는다. 같은 Job을 다시 열거나
   Refresh하면 현재 저장 상태에서 재조회한다. unsupported capture/replay 범위를 확대하지 않는다.

## Admin 표시와 오류

출력 window는 **rendered UTF-8 text 1 MiB 및 fragment 2,048개** 중 먼저 도달한 경계로 제한한다.
버린 앞부분은 ‘표시 범위에서 제외됨’으로 명시하고 보관 삭제로 오해시키지 않는다.
`Browse stored history`는 live 관찰을 pause하고 처음부터 bounded page를 여는 별도 읽기 모드다.
Next page로 이전 저장 내용을 순차 확인할 수 있고, Resume은 현재 서버 상태를 다시 읽는다.
window 밖의 큰 chunk도 통째로 모아 두지 않는다. window의 duplicate/conflict 확인도 보유 fragment와
마지막 append 위치에 한정해 bounded하게 유지한다. 이미 표시 범위에서 제외해 원문을 확인할 수
없는 과거 replay는 명시 오류로 정지하며 무상한 body/hash 목록으로 대체하지 않는다. API에서 읽은 모든 byte를 브라우저가 영구 보관하거나
사용자가 전부 읽었다고 주장하지 않는다.

Agent/stream/Job/route/auth 변경은 cursor·in-flight request·retry·window의 이전 owner를 해제한다.
기존 10초 read deadline·bounded retry·pause/resume·focus/scroll 보호를 유지한다. catch-up은 한 번에
최대 4 page 후 event loop에 양보하며 status 조회와 취소 동작을 막지 않는다. 화면에서 제외한 fragment나
늦은 sequence는 명시한 window 한도 안에서 처리하고, 재조립 불가한 구간을 임의로 메우지 않는다.

| HTTP / 오류 | UI 효과 |
| --- | --- |
| 400 invalid query/cursor/scope/offset | 자동 반복 중지, 현재 선택/필터를 다시 열도록 안내 |
| 401/403 | 자동 반복 중지, 재인증/권한 안내. 이전 principal 선택은 복원하지 않음 |
| 404 Job 없음 | Job 없음 표시, 빈 성공으로 대체하지 않음 |
| 409 `output_cursor_stale` | 기존 context와 새 page를 섞지 않고 보관/복구 변경 안내·명시적 재조회 |
| 413 `output_metadata_too_large` | 해당 entry를 건너뛰거나 legacy 전체 fetch로 숨기지 않고 제한 안내 |
| 500 read-state/unreadable data | 관찰 오류. Job failed로 바꾸거나 원 SQL/출력을 error/log에 노출하지 않음 |
| timeout/network/재시도 가능한 5xx | 기존 유한 retry와 취소 계약, 실패를 empty response로 숨기지 않음 |

응답은 `Cache-Control: no-store`이고 token/cursor/output을 장기 browser storage나 Product/Field log에
저장하지 않는다. API/OpenAPI/Admin schema/client와 결과 화면은 이 transport에 연결되어 있다. 실제 비용·최종 인수는 별도다.

## 경계별 필수 검증

- Application: scope·budget·cursor position/fence 검증과 typed port, I/O·Serde/framework 의존 없음.
- Store: multi-Agent/stream interleave·sequence 지연·duplicate·empty row·NUL/Unicode·oversized row,
  삭제/rollback/reopen/restore·missing/corrupt metadata, bounded SQL와 migration/backup gate.
- SQL index는 `(job_id, id)` 후보부터 query plan과 동일 fixture 측정으로 검토한다.
  측정 없이 다른 filter별 index·cache·pragma를 추가하지 않는다.
- Controller/client: permission·모든 error mapping·opaque codec·2 MiB wire 상한·기존 배열 contract.
- Admin: canonical stream 재조립·중복/conflict·bounded window/history·terminal 최종 prefix·owner 정리.
- UI-AC-06은 실제 동일 schedule의 full-fetch와 page API의 내용/요청/bytes/render 비용으로 판정한다.
  SQL rehearsal나 fixture serializer만으로 실제 UI/API 성능 또는 Linux 인수를 완료하지 않는다.
