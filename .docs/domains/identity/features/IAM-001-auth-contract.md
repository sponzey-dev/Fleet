# IAM-001 — 로컬 인증 구현 contract

상태: I-00에서 확정한 구현 contract. local owner/recovery·restore·Application/HTTP 인증·개인 Admin 화면과 개인 token CLI profile은 연결됐다.
실제 두 사용자 HTTPS browser/API/CLI·Linux Agent 작업 중 회수·복구·bounded 인증 부하 인수를 검증했다. 미배포 변경이며 전체 Fleet SLA·실제 tsc·production PG Controller 지원은 포함하지 않는다.
상위 범위는 [IAM-001](IAM-001-local-accounts.md), 사용자 정책은
[D-013](../../../decisions/decisions.md#d-013), 실행 근거는 [보관 task-list](../../../../.tasks/phase012/task-list.md)다.
이 문서의 endpoint·설정 이름은 구현 시 API/OpenAPI/client와 동기화한다.

## 고정 정책과 상태

- 웹 session 28,800초, PAT 2,592,000초, 설정/reset 코드 900초. 서버 UTC로
  now >= expires_at이면 거절한다. idle/sliding renewal은 없으며 polling·재접속으로 연장하지 않는다.
- actor는 usr_ 접두사와 무작위 128-bit ID이며 로그인 이름과 별개다. legacy bootstrap actor를 새 사람으로 치환하지 않는다.
- 계정은 설정 대기/활성/차단을 구분한다. password verifier 없는 계정은 로그인 가능 owner로 세지 않는다.
  마지막 로그인 가능한 owner를 제거·강등·차단하거나 원격 reset으로 설정 대기로 만들 수 없다.
- owner만 계정 생성·이름/role 변경·차단·타인 reset을 한다. 모든 활성 역할은 본인 password/PAT를 관리한다.
  기존 업무 역할과 자기승인은 유지한다. 신규 계정 권한에 기존 owner/admin 전체 허용 분기를 재사용하지 않는다.
- role/password 변경·차단·reset은 해당 사람의 session/PAT/미사용 설정 코드를 모두 무효화한다.
  이름 변경만으로 credential을 회수하지 않는다. logout은 해당 session, PAT 삭제는 해당 PAT만 회수한다.
- Job 생성/승인·계정 변경·credential 발급의 canonical commit은 현재 계정 상태/permission revision/
  credential revision/human epoch를 같은 application transaction 경계에서 재검증한다.
  회수 commit이 앞서면 거절, 업무 효과 commit이 앞서면 보존한다. 실행 중 Agent 작업은 취소하지 않는다.
- KDF 결과 자체는 발급 권한이 아니다. KDF 중 reset/role 변경·요청 취소/기한 경과 시 session/PAT를 발급하지 않는다.
- record revision은 모든 실제 metadata/credential 변경에 증가하고 credential revision은 role/password/reset/차단에만 증가한다.
  같은 role/표시 이름·이미 차단된 계정의 중복 차단은 revision을 바꾸지 않는다. 실패/overflow는 객체 상태도 보존한다.
  owner 수는 같은 transaction에서 활성+유효 profile verifier 계정만 세며 설정 대기 owner는 포함하지 않는다.

## 입력·비밀번호·secret

- 로그인 이름은 3–64자의 ASCII 영문/숫자/점/밑줄/하이픈, 첫 글자는 영문/숫자다.
  ASCII 소문자로 canonicalize하여 고유성을 검사한다. 앞뒤 공백은 자동 제거하지 않는다.
- 표시 이름은 1–120 Unicode code point, 공백만인 이름·제어 문자 금지. HTML은 textContent/escaping으로 표시한다.
  account ID는 불변이고 표시 이름 변경은 owner 권한이다.
- 새 비밀번호는 NFC 정규화 후 15–128 Unicode code point다. raw 입력은 2,048 UTF-8 bytes,
  정규화 결과는 최대 512 bytes로 제한하고 잘라내거나 trim하지 않는다.
  공백·출력 가능한 Unicode를 허용하며 문자 종류 혼합이나 임의 정기 변경을 강요하지 않는다.
  알려진 취약값·계정/제품의 예상 비밀번호는 local blocklist로 거절한다.
  유출 비밀번호 전체 corpus 검사나 NIST 인증 준수 완료를 주장하지 않는다.
  [NIST password guidance](https://pages.nist.gov/800-63-4/sp800-63b.html#passwordver)
- 정규화는 모든 입력 경계에서 같은 adapter를 사용하고 domain은 정규화된 입력의 순수 길이/상태 규칙을 소유한다.
  login도 같은 정규화를 사용하며 비밀번호를 log/error/Debug/audit/일반 config에 넣지 않는다.
- password 변경·owner 계정 관리·PAT 발급은 현재 password를 같은 요청에서 재검증한다.
  별도 fresh-auth TTL이나 재사용 grant는 만들지 않는다. logout/본인 PAT 회수는 현 credential로 가능하다.
- PAT label은 선택 입력이며 지정하면 UTF-8 최대256 bytes의 비공백 text다. 제어 문자는 거절하고 trim/정규화로 바꾸지 않는다.
  발급 후 label은 불변이고 session/setup/reset에는 넣지 않는다. metadata는 label·ID·created/expires·서버 판정 active만 반환하며 proof/hash/binding은 제외한다.
- 새 password는 Argon2id v19, salt 16 random bytes, output 32 bytes,
  m=19,456KiB/t=2/p=1의 첫 verifier profile로 저장한다.
  PHC의 algorithm/version/cost/salt/output 크기를 먼저 검사하고 해당 profile 밖이면 KDF 전에 거절한다.
  library verify가 저장된 PHC cost를 사용하므로 instance default만으로 resource limit을 보장하지 않는다.
  Domain은 profile ID와 고정 길이 salt/hash component만 검증하며 PHC codec은 adapter가 소유한다.
  저장 형식도 이 semantic value로 명시 변환하고, 다른 profile/크기는 crypto 실행 전에 거절한다.
  [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html),
  [RustCrypto API](https://docs.rs/argon2/0.6.0/argon2/)
- token/session/reset secret은 각각 목적을 구분하는 256 random bits다. 서버에는 목적·owner·revision·expiry·hash만 저장한다.
  raw PAT/설정 코드는 발급 시 한 번만 응답한다. 코드 입력은 HTTPS POST 또는 local TTY/stdin이며 URL에는 넣지 않는다.
  adapter encoding은 fws_/fpat_/fsetup_/freset_ 접두사와 64자 lowercase hex다.
  SHA-256 lookup은 고정 human-credential domain separator·명시 목적·전체 raw 값을 함께 묶는다.
  다른 목적·공백/대문자/길이가 잘못된 encoding은 lookup 전에 거절한다.
  현재 crypto primitive는 PHC 문자열을 입력받지 않으며 고정 cost와 validated salt/hash component만 사용한다.
  향후 PHC 경로를 추가해도 위의 algorithm/version/cost/size 사전 검증을 생략하지 않는다.
- hash/KDF 라이브러리는 adapter에만 둔다. 첫 후보 argon2 0.6.0은 MIT OR Apache-2.0, MSRV 1.85다.
  제품 license AGPL-3.0-only 및 Domain/Application dependency 방향은 변경하지 않는다.

## HTTP·cookie·CSRF

- 개인 인증이 활성화된 Controller는 bootstrap --external-url의 단일 canonical origin을 사용한다.
  origin이 없거나 wildcard/credential/query/fragment를 포함하면 개인 인증 시작을 fail-closed한다.
  기존 옵션을 쓰며 X-Forwarded-*나 요청 Host를 임의의 trusted origin으로 채택하지 않는다.
- Admin과 API는 같은 origin이다. 임의 CORS credential 공유·다른 origin으로 CSRF/비밀번호 전달을 허용하지 않는다.
- HTTPS session cookie는 __Host-fleet_session, Path=/, Secure, HttpOnly, SameSite=Strict, host-only다.
  HTTP lab에서는 명시적 insecure warning/audit 아래 fleet_session 이름을 사용한다. HTTP 예외 flag는 추가하지 않는다.
- login/설정-code claim은 JSON Content-Type·정확한 Origin을 요구한다. 이후 cookie mutation은
  Origin과 session-bound CSRF header를 함께 검증한다. 없는/null/다른 origin과 duplicate credential header는 거절한다.
- CSRF 값은 별도 목적의 HMAC으로 해당 session에 묶어 유도할 수 있다. session 검증 뒤만 반환하고
  browser 메모리에서만 사용한다. GET은 credential을 만들거나 변경하지 않는다.
  [OWASP CSRF](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- 현재 adapter는 별도 목적 메시지 `fleet-human-session-csrf-v1`과 session secret으로 HMAC-SHA256을 계산하고
  constant-time 비교한다. lock 기준 `hmac` 0.12.1·canonical origin parser `url` 2.5.8은 MIT OR Apache-2.0이다.
  CSRF derivation은 추가 DB secret이나 runtime 설정 조회를 만들지 않는다.
- cookie와 Authorization이 동시에 오면 ambiguous_authentication으로 거절한다. 잘못된 방식에서 다른 actor로 fallback하지 않는다.
  개인 mode에서는 legacy token을 받지 않는다. Agent enrollment/identity proof는 이 사람 인증 경계와 별개다.
- auth/계정 응답은 Cache-Control: no-store. password/hash/token/오류 원문·URL secret을 HTML snapshot에 남기지 않는다.
  session secret은 JS에 응답하지 않고, 로그인 성공 시 새 cookie를 발급해 fixation을 막는다.

## 예정 endpoint와 권한

모든 body는 알려진 field만 허용한다. actor/role 주장으로 인증 결과를 덮어쓰지 않는다.
사용자 role은 owner 전용 계정 관리 입력일 때만 검증된 변경 대상으로 취급한다.
아래 credential 발급 응답 외에는 raw secret을 반환하지 않는다.

| Method / path | 인증·권한 / 동작 | 정상 |
| --- | --- | --- |
| GET /api/auth/status | public; legacy/personal·local 설정 필요 여부만, 개인 정보 없음 | 200 |
| POST /api/auth/login | username/password·Origin, generic 실패·rate/KDF 제한; 새 session cookie와 사용자/CSRF | 200 |
| GET /api/auth/session | 현재 session 또는 PAT의 사람 ID/이름/role; cookie만 CSRF 제공 | 200 |
| POST /api/auth/logout | cookie+CSRF, 현 session 회수와 cookie 만료; PAT를 web logout으로 전환하지 않음 | 204 |
| POST /api/auth/setup | 일회성 code/new_password·Origin; 설정/reset claim, 이전 code 소비, 자동 로그인하지 않음 | 204 |
| POST /api/auth/password | 현재 사용자·current_password/new_password; 전체 회수 후 재로그인 | 204 |
| GET /api/auth/tokens | 본인 PAT metadata만, secret/hash 없음 | 200 |
| POST /api/auth/tokens | 본인+current_password; label·30일 PAT를 한 번만 표시 | 201 |
| DELETE /api/auth/tokens/{id} | 본인 소유만; 다른 사람/없는 token ID는 동일 not_found | 204 |
| GET /api/admin/users, /api/admin/users/{id} | owner; bounded metadata, verifier/코드/credential 없음 | 200 |
| POST /api/admin/users | owner+current_password; username/display_name/role, 설정 대기 계정·15분 코드 | 201 |
| PATCH /api/admin/users/{id} | owner+current_password; display_name/role 또는 차단, owner guard·회수 | 200 |
| POST /api/admin/users/{id}/password-reset | owner+current_password; prior password/credential 무효화·설정 대기·15분 코드. 차단 계정도 새 설정으로 복구 | 201 |

로그아웃은 유효한 web session만 처리하고 PAT는 거절한다. 만료/회수된 caller는401이며 cookie는 interface가 지운다.
PAT 회수는 본인 것만 가능하고 자기 요청에 사용한 PAT도 회수할 수 있다. 삭제 뒤 같은 ID는 다른/없는 ID처럼404다.
ownership/purpose 조건은 semantic decode 전에 적용해 손상된 타인의 row도 동일 not_found로 처리한다.
metadata는 lookahead 행까지 ownership/order/bounds를 확인하며 GET은 정리·발급·만료 연장을 하지 않는다.

계정 hard delete·다른 사용자의 raw credential 발급/조회·원격 break-glass는 없다.
POST/DELETE 요청이 서버에 반영됐는지 불명일 때 다른 actor로 재전송하지 않는다.
로그인 상태 변경 중 accepted Job은 유지하고 재인증 후 권한 있는 조회로 확인한다.

## 오류·bounded 자원

| 경계 | 선택값·판정 |
| --- | --- |
| HTTP auth body | JSON 최대 16KiB, password raw/정규화 상한을 KDF 전에 검사 |
| KDF | 기본 1 worker, 최대 2 worker만 허용, 대기 1건. worker scratch 최대 38MiB(2×19MiB), 대기에는 password 상한만 보관 |
| deadline/초과 | 총 인증 처리 deadline 30초. 한도 초과는 429, worker/store 일시 실패/기한은 503. 늦은 crypto 결과로 발급하지 않음 |
| rate limiter | canonical username별 실패 5회/300초. 없는/차단 계정도 같은 규칙·dummy KDF·generic 401. 후보 key 512개 상한과 global KDF cap; full은 429. 영구 계정 lockout 없음 |
| session quota | 사용자당 8, 전체 lookup row 4,096. 초과 시 429/session_limit; 조용한 eviction/무제한 발급 없음 |
| PAT quota | 사용자당 16, 전체 lookup row 8,192. 초과 시 429/token_limit. 현 role 이상 권한 없음 |
| metadata paging | 기본 25·최대 100행, opaque cursor·표준 error·secret 없는 DTO |
| cleanup | startup 및 발급/회수 use case에서 만료/회수된 lookup row(이전 human epoch·credential revision 포함) 최대 128개/종류/호출. per-user 활성 quota는 현재 유효 binding만, global lookup cap은 정리 후 남은 전체 row 기준. 주기 worker 없음. account/audit 삭제 금지 |
| payload 오류 | 400 invalid_request, 413 request_too_large; missing 필수 auth endpoint의 404는 client hard error |
| 인증/권한 | 401 unauthorized는 없는/차단 계정·틀린 password·만료/회수에 공통. 403 forbidden은 인증 후 permission 또는 CSRF 실패. 내부 SQL/hash/원문 오류 없음 |
| 경합/상태 | 409 user_exists/last_owner/state_conflict. stale 권한·회수 credential은 mutation 전에 401/403으로 거절 |

유효한 로그인이라도 quota가 가득 차면 새 credential/audit 없이 429로 거절한다. 이때 bounded lookup 정리는 commit해
과대 snapshot의 정리 진행을 보장할 수 있다. 한 요청의 UTC 관측이 뒤로 가거나 monotonic deadline/cancellation이 끝나면 발급을 거절한다.

기술값 선택 근거는 로컬 [crypto 비용](../../../../target/iam-rehearsal/kdf-cost-sequential.json),
[병렬 비용/RSS](../../../../target/iam-rehearsal/kdf-parallel-sequential.json),
[lookup layout](../../../../target/iam-rehearsal/credential-limits-prototype.json)다.
19/32/64MiB 후보에서 보안 하한을 유지하는 19MiB를 선택하고, 작은 interactive 범위에서 기본 worker/queue를 1/1로 제한한다.
2 worker는 RSS 약 48MB·scratch 38MiB로 측정됐으나 wall-time 편차가 크므로 throughput/SLA를 약속하지 않는다.
4,096 session+8,192 PAT의 독립 SQLite layout은 약 7.1MB, 128행 정리를 기록했다.
이는 Python SQLite fixture이며 actual bundled store/schema·quota/cleanup 원자성은 후속 repository 시험이 필수다.
각 사용자 한도는 이 global budget 안에서 여러 로그인/CLI 용도를 허용하는 보수적 상한이다.

위 deadline은 처리 권한의 종료 조건이며 KDF native 연산을 강제 취소하는 보장은 아니다.
worker는 crypto만 수행하고 DB write 권한이 없다. 취소/기한 경과 reply는 버리고 종료 시 모든 thread를 join한다.
구현 worker의 완료되었지만 아직 소비하지 않은 reply도 workers+1 admission 한도에 포함한다.
대기 queue 자체는 1개 slot이며, idle worker가 아직 dequeue하지 않은 순간에도 초과 요청을 보수적으로 거절할 수 있다.
실제 bounded adapter의 [재측정](../../../../target/iam-rehearsal/password-adapter-measurement.json)은
1 worker·8 samples/종류에서 hash/valid/wrong/dummy 중앙값 약0.50–0.52초,
test child RSS 최고31,883,264 bytes를 기록했다. debug 빌드의 격리 CPU/channel 비용이며
Store/TLS/Agent 부하 인수나 전체 Fleet 성능 SLA를 뜻하지 않는다.
Agent heartbeat/dispatch/read deadline 유지와 실제 HTTPS 인수는 0016/0017에서 검사한다.
실제 환경에서 안전 guard가 실패하면 보안 하한을 낮추지 않고 해당 task를 미완료로 남긴다.

## local 전환·복구·restore

- local 명령은 controller 중지·OS data-dir 소유권·exclusive lock을 확인한다. password는 TTY/stdin으로 받는다.
  새 Controller는 같은 lock을 생명주기 동안 보유한다. 구 binary 종료 절차를 upgrade 문서에서 분리한다.
  Unix data-dir은 effective OS user 소유의 실제 directory·0700, `.controller.lock`은 같은 owner의
  regular file·0600·link count 1이어야 한다. 새 경로만 private mode로 생성하고 기존 권한은 자동 변경하지 않는다.
  directory/lock의 마지막 symlink·lock hardlink/특수 파일을 거절하며 경합은 대기 없이 실패한다.
  lease는 종료 시 명시적으로 unlock하고 lock file은 삭제/잘라내지 않는다. 이는 참여하는 process 사이의
  advisory lock이며 같은 OS user의 악성 process나 lock을 모르는 구 binary의 종료 증거를 대신하지 않는다.
- local setup command는 `fleet controller admin init-owner --data-dir <dir> --username <name>`이다.
  `--display-name`은 metadata이며 역할은 owner로 고정한다. 기본 controlling TTY에서 숨김 입력·동일 재입력을 받는다.
  `--password-stdin`을 명시하면 UTF-8 비밀번호 한 줄을 EOF까지 받고 끝의 LF/CRLF 한 개만 제거한다.
  공백은 보존하며 raw2048bytes를 넘거나 control/여러 line/잘못된 UTF-8이면 거절한다. argv/env/password-file 입력은 없다.
  TTY는 취소(Ctrl-C/D/Z)·오류·성공 시 입력 queue를 비우고 mode를 복원한다. 잘못된/초과 입력도
  line ending까지 메모리를 늘리지 않고 버려 남은 paste가 echo 상태로 넘어가지 않게 한다.
  복원은 output drain을 기다리지 않는다. Darwin canonical 복귀의 pending-input 표시는 복원 후 flush로 지운다
  ([XNU tty implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/tty.c)).
  crypto request의 고정 deadline은 interactive 입력이 끝난 뒤 시작하며 CPU work·commit까지 갱신하지 않는다.
- custom SQLite를 쓰면 `controller init`, `controller admin init-owner`/`recover-owner`, `controller start`에 같은 `--db`를 전달한다.
  local init/owner는 Postgres runtime을 열지 않는다. 새 data-dir의 owner 명령은 필요한 DB/signing identity도 준비한다.
  personal/restored mode의 init은 기존 signing identity가 없으면 backup 복구를 요구하고 새 Agent trust를 만들지 않는다.
- 첫 owner의 verifier/불변 ID·개인 mode·구 shared token 종료를 한 transaction으로 commit한다.
  crash 후에는 전환 전 상태 또는 유효 owner+legacy 거절 상태만 허용한다.
- local recovery command는 `fleet controller admin recover-owner --data-dir <dir> --username <기존 login 이름>`이다.
  TTY/`--password-stdin`은 init-owner와 같은 입력 계약을 사용한다. 같은 OS user로 Controller를 멈춘 뒤 실행하고 완료 후 정상 시작한다.
  canonical login 이름으로 저장소의 불변 user ID를 찾고 선택한 사람의 새 verifier/owner 활성 상태를 원자적으로 설정한다.
  해당 사람의 기존 session/PAT/미사용 코드만 회수하며 다른 사람·human epoch·Agent trust는 보존한다.
  없는 사용자/DB·Legacy mode에서 계정을 새로 만들어 복구한 것으로 처리하지 않는다.
  원 signing pair는 비밀번호 입력 전에 의미 검증하고, 누락/불일치는 원 key backup 복구를 요구한다.
  새 token/default password를 원격 endpoint로 생성하거나 과거 actor를 치환하지 않는다.
- restore는 검증한 임시 DB에서 별도 human credential epoch를 바꾸고 session/PAT/미사용 설정 코드를 무효화한 뒤 교체한다.
  계정/password verifier·backup 내 Job/Audit/Agent identity는 보존한다. 기존 Agent delivery epoch 회전은 별도로 유지한다.
  dry-run은 양쪽 epoch·DB·파일을 바꾸지 않는다. 실패 target 보존·쓰기 중단점·backup 이후 손실 구간을 rehearsal한다.
  검사 scratch는 새 0600 파일에만 만들고 종료 시 제거한다. backup은 source를 auto-migrate하지 않으며,
  실제 integrity/schema·manifest 일치·원 signing pair를 확인한다. 모든 writer를 먼저 중지해야 한다.
  archive output은 private/noclobber이며 Debug/error에 content나 private-key path를 넣지 않는다.
  actual restore는 target과 같은 filesystem의 새 private staging만 사용하고 두 epoch 회전 후 파일/디렉터리를 sync한다.
  existing target은 atomic directory exchange, absent target은 no-replace rename이며 미지원 FS는 fail-closed다.
  교체 성공 후 sync/cleanup failure는 설치 전 실패와 구분해 경고하고 필요하면 rollback staging을 보존한다.
- 개인 계정이 없던 옛 backup을 복구해도 legacy token을 다시 활성화하지 않는다.
  사람 인증은 local 설정 필요 상태로 두고 OS 권한을 확인한 first-owner/recovery 명령으로만 복구한다.
  legacy row/actor 이력은 보존하며 Agent trust/identity와 별도로 처리한다.

## 구현 진입·인수 연결

domain: 불변 ID/role/state/expiry·입력 순수 규칙. application: 인증·계정·회수·전환 use case와 port.
store: migration/원자 commit·epoch/quota/정리. adapter: KDF/token/정규화·HTTP/CLI·bootstrap/worker.
DTO/persistence/domain/view model을 별도로 변환하고 runtime env/config를 재조회하지 않는다.

IAM-AC-01은 actor/과거 이력·self approval, AC-02는 owner/self·직접 API/CSRF, AC-03은 고정 기한·회수/commit 순서,
AC-04는 전환/restore/local recovery·redaction/bounded 자원을 판정한다.
먼저 정상 login+보호 API/발급이 성공해야 이후 거절 시험이 유효하다. 미구현 404·always-deny로 통과하지 않는다.
현재 측정/명세는 이 기능 인수를 대체하지 않는다. 구현과 함께 API/OpenAPI/Admin schema·security/storage/retention·ENKO README를 갱신한다.
