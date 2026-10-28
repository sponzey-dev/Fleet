# IAM-001 — 단일 조직의 로컬 관리자 계정

정책 기준일: 2026-10-27. 상태: 단일 조직 로컬 계정 기능 인수 검증됨·미배포.
목적은 사람마다 로그인해 기존 권한으로 작업하고 요청·승인의 actor를 구분하며 접근을 회수하는 것이다.

## 목표와 확정 범위

[GOAL-06](../../../product/overview.md), [P-04](../../../plans/plan.md#p-04),
[D-006](../../../decisions/decisions.md#d-006)/[D-012](../../../decisions/decisions.md#d-012)를 따른다.
검토 중 확정한 기한·권한·전환/복구 정책은 [D-013](../../../decisions/decisions.md#d-013)을 따른다.
사용자가 단일 조직의 개인별 계정만, Fleet 자체 아이디·비밀번호를 확정했다.
실행 순서와 완료 근거는 [보관 개발 계획](../../../../.tasks/phase012/plan.md)과 [완료 목록](../../../../.tasks/phase012/task-list.md)이 소유한다.
I-00의 위임 기술값과 예정 HTTP/전이 계약은 [인증 구현 contract](IAM-001-auth-contract.md)를 따른다.

HTTP는 legacy mode의 bootstrap token과 personal mode의 cookie/PAT를 구분한다.
Domain/Application 계정·인증·고정 만료·회수, identity repository, local 첫 owner·복구와
restore credential 무효화와 HTTP 로그인·session/logout·설정 claim·cookie/CSRF 기반은 구현되어 있다.
owner 계정 목록/상세 metadata와 생성/변경/reset도 연결되어 있으며 본인 password 변경/PAT 발급·조회·회수도 연결되어 있다. Command·DriftCheck·직접/카탈로그 Runbook 생성·승인/거절·명시적 취소·수동 만료·remediation 승인 요청/Job 생성의 원자 업무 transaction도 최신 권한을 재검증한다.
개인 Admin 로그인·owner/self credential 화면과 인증 generation 연결도 구현됐다. 개인 token CLI 입력/profile도 연결됐으며 실제 두 사용자 HTTPS browser/API/CLI·Linux Agent 작업/회수·복구·인증 부하 인수를 검증했다.
세부 현재 지원은 [기능표](../../../../docs/feature-matrix.md)와 실제 source/test를 함께 확인한다.
IAM-AC-01–04의 실제 증거는 현재 task 목록이 소유한다. 이 인수는 production 용량·OIDC·project 격리·출시 인수로 확대하지 않는다.

- 계정 생성·목록·역할 변경·비활성화, 본인 비밀번호 변경·관리자 reset, 첫 owner 설정과 접근 복구.
- 웹 로그인/logout/session과 개인 CLI/API token. 기존 owner/admin/operator/viewer 업무 권한 유지.
- 계정 변경·요청·승인의 authenticated actor와 감사, 과거 이력과 기존 Agent identity 보존.
- OIDC/MFA/공개 가입/메일 전달, project 격리, real SecretProvider는 범위 밖이다.

## 사용자·state·보안 경계

1. 이름과 별개인 불변 account/actor ID를 사용한다. 이름·역할 변경과 비활성화가 Job/Approval/Audit의
   과거 actor를 바꾸지 않는다. 실제 actor는 인증 결과에서 결정하며 request body의 actor/role을 신뢰하지 않는다.
2. account 활성/비활성, credential 발급·만료·회수, bootstrap/reset 일회성 전이를 명시한다.
   일반 계정 삭제로 감사 참조를 끊지 않는다. 마지막 활성 owner 제거는 원자적 guard로 막고 복구 경로를 제공한다.
3. web session과 개인 token은 종류·owner·expiry·revocation이 구분된다.
   token은 한 번만 표시하고 서버에는 hash만 저장한다. 비밀번호는 단순 token hash와 분리된
   password-hashing adapter에서 검증하며 raw password·복구 가능한 암호문을 일반 DB/config에 저장하지 않는다.
4. 회수 이후 새 인증 요청은 거절한다. Job 생성·승인·계정 변경·credential 발급의 effect commit은
   최신 account/role/credential revision을 같은 use-case transaction 경계에서 재검증한다.
   회수가 먼저 commit되면 오래된 요청은 거절하고, 업무 효과가 먼저 commit되면 보존한다.
   KDF 검증 중 password가 변경돼도 이전 검증으로 새 session을 발급하지 않는다.
   이미 승인된 실행 중 Job·Agent session은 취소하거나 이력을 삭제하지 않는다.
5. 계정 생성·타인 password reset·role 변경·차단은 owner만 한다. 각 활성 사용자는 본인 password/PAT를
   관리한다. admin의 기존 업무 권한과 자기승인 허용은 유지한다. owner/admin 일괄 허용 분기가
   신규 계정 관리 권한까지 허용하지 않는지 직접 API 부정 시험으로 검증한다.
6. 기존 공용token은 비밀번호로 변환하지 않는다. OS data-dir 소유권·exclusive lock을 확인한 local
   명령에서 첫 owner 활성화와 구 token 종료를 원자적으로 전환한다. 실패/crash는 전환 전 또는 전환 후
   안전 상태여야 한다. 접근 복구는 local 명령만 허용한다. 실제 restore 시 사람 credential epoch를 새로
   만들고 기존 session/PAT/미사용 설정·reset 코드를 모두 거절한다. 계정/password verifier·backup 내
   작업 이력·Agent identity는 보존하고 기존 Agent delivery epoch 회전은 별도 계약으로 유지한다.
7. web session은 JS가 secret을 읽지 않는 cookie 방식과 서버 검증·CSRF 방어를 설계 기준으로 둔다.
   브라우저 장기 storage/URL/HTML snapshot에 secret을 넣지 않는다. 개인 CLI credential profile은
   별도 owner/파일권한을 유지하며 password를 보관하지 않는다.
8. HTTPS가 제품 인증의 전제다. 기존 HTTP lab 허용과 warning/audit 정책은 유지하며,
   HTTP fixture 결과를 production transport 인수로 바꾸지 않는다.

### 확정 정책과 기술값 선택

2026-10-27 검토 대화의 세 답변으로 다음 기준을 확정했다. 전부 예정 contract이며 구현 완료가 아니다.

| 정책 | 판정 기준 |
| --- | --- |
| 웹 session | 발급 시각부터 고정 8시간. 별도 idle expiry 없음. 자동 poll/재접속으로 연장하지 않음 |
| 개인 CLI/API token | 발급부터 30일. 현재 사용자에 귀속되며 현재 role 권한을 넘을 수 없음 |
| 일회성 설정/reset 코드 | 발급부터 15분, 단일 사용. 사용자 입력으로 HTTPS POST 또는 local TTY/stdin에 전달. URL query/fragment에 넣지 않으며 이메일/링크 발송 기능은 추가하지 않음 |
| 만료 | 서버 UTC로 now >= expires_at이면 거절. 직전·동일·직후 및 재시작 후를 검사 |
| 관리 권한 | owner만 타인 계정을 생성/reset/role 변경/차단. 각 활성 사용자는 본인 password/PAT 관리. 기존 업무 권한·자기승인 유지 |
| 회수 | disable/role/password 변경은 해당 사람의 모든 session/PAT/미사용 설정·reset 코드 무효화. logout은 해당 session, 개별 PAT 회수는 해당 token. 타인·Agent·commit한 Job은 유지 |
| 전환/복구/restore | 위 local-only·last-owner guard·원자적 cutover·별도 human epoch 규칙 적용. dry-run은 무변경. rollback은 쓰기 중단점과 backup 이후 손실 구간을 명시 |

POL-05의 KDF/library·cost·worker/queue/입력/발급 quota·throttle·정리 한도는 사용자가 보안 하한과 격리
실측에 따른 선택을 위임했다. I-00에서 공식 권고와 대상 hardware/OS·단위·근거·초과 거절을 기록한다.
password 조건/Unicode/상한·fresh reauthentication의 세부 contract와 경계 시험도 이 단계에서 고정한다.
전체 Fleet latency SLA나 근거 없는 최적화 수치를 추가하지 않는다. KDF/queue 포화 때도 기존
heartbeat/Job deadline을 지키고 중복 실행·무제한 발급·무제한 메모리가 없어야 한다.
만료/회수 lookup row는 bounded 정리하되 account와 append-only audit를 삭제하지 않는다.

### 검토한 외부 보안 근거

아래는 안전한 구현 선택의 근거이며 사용자 정책/제품 전체 인증 완성의 증거가 아니다.
구현 시 선택 library/지원 API·license와 대상 기기 측정으로 다시 확인한다.

- 비밀번호 저장: adaptive password hashing과 사용자별 salt를 적용하고 빠른 token digest를 재사용하지 않는다.
  Argon2id를 우선 검토하되 cost와 worker 한도는 POL-05에서 측정·확정한다.
  [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- 웹 session: HTTPS의 Secure, HttpOnly, 명시적 SameSite와 서버 logout·만료 처리를 검토한다.
  [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).
- 로그인: 없는/비활성 계정과 틀린 비밀번호의 오류 표현을 통일하고 과도한 시도를 제한한다.
  [OWASP Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
- cookie mutation은 서버 CSRF 검증을 포함하고 SameSite 하나에만 의존하지 않는다.
  [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

<a id="acceptance"></a>
## 인수 기준

모든 사례는 예정 시험이다. 실제 expected/actual·source/environment·증거 위치를 남긴 뒤에만 PASS로 바꾼다.

| ID | 입력·행동·환경 | 합격 / 불합격 판정 | 검증 |
| --- | --- | --- | --- |
| IAM-AC-01 | 격리 조직의 A가 harmless Command/catalog Runbook 요청, 권한 있는 B가 승인. 이후 이름·role 변경/차단, 기존 자기승인도 수행 | 서버 결정 A/B 불변 ID와 과거 이력·target/signature/provenance 유지. 자기승인에 새 금지 조건을 넣지 않음. actor 위조/치환·승인 우회면 실패 | domain/application/store atomic tests, 두 browser context·직접 API·Linux Agent 결과 |
| IAM-AC-02 | 유효한 로그인·보호 API 성공을 먼저 확인. 4역할로 모든 관리 route·본인 credential 관리, spoof·admin의 타인 계정 관리, login/reset/logout CSRF·fixation·없는/비활성 계정 login을 직접 호출 | owner-only 타인 관리와 본인 관리 matrix만 허용. 거절 시 효과 없음. 404/always-deny로 성공 전제를 대체하거나 UI 검사만 있으면 실패. secret/계정 존재 노출 없음 | route contract·CSRF·동일 origin·rate/입력 한도 fixtures, 실제 API/CLI/browser. auth 필수 404는 hard error |
| IAM-AC-03 | 8시간/30일/15분 직전·동일·직후, poll 연장 여부, 유효 cookie/PAT 성공→logout/회수→replay, disable/role/password 변경, 승인·발급·회수/KDF 경합·재시작 | 확정 기한·회수 범위·commit 순서를 만족. 옛 credential로 새 효과 commit 없음. 타인/Agent/이미 commit한 Job은 유지. stale role·회수 credential 부활·무한 observer면 실패 | clock·transaction race/restart tests, delayed UI A→B 전환, 응답 불명 Job 생성 중 logout 후 자동 재제출 없음, 실제 CLI 재사용 |
| IAM-AC-04 | empty/schema27 DB의 local owner 전환, cutover crash·last-owner 경합·코드 재사용/만료·local 복구·backup/restore/dry-run·rollback, sentinel scan와 포화 KDF 부하 | 계정/기존 actor·backup 내 Job/Audit/Agent 보존, 원자적 구 token 종료. restore 후 옛 사람 credential/코드 거절·dry-run 무변경. 보안 하한·선택한 resource cap과 기존 runtime deadline 유지. 누출/lockout/손실/무한 자원이면 실패 | migration fixtures·임시 CLI profile/data-dir, PG 변경 시 실DB repository, 실제 HTTPS 두 사용자/복구·동일 부하. 예정 시험과 과거 PASS 구분 |

account/password/session/PAT의 기대 전이·오류·expiry·permission fixture는 POL 결정 후 구체화한다.
실제 두 사용자 검증은 테스트 account만 사용하고 필요한 TLS·시험서버의 변경은 실행 시 별도 영향 조건을 따른다.
시험 후 발급 credential·서비스·tunnel·browser session을 정리하고 기존 DB·identity·복구점은 보존한다.

## 구현 소유권과 계약 동기화

Domain은 identity·state·permission, Application은 account/auth/revoke/recovery use case와 port,
Store는 persistence/migration, Controller/CLI는 transport/bootstrap/composition, Admin은 view/effect를 소유한다.
hash library를 Domain에 넣거나 Application이 SQL/env/cookie type을 직접 사용하지 않는다.
Agent SessionRegistry와 human session 저장소를 합치지 않는다.

API/security/storage/feature matrix/README EN·KO와 client schema/test는 실제 구현 변경과 동기화한다.
본 문서만으로 새 endpoint·schema 번호·명령이 현재 지원된다고 문서화하지 않는다.
