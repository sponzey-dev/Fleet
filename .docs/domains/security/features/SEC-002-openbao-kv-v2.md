# SEC-002 — OpenBao KV v2 비밀 템플릿 실행

기준일: 2026-10-28. 상태: 범위·정책 확정, 실제 provider 미구현·인수 미실행.
[GOAL-06](../../../product/overview.md), [P-05](../../../plans/plan.md#p-05),
[D-007/D-014](../../../decisions/decisions.md#d-007)의 단일 provider 범위다.
검토에서 확정한 미리보기/검사·token 회수 실패 정책은 [D-015](../../../decisions/decisions.md#d-015)를 따른다.
현재 사실은 source/test와 [기능표](../../../../docs/feature-matrix.md)가 우선하며,
구현 순서는 [개발 계획](../../../../.tasks/plan.md)이 소유한다.

## 사용자 결과와 범위

운영자가 실제 비밀값 대신 기존 `secret://...` 참조를 포함한 Runbook을 요청하고 승인받는다.
실행 Agent가 자신에게 허용된 OpenBao 값만 조회해 `file.template`의 목적 파일에 적용한다.
Controller/Git에는 참조와 비밀 body 없는 결과만 남는다.

- 첫 backend: OpenBao KV v2. Vault 지원 보장·다중 backend·provider plugin은 제외한다.
- 조회 주체: Agent. Controller는 비밀 조회·중계·보관 서버가 아니다.
- 인증: Agent별 제한된 AppRole, 시작 시 한 번 읽는 전용 private credential 파일과 공개 CA.
  작업 준비별 단기 service token을 메모리에서만 사용한다. 공용 관리자/root token을 사용하지 않는다.
- 교체: KV 값은 다음 새 실행의 조회부터 반영한다. 접속정보 파일 변경은 명시적 Agent 재시작 때 반영한다.
  이미 적용한 파일의 자동 재적용/원복·작업 재실행·동적 DB secret lease 관리는 제외한다.
- 실제 secret 목적 파일은 의도된 보관 경계다. 그 파일을 읽을 수 있는 host 운영자를 DLP로 통제한다는 기능은 아니다.
- dryRun/checkMode에서는 참조 형식·로컬 mapping만 확인하고 provider 인증/조회/회수 요청을 하지 않는다.
  생략되는 template는 실제 비밀값 없이 symbolic plan으로 skip한다. checkMode의 기존 저위험 검사는 유지한다.
  로컬 `fleet apply`는 기존 validation-only이며 provider 설정·credential 파일도 읽지 않는다.

## 소유권과 보안 계약

1. Runbook은 기존 SecretRef 문법만 사용한다. Agent의 bootstrap mapping이 정확한 ref를
   KV mount/path/field에 연결하고 provider ACL이 다시 제한한다. 임의 URL·auth role·CA·mount 변경은 Job 입력으로 받지 않는다.
   unknown ref는 provider에 요청하기 전에 거절한다. 새 query/fragment 문법을 만들지 않는다.
2. 같은 KV path는 작업 준비에서 한 번 읽은 값/버전을 재사용한다. 작업이 끝나면 cache를 폐기하고 다음 Job은 새로 읽는다.
   여러 KV path의 전역 snapshot이나 provider transaction은 보장하지 않는다. 첫 버전은 문자열 field만 지원한다.
3. 승인·서명·target/expiry/nonce와 durable execution admission/start intent를 확인한 뒤 조회한다.
   전체 참조 조회/렌더 준비가 성공하기 전 host effect를 시작하지 않는다. 중복 작업은 새 token/조회/파일 적용을 반복하지 않는다.
4. 설정·credential/CA 파일은 bootstrap에서만 검증·읽는다. credential은 owned0600 regular file이며 link/special/과대 파일을 거절한다.
   원문을 일반 config/DB/wire/args/URL/환경 dump에 넣지 않는다. runtime 설정 재조회·웹 편집기는 없다.
5. provider는 HTTPS·hostname/공개 CA 검증, redirect 거절과 고정 origin을 사용한다.
   response bytes·참조 수·문자열/최종 rendered bytes·총 준비 메모리·최종 metadata/report 크기·동시 요청·준비 총기한·token TTL/cleanup 한도는 실행 전 S-00에서 단위/근거와 함께 고정한다.
   초과는 typed safe 오류이며 보안 하한을 낮추거나 무제한 기본값을 사용하지 않는다.
6. AppRole 응답 불명은 자동 재발급하지 않는다. 유한 server token TTL·최소 read 정책이 시험/provisioning 조건이다.
   token은 준비 수명만 갖고 **조회 완료 후 host 적용 전에** bounded revoke-self 성공을 확인한다.
   실패/응답 불명/기한 초과는 준비 실패이며 파일을 적용하지 않는다. 오류/취소 중에도 owner가 cleanup을 시도한다.
   회수 실패·SIGKILL은 원격 회수를 성공으로 가장하지 않으며 유한 server TTL에 의존하는 한계를 기록한다.
   SecretID 변경/만료/회수와 이미 발급된 token의 기한/회수는 각각 검증한다.
   성공적으로 회수한 뒤의 ready snapshot은 host 적용 시 token을 재발급하거나 provider를 재조회하지 않는다.
7. KV 정적 값의 버전/삭제와 token 수명은 별개다. 이미 읽거나 쓴 값을 소급 회수·원복했다고 주장하지 않는다.
   실패·만료·취소 때 새로운 secret 조회를 중단하고 다른 provider·빈값·옛 cache로 fallback하지 않는다.
8. 민감 content의 plan/spec/오류/Debug는 redact한다. 목적 파일·owned temp는 안전한 mode로 **생성 순간부터** 보호한다.
   secret 경로는 atomic publish 실패 후 직접 overwrite하지 않는다. commit 전 실패는 기존 파일 bytes/mode를 보존한다.
   postcommit durability 실패는 설치 여부와 구별한다. crash temp가 존재하는 구현은 private 보관·owner/inode 검증·bounded 정리까지 제공한다.
9. secret-bearing Runbook의 artifact body는 전부 생략한다. 안전한 output/final metadata만 durable journal/receipt에 연결하고,
   raw credential/값/rendered body를 저장해 복구하지 않는다. 원문 body의 일반 artifact replay·orphan 문제 전체는 별도 RES-003/004다.
   host 효과 전 final-report 용량을 예약한다. 최초 commit한 artifact ID/metadata와 최종 body는 불변이며 replay는 exact 저장 bytes만 쓴다.
   Controller는 immutable stored Runbook의 SecretRef 분류로 body 포함 final을 inbox staging/ArtifactStore put 전에 거절한다.
   빈 `Some` body도 거절하고 Agent의 omission 선언을 그대로 신뢰하지 않는다. 올바른 body 없는 metadata와 공개 artifact는 구분한다.
10. cancel/reconnect/restart·late/duplicate 보고는 canonical terminal을 덮거나 host 작업을 자동 재실행하지 않는다.
    준비 실패의 host 효과0과 적용 시작 뒤의 단계별 실패를 구분한다. 이미 승인한 Agent 작업은 사람 계정 회수만으로 소급 취소하지 않는다(D-013).
    이 효과0은 실패한 Agent의 준비 단계 기준이다. 다른 Agent의 성공을 되돌리지 않고 fanout의 기존 partial_success/개별 Assignment를 보존한다.
    late-G2/이미 dispatched된 cancel 뒤의 **모든 content body가 없는** Runbook final은 owner/digest/output·namespace/epoch guard를 유지해
    audit/inbox disposition과 verified receipt로 정리한다. 이미 terminal인 결과/기존 artifact 효과를 변경하거나 late metadata를 새 성공 효과로 저장하지 않는다.
    body 포함·잘못된 owner·변경된 body·미dispatch 취소·기존 미지원 remediation은 fail-closed를 유지한다.
    owner가 먼저 관측한 취소/deadline은 늦은 revoke 성공으로 실행 권한을 회복하지 못한다. 먼저 완료된 publish는 이후 취소로 자동 원복하지 않는다.

원문 경계 구분: 금지 대상은 Fleet의 Controller↔Agent report/wire, 일반 DB/journal/artifact/output/운영 로그·오류다.
KV 값의 provider 저장소·승인 목적 파일, AppRole 접속정보의 전용 private bootstrap 파일은 의도된 보관 경계다.
OpenBao auth/read의 필수 HTTPS payload·bounded process 메모리·private temp·격리 fixture의 provisioning 자료는
필요한 수명으로만 보유하고 Fleet 증거/일반 저장소로 복제하지 않는다. provider 원문 요청/응답을 wire 증거 파일로 저장하지 않는다.
임시 파일은 private 생성과 실패/crash 뒤 owner/inode 검증·bounded 정리를 별도로 검증한다.

## 인수 기준

| ID | 합격 조건과 실패 조건 | 실제 검증 |
| --- | --- | --- |
| SEC-AC-01 | A 요청/B 승인된 signed Runbook이 허용 Linux Agent에서 기대 파일 bytes/mode를 만들고 actor·target/provenance·body 없는 결과가 일치. stub/helper 성공만 있으면 실패 | 실제 HTTPS OpenBao/AppRole/KV + Controller/persistent Agent·기존 Runbooks UI/API/CLI·직접 파일 비교 |
| SEC-AC-02 | forbidden/unknown/missing/삭제/파괴·field/type 오류·만료·TLS/timeout/cancel·자원 초과와 조회 뒤 revoke 실패를 typed safe 실패로 처리. 준비 단계 파일/host 변경0, atomic commit 전 실패 기존 bytes/mode 유지. 빈값/부분 준비를 성공으로 보고하면 실패 | 최소권한 두 Agent, 사전 원본/hash/mode, request counter·fault injection·실 provider 중단/거절·revoke 응답 유실 |
| SEC-AC-03 | path별 준비 내 값/버전 일치·다음 Job 갱신값·bootstrap credential 재시작 반영. SecretID/token 각각의 만료/회수·응답 불명·유한 TTL과 적용 전 회수 성공을 증명. dryRun/checkMode/apply의 provider0, ready 뒤 재조회0. 정적 KV의 동적 lease를 주장하면 실패 | 실제 KV 갱신·AppRole 제한/회수·controlled monotonic time와 실제 짧은 TTL; preview request counter0·자동 재실행0 |
| SEC-AC-04 | sentinel 및 접속정보가 자동 생성된 log/audit/error/Debug/output/API/Controller DB·Agent journal·Fleet wire/artifact body에 없음. secret-bearing Job의 body 포함 final은 staging/파일 put 전 거절. 위 허용 경계·private temp/crash 정리와 metadata final의 no-rerun·terminal/receipt를 검증. 금지 경계의 원문 또는 불안전 temp는 실패 | secret 비출력 scan·early-reject side-effect counter·공개 artifact 회귀·filesystem mode·metadata-only late-G2/cancel/fault/reopen·실제 Agent 종료/Controller restart·최종 감사 |

S-00의 구체 limits/파일 mode/실패 표는 위 조건 아래 고정한다. 기존 bootstrap-only·TDD·계층·source index와
API/protocol/storage/security 문서 동기화를 따른다. 권한·지원 범위를 바꾸는 예외는 별도 사용자 결정 없이는 만들지 않는다.
기능 인수는 전체 Fleet SLA·production PG Controller·일반 artifact recovery·출시 인수를 대체하지 않는다.

## 기술 근거

- [KV v2 API](https://openbao.org/docs/api/secret/kv/kv-v2/): 문자열 field·versioned read와 deletion/destroyed metadata 확인의 기반.
- [AppRole API](https://openbao.org/docs/api/auth/approle/): 기계별 role/SecretID·token TTL/정책 경계.
- [Lease 개념](https://openbao.org/docs/concepts/lease/): KV는 동적 secret lease를 발급하지 않는다.

공식 문서는2026-10-28 확인했다. 격리 시험의 정확한 provider version/API 응답·환경은 실행 전 별도 고정한다.
