# 결정 기록

확인된 제품·운영 선택과 아직 필요한 결정을 분리한다. 계획의 추천이나 질문 발송만으로
미확정 항목을 확정하지 않는다. 전체 계획: [plan.md](../plans/plan.md).

## 재사용하는 결정

| ID | 질문 / 선택 결과 | 근거와 확인 출처 |
| --- | --- | --- |
| D-001 | 어떤 제품인가? self-hosted OSS Linux 서버 운영 자동화, outbound Agent와 검토·승인·서명·결과·audit 루프 | 사용자 재정의 요청과 이를 바탕으로 재계획하라는 현재 요청, README의 확정 정의 |
| D-002 | 구버전 wire를 호환하는가? 폐기. Controller/Agent paired v2만 지원 | 사용자 ‘구버전 호환 폐기, 다른건 권장안’, 현 AGENTS 7.3. local data migration·backup 안전성은 유지 |
| D-003 | 어떤 구조와 개발법인가? 단일 binary, 계층/port-adapter, Rust domain/application 분리, static ES module Admin, TDD·필요한 Tidy First | 사용자가 제공한 AGENTS 1–3, 7. 새 framework 또는 일괄 runtime 재작성은 채택하지 않음 |
| D-004 | 명칭·라이선스·배포는? `@sponzey/fleet`, 실행/파일명 `fleet`, `.fleet`, `AGPL-3.0-only`, GitHub 조직 유지, OIDC Trusted Publishing | 기존 사용자 명시 선택, manifest/LICENSE, AGENTS 5.5/7.5. GitHub active account는 push 때 Leonard-Sponzey 확인 |

<a id="d-005"></a>
## D-005 — 전체 우선순위: 확정

- 질문: 남은 결과 신뢰성 장애 검증 → 장시간 결과 화면 → catalog 실행 연결 → 개인 계정/실제 SecretProvider → 부하 검증/측정 최적화 순으로 진행할 것인가?
- 답변: **‘권장 순서로 확정’**. 2026-10-23 이번 `project-planning` 대화의 사용자 응답.
- 이유: 이미 구현된 핵심 루프의 검증과 일상 사용성을 먼저 완성하고, 팀/secret/규모 확장은 별도 경계에서 검증한다.
- 함께 확정: 리팩토링은 관련 기능의 경계별로 수행. HA·Windows·자동 update는 후속 확장으로 분리.
- 영향: [P-01–P-06](../plans/plan.md)을 기본 순서로 사용한다. identity/provider 개별 기술과 신규 수치 SLA까지 확정한 것은 아니다.

<a id="d-011"></a>
## D-011 — 2026-10-23 개발 실행 계획: 당시 확정

- 확인일: 2026-10-23, `개발 계획 수립` 대화의 두 사용자 응답.
- 당시 기록 처리: **‘기존 계획 업데이트’**. 당시 `.tasks/plan.md`를 갱신하고 task001~056 및 phase002~phase010은 이동·초기화하지 않았다.
- 실행 범위: **‘앞 세 영역으로 한정’**. P-01 Linux 장애 검증 → P-02 장시간 결과 관찰 → P-03 catalog 승인·실행 연결.
- 영향: 과거 실행 계획의 Admin/catalog 제외를 이번 범위에서는 교체한다. 기존 신뢰성·보안 결정과 미완료 task056은 유지한다.
- 제외 유지: IAM/실제 SecretProvider/전체 Fleet 성능 검증과 RES-003/004 등 후속 작업을 이번 완료로 선언하지 않는다. D-005의 전체 순서도 변경하지 않는다.
- 근거 상세: [보관 실행 계획의 Current Plan Assessment](../../.tasks/phase011/plan.md#2-current-plan-assessment).
- 당시 추가 조사: catalog 실행 Application 유스케이스는 있지만 HTTP/CLI/Admin 실행 연결은 없다.
  Job/provenance/Assignment 저장 이후 Approval/audit가 별도 호출되므로 전체 생성 원자성도 인수 대상으로 둔다.
  이는 CAT-002 목표의 구체화이지 새로운 제품 기능이나 호환성 폐기 결정이 아니다.
- 현재: 해당 범위는 완료 기록이 있으며 D-012에 따라 phase011로 이동했다. 당시 기준선을 현재 미완료로 재사용하지 않는다.

<a id="d-012"></a>
## D-012 — 개인별 로컬 관리자 계정의 다음 실행 계획: 확정

- 확인일: 2026-10-27. 개발 계획 수립 질문 3개에 대한 사용자 응답.
- 기록 처리: **‘이동 보관 후 다음 계획 작성’**. .tasks root의 78개 파일을 phase011로 내부 이동하고
  기존 phase002–phase010의 9개 폴더를 유지한다. 별도 복사 backup은 아니다.
- 실행 범위: **‘개인별 관리자 계정에 한정’**. 단일 조직의 로그인·역할·접근 회수·감사 기록,
  관련 인증 경계 정리를 포함한다. 실SecretProvider·전체 부하 최적화·project 격리는 후속 계획이다.
- 첫 로그인 경로: **‘Fleet 자체 아이디·비밀번호’**. 외부 OIDC는 이번 범위에 포함하지 않는다.
- 영향: 전체 우선순위 D-005는 유지. P-01–03 완료 증거를 보관하고 P-04를
  [당시 개발 계획](../../.tasks/phase012/plan.md)으로 구체화했다. 이번 답변은 구현·운영 DB 변경·배포 승인이 아니다.
- 당시 미확정: D-006의 session/credential·관리 권한·승인·전환/복구·인증 기술값. 이후 D-013 답변으로 아래와 같이 구체화했다.

<a id="d-006"></a>
## D-006 — 개인 identity: 범위·정책 확정

- D-012로 단일 조직·개인 계정·Fleet 자체 아이디/비밀번호를 확정했다.
- 이후 검토 대화의 D-013으로 기한·관리/자기 권한·회수·자기승인·local 전환/복구·restore 기준을 확정했다.
- KDF·자원 한도 등 기술값은 보안 하한과 격리 측정으로 I-00에서 선택하도록 위임받았다.
  미합의 SLA를 만들거나 보안 하한을 낮추는 권한은 포함하지 않는다.
- 기준은 [IAM-001](../domains/identity/features/IAM-001-local-accounts.md)와
  [POL-01–05](../../.tasks/phase012/plan.md#6-risks-and-decisions)에 반영했다. 정책 확정과 후속 기능 인수는 구분하며 현재 source/기능표·완료 기록을 따른다.

<a id="d-013"></a>
## D-013 — 개인 계정 검토의 인증·권한·전환 정책: 확정

- 확인일: 2026-10-27. 개발 계획 검토의 세 질문에 사용자 모두 권장안으로 답변.
- 기한: 웹 session 고정 8시간(자동 조회로 연장 없음, 별도 idle expiry 없음), 개인 CLI/API token 30일,
  일회성 설정/reset 코드 15분. 기존 URL secret 금지에 따라 비밀값 없는 안내와 POST/TTY 코드 입력 방식 사용.
- 권한: 계정 생성·타인 reset·role 변경·차단은 owner만. 모든 활성 사용자는 본인 password/PAT 관리.
  기존 admin 업무 권한·자기승인 허용 유지. 계정 차단·role/password 변경은 해당 사람의 모든 session/PAT를 회수하고
  미사용 설정/reset 코드도 재사용하지 못하게 한다. 기존 Agent 작업은 계속한다.
- 전환/복구: server-local 명령으로 첫 owner 준비 후 공용 token 종료, 마지막 owner 제거 금지.
  접근 복구도 local 명령만. backup restore는 계정·backup 내 작업 이력·Agent identity를 보존하고
  사람의 기존 session/PAT/미사용 코드만 무효화한다. 기존 Agent delivery epoch 계약은 변경하지 않는다.
- 기술값: KDF 비용·동시 처리 한도 등은 보안 하한과 격리 측정으로 I-00에서 선택한다.
  전체 Fleet SLA 추가·운영 시스템 변경·구현/배포 승인이 아니다.
- 구현 구체화: 회수보다 먼저 commit된 Job/승인은 보존한다. 이후의 mutation/발급 commit은 최신
  계정·권한·credential revision을 검증하고 거절한다. 전환·restore는 실패/rollback 보존 시험을 갖춘다.
- 영향: 개발 계획 전체 phase·IAM-AC-01–04, 전체 계획 P-04·기능 지도·문서 지도를 동기화한다.
  결정 당시 기능은 미구현이었다. 이후의 부분 구현과 남은 인수는 현재 기능표와 source/test로 확인하며,
  이 정책 확정 자체를 구현·제품 인수 완료로 해석하지 않는다.

<a id="d-007"></a>
## D-007 — 첫 실제 SecretProvider: 확정

- 확인일:2026-10-28. 다음 개발 계획 수립의 사용자 답변.
- backend/범위: **OpenBao KV v2부터 연결**, 승인된 Runbook의 file.template만 우선한다.
  private Git·S3·동적 DB credential·전체 부하 최적화는 후속이다.
- 조회/권한: **Agent 직접 조회·작업별 단기 인증**. Agent별 제한된 AppRole·정확 reference mapping/읽기 ACL을 사용하고
  Controller와 Git에는 참조만 남긴다. Controller 대리 조회·raw secret 중계는 제외한다.
- bootstrap: Agent 전용 비밀 파일은 시작할 때만 읽는다. AppRole 단기 token은 작업 준비 중 메모리에서만 사용한다.
  접속 실패/만료 때 조회를 중단한다. token 정리/유한 TTL과 KV 값 버전은 별개로 검증한다.
- 교체: 값은 다음 새 실행부터 반영하고 접속정보는 명시적 Agent 재시작으로 교체한다.
  이미 적용한 파일의 자동 원복/재적용·작업 재실행·KV의 동적 lease 갱신은 포함하지 않는다.
  후속 D-015에서 preview 접근0과 적용 전 token 회수 실패의 중단을 확정했다.
- 기준: [SEC-002](../domains/security/features/SEC-002-openbao-kv-v2.md).
  구체 limits·설정명·안전한 파일 구현·정확 시험 환경은 S-00에서 보안 하한·검증 기준 아래 고정한다.
  중요한 정책/범위를 바꾸는 예외는 별도 결정한다.

<a id="d-014"></a>
## D-014 — OpenBao 실행 계획과 기록 처리: 확정

- 확인일:2026-10-28. 사용자 답변: **이동 보관 후 다음 계획 작성**.
- 완료된 개인 계정 root 파일41개(plan/state/task-list/진행 문서)를 .tasks/phase012로 내부 이동했다.
  기존 phase002–phase011의10개 폴더와 소스를 유지했으며 별도 복사 backup이 아니다.
- 다음 실행 범위는 D-007의 OpenBao KV v2·Agent 직접 조회·준비별 단기 인증이다.
  필요한 민감 data/file·실행 admission/metadata 보고 경계 보강을 포함하고 전체 provider/보고/성능 재작성은 제외한다.
- 영향: P-05·SEC-002·현재 [개발 계획](../../.tasks/plan.md)·기능/문서 지도를 동기화한다.
  계획 확정은 코드 구현·운영 환경 변경·서비스 설치/중단·credential 발급·배포 승인이 아니다.

<a id="d-015"></a>
## D-015 — OpenBao 계획 검토의 미리보기·회수 실패 정책: 확정

- 확인일:2026-10-28. 계획 검토의 두 질문에 사용자 모두 권장안으로 답변.
- **미리보기·검사에서는 비밀 조회 없음**: signed dryRun/checkMode도 AppRole/비밀 read/revoke 요청0이다.
  Agent에 시작 시 주입된 mapping과 참조 형식을 검사하고 secret template는 원문 없는 symbolic plan으로 skip한다.
  값의 존재/읽기 권한은 실제 실행에서 확인한다. 기존 checkMode 저위험 검사는 유지한다.
  로컬 fleet apply는 기존 validation-only에 따라 provider 설정/credential도 읽지 않고 문법만 검사한다.
- **회수 실패 시 파일 적용 중단**: 조회 완료 후 host 적용 전에 작업용 token의 bounded revoke-self 성공을 확인한다.
  실패/응답 불명/기한 초과는 준비 실패·파일 변경0이다. 원격 token은 TTL까지 남을 수 있음을 표시하고 회수를 가장하지 않는다.
  성공적으로 회수한 ready snapshot은 재인증 없이 사용하며 이미 적용한 파일을 소급 취소하지 않는다.
- 영향: [P-05](../plans/plan.md#p-05), [SEC-002](../domains/security/features/SEC-002-openbao-kv-v2.md),
  현재 [계획](../../.tasks/plan.md)의 X-04/06·S-00/01/02/03/04·완료 기준을 동기화한다.
  기존 OpenBao/Agent/AppRole 범위와 단일 조직 계정·wire 정책은 바꾸지 않는다. 구현/시험 실행 승인은 아니다.

<a id="pending-decisions"></a>
## 해당 단계 전에 결정할 항목

| ID / 상태 | 결정 질문과 현재 권장 검토안 | 영향 / 답을 받을 시점 |
| --- | --- | --- |
| D-006 / 확정 | local 계정·단일 조직, D-013 기한/권한/회수·자기승인·전환/복구 확정 | I-00은 기술 contract·격리 측정의 선택 단계. IAM-002 project 격리는 후속 별도 |
| D-007 / 확정 | OpenBao KV v2·Agent 직접 조회·AppRole/준비별 단기 token·bootstrap 전용 파일·실패 중단/다음 Job 값 반영 | SEC-002/S-00에서 구체 contract·격리 한도/환경 고정. private Git·S3·동적 credential 제외 |
| D-008 / 미확정 | 대표 hardware/workload, heartbeat/dispatch/query latency, 메모리·queue·오류/회귀 허용치는? | QUA-001에서 baseline 측정 후 최적화 전 승인. 기존 100 Agent/총 1000 Job 설계 후보를 실제 최대 지원/SLA로 승격하지 않음 |
| D-009 / 미확정 | 결과 신뢰성 미지원 경로와 journal/inbox/nonce 보존 증가를 어떤 출시 경계로 다룰 것인가? | RES-003/004와 P-07 출시 판정 전. 지원 경로 확장 또는 명시적 제한·운영 경보/절차의 대안을 제시. 임의 purge/TTL·자동 재실행·지원 확대 금지 |
| D-010 / 미확정 | 목표 출시일·버전, 유상 지원/edition, 추가 플랫폼·외부 연동의 실제 사용자 요구와 예산은? | 날짜·가격·구매·외부배포를 약속하기 전. 현 계획은 기능 순서이며 납기/상업 계약 아님 |

답변이 필요한 단계에 도달하면 대안·위험·검증·rollback을 짧게 제시해 결정한다.
P-04의 로컬 계정 기능 인수는 D-006/D-013의 확정 정책을 따른다. 현재 증거는 task 목록이 소유한다.
P-05의 D-007은 확정했다. 구현은 S-00의 구체 contract·격리 시험 조건부터 진행하며 이미 확정한 계정 정책을 다시 선택하지 않는다.
실제 root 설치·중단·재부팅은 대상과 영향 확인 및 현재 task의 명시 승인 조건을 따른다.
