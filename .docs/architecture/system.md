# 시스템·책임 경계와 자원

이 문서는 현재 아키텍처와 목표로 이동할 경계, state ownership·resource 계획을 소유한다.
제품 범위는 [overview](../product/overview.md), 강제 작업 규칙은 [AGENTS](../../AGENTS.md),
wire/API/storage의 세부 계약은 각각 기존 `docs/` 문서가 소유한다. 결정: D-001–D-004.

## 현재 배포와 데이터 흐름

```text
운영자 CLI / 정적 Web Admin
        | HTTPS REST (인증된 actor·permission)
        v
단일 active Controller (Axum/Tokio)
        | Application use case -> SQLite + local artifact files
        | SessionRegistry -> session별 bounded queue / single writer
        ^ WSS: Agent가 outbound 연결
Agent runtime -> signed task 검증 -> execution admission/start intent
        |                         -> runner의 host side effect
        v
Agent local journal -> report replay -> Controller inbox/effect/receipt
                                           -> signed receipt 검증 후 exact cleanup
```

마지막 journal 경로는 모든 task type에 동일하게 적용되는 것이 아니다. 지원 범위는
[protocol](../../docs/protocol.md)의 현재 계약을 따른다. active session과 heartbeat는 DB의
Job/Assignment 완료 상태가 아니며 send 성공은 accepted/started가 아니다.

기본 운영은 Linux, 단일 Controller, SQLite, local artifact store, HTTPS/WSS다.
HTTP는 loopback/LAN이라도 단기 lab/test 전용 경고·audit를 유지한다.
Postgres feature가 있어도 현재 startup recovery가 거절하므로 운영 대안으로 안내하지 않는다.
shared data directory를 여러 Controller에 연결하거나 lease 없이 worker를 복제하지 않는다.

## 현재 기술과 모듈 책임

| 경계 | 소유 책임 / 허용 dependency | 남은 이동·주의 |
| --- | --- | --- |
| `fleet-domain` | 순수 entity/value/state/policy, project·external dependency 없음 | I/O/framework/wire DTO 금지 |
| `fleet-application` | domain use case, authorization/dispatch orchestration와 port, domain dependency | concrete store/network/process/env 금지 |
| `fleet-protocol` | versioned Serde JSON wire DTO와 명시 변환 | domain behavior를 복제하지 않음, v2 paired cutover |
| `fleet-core` | bootstrap settings/identity/logging support, project dependency 없음 | domain model의 대체 owner 아님 |
| `fleet-store` | SQLite 및 optional `postgres` adapter, Agent journal 분리 저장 | Controller DB와 Agent journal은 독립 lifecycle; SQLx/SeaORM 아님 |
| `fleet-runner` | process·package·service·file/template side effect, domain dependency | child group/cancel/timeout/output/path boundary |
| `fleet-controller` | HTTP/WSS interface, static serving, composition·session registry·workers | handler에서 domain state 규칙/직접 canonical write를 늘리지 않음 |
| `fleet-agent` | process-local supervisor, bounded journal worker, receipt verifier | 독립 binary 없음, Agent runtime 전체 이전 완료 아님 |
| `fleet-cli` | 유일한 `fleet` binary, clap/bootstrap/composition; active Agent socket/task/report 조립도 현재 잔존 | 새 규칙을 CLI에 계속 넣지 않고 실제 seam별 이전 |
| `web-admin` | HTML/CSS/native ES modules, API client와 local view state | `allowJs/checkJs/strict/noEmit`, Node test/static-copy build. React/Vite/Node server 아님 |
| `npm/fleet`와 platform package | `@sponzey/fleet` launcher, Darwin/Linux arm64/x64 binary distribution | npm은 Rust runtime 대체가 아님 |

Rust workspace는 edition 2024, Axum/Tokio, rusqlite, optional postgres/native TLS,
Ed25519/Rustls, clap, git2/libgit2를 사용한다. 후보 기술을 새로 도입한 계획으로 쓰지 않는다.

## 데이터·side-effect 소유권

| 데이터 / 자원 | canonical owner | 타 component가 할 수 없는 것 |
| --- | --- | --- |
| Job·Assignment·Approval·target snapshot | Application use case → repository transaction | UI/handler가 상태 추정·직접 overwrite, label 변경으로 기존 target 재계산 |
| authenticated actor·permission | 인증·권한 application boundary | request body/UI actor·role 신뢰 |
| active socket·liveness·connection ack | Controller SessionRegistry runtime | socket handle을 durable domain truth로 저장 |
| Agent admission/start intent·pending report | Agent application port / local journal adapter | reconnect를 재실행 권한으로 해석 |
| Controller inbox/effect/stored receipt | owner-bound application transaction와 receipt boundary | effect commit 전 ACK, 다른 owner/digest report를 같은 key로 수용 |
| output·final·Agent log·Product log·audit | 별도 저장·보존 경계 | stdout를 Product log에 dump, audit를 일반 retention에 포함 |
| artifact body / metadata | local filesystem adapter / application-store transaction | file+DB를 가짜 원자 transaction으로 취급, secret body 저장을 기본 허용 |
| catalog source/revision/document·activation | catalog use case와 repository, immutable provenance | browser 본문 복사로 catalog execution provenance 우회 |
| process·service·file 변경 | runner adapter, task lifecycle owner | cancel 시 이미 발생한 host effect가 rollback됐다고 주장 |
| background worker | runtime composition의 명시 owner | owner 없는 detached task, 무한 queue, shutdown/join 없는 실행 |

현재 기존 역할/operation permission 정책은 fleet-domain의 admin_identity가 소유한다.
bearer lookup은 application repository port를 사용하지만 HTTP request context 조립은 Controller에 남아 있다.
계정/credential의 순수 Domain 규칙과 Application transaction·local owner·관리·설정/password use case를 구현했다.
Controller의 bounded password worker와 고정 Argon2id/NFC/목적별 token adapter,
Application 로그인·session/PAT 발급·회수 및 identity store가 구현되어 있다.
HTTP 개인 로그인·session/logout·설정 claim과 cookie/PAT·CSRF adapter가 연결되어 있다.
owner 계정 목록/상세는 bounded query와 metadata projection으로, 생성/변경/reset은 same-request PW·원자 회수/audit로 연결되어 있다.
본인 password 변경/PAT 발급·조회·회수도 연결되어 있다. Command·DriftCheck·직접/카탈로그 Runbook 생성·승인/거절·명시적 취소·수동 만료·remediation 승인 요청/Job 생성은 동일 transaction의 최신 권한 guard를 사용한다. 개인 Admin 화면·auth generation·CLI token profile과 제한된 실제 HTTPS/Linux 인수를 검증했고 [phase012](../../.tasks/phase012/state.md)에 보관했다. 전체 Fleet SLA·출시 인수는 별도다.
auth repository adapter는 read/transaction별로만 공용 store mutex를 취하고 KDF 계산 중에는 guard를 보유하지 않는다.

다음 SEC-002의 **목표 경계**는 Agent의 OpenBao KV v2 직접 조회·AppRole/작업 준비별 단기 token이다.
Controller/Git에는 참조만 남기고 bootstrap 설정/전용 credential 파일은 시작 시 한 번만 읽는다.
기존 실제 Agent는 여전히 DisabledSecretProvider를 사용한다. 선택한 backend가 이미 연결됐다고 가정하지 않는다.
구체 보안/인수 계약은 [SEC-002](../domains/security/features/SEC-002-openbao-kv-v2.md)를 따른다.

schema/API/receipt 필드는 이 표에 복사하지 않는다. 각각 [storage](../../docs/storage.md),
[API](../../docs/api.md), [protocol](../../docs/protocol.md), [security](../../docs/security.md)를 수정 기준으로 삼는다.

<a id="refactoring"></a>
## 점진적 리팩토링 — ARC-001

리팩토링은 별도 전면 재작성 phase가 아니다. 실제 lifecycle·보안·I/O 경계가 변경을 막을 때만 수행한다.

1. UI-001: polling owner/cancel과 pure rendering을 characterization. API client/effect와 view state를 분리한다.
2. CAT-002: catalog 선택/async sync state와 command 생성 경계. server provenance use case를 재사용한다.
3. RES/IAM/SEC: CLI socket/task adapter, Controller auth/session/dispatch의 독립 owner부터 작은 단위로 분리한다.
4. QUA-001: 측정한 store checkout/lock/worker 병목만 바꾼다. 실제 교체가 없으면 새 strategy/trait/crate를 만들지 않는다.

각 tidy는 동작/API/wire/schema 변경과 분리하고 characterization → 이동 → 동일 test 및 dependency 검증을 남긴다.
Domain zero dependency, application inward dependency, store↔runner 무의존과 `source.md`를 확인한다.
파일 길이 감소나 추출한 module 수는 사용자 성과·완료 기준이 아니다.

## 리소스 조사와 재사용 계획

아래 표는 초기 프로젝트 정리 당시의 read-only 관찰과 과거 기록이다. OpenBao 계획 작성에서
Docker daemon·VM·LAN 서비스 상태를 다시 확인한 목록이 아니다. 이번 계획에서 환경 생성/부팅/설치는 하지 않았다.
후속 개인 계정 시험의 종료·credential/자원 정리 근거는
[phase012](../../.tasks/phase012/state.md)와 해당 acceptance/resource 증거가 소유한다.
새 provider 시험에서는 그 증거만으로 현재 환경이 준비됐다고 가정하지 않고 소유권/사용 상태를 다시 확인한다.

| 자원 | 대상·소유 범위 / 조사 결과 | 재사용·갱신 판단과 검증 |
| --- | --- | --- |
| local Cargo workspace/lockfile | 9 crates, version 0.0.20. `target/debug/fleet` 파일 존재 | manifest/lockfile 재사용. binary mtime으로 source 일치 판단 금지; 재개 시 source/diff digest·실제 version·gate 확인 |
| Web Admin build | `web-admin/dist` 존재, Node test/typecheck/static-copy scripts 존재 | source 기준 재생성·검증 후 배포. dist 존재만으로 최신 UI 주장 금지 |
| Docker | CLI와 daemon 목록 조회 확인, 다른 프로젝트의 running/stopped containers 존재. Fleet 전용 container는 목록에 없음 | unrelated DB/container를 재사용·삭제하지 않음. 다음 실DB 작업에서 image/version·소유권·data 격리를 확인해 재사용 또는 별도 disposable DB 생성 이유 기록 |
| Parallels | `prlctl list -a`: 중지된 Windows 11 개발 VM 한 대, Linux 없음 | 이 VM은 Linux recovery 대상 아님. 시작·삭제·변경하지 않음 |
| 과거 QEMU Ubuntu 24.04 arm64 guest | task056에 exact source build/preflight 기록. 현재 `/tmp/fleet-linux-smoke.u9whBv` 없음, 대상 QEMU process 관찰 안 됨 | 준비됐다고 가정하지 않음. 복구 가능한 기존 image/overlay를 먼저 확인하고, 없으면 disposable Linux 새 준비의 이유·격리·종료 계획을 기록 |
| 과거 LAN 서버 `192.168.20.123` | 이전 task의 SSH timeout 기록. 이번에는 네트워크/계정 접속을 재시도하지 않음 | 현재 사용·data·서비스 owner 재확인 전 destructive smoke 대상 금지 |
| live Postgres gate | task056에 disposable PG17 Store 13 tests 통과·container 제거 기록 | 실행 결과 재사용은 해당 source에 한정. 새 adapter 변경 시 다시 격리 실DB gate; 현재 Controller 지원 증거 아님 |
| release artifacts/npm packages | wrapper 1종 + OS/arch 4종, standalone archives/signature scripts | 각 target/channel을 별도 실행 대상으로 관리. 이번에는 registry/network 배포 상태 확인·publish 안 함 |

### 실행 산출물의 교체와 정리

공식 대상마다 source 기준·version·checksum·설치 경로·service ExecStart/npm resolved binary를 식별한다.
새 산출물은 임시 경로에서 해당 platform/기능 gate를 통과한 후 공식 경로로 반영한다.
실제 참조·실행 version을 확인한 뒤 이전 중복 binary와 임시 배포물을 제거하고 경로를 다시 검증한다.
실패한 새 binary를 승격하거나 정상 파일부터 삭제하지 않는다.

같은 target/channel의 기본 보관은 검증된 최신 실행 파일 하나다. OS/arch/channel이 다른 필수 파일,
시스템/공용 도구, immutable published release tag는 중복 청소 대상으로 보지 않는다.
rehearsal rollback에 필요한 이전 binary/snapshot은 사용자 확인된 예외로 target·사유·해소 조건·정리 시점을
남겨 제한 보존한다. 예외 종료 후 정리하고, 남아 있으면 ‘최신 파일만 유지 완료’라 하지 않는다.
정리는 실제 구현/운영 작업 범위에서 수행하며 계획 문서 작성만으로 파일·VM·volume을 삭제하지 않는다.
