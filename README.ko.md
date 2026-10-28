# Sponzey Fleet

[English README](README.md)

Sponzey Fleet는 직접 설치해서 운영하는 오픈소스 서버 운영 자동화 플랫폼입니다.
명령 실행, 반복 작업을 담은 Runbook, 서버 상태 확인, Policy에 따른 복구를 한 흐름으로
연결하고, 실행 대상 확인·승인·작업 서명·감사 기록을 함께 제공합니다.

주요 사용자는 여러 Linux 서버를 관리하는 운영자입니다. NAT나 사설망 뒤의 서버도
관리 대상으로 삼습니다. 작업마다 서버에 SSH로 접속하는 대신 Controller에서 작업을
요청하고, 서버마다 설치된 Agent가 연결을 유지하며 상태를 보고하고 서명된 작업을 실행합니다.
이를 위해 Agent에서 Controller로 나가는 네트워크 연결은 가능해야 합니다.

npm 패키지 이름은 **`@sponzey/fleet`**, 실행 파일과 명령 이름은 **`fleet`**입니다.

[프로젝트 목표](#프로젝트-목표), [주요 기능](#주요-사용-흐름과-기능),
[현재 개발 상태](#현재-개발-상태와-지원-범위)를 먼저 읽거나,
[설치하기](#설치하기)와 [컴퓨터 한 대로 시작하기](#초보자-설정-컴퓨터-한-대에서-controller와-agent-실행하기)로 이동하세요.

## 프로젝트 목표

Fleet의 목표는 반복되는 서버 운영 작업을 쉽게 재현하고, 검토하고, 설명할 수 있게 만드는 것입니다.

- Agent의 outbound 연결을 이용해 작업마다 각 서버에 들어가는 SSH 연결 없이 운영합니다.
- 반복 명령과 설정 변경을 대상이 분명한 Job과 Runbook으로 만들고, 필요한 검토·승인과
  감사 기록을 남깁니다.
- 서버가 선언한 Policy를 계속 만족하는지 확인하고, 차이가 생기면 승인된 수정과
  새로운 검증 결과까지 연결합니다.
- 연결 장애나 프로세스 재시작 뒤에도 작업 결과를 이해할 수 있게 합니다. 지원하는
  보고는 저장 확인을 받을 때까지 보존하고, 실행 여부가 불확실하면 성공으로 추정하거나
  같은 명령을 자동으로 다시 실행하지 않고 그 상태를 드러냅니다.

핵심 성공 기준은 하나의 운영 흐름이 이어지는 것입니다. 서버를 등록하고, 실행 대상을
검토하고, 작업을 요청한 뒤, Agent별 출력과 결과를 확인하고 감사 기록에서 행동을 추적할
수 있어야 합니다. Policy 작업은 문제 발견뿐 아니라 수정 후 검증까지 포함합니다.
[품질 기준](.docs/architecture/quality-targets.md)의 설치 시간과 관리 규모 수치는 설계 후보이며,
이미 측정해 보장하는 성능이나 서비스 수준은 아닙니다.

## 주요 사용 흐름과 기능

1. Enrollment token으로 Agent를 등록하고 `role=web`, `env=test` 같은 label을 붙입니다.
2. Web Admin이나 CLI에서 연결 상태, 서버 목록, facts와 metrics를 확인합니다.
3. Agent ID나 label로 대상을 고르고 미리 봅니다. 생성된 Job은 그 시점의 대상 목록을
   유지하므로 나중에 label이 바뀌어도 기존 Job의 대상이 조용히 바뀌지 않습니다.
4. 명령이나 Runbook을 요청합니다. 승인이 필요한 작업은 운영자의 결정을 기다리고,
   Controller가 작업에 서명하면 Agent가 이를 검증한 뒤 실행합니다.
5. Agent별 진행 상태, 출력, 최종 결과와 감사 기록을 확인합니다. 필요하면 취소할 수 있고,
   실행에는 제한 시간이 있습니다.
6. 지속적인 상태 점검이 필요하면 Policy를 배정하고 drift check 일정을 설정합니다.
   Remediation 제안을 검토·승인해 수정 Runbook을 실행하고, 검증 결과를 확인합니다.

**Job**은 운영자가 요청한 작업이고, **Assignment**는 그 Job을 Agent 한 대에서 처리하는
단위입니다. 같은 Job을 여러 대에 보내도 서버마다 결과가 다를 수 있습니다.

| 기능 | 현재 제공하는 흐름 |
| --- | --- |
| Agent 관리 | 등록, label, 연결 상태, 컴퓨터 정보(facts), 실행 가능 기능 선언, 사용량(metrics) snapshot |
| 명령 실행 | 대상 미리 보기, 여러 Agent의 개별 작업 상태, 출력 수집, 승인 검사, 취소와 timeout |
| Runbook | package·service·file copy·template 작업을 YAML 단계로 표현하고 서명된 Job으로 원격 실행. `fleet apply`는 현재 문서 검증만 하며 실행하지 않음 |
| Policy와 remediation | 정기 상태 검사, drift 이력, 승인된 수정, 새로운 검증 증거를 바탕으로 한 해결 처리 |
| 공개 Git catalog | 공개 HTTPS 저장소 등록, 제한된 sync와 문서 검증, 명시적인 revision 활성화와 문서 출처 기록. 활성화 자체는 작업 실행이 아님 |
| 운영 인터페이스 | Controller가 제공하는 Web Admin, CLI, 보호된 REST API, OpenAPI와 Swagger UI |
| 운영 기록 | Job/Assignment 상태, 작업 출력, Agent 운영 로그, 감사 기록, 보존 기간 관리, Controller 백업·복구 |

Facts는 컴퓨터의 구성 정보, metrics는 수집 시점의 사용량, 작업 출력은 실행한 명령의
stdout/stderr입니다. 목적이 다르므로 별도 기록으로 다룹니다. Fleet는 작업과 Policy를
운영하는 데 필요한 가시성을 제공하며, 전체 모니터링·로그 분석·알림 플랫폼을 대체하는
것을 목표로 하지 않습니다.

## 현재 개발 상태와 지원 범위

이 정의는 **2026-10-23 저장소 상태**를 기준으로 확인했습니다. 현재 checkout의 기준은
tag `v0.0.20`(`6683792`)이고 manifest도 `0.0.20`입니다. 작업 트리에는 그 tag 이후의
미커밋 보고 전달·복구 변경도 들어 있습니다. 이 README는 현재 checkout을 설명하며,
최신 공개 버전이나 npm 배포물에 이 변경이 포함됐는지까지 확인한 것은 아닙니다.

핵심 운영 흐름은 구현되어 있습니다. 운영 안정성 보강과 일부 사용자 흐름은 진행 중입니다.

| 분야 | 현재 경계 |
| --- | --- |
| 운영 구성 | 단일 Controller·SQLite·Linux Agent가 주된 경로. macOS binary와 명령 실행은 있지만 서비스 관리와 호스트 정보 수집은 Linux와 동등하지 않음 |
| 결과 전달 | Persistent Command와 artifact가 없는 Runbook에는 로컬 보고 journal, 재전송, 서명된 저장 확인, 출력 조각 확인이 구현됨. DriftCheck 증거와 최종 보고도 receipt를 사용함. Artifact를 만드는 Runbook 보고, 직접 one-shot 결과, Drift 실행 복구에는 별도 한계가 있음. [Protocol 문서](docs/protocol.md) 참고 |
| 장애 복구 | 실행 결과를 확인할 수 없으면 `failed`와 `execution_outcome_unknown` 같은 사유로 표시하고 자동 재실행하지 않음. 외부 변경이 정확히 한 번 일어나거나 프로그램 출력의 모든 byte를 수집했다는 보장은 아님 |
| PostgreSQL | 선택 feature로 adapter와 repository test가 존재함. 현재 Controller는 Assignment·보고 복구가 지원되지 않는 Postgres 구성을 시작 단계에서 거부하므로, 이 checkout의 사용 가능한 runtime 경로는 SQLite임 |
| Web Admin | Run/Runbooks 공통 Job 관찰은 일시정지·재개, 늦은 응답 차단과 부분 성공을 포함한 종료 결과를 지원함. 저장 출력의 page 조회와 이력 탐색은 구현됨. SQLite 관찰 경로의 Linux·브라우저·출력 비용 검증을 마쳤음. 활성 catalog Runbook을 검토해 승인 요청으로 제출하고 대상과 Job의 원래 출처를 보존함. 이 checkout에서 공개 Git부터 실행 결과까지 두 Linux Agent와 실제 브라우저로 제한된 범위의 인수를 검증함 |
| 운영자 계정과 secret | Bootstrap 인증·role별 권한 검사와 로컬 `fleet controller admin init-owner` / `recover-owner` 명령이 있음. 개인 HTTP 로그인·session/logout·설정과 cookie/PAT 인증 기반은 연결됨. owner 계정 조회·생성·변경·reset도 연결됨. 본인 password 변경/PAT 발급·조회·회수도 연결됨. Command·DriftCheck·직접/카탈로그 Runbook 생성·승인/거절·명시적 취소·수동 만료·remediation 승인 요청/Job 생성은 원자 업무 transaction에서 최신 권한을 재검증함. 개인 Admin 로그인·계정 화면은 연결됨. 개인 CLI token 입력/profile 연결은 구현됨. 이 checkout에서 두 사용자 HTTPS 브라우저/API/CLI·회수 중 Linux Agent 실행·복구/restore·제한된 인증 부하 인수를 검증함. 미배포 변경이며 운영 용량이나 출시 인수 완료를 뜻하지 않음. OIDC/project RBAC·외부 SecretProvider는 별도 후속 범위. [로컬 계정 계약](.docs/domains/identity/features/IAM-001-auth-contract.md) 참고. |
| 검증 | 로컬 release 검사·실제 PostgreSQL Store 계약·persistent Command 재시작/재부팅·장시간 UI/catalog·개인 계정 HTTPS/Linux의 제한된 인수 기록이 있음. 명시된 경로의 증거이며 모든 실행 경로의 완전한 복구·운영 용량·향후 기능의 출시 준비까지 검증한 것은 아님 |

Controller와 Agent는 protocol v2를 사용하며 함께 업그레이드해야 합니다. v1 상호운용이나
혼합 버전 fallback은 지원하지 않습니다. 기존 로컬 데이터 migration과 백업·복구 안전장치는
계속 유지합니다.

장기 확장에는 완전한 mTLS client 인증서 검증, 외부 secret·S3 adapter, 팀 계정 체계,
HA coordination, Windows service, 알림, 서명된 자동 업데이트가 있습니다.
현재 지원 완료 기능으로 소개하지 않습니다. Ansible 연동도 향후 일부 문법을 가져오는
bridge이며 완전 호환을 목표로 하지 않습니다. CI/CD나 endpoint 보안 제품도 Fleet의
포지션이 아닙니다. 원래 제안의 Team/Enterprise edition은 향후 제품 구상이며,
상용 제공 범위와 가격이 이 저장소에서 확정된 것은 아닙니다.

상세 문서는 [문서 지도](.docs/README.md)에서 시작하세요.
[제품 범위](.docs/product/overview.md), [기능 지도](.docs/product/capabilities.md),
[전체 계획](.docs/plans/plan.md)을 연결해 두었습니다. 확정한 순서는 장애 복구 검증,
장시간 작업 관찰, catalog에서 실행까지 연결, 개인 계정·실제 SecretProvider,
측정 기반 성능 개선입니다. 리팩토링은 각 기능의 경계별로 진행합니다.
구현 세부와 제한은 [기능표](docs/feature-matrix.md)와 protocol·storage·security 계약을
함께 참고하세요. [초기 제안](.docs/archive/project-proposal.md)은 현재 계획이 아닌 이력입니다.

## 서비스 형태와 구성

현재 Fleet는 사용자가 직접 운영하는 인프라에 설치합니다. 하나의 `fleet` 실행 파일이
Controller, Agent, 운영자 CLI 역할을 제공합니다.

- **Controller**는 관리 본부입니다. Job과 운영 데이터를 저장하고, Agent와 운영자를
  인증하고, 승인·작업 전달을 처리하며 Web Admin과 API를 제공합니다.
- **Agent**는 관리할 컴퓨터마다 실행합니다. Controller로 outbound WebSocket 연결을
  유지하고, 컴퓨터 정보를 수집하고, 허용된 서명 작업을 실행합니다.
- **Web Admin**은 Controller의 `/admin`에서 제공하는 정적 웹 화면입니다.
  CLI나 REST API로도 운영할 수 있으며 별도의 Node.js 웹 서버는 runtime 구성에 없습니다.

Controller 하나에 여러 Agent를 연결할 수 있습니다. 현재 설계는 활성 Controller 한 대를
전제로 하며, HA나 multi-tenant 운영은 완성되지 않았습니다. 실제 운영과 장시간 실행에서는
내장 TLS 또는 HTTPS reverse proxy를 통해 HTTPS/WSS를 사용합니다.

배포 형태는 npm wrapper와 Linux/macOS arm64/x64별 binary package, standalone release
archive입니다. Linux 서비스 명령은 systemd를 대상으로 합니다. macOS package 배포가
동일한 서비스·primitive 지원을 뜻하지 않으며 Windows service는 향후 범위입니다.

## 기술 스택

| 기술 | 현재 구현에서 맡는 역할 |
| --- | --- |
| Rust, edition 2024 | Controller, Agent runtime, CLI, domain 규칙, 저장소 adapter, 호스트 작업 |
| Axum·Tokio | Controller HTTP/WebSocket, 비동기 runtime, worker lifecycle |
| SQLite·`rusqlite` | 기본 Controller 저장소와 Agent 보고 journal. Artifact 본문은 로컬 filesystem에 저장 |
| Serde / JSON·YAML 문서 | JSON wire/API 메시지, Fleet YAML Runbook과 Policy |
| Ed25519·Rustls | 작업·receipt 서명, Controller 신뢰 검증, TLS 통신 지원 |
| clap | `fleet` 명령과 하위 명령 UX |
| HTML·CSS·native JavaScript ES module | Web Admin. `allowJs`/`checkJs` 검사와 Node test·정적 파일 복사 build를 사용하며 React/Vite 앱은 아님 |
| libgit2의 `git2` binding | 공개 HTTPS Git catalog의 제한된 fetch와 검증 |
| npm·GitHub Actions | 플랫폼 binary 배포, release 검사, OIDC Trusted Publishing. Node.js가 Fleet 서버를 실행하는 것은 아님 |

Rust workspace는 domain, application use case, protocol, store, runner, Controller,
Agent 지원 코드와 CLI 조립을 구분합니다. Agent runtime 분리는 진행 중입니다.
현재 active socket/task adapter는 CLI에 남아 있고, `fleet-agent`는 session 상태,
제한된 journal worker와 receipt 검증을 소유합니다. PostgreSQL은 선택적인 `postgres`
adapter를 사용하며 SQLx나 SeaORM을 쓰지 않습니다.

## 준비물

처음 시작할 때는 다음이 있으면 됩니다.

- macOS 또는 Linux 컴퓨터
- Node.js와 npm
- 터미널
- 웹 브라우저

Node.js와 npm이 설치되어 있는지 확인합니다.

```bash
node --version
npm --version
```

둘 중 하나라도 명령을 찾을 수 없다고 나오면 Node.js LTS 버전을 먼저 설치하세요.

## 설치하기

어느 터미널에서든 `fleet` 명령을 사용할 수 있도록 전역 설치합니다.

```bash
npm install -g @sponzey/fleet
fleet --version
```

`npm install @sponzey/fleet`처럼 프로젝트 안에만 설치했다면 `fleet` 대신
`npx fleet`로 실행합니다.

설치 후 `fleet: command not found`가 나온다면 npm 명령 설치 경로를 확인합니다.

```bash
echo "$(npm prefix -g)/bin"
```

출력된 경로를 shell의 `PATH`에 추가하고 새 터미널을 여세요.

이 저장소에서 직접 빌드하려면 다음 명령을 사용합니다.

```bash
cargo build -p fleet-cli
./target/debug/fleet --version
```

소스 빌드를 사용할 때는 아래 예시의 `fleet`를 `./target/debug/fleet`로 바꾸면
됩니다.

## 명령 하나로 데모 실행하기

실제 설정을 시작하기 전에 데모부터 실행해 볼 수 있습니다.

```bash
fleet demo
```

임시 Controller와 Agent를 만들고, 작은 작업을 실행한 뒤 Web Admin 주소를 보여줍니다.
데모가 끝나면 임시 데이터는 자동으로 정리됩니다.

## 꼭 알아야 할 값 세 가지

설정하는 동안 다음 값을 만나게 됩니다.

| 값 | 무엇인가요? | 어디에 사용하나요? |
| --- | --- | --- |
| Admin token | 개인 계정 전환 전의 공용 초기 설정 credential | 초기 Web Admin 화면에 입력합니다 |
| Personal token | 한 사람의 30일짜리 CLI/API credential | `fleet login`의 숨김 입력창에 넣습니다. 계정 비밀번호와 다릅니다 |
| Enrollment token | Agent를 처음 등록할 때 쓰는 짧은 유효기간의 일회용 코드 | `fleet agent init`에만 사용합니다 |
| Data directory | 키, 설정, Controller 또는 Agent 데이터가 들어 있는 폴더 | 해당 역할을 다시 시작할 때 항상 같은 폴더를 사용합니다 |

Admin token과 Enrollment token은 서로 다른 값입니다. 바꿔서 사용할 수 없습니다.

## 초보자 설정: 컴퓨터 한 대에서 Controller와 Agent 실행하기

처음 배울 때 가장 안전한 방법입니다. 같은 컴퓨터에서 터미널 두 개를 사용합니다.

### 1단계: Controller 초기화

첫 번째 터미널을 열고 실행합니다.

```bash
mkdir -m 700 -p fleet-controller
fleet controller init --data-dir ./fleet-controller
```

명령을 실행하면 `admin token`이 한 번 표시됩니다. 비밀번호 관리자나 안전한 임시
공간에 복사해 두세요. Controller에는 token 원문이 아니라 hash만 저장되므로 같은
token을 다시 보여주지 않습니다.

Controller 초기화는 보통 처음 한 번만 합니다.

macOS/Linux에서 Controller 데이터 폴더는 Fleet을 실행하는 OS 사용자 소유이고
권한이 `0700`이어야 합니다. 본인 소유의 기존 폴더라면 구 Controller를 먼저 멈춘 뒤
`chmod 700 ./fleet-controller`를 실행하세요. Fleet은 권한을 확인하고 실행 중 폴더의
독점 잠금을 유지하며, 기존 폴더 권한을 자동으로 바꾸지는 않습니다. 이전 Fleet은
이 잠금을 사용하지 않으므로 업그레이드 전에 직접 종료해야 합니다.

### 2단계: Controller 시작

같은 터미널에서 실행합니다.

```bash
fleet controller start \
  --host 127.0.0.1 \
  --port 7700 \
  --data-dir ./fleet-controller \
  --external-url http://127.0.0.1:7700
```

이 터미널은 닫지 마세요. `Ctrl+C`를 누르거나 터미널을 닫으면 Controller도
종료됩니다.

여기서는 한 컴퓨터에서 연습하므로 `http://`를 사용합니다. HTTP는 암호화되지 않기
때문에 Sponzey가 경고를 표시합니다.

### 3단계: Web Admin 열기

브라우저에서 다음 주소를 엽니다.

```text
http://127.0.0.1:7700/admin
```

1단계에서 저장한 admin token을 입력합니다. 아직 Agent가 없어도 Web Admin 화면은
열려야 합니다.

서버 로컬 명령으로 첫 owner로 전환했다면 공용 token 대신 아이디·비밀번호로 로그인합니다.
Settings의 My account에서 본인 비밀번호·개인 token을, People에서 owner가 다른 계정을
관리합니다. Controller에는 Agent 등록·서명 신뢰 기능이 있습니다. 새 계정을 받은 사람은
Set up or reset a password에서 한 번 표시된 코드를 사용해 비밀번호를 정한 뒤 로그인합니다.
코드는 15분 뒤 만료됩니다. 로그아웃해도 실행 중인 Agent 작업은 계속됩니다.

### 4단계: Agent 등록 token 만들기

두 번째 터미널을 엽니다. Controller는 계속 실행 중이어야 합니다.

```bash
fleet enroll-token create \
  --data-dir ./fleet-controller \
  --labels role=test,env=local
```

출력된 token을 복사하세요. 이 값은 Enrollment token이며 admin token이 아닙니다.
Web Admin에서도 Enrollment token을 만들 수 있습니다.

### 5단계: Agent 초기화

아래 명령의 `PASTE_ENROLLMENT_TOKEN_HERE`를 4단계에서 받은 token으로 바꾼 다음
실행합니다.

```bash
mkdir -p fleet-agent
fleet agent init \
  --data-dir ./fleet-agent \
  --url http://127.0.0.1:7700 \
  --token PASTE_ENROLLMENT_TOKEN_HERE \
  --name my-first-agent \
  --labels role=test,env=local
```

Agent 초기화 과정에서 Agent identity를 만들고 Controller identity를 고정합니다.
하나의 Agent data directory에서는 보통 처음 한 번만 실행합니다.

### 6단계: Agent 시작

두 번째 터미널에서 실행합니다.

```bash
fleet agent start --data-dir ./fleet-agent
```

이 터미널도 계속 열어 두세요. Web Admin을 새로 고치면 Agent 목록에
`my-first-agent`가 보여야 합니다.

연결을 한 번만 확인하고 종료하려면 다음처럼 실행합니다.

```bash
fleet agent start --data-dir ./fleet-agent --once
```

일반 실행에서는 네트워크나 Controller가 잠시 끊겨도 Agent가 계속 재접속을
시도합니다.

## 실제 설정: Controller와 Agent를 서로 다른 컴퓨터에서 실행하기

설정 순서는 같습니다. 다만 Agent에서 Controller 컴퓨터의 실제 IP 주소나 DNS 이름을
사용해야 합니다.

아래에서는 Controller 주소가 `192.168.0.10`이라고 가정합니다. 이 값을 실제 주소로
바꿔서 사용하세요.

### 1단계: Controller 컴퓨터의 주소 확인

Linux에서는 다음 명령을 사용할 수 있습니다.

```bash
hostname -I
```

macOS Wi-Fi에서는 다음 명령을 사용할 수 있습니다.

```bash
ipconfig getifaddr en0
```

공유기나 클라우드 서버 관리 화면에서도 주소를 확인할 수 있습니다.

### 2단계: Controller 초기화와 시작

Controller 컴퓨터에서 실행합니다.

```bash
mkdir -p fleet-controller
fleet controller init --data-dir ./fleet-controller
```

출력된 admin token을 안전하게 보관한 다음 Controller를 시작합니다.

```bash
fleet controller start \
  --host 0.0.0.0 \
  --port 7700 \
  --data-dir ./fleet-controller \
  --external-url http://192.168.0.10:7700
```

여기서 두 주소는 의미가 다릅니다.

- `--host 0.0.0.0`은 모든 network interface에서 연결을 받겠다는 bind 값입니다.
  Agent가 접속할 수 있는 주소가 아닙니다.
- `--external-url http://192.168.0.10:7700`은 Agent와 관리자가 실제로 사용하는
  주소입니다.

`--external-url`이나 `agent init --url`에는 절대로 `0.0.0.0`을 넣지 마세요.

선택한 port가 firewall에서 허용되어야 합니다. 다른 컴퓨터에서
`http://192.168.0.10:7700/admin`이 열리지 않는다면 Controller 실행 여부, IP 주소,
공유기/network 정책, 운영체제와 cloud firewall을 먼저 확인하세요.

### 3단계: Controller에서 Enrollment token 만들기

Controller 컴퓨터에서 실행합니다.

```bash
fleet enroll-token create \
  --data-dir ./fleet-controller \
  --labels role=web,env=test
```

출력된 token을 Agent 컴퓨터로 안전하게 전달합니다. Enrollment token은 유효기간이
짧으며, 채팅방·업무 티켓·소스 코드에 올리면 안 됩니다.

### 4단계: Agent 컴퓨터 설치와 초기화

Agent 컴퓨터에서 실행합니다.

```bash
npm install -g @sponzey/fleet
mkdir -p fleet-agent
fleet agent init \
  --data-dir ./fleet-agent \
  --url http://192.168.0.10:7700 \
  --token PASTE_ENROLLMENT_TOKEN_HERE \
  --name web-01 \
  --labels role=web,env=test
```

이어서 Agent를 시작합니다.

```bash
fleet agent start --data-dir ./fleet-agent
```

`http://192.168.0.10:7700/admin`을 열어 `web-01`이 online으로 표시되는지 확인합니다.

> `127.0.0.1`은 항상 “지금 이 컴퓨터”를 뜻합니다. Agent가 다른 컴퓨터에 있다면
> SSH tunnel을 사용하지 않는 이상 `127.0.0.1`을 Controller 주소로 쓰면 안 됩니다.

## 실제 운영이나 장시간 실행에는 HTTPS 사용하기

HTTP는 admin token, Agent 등록 과정, 작업, Agent 데이터를 암호화하지 않습니다.
HTTP는 로컬 연습, 사설 lab, 짧은 테스트에만 사용하세요. 운영 환경, 고객 환경, 여러
사람이 사용하는 환경, 인터넷에 연결된 환경, 장시간 실행하는 환경에서는 HTTPS가
필수입니다.

### 방법 A: Sponzey 내장 HTTPS

Controller에 인증서 체인과 private key를 준비한 다음 실행합니다.

```bash
fleet controller start \
  --host 0.0.0.0 \
  --port 7700 \
  --data-dir /var/lib/fleet \
  --external-url https://fleet.example.com:7700 \
  --tls-cert /etc/fleet/tls/fullchain.pem \
  --tls-key /etc/fleet/tls/privkey.pem
```

TLS private key는 Controller를 실행하는 계정만 읽을 수 있어야 합니다.

Agent도 같은 HTTPS 주소로 초기화합니다.

```bash
fleet agent init \
  --data-dir /var/lib/fleet \
  --url https://fleet.example.com:7700 \
  --token PASTE_ENROLLMENT_TOKEN_HERE \
  --name web-01 \
  --labels role=web,env=prod
```

사설 CA나 self-signed 인증서를 사용한다면 Agent 초기화 명령에 다음 옵션을
추가합니다.

```text
--tls-ca-cert /path/to/ca.pem
```

### 방법 B: HTTPS reverse proxy

Nginx, Caddy, cloud load balancer 같은 reverse proxy가 HTTPS를 처리하게 할 수도
있습니다. 이 경우 Sponzey는 Controller의 loopback에서만 실행합니다.

```bash
fleet controller start \
  --host 127.0.0.1 \
  --port 7700 \
  --data-dir /var/lib/fleet \
  --external-url https://fleet.example.com
```

Proxy가 HTTPS 요청과 WebSocket 연결을 모두 `127.0.0.1:7700`으로 전달하도록
설정해야 합니다.

## Web Admin에서 할 수 있는 일

Agent가 연결된 뒤 Web Admin에서 다음 작업을 할 수 있습니다.

- Agent online/offline 상태와 inventory 확인
- facts, metrics, drift history, 안전하게 정리된 Agent log 확인
- command와 runbook job 생성
- 여러 Agent 작업을 만들기 전에 selector 대상 미리 보기
- Agent별 assignment 상태와 job output 확인
- approval 요청 생성, 승인, 거절
- policy 저장·배정과 drift check 일정 설정
- 공개 catalog source, 검증된 revision, runbook/policy 메타데이터 확인
- remediation 진행 상태와 audit event 확인

**Run**이나 **Runbooks**에서 작업 기록을 선택하면 **Selected job** 영역이 열립니다.
Agent별 Assignment와 마지막 정상 갱신 시각은 관찰 상태와 따로 표시됩니다.
**Pause observation**은 조회만 멈추며 실행 중인 작업을 취소하지 않습니다.
**Resume observation**을 누르면 Controller에서 다시 조회합니다. 다른 메뉴로 갔다가
돌아와도 선택한 작업을 새로 읽습니다. **Clear token**은 이 페이지 메모리의 token을
지우고 Job·artifact 조회를 중단합니다.
같은 작업 기록을 두 화면에서 모두 열 수 있습니다. 좁은 화면에서는 Tab 키로
Assignment 표에 이동한 뒤 방향키로 오른쪽 열을 읽을 수 있습니다.

권한이나 연결 오류는 관찰을 멈추거나 잠시 재시도하게 할 뿐, 작업 실패를 뜻하지
않습니다. Artifact를 열어 볼 때도 관찰이 일시정지되며 직접 재개할 수 있습니다.
일부 Agent만 성공한 `partial_success`도 종료된 결과입니다. Agent별 Assignment에서
어느 대상이 성공하거나 실패했는지 확인하세요.
결과 화면은 저장 출력을 조금씩 나눠 읽습니다. 실시간 화면에서 보여 주는 양에는
한도가 있으며, 이전 내용이 표시 범위에서 빠지면 안내가 나옵니다. **Browse stored history**로
처음부터 읽고, **Next page**로 이어서 볼 수 있습니다. 다시 실시간 결과를 보려면
**Resume live observation**을 누르세요.
Jobs 목록은 조회 시점의 스냅샷입니다. **Refresh**로 목록을 갱신하거나 Job을 선택해
현재 결과를 확인하세요.

Job은 Agent로 보내기 전에 먼저 저장됩니다. Agent가 offline이면 assignment가 queued
상태로 남고, Agent가 다시 연결된 뒤 전달될 수 있습니다.

Linux와 macOS에서는 출력 처리 실패, 작업 취소, 제한 시간 초과 시 명령을 중단합니다.
같은 process group의 자식 프로세스도 정리하지만, 이미 바뀐 파일이나 설정을 되돌리지는
않습니다. 계속 켜 두어야 하는 서비스는 shell 명령을 백그라운드에 남기기보다
service 명령이나 runbook으로 관리하세요.

## Policy와 remediation을 쉽게 이해하기

**Runbook**은 “지금 이 단계들을 실행하라”는 문서입니다. **Policy**는 “이 상태가 계속
유지되어야 한다”는 문서입니다.

예를 들어 `role=web` label이 있는 모든 Agent에서 nginx가 실행 중이어야 한다는 policy를
만들 수 있습니다.

Remediation은 다음 순서로 진행됩니다.

1. 서명된 drift check가 컴퓨터 상태와 policy가 다르다고 보고합니다.
2. Controller가 remediation 제안을 만듭니다.
3. 운영자가 내용을 확인하고 승인합니다.
4. Controller가 runbook job을 만들고 서명합니다.
5. Agent가 job을 실행하고 결과를 보고합니다.
6. Controller가 verification check를 실행합니다.
7. 새로 확인된 compliant 증거가 remediation과 원본 drift를 resolved 처리합니다.

Remediation은 approval을 우회하지 않습니다. 예전 수동 `running`, `result`, `verify`
API/CLI 명령은 deprecated 상태이며 `409`를 반환합니다. 인증된 Agent event와 저장된
verification evidence가 실제 상태의 기준입니다.

전체 문법과 고급 예시는 [Runbook 문서](docs/runbooks.md),
[Policy 문서](docs/policy.md), [API 계약](docs/api.md)을 참고하세요.

## 공개 runbook·policy catalog 추가하기

Catalog는 검증 가능한 runbook과 policy 문서를 담은 공개 HTTPS Git 저장소입니다. Source를
등록해도 바로 내려받지 않고, sync가 끝나도 바로 활성화되지 않으며, 활성화해도 Agent에서
실행되지는 않습니다. 검토할 시간을 확보하기 위해 세 단계를 분리했습니다.
CI workflow처럼 catalog와 관계없는 YAML 파일은 건너뜁니다. 다만 Fleet `Runbook` 또는
`Policy`라고 선언한 파일은 sync가 성공하려면 반드시 올바른 문서여야 합니다.

Web Admin에서 **Runbooks** 또는 **Policies** 메뉴를 여세요. Catalog의 각 목록은
**First page**, **Next page**, **Retry**로 탐색합니다. source, revision, document 순서로
선택하며, 페이지를 바꿔도 선택했던 항목을 다른 것으로 자동 교체하지 않습니다. 목록 조회는
문서 본문을 내려받거나 Job을 실행하지 않습니다.

Source를 추가하려면 Catalog 패널의 **Manage catalog sources and revisions**를 펼치고 진행하세요.

1. 짧은 source ID, 공개 `https://` Git URL, 따라갈 branch 또는 tag를 입력한 뒤
   **Register source**를 누릅니다.
2. `sync-2026-08-31-01`처럼 새 operation ID를 입력하고 **Start sync**를 누릅니다.
   패널은 Controller가 반환한 실제 operation ID로 진행 중·완료·실패·취소를 확인합니다.
   접수는 완료가 아닙니다. **Stop observing**은 화면 추적을 멈추고 **Check again**은 상태 조회를
   재개합니다. 조회는 3분 뒤 멈춥니다. 요청 결과를 알 수 없으면 다시 제출하기 전에 확인하세요.
   화면은 변경 요청을 자동 재전송하지 않습니다. 기존 operation을 조회하려면 source와 실제 ID를
   입력하고 **Check entered operation**을 누릅니다.
3. Catalog를 새로 고친 뒤 source와 준비된(ready) revision을 선택합니다. 선택한 값이 **Source ID**와
   **Ready commit**에 채워집니다. **Activate ready revision**을 누르고 확인 창의 전체 source와 commit을
   검토한 뒤 **Activate exact revision**을 누릅니다. Cancel은 활성화 요청 없이 폼으로 돌아갑니다.
   활성 pointer는 Catalog 새로 고침으로 확인하세요. 활성화는 Job을 만들거나 실행하지 않습니다.

세 열은 source, revision, document의 메타데이터만 보여 줍니다. 문서 본문을 목록에
노출하지 않으며, sync 성공을 활성화로 간주하지도 않습니다.

활성화한 Runbook을 실행하려면 **Runbooks** 메뉴에서 다음 순서로 진행하세요.

1. source → 활성화된 ready revision → Runbook 문서를 선택합니다. Policy나 비활성 revision은
   여기서 실행할 수 없습니다. 활성 revision이 바뀌면 Catalog를 새로 고치고 원하는 문서를 다시 선택하세요.
2. **Run from this catalog**에서 `role=web,env=test`처럼 대상 label을 입력하고
   **Review document and targets**를 누릅니다. **Review stored Runbook**을 펼쳐 저장된 본문을
   읽으세요. 전체 source·commit·path·checksum과 선택된 Agent ID를 확인합니다.
   disabled Agent는 제외되며 offline Agent는 선택될 수 있습니다. 대상이 없으면 제출할 수 없습니다.
3. 검토 확인란을 체크하고 **Create catalog Job**을 누릅니다. 문서 참조와 검토한 Agent ID로
   승인 요청을 만듭니다. 이 확인란은 실행 승인을 대신하지 않습니다.
4. 같은 페이지의 **Approvals**에서 승인하거나 거절합니다. 승인한 뒤 **Selected job**에서
   Agent별 상태와 저장 출력을 확인하세요. 다른 revision을 활성화해도 Job의 원래 문서 출처는 유지됩니다.

문서·대상 label·메뉴·token을 바꾸면 현재 검토가 취소됩니다. 제출 응답이 시간 초과되면
재시도 전에 **Check stored Job ID**으로 결과를 확인하세요. Controller가 해당 Job이 없다고
확인한 경우 **Retry the same Job ID**로 같은 요청을 다시 보냅니다. 결과가 불명확하다고 화면이
자동으로 새 Job을 만들지는 않습니다.

`fleet login` 이후에는 source 등록·sync·활성화를 CLI로도 할 수 있습니다.

```bash
fleet catalog register public-operations https://example.com/operations.git main
fleet catalog sync public-operations sync-2026-08-31-01
fleet catalog list
fleet catalog activate public-operations READY_REVISION의_전체_COMMIT_ID
```

Catalog 등록·sync·활성화는 owner 또는 administrator만 할 수 있습니다. 공개 HTTPS
저장소만 사용하며 private 저장소 credential은 catalog 설정으로 지원하지 않습니다.

## 개인 계정과 선택 사항인 CLI 로그인

한 컴퓨터 실습의 공용 admin token은 초기 설정용입니다. 사람마다 아이디를 만들려면
먼저 Controller를 멈춥니다. Controller 컴퓨터에서 실습 때와 같은 폴더로 이동해 실행하세요.

```bash
fleet controller admin init-owner --data-dir ./fleet-controller --username owner
```

숨김 입력창에 새 비밀번호를 두 번 입력합니다. 15자 이상인 고유한 긴 문장을 사용하세요.
첫 owner가 생기면서 공용 token 사용이 영구 종료됩니다. 원래 데이터 폴더와 서명키는
보존하세요. 사용자 지정 `--db`를 쓰면 이 명령에도 같은 설정을 전달해야 합니다.
앞에서 사용한 시작 명령으로 Controller를 다시 켜고 `/admin`에서 `owner`로 로그인합니다.
여러 사람이 쓰거나 계속 운영할 때는 설정한 HTTPS 주소를 사용하세요.

owner는 **Settings → People**에서 다른 계정을 만들고 한 번 표시되는 설정 코드를
안전하게 전달합니다. 받은 사람은 15분 안에 로그인 화면의 **Set up or reset a password**에서
비밀번호를 정한 뒤 로그인합니다. 웹 로그인은 8시간이며 새로고침으로 늘어나지 않습니다.

CLI를 쓰려면 **Settings → My account → Connect CLI or API**에서 현재 비밀번호를
입력하고 개인 token을 만드세요. token은 30일 동안 유효하며 한 번만 표시됩니다.
본인 컴퓨터에서 주소를 실제 Controller HTTPS 주소로 바꿔 실행합니다.

```bash
fleet login --controller-url https://fleet.example.com
```

숨김 입력창에 개인 token을 붙여넣고 Enter를 누르세요. 계정 비밀번호를 넣는 곳이 아닙니다.
Fleet은 서버에서 token을 확인한 뒤 profile을 저장합니다. 자동화 도구는 `--token-stdin`으로
한 token을 stdin에 전달할 수 있습니다. shell 기록이나 환경변수에는 비밀값을 넣지 마세요.
이후 같은 폴더에서 다음 명령이 저장한 profile을 사용합니다.

```bash
fleet agents remote-list
fleet jobs list
fleet approvals list
fleet remediations list
fleet audit export --category security --limit 100
```

기본 profile은 현재 폴더 아래 `.fleet/cli-profile.json`입니다. 주소와 token이 들어 있으며
계정 비밀번호는 저장하지 않습니다. macOS/Linux에서는 본인 소유의 `0600` 권한 파일로
원자적으로 저장합니다. 공유하거나 commit하지 마세요. 다른 위치를 쓰려면 login과 이후
명령에 `--profile-path /본인의/비공개/경로/profile.json`을 지정하세요. 주소만 다른 서버로
바꿔 저장 token을 전송할 수는 없으므로, 해당 서버에 별도로 로그인해야 합니다.

사설 CA를 쓰는 Controller라면 `fleet login`에 `--tls-ca-cert /경로/public-ca.pem`을
추가하세요. profile은 공개 CA 파일의 경로를 기록하고 CLI 명령을 시작할 때 읽으므로,
그 파일은 본인 컴퓨터에 보관해야 합니다. 인증서·hostname 검증은 유지되며 시스템이나
브라우저의 신뢰 설정은 바뀌지 않습니다. 여기에 개인키 파일을 넣지 마세요.

CLI 접근은 **Settings → My account → Your personal tokens**에서 해당 token을 회수하면
끊어집니다. 이후 요청은 인증 오류를 받습니다. 무효·만료·회수 오류가 Agent 작업 실패를
뜻하지는 않습니다. 재인증한 뒤 기존 작업 결과를 확인하세요. 웹 로그아웃은 해당 웹 로그인만
끝냅니다. 비밀번호·역할 변경, 차단, reset은 그 사람의 모든 로그인과 token을 회수하지만
이미 접수된 Agent 작업은 계속됩니다.

모든 owner가 접근할 수 없게 됐다면 Controller를 멈추고 해당 서버에서 실행합니다.

```bash
fleet controller admin recover-owner --data-dir ./fleet-controller --username owner
```

기존 로그인 이름, 원래 데이터 폴더, 사용자 지정 `--db`가 있으면 같은 설정을 사용하세요.
새 비밀번호를 두 번 입력한 뒤 Controller를 다시 켜고 로그인합니다. 그 사람의 이전
credential은 회수됩니다. 원격 명령이나 서명키 재생성 기능은 아닙니다. 서명키가 없다면
백업에서 원본을 복구해야 합니다.

## Linux에서 계속 실행하기

systemd를 사용하는 Linux에서는 먼저 service가 사용할 data directory로 Controller나
Agent를 초기화합니다. 설치 전에 생성될 unit을 확인하세요.

```bash
fleet controller install-service \
  --data-dir /var/lib/fleet \
  --dry-run

fleet agent install-service \
  --data-dir /var/lib/fleet \
  --dry-run
```

Service 설치와 삭제에는 Linux와 root 권한이 필요합니다.

```bash
sudo fleet agent install-service --data-dir /var/lib/fleet
sudo fleet agent start-service
sudo fleet agent status-service
sudo fleet agent logs-service
```

Controller service 명령도 같은 형태입니다. 운영에 사용하기 전 dry-run 출력과
HTTPS/reverse proxy 설정이 맞는지 반드시 확인하세요.

## Controller 백업하기

업그레이드, migration, 다른 컴퓨터로 이동하기 전에는 Controller를 백업하세요.
SQLite에 쓰는 중이 아니도록 Controller와 이전 버전의 프로세스를 먼저 종료하세요.
백업과 실제 복원은 Controller와 같은 data-dir의 독점 잠금을 사용합니다.

```bash
fleet controller backup \
  --data-dir ./fleet-controller \
  --output ./fleet-controller.backup.json
```

백업에는 Controller 키와 운영 데이터가 들어 있습니다. 비밀 정보처럼 보관하세요.
새 파일을 0600 권한으로 만들며 같은 이름의 기존 파일은 덮어쓰지 않습니다.
dry-run은 원본과 복원 대상을 바꾸지 않고, 임시 private 파일에서 DB와 서명키를 검사한 뒤 삭제합니다.

원본과 복원 대상을 바꾸지 않고 백업을 검사하려면 다음 명령을 사용하세요.

```bash
fleet controller restore \
  --data-dir ./restore-check \
  --input ./fleet-controller.backup.json \
  --dry-run
```

빈 data directory에 복구하려면 다음처럼 실행합니다.

```bash
fleet controller restore \
  --data-dir ./fleet-controller-restored \
  --input ./fleet-controller.backup.json
```

실제 복구에서는 계정·비밀번호 검증 정보·Agent identity를 보존하지만 기존 웹 로그인·개인 토큰과
사용하지 않은 설정·재설정 코드는 모두 무효화합니다. 사용할 수 있는 owner가 없는 옛 백업은
서버에서 owner를 설정해야 하며 옛 공용 토큰을 다시 활성화하지 않습니다. 복구 전 Controller를 중지하세요.
private 임시 영역에서 검증한 뒤 디렉터리를 한 번에 교체합니다. 설치 후 정리 대기나 저장 확정 실패 경고가
나오면 Controller를 중지한 채 백업과 복원 대상을 확인하세요.

실제 복구에서는 Controller의 delivery namespace는 유지하고 store epoch는 새로 만듭니다.
Agent는 persistent session의 TaskAck, TaskStarted, TaskRejected, 확인되지 않은 Command와 artifact가 없는 Runbook의 stdout/stderr 조각, 그리고 artifact가 없는
Command/Runbook 최종 결과를 owner만 읽을 수 있는 `<agent-data-dir>/journal/reports.sqlite3`에
저장합니다. 전송 전에 저장하고, 연결이 끊겼다가 다시 연결되면 미확인 보고를 재전송합니다.
TaskStarted는 Command, Runbook, Drift 실행을 시작하기 전에 journal에 저장합니다. 실행 전 거절도
`TaskRejected`로 journal에 먼저 저장하며, Controller는 Agent·Job·Assignment 소유자를 확인합니다.
TaskAck, TaskStarted, 실행 전 TaskRejected의 상태 전이와 Job 집계·감사 기록·inbox 표식을 한 번에
저장한 뒤 서명된 `stored` receipt를 돌려줍니다. 거절 사유는 민감정보를 가린 채 저장하고,
아직 수락되지 않은 Assignment만 거절 상태로 바꿉니다. Agent는 해당 보고와 정확히 일치하는
receipt를 검증한 뒤에만 journal에서 지웁니다. Persistent DriftCheck의 evidence와 terminal `TaskResult`도
각각 별도 report와 receipt로 이 경로를 사용합니다. evidence receipt는 evidence 저장 확인이지 Job이나
Assignment 성공이 아니며, terminal result는 별도 receipt로 확인합니다. 일치하는 no-artifact DriftCheck
최종 보고가 G2 뒤 도착해도 기존 terminal 상태를 바꾸지 않습니다. artifact가 있는 Runbook 최종 보고는
인증된 v2 Controller 효과와 서명된 receipt를 사용하지만, Agent는 보고서와 artifact body를 journal에
저장하지 않습니다. SQLite Controller는 이미 inbox에 저장된 pending 최종 보고를 시작 시와 30초마다
제한된 묶음(최대 100건·본문 8 MiB)으로 재처리합니다. 저장된 본문과 소유 Agent를 다시 확인하고 효과를
commit한 뒤에만 receipt를 저장합니다. 효과는 이미 commit됐지만 receipt 저장이 빠진 경우에는 본문 없이
key/digest만 최대 100건씩 확인해 효과를 반복하지 않고 receipt를 복구합니다. 연결된 Agent가 있으면 단일
session writer로 전달합니다. 출력 누락,
손상·미지원 보고, 이미 끝난 Assignment는 성공으로 간주하지 않고 pending 상태로 둡니다. inbox에 저장되기
전에 연결이 끊기면 Agent가 이 artifact 보고를 재전송할 수 없습니다. Postgres 복구와 직접 실행하는
one-shot 결과는 별도/미지원 경로입니다.
G2가 Assignment를 `failed/execution_outcome_unknown`으로 확정한 뒤 같은 Agent의 lifecycle 보고가 도착하면
Controller는 Assignment·Job·G2 사유를 바꾸지 않고 감사 기록과 inbox 표식만 저장한 뒤 서명된 receipt를 보냅니다.
receipt는 보고를 저장했다는 뜻이지 작업 성공 증거가 아니며, 이를 확인한 Agent는 뒤에 남은 보고를 계속 재전송할 수 있습니다. 백업 시점 이후
Controller에서 이미 확인된 보고는 복구되지 않으며, task 실행이 만든 모든 출력 byte를
Agent가 전부 읽었다는 보장도 아닙니다. Persistent Command와 artifact가 없는 Runbook의 최종 보고에는 Agent journal에 저장한
stdout/stderr 조각 수와 출력이 잘렸는지가 포함됩니다. Controller는 보고된 조각이 stream별 순서대로
모두 저장될 때까지 결과를 확정하거나 receipt를 보내지 않으며, 출력이 잘린 작업을 성공으로 처리하지
않습니다. 이는 Agent가 journal에 저장한 조각의 전달을 확인하는 기능이지, 프로그램 출력 전체를
빠짐없이 수집한다는 뜻은 아닙니다. 이 요약은 active v2 형식에서 필수이며, 요약이 없는 구형 최종
보고를 받아주는 호환 fallback은 없습니다.
SQLite Controller는 시작할 때 listener를 열기 전에, 이후에는 30초마다 미완료 작업을 확인합니다.
작업 timeout에 5분의 유예 시간을 더한 시각이 지났는데 결과가 없으면 `failed`와
`execution_outcome_unknown`으로 표시합니다. 이는 작업이 실제로 실패했다는 뜻이 아니라 Controller가
실행 여부를 확인할 수 없다는 뜻이며, 같은 작업을 자동 재실행하지 않습니다. Postgres Controller는
복구 계약 구현이 끝날 때까지 시작되지 않습니다.
Controller와 모든 Agent를 함께 업그레이드해야 합니다. protocol v1 Agent는 거부되며 호환
fallback은 없습니다.

## 자주 생기는 문제

### `fleet: command not found`

전역 설치 후 새 터미널을 여세요. 그래도 안 되면 `$(npm prefix -g)/bin`을 확인하고
해당 경로를 `PATH`에 추가합니다.

### `controller is not initialized`

`fleet controller init`을 한 번 실행합니다. `controller init`과 `controller start`의
`--data-dir`이 정확히 같은지 확인하세요.

### `agent is not enrolled`

`fleet agent init`을 한 번 실행합니다. `agent init`과 `agent start`의 Agent
`--data-dir`이 정확히 같은지 확인하세요.

### Agent가 Controller에 연결되지 않음

다음 순서로 확인하세요.

1. Controller 터미널이나 service가 계속 실행 중인가요?
2. Agent가 자신의 `127.0.0.1`이 아니라 Controller의 IP 또는 DNS 이름을 사용하나요?
3. 운영체제와 cloud firewall에서 `7700` port가 열려 있나요?
4. Controller가 TLS를 사용한다면 URL도 `https://`로 시작하나요?
5. 사설 CA라면 Agent 초기화 때 `--tls-ca-cert`를 지정했나요?

### Web Admin에 Agent가 보이지 않음

Agent 터미널에서 등록, identity, 연결 오류를 확인하세요. Enrollment token은 보통 한
번만 사용할 수 있으므로 이미 사용한 token을 반복해서 쓰지 말고 새 token을 만드세요.

### `WARNING: insecure HTTP controller URL enabled`

오류가 아니라 경고입니다. 통신이 암호화되지 않았다는 뜻입니다. 로컬 또는 짧은
테스트가 아니라면 HTTPS를 사용하세요.

### Web Admin에 `{"error":"not_found"}`가 표시됨

`/admin` 주소를 여세요. 예: `http://127.0.0.1:7700/admin`

### Job이 계속 queued 상태임

대상 Agent가 offline이거나 앞선 assignment가 끝나기를 기다리고 있을 수 있습니다.
Agent를 시작하고 Job과 Audit 화면을 확인하세요. queued 작업을 완료된 것으로 처리하지
않습니다.

## 보안 주의사항

- Admin token, Enrollment token, private key, backup 파일을 commit하지 마세요.
- 실제 환경에서는 HTTPS를 사용하세요.
- Controller, Agent, TLS private key 파일은 필요한 service 계정만 읽을 수 있게 하세요.
- 권한이 필요한 작업을 실행하기 전에 target preview와 approval 내용을 확인하세요.
- 업그레이드나 위험한 유지보수 전에는 Controller를 백업하세요.

자세한 내용은 [보안 문서](docs/security.md), [저장소 문서](docs/storage.md),
[기능 매트릭스](docs/feature-matrix.md)를 참고하세요.

## API와 개발 문서

Controller는 다음 주소를 제공합니다.

```text
/admin         Web Admin
/openapi.json  OpenAPI 3.1 JSON
/swagger-ui    API 테스트 화면
```

HTTP로 연 Swagger UI에는 실제 admin token을 입력하지 마세요.

화면 테스트를 실행하기 전에 개발용 의존성을 설치합니다. 여러 OS/CPU의 배포 패키지가 한 workspace에 있어 개발용 설치에만 --force를 쓰며 설치 script는 끕니다. jsdom은 테스트 전용이며 Fleet 실행 파일에 포함되지 않습니다.

```bash
npm ci --workspace web-admin --force --ignore-scripts
```

개발자가 주로 사용하는 검증 명령은 다음과 같습니다.

```bash
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
npm test --workspace @sponzey/fleet
npm test --workspace web-admin
npm run typecheck --workspace web-admin
npm run build --workspace web-admin
```

전체 release 절차는 [release gate](docs/release-gate.md)를 참고하세요.

## 라이선스

Sponzey Fleet는 GNU Affero General Public License version 3 only
(`AGPL-3.0-only`)를 사용합니다. 별도 표시가 없는 한 Rust workspace, Web Admin, npm
wrapper, 배포 binary에 같은 라이선스가 적용됩니다. [LICENSE](LICENSE)와
[라이선스 설명](docs/license.md)을 참고하세요.
