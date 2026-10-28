# Sponzey Fleet Release Gate

작성일: 2026-07-07

이 문서는 release 전 반드시 확인할 검증 명령과 smoke check를 정리한다.

## Required Local Gate

일반 개발 머신에서 release 후보를 확인할 때 실행한다.

Web Admin의 DOM 검증은 jsdom 개발 의존성을 쓴다. 아래 npm ci는 여러 OS/CPU workspace의 metadata를 함께 설치하므로 --force를 쓰고 script 실행은 끈다. 제품 binary·platform 선택과 Trusted Publishing 정책은 바꾸지 않는다.

```bash
npm ci --workspace web-admin --force --ignore-scripts
```



```bash
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
npm test --workspace @sponzey/fleet
npm test --workspace web-admin
npm run typecheck --workspace web-admin
./scripts/npm_local_pack_smoke.sh
./scripts/npm_platform_local_install_smoke.sh
./scripts/npm_demo_smoke.sh
./scripts/smoke_mvp.sh
./scripts/smoke_immediate_dispatch.sh
./scripts/smoke_remote_tls_loopback.sh
./scripts/signature_verification_smoke.sh
./scripts/storage_decision_gate.sh
./scripts/hardening_audit.sh
git diff --check
```

## Focused Store Gate

Schema, repository, backup/restore compatibility를 변경한 task는 Required Local Gate에
앞서 아래 빠른 gate를 먼저 실행한다.

```bash
cargo test -p fleet-store migration_from_versioned_previous_fixture_adds_columns_without_losing_rows
cargo test -p fleet-store sqlite_store_implements_application_repository_contracts
cargo test -p fleet-store controller_delivery_identity
cargo test -p fleet-store sqlite_inbox
cargo test -p fleet-store sqlite_inbox_output_
cargo test -p fleet-store sqlite_pending_final_report
cargo test -p fleet-store sqlite_inbox_simple_final_effect
cargo test -p fleet-store sqlite_inbox_final_effect_refuses
cargo test -p fleet-store sqlite_inbox_failed_final
cargo test -p fleet-store sqlite_inbox_artifact_final
cargo test -p fleet-store sqlite_inbox_remediation_final
cargo test -p fleet-controller committed_inbox_remediation_final_is_recovered_into_one_verification_job
cargo test -p fleet-store verification_resolution_recovery_lists_only_bounded_durable_successes
cargo test -p fleet-controller persisted_verification_result_and_evidence_resolve_remediation_after_restart
cargo test -p fleet-store assignment_recovery
cargo test -p fleet-controller assignment_recovery
cargo test -p fleet-controller authenticated_final_result_commits_and_replays_stored_receipt
cargo test -p fleet-store sqlite_command_final_waits_for_exact_output_chunk_prefix_before_commit
cargo test -p fleet-store sqlite_truncated_command_final_is_never_success_and_audit_keeps_only_summary
cargo test -p fleet-store sqlite_no_artifact_runbook_final_waits_for_exact_output_prefix
cargo test -p fleet-protocol final_result_body_requires_strict_output_summary
cargo test -p fleet-runner output_chunks_keep_sequence_order
cargo test -p fleet-cli persistent_command_final_result_replays_after_reopen_and_exact_receipt_cleans_it
cargo test -p fleet-cli command_output_journal_failure_never_commits_a_final_summary
cargo test -p fleet-cli persistent_runbook_no_artifact_final_result_is_journaled_and_replays_after_reopen
cargo test -p fleet-cli persistent_runbook_final_result_is_journaled_even_when_output_queue_is_full
cargo test -p fleet-cli runbook_final_status_reflects_failed_or_canceled_step_outcomes
cargo test -p fleet-cli canceled_before_start_runbook_final_result_is_journaled_without_legacy_event
cargo test -p fleet-controller authenticated_late_g2_runbook_final_result_gets_receipt_without_changing_terminal_state
cargo test -p fleet-cli persistent_command_commits_start_intent_before_child_and_completes_record_with_result
cargo test -p fleet-cli journal_admission_failure_prevents_task_ack_and_command_side_effect
cargo test -p fleet-cli new_agent_process_converts_interrupted_admission_and_start_to_typed_final_reports
cargo test -p fleet-cli same_process_reconnect_skips_live_owner_then_reconciles_after_owner_ends
cargo test -p fleet-store sqlite_late_final_after_g2_is_dispositioned_once_without_overwriting_terminal_state
cargo test -p fleet-controller authenticated_late_g2_final_result_gets_receipt_without_changing_terminal_state
cargo test -p fleet-controller drift_report_message_is_stored_and_audited
cargo test -p fleet-store controller_inbox_v25_migration_preserves_receipts_and_accepts_drift_evidence
cargo test -p fleet-store drift_evidence_class_migrates_v3_journal_and_preserves_existing_reports
cargo test -p fleet-store sqlite_drift_proposal_audits_and_inbox_marker_rollback_together
cargo test -p fleet-cli persistent_drift_evidence_report_is_journaled_and_replays_exactly_after_reopen
cargo test -p fleet-controller authenticated_drift_evidence_receipt_commits_effects_once_without_completing_job
cargo test -p fleet-cli persistent_drift_check_terminal_result_is_journaled_and_replays_after_reopen
cargo test -p fleet-store sqlite_late_drift_final_after_g2_is_dispositioned_without_terminal_downgrade
cargo test -p fleet-controller authenticated_late_g2_drift_final_preserves_terminal_state_and_replays_receipt
cargo test -p fleet-controller authenticated_artifact_final_result_commits_prepared_body_and_replays_receipt
cargo test -p fleet-store sqlite_inbox_artifact_final_retries_after_metadata_failure_without_partial_db_effect
cargo test -p fleet-cli persistent_runbook_no_artifact_final_result_is_journaled_and_replays_after_reopen
cargo test -p fleet-controller legacy_result_retry_after_artifact_failure_preserves_partial_commit
cargo test -p fleet-cli missing_program_task_commits_stderr_and_final_result_before_delivery
cargo test -p fleet-cli canceled_before_start_command_final_result_is_journaled_without_legacy_event
cargo test -p fleet-cli timed_out_persistent_command_journals_final_result_instead_of_legacy_event
cargo test -p fleet-store local_artifact_store_put_replay_never_replaces_existing_object
cargo test -p fleet-store local_artifact_store_put_rejects_existing_symlink
cargo test -p fleet-store controller_inbox_schema_migrates_v23
cargo test -p fleet-store newer_controller_schema_is_rejected
cargo test -p fleet-cli controller_restore_refuses_incompatible_schema_version
cargo test -p fleet-cli controller_backup_restore_roundtrip_restores_database_and_keys
cargo test -p fleet-controller task_result_from_other_authenticated_agent_cannot_complete_assignment
cargo test -p fleet-protocol rejects_v1_session_message_after_protocol_hard_cut
cargo test -p fleet-protocol v2_auth_acceptance_requires_delivery_identity
cargo test -p fleet-protocol rejects_v1_controller_auth_acceptance_after_protocol_hard_cut
cargo test -p fleet-protocol auth_accepted_roundtrips_controller_delivery_identity
cargo test -p fleet-protocol active_session_message_size_is_bounded
cargo test -p fleet-cli authenticated_session_requires_valid_controller_delivery_identity
cargo test -p fleet-controller authenticated_session_acceptance_contains_durable_controller_identity
cargo test -p fleet-protocol rejects_v1_session_message_after_protocol_hard_cut
cargo test -p fleet-protocol auth_accepted_roundtrips_controller_delivery_identity
cargo test -p fleet-cli authenticated_session_requires_valid_controller_delivery_identity
cargo test -p fleet-controller authenticated_session_acceptance_contains_durable_controller_identity
cargo test -p fleet-protocol active_v2_report_payloads_roundtrip_through_session_envelope
cargo test -p fleet-protocol active_v2_report_envelope_validates_body_digest_and_owner
cargo test -p fleet-protocol active_session_message_size_is_bounded
cargo test -p fleet-controller authenticated_output_report_reissues_after_signing_key_rotation_without_repeating_effect
cargo test -p fleet-controller authenticated_websocket_commits_and_returns_persisted_output_receipt
cargo test -p fleet-controller authenticated_websocket_commits_and_returns_persisted_output_and_lifecycle_receipts
cargo test -p fleet-controller authenticated_late_g2_lifecycle_reports_get_receipts_without_changing_terminal_state
cargo test -p fleet-store sqlite_inbox_task_ack_effect_commits_assignment_job_audit_and_marker_atomically
cargo test -p fleet-store sqlite_inbox_task_started_effect_commits_assignment_job_audit_and_marker_atomically
cargo test -p fleet-store sqlite_inbox_task_rejected_effect_commits_terminal_reason_job_audit_and_marker_atomically
cargo test -p fleet-store sqlite_inbox_late_g2_lifecycle_reports_commit_disposition_without_changing_terminal_state
cargo test -p fleet-protocol task_ack_lifecycle_body_is_strict_and_stable
cargo test -p fleet-protocol task_started_lifecycle_body_is_strict_and_stable
cargo test -p fleet-protocol task_rejected_lifecycle_body_is_strict_and_stable
cargo test -p fleet-cli persistent_task_rejection_replays_after_reopen_and_cleans_only_after_signed_receipt
cargo test -p fleet-cli persistent_command_commits_start_intent_before_child_and_completes_record_with_result
cargo test -p fleet-cli agent_report_delivery_orders_task_ack_started_then_rejected_before_final_result
cargo test -p fleet-cli agent_report_scan_does_not_resurrect_a_receipt_acknowledged_row
cargo test -p fleet-controller stored_report_receipt_uses_the_single_session_writer_queue
cargo test -p fleet-cli command_output_is_committed_to_agent_journal_with_stable_exact_report_identity
cargo test -p fleet-cli journaled_command_output_replays_after_reopen_and_stale_restore_epoch_receipt_cannot_clean_it
cargo test -p fleet-agent forged_or_wrong_identity_receipts_do_not_authorize_cleanup
cargo test -p fleet-store sqlite_signed_receipt_rejects_pending_digest_epoch_and_reissues_for_current_signer
cargo test -p fleet-store sqlite_signed_receipt_reissues_exact_committed_report_after_signing_key_rotation
cargo test -p fleet-store output_retention_keeps_committed_report_tombstone_and_receipt_without_resurrecting_output
cargo test -p fleet-agent receipt_verifier::tests::previous_signer_is_accepted_only_within_rotation_grace
cargo test -p fleet-cli agent_report_retry_delay_is_bounded_exponential
```

이 gate는 test fixture path를 env var로 받지 않아야 하며, runtime DB URL 또는
process env를 중간에 변경하지 않아야 한다.

`dist/release/SHA256SUMS`가 존재하면 standalone artifact도 검증한다.

```bash
./scripts/verify_standalone_artifacts.sh dist/release
```

`dist/release/SHA256SUMS.sig`가 존재하면 release public key를 명시해 checksum
manifest signature도 검증한다.

```bash
./scripts/verify_release_signature.sh dist/release ./release-public-key.pem
```

Tagged releases and manual workflow runs are fail-closed: the release workflow
requires the `RELEASE_SIGNING_PRIVATE_KEY` repository secret and the matching
committed `docs/release-signing-public.pem`. It verifies the pair before
publishing `SHA256SUMS.sig` and the public key with tagged release assets. A
manual dry-run retains only `SHA256SUMS`, its detached signature, and the
public key as a short-lived verification artifact; it does not publish npm
packages or create a GitHub Release. This signing key is separate from npm
Trusted Publishing and is never written to an artifact.

`target/release/fleet`가 존재하면 Linux release binary는 glibc baseline도 확인한다.

```bash
./scripts/check_linux_glibc_baseline.sh target/release/fleet
```

## One Command Gate

가능하면 release 전 아래 script를 사용한다.

```bash
./scripts/release_readiness_gate.sh
```

이 script는 local pack, platform package, npm demo, MVP smoke, immediate
dispatch smoke, remote TLS loopback smoke, release signature fixture smoke,
artifact store decision/settings boundary check, optional standalone artifact
verification, optional real signature verification, hardening audit를 함께 실행한다.
실제 release signature 검증에 기본값이 아닌
public key가 필요하면 명시적으로 전달한다.

```bash
./scripts/release_readiness_gate.sh --release-public-key ./release-public-key.pem
```

## Manual Linux Gate

systemd, nginx runbook, reboot persistence처럼 destructive하거나 root 권한이
필요한 항목은 일반 local gate에 포함하지 않는다. 사용자 데이터가 없는
disposable Linux VM에서만 실행한다. Fleet data directory는 새롭고 비어 있어야 하며
Fleet systemd unit이 이미 설치되어 있으면 preflight에서 중단한다. 이 gate는
`/etc/systemd/system`과 선택한 data directory에 persistent change를 만들고
nginx package/service도 설치할 수 있으므로 snapshot 또는 복구 경로를 먼저 확인한다.

```bash
sudo env FLEET_MANUAL_DISPOSABLE_CONFIRMATION=YES \
  FLEET_DATA_DIR=/var/lib/fleet-task056 \
  ./scripts/release_readiness_gate.sh --include-manual
```

초기화 시 admin token이 한 번 출력된다. 복구 smoke에서 사용하므로 안전한 곳에
임시 보관하고, 명령 실행 시 표시되지 않는 입력 프롬프트에 붙여 넣는다. token은
smoke state나 명령행에 저장되지 않는다. 설치 후 같은 data directory를 지정해
Controller 재시작, Agent 강제 재시작, reboot 준비를 순서대로 실행한다.

```bash
sudo env FLEET_MANUAL_DISPOSABLE_CONFIRMATION=YES FLEET_DATA_DIR=/var/lib/fleet-task056 \
  python3 scripts/manual_task_recovery_smoke.py controller-restart
sudo env FLEET_MANUAL_DISPOSABLE_CONFIRMATION=YES FLEET_DATA_DIR=/var/lib/fleet-task056 \
  python3 scripts/manual_task_recovery_smoke.py agent-restart
sudo env FLEET_MANUAL_DISPOSABLE_CONFIRMATION=YES FLEET_DATA_DIR=/var/lib/fleet-task056 \
  python3 scripts/manual_task_recovery_smoke.py prepare-reboot
```

`prepare-reboot`는 in-flight Command와 synced side-effect marker만 준비하며 reboot하지
않는다. 출력된 job id/marker 정보를 확인한 뒤 disposable VM을 수동 reboot한다.
복귀 후 Controller/Agent service 및 저장된 결과를 확인한다.

```bash
sudo reboot
sudo env FLEET_DATA_DIR=/var/lib/fleet-task056 \
  ./scripts/release_readiness_gate.sh --verify-manual-reboot
```

Controller restart는 성공 결과·output과 단일 side effect를, Agent 강제 종료와 host
reboot는 stored output과 `failed/execution_outcome_unknown`, 재실행되지 않은 marker를
확인한다. 재부팅 검증 후 token을 보관하던 임시 복사본을 안전하게 제거한다.

## Live PostgreSQL Store Gate

The feature-only Postgres tests do not connect to a database. For a live Store
contract check, set `FLEET_TEST_POSTGRES_URL` in the test process environment to
an empty, dedicated disposable database. Never point it at production or a
shared database: the tests run migrations and delete fixture rows. Use a fresh
database for each full run and serialize the shared fixtures:

```bash
cargo test -p fleet-store --features postgres postgres_ -- --ignored --test-threads=1
```

This runs the ignored `postgres_*` Store integration tests. Keep URL credentials
out of command logs and reports. This gate validates the Postgres Store
repository contracts; it does not claim Controller report/receipt recovery on
Postgres, which remains unsupported.

## Registry Gate

npm registry publish 이후 실제 global install 경로를 확인한다.

```bash
./scripts/release_readiness_gate.sh --include-registry
```

## Stale Documentation Scan

문서 갱신 task에서는 아래 scan을 반드시 확인한다.

```bash
rg -n --glob '!docs/release-gate.md' "dev-insecure-loopback|insecure remote HTTP|planned release package|fleet agent enroll|agent enroll --" README.md README.ko.md PROJECT.md docs npm
```

허용 가능한 결과:

- 과거 phase 설명 또는 compatibility note로 명확히 표시된 경우
- `agent enroll` alias를 의도적으로 compatibility note로 설명하는 경우

허용하지 않는 결과:

- 현재 getting started 경로에 존재하지 않는 옵션이 남은 경우
- HTTP 원격 사용 정책이 현재 구현과 반대로 설명된 경우
- 이미 publish되는 platform package를 planned로 설명하는 경우
- 현재 권장 UX인 `agent init` 대신 `fleet agent enroll`을 기본 예시로 사용하는 경우

## Current-State Review Scan

MVP 계획 또는 current-state 문서를 갱신하는 task에서는 아래 scan을 확인한다.
이 scan은 0건을 요구하는 gate가 아니라, 결과가 현재 feature matrix, release
notes, policy 문서의 Known Limits 또는 Planned/Partial 상태와 일치하는지
리뷰하는 manual gate다.

```bash
rg -n "follow-up|후속|not implemented|Planned|Current MVP Limits|Known Limits" docs README.md README.ko.md
```

허용 가능한 결과:

- `docs/feature-matrix.md`의 `Planned` 또는 `Partial` 상태가 `.tasks/plan.md`의 남은 phase와 일치하는 경우
- `docs/release-notes-mvp.md`의 Known Limits가 아직 구현되지 않은 multi-controller scheduled drift/retention coordination, official release key publication, capability hardening follow-up을 명시하는 경우
- README의 follow-up 설명이 즉시 사용 가능한 대체 command 또는 현재 제한을 함께 설명하는 경우

허용하지 않는 결과:

- 이미 구현된 기능을 current-state 문서에서 `not implemented`로 설명하는 경우
- `.tasks/plan.md`의 phase와 맞지 않는 과거 `Task NNN` 참조가 남은 경우
- policy, security, protocol 문서가 HTTP test-only, approval, audit, capability, replay 정책을 서로 다르게 설명하는 경우

## Completed MVP P0 Gate

`.tasks/phase005/plan.md`의 MVP P0 목표는 완료된 기준선으로 보관되어 있다. 현재
Required Local Gate에는 MVP에서 추가된 capability, replay, scheduled drift,
retention, schema fixture, CLI profile, Web Admin target preview, release
signature smoke가 포함되어야 한다. 해당 smoke가 빠지면 release 후보로 보지 않는다.

## Feature Gate Map

현재 전체 순서는 [프로젝트 계획](../.docs/plans/plan.md), 기능별 지원 상태는
[기능 지도](../.docs/product/capabilities.md)가 소유한다. 아래는 경계별 검증 연결이다.
기존 gate를 유지하며 새 기능의 gate는 그 구현과 함께 추가한다. 모든 행이 미구현이거나
현재 release에 무조건 추가되는 것은 아니다. 실제 실행 여부는 사례별 증거로 확인한다.

| Gate | Feature ID | Required validation / current distinction |
| --- | --- | --- |
| Runbook/artifact | RBK-001, RES-003 | render/checksum/metadata regression; Agent artifact pre-inbox replay와 file/DB orphan는 별도 미완료 |
| Remediation | DRF-001 | approval/job/result/audit, report 순서·freshness·owner·origin-only resolution, atomic rollback 회귀 |
| Reliable reporting / Linux recovery | RES-001/002 | local replay/receipt/output coverage와 실제 Controller restart·Agent kill/restart·host reboot 사례를 구분. Linux 세 사례 미실행이면 P-01 미완료 |
| Output observation | UI-001 | long-running/route return/race/auth/cancel, cursor/retention, request/byte baseline, 실제 browser |
| Catalog execution | CAT-001/002 | existing fake Git/activation/provenance/paging/deterministic gate 유지; Admin active selection→approval→Job 연결 추가. Timing workflow 존재는 실제 pinned-runner PASS와 다름 |
| Local administrator identity | IAM-001 | owner/self 직접 API matrix·고정 만료·최신 권한 commit·두 사용자 HTTPS browser/API/CLI·Linux 작업 중 credential 회수·전환/복구/restore·bounded 인증 부하와 비밀/자원 회수 |
| Project scope | IAM-002 | 별도 project membership·direct-ID isolation. 로컬 계정 인수로 대체하지 않음 |
| Secret provider | SEC-002 | 실제 adapter integration·lease/rotation·negative permission/redaction, body omission |
| Postgres | EXT-002 | shared repository·live DB + Assignment/report recovery·startup·restore·soak. Store PASS만으로 Controller 지원 아님 |
| Artifact lifecycle | RES-004, EXT-003 | retention·quota·disk-full·replay cutoff·orphan와 local/S3 adapter 계약 |
| Trust / mTLS | SEC-001, EXT-001 | signing rollout 회귀와 별도 client cert listener enforcement·issue/renew/revoke tests |
| Notification/export | EXT-004 | redacted payload, bounded retry/dedup, destination failure |
| Installer/package/update | REL-001, EXT-005 | 기존 archive signature/wrapper 회귀; 신규 package·signed update/rollback은 별도 |
| HA | EXT-007 | two-controller leader/lease/fencing/claim·crash/partition |
| Compliance audit | EXT-008 | tamper detection, signed manifest, restore·retention. WORM 주장 금지 |
| Cross-platform | EXT-006 | capability별 실제 Windows/macOS 서비스·primitive/cancel gate |
| Import/plugin | EXT-009/010 | subset unsupported report·no-execution import; signed manifest·disabled default·timeout/output limit |
| Scale/load | QUA-001 | 승인한 hardware/workload·latency/resource/회귀 기준과 reproducible baseline/soak. 총 1000 Job 후보와 1000 output chunk fixture는 다름 |

## Release Gate 원칙

로컬 계정 인수는 exact source/binary/assets·TLS hostname/신뢰 경로·SQLite·격리 Agent를 기록한다.
브라우저 인증서 예외는 사람이 해당 시험 사이트에서 수행한 사실과 API/CLI/Agent의 명시적 CA 검증을 구분한다.
일반 HTTP fixture·합성 DB row·PG feature compile을 실제 HTTPS 로그인/실DB 인수로 세지 않는다.
로그인 부하에서 worker/queue 한도·typed 거절, 기존 heartbeat·작업 deadline·중복 없음과
protected-read/RSS 관측을 보고한다. 같은 조건이 아닌 측정을 속도 개선이나 전체 Fleet SLA로 표현하지 않는다.
Node typecheck script의 API surface/config 검사는 실제 TypeScript compiler 실행과 구분한다.
registry publish·배포 archive/signature·glibc release baseline·root/reboot gate는 해당 출시 범위에서 별도 수행한다.

- release gate는 runtime env patch나 숨은 config file을 요구하지 않아야 한다.
- HTTP smoke는 test-only warning이 유지되는지 확인해야 한다.
- HTTPS smoke는 production path가 문서상 존재함을 확인해야 한다.
- Web Admin smoke는 API schema와 UI client가 어긋나지 않게 해야 한다.
- registry smoke는 사용자 설치 경로에서 `fleet --help`가 실행되는지 확인해야 한다.
