# Repository script source index

These scripts run local checks, package staging, release verification and
operator rehearsals. They do not own Fleet domain or controller state.

| Path | Kind | Responsibility | Boundary / Side effects |
| --- | --- | --- | --- |
| `test_manual_admin_identity_smoke.py` | Test | Verifies implicit-reset preservation, owned-child cleanup, nested Controller lease/symlink rejection and embedded contract build-proof invalidation. | Isolated temporary fixtures, local flock and mocked builds only; no real Fleet data, process, VM or service. |
| `test_hardening_environment_guards.py` | Test | Verifies known child-fixture environment reads, path-scoped exceptions and rejection of production reads, unknown fixture variables and mutation. | Minimal temporary source trees and a copied audit script; reaching a later missing gate is separate from full repository audit success. |
| `check_linux_glibc_baseline.sh` | Tooling | Checks Linux release binary baseline | Inspects binary metadata |
| `catalog_performance_gate.sh` | Tooling | Records and compares catalog benchmark timing evidence | Runs a deterministic Cargo test and writes/reads benchmark reports |
| `catalog_performance_gate.py` | Tooling | Implements catalog timing report validation and comparison | Runs benchmark subprocesses and reads/writes report JSON |
| `hardening_audit.sh` | Tooling | Audits source and package hardening invariants | Reads repository files |
| `manual_linux_nginx_runbook_smoke.sh` | Tooling | Rehearses Linux nginx runbook behavior | Manual privileged host actions |
| `manual_npm_registry_smoke.sh` | Tooling | Rehearses installed registry package behavior | Network/npm registry access |
| `manual_systemd_reboot_smoke.sh` | Tooling | Installs Fleet systemd services in a fresh data directory and checks service persistence | Disposable-host confirmation; writes `/etc/systemd/system` and the selected data directory |
| `manual_task_recovery_smoke.py` | Tooling | Verifies Command output/result recovery after Controller restart, Agent restart, and host reboot | Requires an approved test command, root/systemd, interactive token input, and a disposable VM; reboot remains operator-controlled |
| `manual_admin_identity_smoke.py` | Tooling | Proves the fixed debug binary/source/embedded contracts/assets and rehearses first-owner cutover, local recovery, dry-run, two-epoch restore, audit rollback, offline contention and old-backup local setup. | Marked private fixture and loopback HTTP only; owns process cleanup, keeps raw credentials/output in memory and writes metadata proof. Reset locks outer/nested Controller roots before changing proof/data. Synthetic credential rows are separate from personal-login acceptance. |
| `test_manual_task_recovery_smoke.py` | Test | Checks recovery expectations including exact Controller/Agent unknown-outcome error forms, generated probe output/marker writes and quoting, loopback-only API access, and reboot state shape | Runs harmless shell probes in temporary directories with stubbed delay/sync; no Fleet service or network access |
| `npm_demo_smoke.sh` | Tooling | Verifies packed wrapper demo flow | Builds and executes temporary package |
| `npm_local_pack_smoke.sh` | Tooling | Verifies packed wrapper launcher | Builds and executes temporary package |
| `npm_platform_local_install_smoke.sh` | Tooling | Verifies optional platform package installation | Builds, packages and executes temporary install |
| `npm_publish_current_platform.sh` | Tooling | Publishes/dry-runs the current platform package | npm registry credentials and publication |
| `npm_stage_current_platform.sh` | Tooling | Stages current native platform package | Builds and writes staging artifacts |
| `release_readiness_gate.sh` | Tooling | Runs local release readiness checks and suppresses leaked smoke credentials | Executes verification commands |
| `run_agent.sh` | Tooling | Starts local Fleet Agent development process | Executes Fleet binary |
| `run_controller.sh` | Tooling | Rebuilds embedded assets and forwards explicit Controller commands, shorthand init/admin or bare start options. | Executes the fixed debug Fleet binary; initialization preflight applies only to start. |
| `test_run_controller_script.py` | Test | Checks Controller/admin/init/help/start argument forwarding and start-only initialization preflight, including paths with spaces. | Temporary no-op Cargo and fixture argument recorder; no product binary replacement, service, credential or network access. |
| `sign_release_sums.sh` | Tooling | Signs release checksums | Reads signing material and writes signature |
| `signature_verification_smoke.sh` | Tooling | Verifies release signature workflow | Builds temporary artifacts |
| `smoke_immediate_dispatch.sh` | Tooling | Verifies immediate task dispatch | Starts local Fleet processes |
| `smoke_mvp.sh` | Tooling | Verifies MVP controller-agent workflow without printing its admin token | Starts local Fleet processes |
| `smoke_remote_tls_loopback.sh` | Tooling | Verifies TLS loopback workflow | Starts local Fleet processes |
| `storage_decision_gate.sh` | Tooling | Checks storage decision prerequisites | Reads repository state |
| `test_catalog_performance_gate.js` | Test | Verifies catalog benchmark report validation and threshold policy | Creates disposable JSON report fixtures and executes the gate script |
| `verify_release_signature.sh` | Tooling | Verifies signed release checksums | Reads public key and artifacts |
| `verify_standalone_artifacts.sh` | Tooling | Verifies standalone release artifacts | Reads release artifacts |
