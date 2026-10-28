#!/usr/bin/env python3
"""Exercise local owner cutover, recovery and restore in the marked private fixture.

Uses the fixed debug Fleet binary and loopback HTTP. Kills only its own waiting
owner process, injects/removes one fixture-only SQLite audit trigger, and preserves
fixture data after success. --reset-fixture deletes only the marked fixture's data
child after confirming no participating Controller holds its lease. Raw generated
password/tokens and captured process output stay in memory; proof JSON is metadata.
Credential rows seeded below are synthetic repository fixtures, not native login/API evidence.
"""

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / "target/debug/fleet"
EMBEDDED_CONTRACTS = ("docs/openapi.json", "docs/swagger-ui.html")
FIXTURE = ROOT / "target/iam-rehearsal/local-owner"
PURPOSE = "codex-owned-local-owner-rehearsal"
TABLES = ("agents", "agent_identities", "admin_tokens", "audit_events", "admin_auth_state", "admin_accounts", "admin_credentials")


class RehearsalFailure(Exception):
    """Carries a static diagnostic code, never captured output or request data."""


def require(condition, code):
    if not condition:
        raise RehearsalFailure(code)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_proof(value):
    with private_file(FIXTURE / "proof.json") as stream:
        stream.seek(0)
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.truncate()


def build_current_binary():
    """Records Rust/manifest inputs, embedded API/docs and assets for the fixed binary."""
    record = ROOT / "target/iam-rehearsal/fleet-binary-build.json"
    original = None
    if record.exists():
        metadata = record.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid()
                and metadata.st_nlink == 1 and not stat.S_IMODE(metadata.st_mode) & 0o022, "unsafe_build_record")
        previous = json.loads(record.read_text())
        require(previous["purpose"] == "codex-owned-iam-acceptance" and previous["owner_uid"] == os.geteuid(), "foreign_build_record")
        original = previous.get("initial_before", previous.get("before"))
    inputs = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", *(ROOT / path for path in EMBEDDED_CONTRACTS)]
    for crate in sorted((ROOT / "crates").iterdir()):
        if (crate / "Cargo.toml").is_file():
            inputs.append(crate / "Cargo.toml")
            inputs.extend(sorted((crate / "src").rglob("*.rs")))
            if (crate / "build.rs").is_file():
                inputs.append(crate / "build.rs")
    assets = sorted(path for path in (ROOT / "web-admin").iterdir() if path.suffix in (".js", ".css", ".html", ".json"))
    before = None if not BINARY.exists() else {"sha256": digest(BINARY), "size": BINARY.stat().st_size, "mtime_ns": BINARY.stat().st_mtime_ns}
    data = {"purpose": "codex-owned-iam-acceptance", "owner_uid": os.geteuid(), "status": "before-build",
            "binary_path": "target/debug/fleet", "before": before, "initial_before": original or before,
            "sources": {str(path.relative_to(ROOT)): digest(path) for path in inputs},
            "assets": {str(path.relative_to(ROOT)): digest(path) for path in assets}}
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(json.dumps(data, indent=2) + "\n")
    built = subprocess.run(["cargo", "build", "--manifest-path", str(ROOT / "Cargo.toml"), "-p", "fleet-cli"],
                           cwd=ROOT, text=True, capture_output=True, timeout=180, check=False)
    (record.parent / "fleet-binary-build.log").write_text(built.stdout + built.stderr)
    require(built.returncode == 0, "official_binary_build_failed")
    for group in ("sources", "assets"):
        require(all(digest(ROOT / path) == expected for path, expected in data[group].items()), "source_changed_during_build")
    data["after"] = {"sha256": digest(BINARY), "size": BINARY.stat().st_size, "mtime_ns": BINARY.stat().st_mtime_ns}
    data["status"] = "rebuilt-current"
    record.write_text(json.dumps(data, indent=2) + "\n")


def private_file(path):
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid()
                and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_nlink == 1, "unsafe_fixture_file")
    except BaseException:
        os.close(descriptor)
        raise
    return os.fdopen(descriptor, "r+")


@contextlib.contextmanager
def fixture_lease(reset):
    require(os.name == "posix", "unix_fixture_required")
    if not FIXTURE.exists():
        FIXTURE.mkdir(mode=0o700)
    metadata = FIXTURE.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o700, "unsafe_fixture_directory")
    marker = FIXTURE / "fixture-owner.json"
    expected = {"purpose": PURPOSE, "owner_uid": os.geteuid()}
    if marker.exists():
        with private_file(marker) as stream:
            require(json.load(stream) == expected, "foreign_fixture_marker")
    else:
        require(not any(FIXTURE.iterdir()), "unmarked_fixture_not_empty")
        with private_file(marker) as stream:
            json.dump(expected, stream)
    with private_file(FIXTURE / ".smoke.lock") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        data = FIXTURE / "data"
        running = {"status": "running", "purpose": PURPOSE, "owner_uid": os.geteuid(),
                   "harness_sha256": digest(Path(__file__))}
        if data.exists():
            require(reset, "fixture_exists_use_explicit_reset_after_review")
            metadata = data.lstat()
            require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid()
                    and stat.S_IMODE(metadata.st_mode) == 0o700, "unsafe_existing_data_fixture")
            with contextlib.ExitStack() as leases:
                # The restore rehearsal adds one nested Controller root. Reset must stop
                # both lifetimes before touching proof/data, not just the outer Controller.
                for candidate in (data, data / "legacy-restored"):
                    if not candidate.exists() and not candidate.is_symlink():
                        continue
                    metadata = candidate.lstat()
                    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid()
                            and stat.S_IMODE(metadata.st_mode) == 0o700, "unsafe_nested_controller_fixture")
                    lock = candidate / ".controller.lock"
                    require(lock.exists(), "existing_fixture_has_no_controller_lease")
                    held = leases.enter_context(private_file(lock))
                    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                write_proof(running)
                shutil.rmtree(data)
        else:
            write_proof(running)
        yield data


def run(arguments, password=None, expected=0, wrapper=False):
    command = [str(ROOT / "scripts/run_controller.sh")] if wrapper else [str(BINARY)]
    result = subprocess.run(command + arguments, cwd=ROOT, input=password,
                            text=True, capture_output=True, timeout=35, check=False)
    require(result.returncode == expected, "cli_exit_status_mismatch")
    return result.stdout, result.stderr


def snapshot(database):
    with sqlite3.connect(database) as connection:
        return {table: connection.execute("SELECT * FROM " + table + " ORDER BY rowid").fetchall() for table in TABLES}


def request(base, path, token=None, body=None):
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    encoded = None if body is None else json.dumps(body).encode()
    req = Request(base + path, data=encoded, headers=headers)
    try:
        with urlopen(req, timeout=2) as response:
            return response.status, response.read(1_048_577)
    except HTTPError as error:
        return error.code, error.read(1_048_577)


def require_response(status, body, expected):
    require(status != 404, "mandatory_endpoint_missing")
    require(status == expected and len(body) <= 1_048_576, "http_contract_mismatch")


def stop(process, kill=False):
    if process.poll() is None:
        process.kill() if kill else process.terminate()
    try:
        output = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        output = process.communicate(timeout=3)
    require(sum(len(part or "") for part in output) <= 262_144, "process_output_budget_exceeded")
    return tuple(part or "" for part in output)


@contextlib.contextmanager
def controller(data, captures):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    base = "http://127.0.0.1:" + str(port)
    process = subprocess.Popen([str(BINARY), "controller", "start", "--host", "127.0.0.1",
                                "--port", str(port), "--external-url", base, "--data-dir", str(data)],
                               cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 5
        ready = False
        while time.monotonic() < deadline and process.poll() is None:
            try:
                status, body = request(base, "/healthz")
                require_response(status, body, 200)
                require(json.loads(body).get("status") == "ok", "invalid_health_response")
                ready = True
                break
            except (URLError, TimeoutError, ConnectionError):
                time.sleep(0.025)
        require(ready, "owned_controller_not_ready")
        yield base
    finally:
        captures.extend(stop(process))


def wait_for_held_lease(data, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and process.poll() is None:
        with private_file(data / ".controller.lock") as probe:
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(probe, fcntl.LOCK_UN)
            except BlockingIOError:
                return
        time.sleep(0.01)
    raise RehearsalFailure("owner_did_not_hold_exclusive_lease")


def protected_read(base, token, expected=200):
    status, body = request(base, "/api/agents", token=token)
    require_response(status, body, expected)
    if expected == 200:
        require(b"agent-iam-fixture" in body, "positive_inventory_fixture_missing")
        json.loads(body)


def rehearse_recovery_restore(data, captures, token, keys, legacy_backup):
    """Native offline composition proof; personal HTTP authentication is a later gate."""
    database = data / "controller/fleet.db"
    replacement = "Lantern-" + secrets.token_urlsafe(32)
    now = int(time.time())
    # Only this marked disposable DB is seeded. These rows prove persistence/binding changes,
    # while the Rust file→Application tests prove positive-before/negative-after authentication.
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        owner = dict(connection.execute("SELECT * FROM admin_accounts WHERE username='fixture-owner'").fetchone())
        epoch = connection.execute("SELECT epoch FROM admin_auth_state WHERE id=1").fetchone()[0]
        delivery = tuple(connection.execute("SELECT namespace,store_epoch FROM controller_delivery_identity WHERE id=1").fetchone())
        for kind, lifetime in (("web_session", 28800), ("personal_token", 2592000),
                               ("setup_grant", 900), ("reset_grant", 900)):
            user = owner["user_id"]
            revision = owner["credential_revision"]
            if kind.endswith("grant"):
                user, revision = "usr_" + secrets.token_hex(16), 0
                connection.execute("INSERT INTO admin_accounts (user_id,username,display_name,role,status,record_revision,credential_revision) VALUES (?,?,?,'viewer','pending_setup',0,0)",
                                   (user, "fixture-" + kind, "Pending fixture"))
            connection.execute("INSERT INTO admin_credentials (credential_id,kind,user_id,credential_revision,epoch,digest,created_at,expires_at,state) VALUES (?,?,?,?,?,?,?,?,'active')",
                               ("crd_" + secrets.token_hex(16), kind, user, revision, epoch,
                                secrets.token_bytes(32), now, now + lifetime))
    saved = snapshot(database)
    personal_backup = data / "personal-backup.json"
    captures.extend(run(["controller", "backup", "--data-dir", str(data), "--output", str(personal_backup)]))
    before_bytes = database.read_bytes()
    captures.extend(run(["controller", "restore", "--data-dir", str(data), "--input", str(personal_backup), "--dry-run"]))
    require(database.read_bytes() == before_bytes and snapshot(database) == saved, "dry_run_changed_source_or_epochs")
    bad = json.loads(personal_backup.read_text())
    bad_database = next(item for item in bad["files"] if item["path"] == "controller/fleet.db")
    damaged = b"synthetic corrupt database"
    bad_database.update(content_hex=damaged.hex(), size_bytes=len(damaged), sha256=hashlib.sha256(damaged).hexdigest())
    invalid_backup = data / "invalid-backup.json"
    with private_file(invalid_backup) as stream:
        json.dump(bad, stream)
    for dry_run in (True, False):
        arguments = ["controller", "restore", "--data-dir", str(data), "--input", str(invalid_backup), "--force"]
        captures.extend(run(arguments + (["--dry-run"] if dry_run else []), expected=2))
        require(database.read_bytes() == before_bytes and snapshot(database) == saved, "corrupt_restore_changed_target")
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TRIGGER iam_restore_audit_fault BEFORE INSERT ON audit_events WHEN NEW.action='admin_credentials_invalidated_after_restore' BEGIN SELECT RAISE(ABORT,'synthetic restore audit failure'); END")
    fault_backup = data / "audit-fault-backup.json"
    try:
        captures.extend(run(["controller", "backup", "--data-dir", str(data), "--output", str(fault_backup)]))
    finally:
        with sqlite3.connect(database) as connection:
            connection.execute("DROP TRIGGER iam_restore_audit_fault")
    before_fault = snapshot(database)
    captures.extend(run(["controller", "restore", "--data-dir", str(data), "--input", str(fault_backup), "--force"], expected=2))
    require(snapshot(database) == before_fault, "restore_audit_fault_changed_target")
    recovery = ["controller", "admin", "recover-owner", "--data-dir", str(data),
                "--username", "fixture-owner", "--password-stdin"]
    captures.extend(run(recovery, replacement + "\n"))
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        changed = dict(connection.execute("SELECT * FROM admin_accounts WHERE user_id=?", (owner["user_id"],)).fetchone())
        require(changed["password_hash"] != owner["password_hash"] and changed["credential_revision"] == owner["credential_revision"] + 1,
                "native_recovery_did_not_replace_verifier_and_revision")
        require(connection.execute("SELECT epoch FROM admin_auth_state WHERE id=1").fetchone()[0] == epoch, "local_recovery_rotated_other_people_epoch")
        require(connection.execute("SELECT count(*) FROM admin_credentials WHERE user_id=?", (owner["user_id"],)).fetchone()[0] == 0,
                "native_recovery_did_not_revoke_and_reclaim_target_lookups")
        require(connection.execute("SELECT count(*) FROM admin_credentials WHERE kind IN ('setup_grant','reset_grant') AND state='active'").fetchone()[0] == 2,
                "native_recovery_changed_other_people_grants")
    safety_backup = data / "pre-restore-safety-backup.json"
    captures.extend(run(["controller", "backup", "--data-dir", str(data), "--output", str(safety_backup)]))
    captures.extend(run(["controller", "restore", "--data-dir", str(data), "--input", str(safety_backup), "--dry-run"]))
    with controller(data, captures):
        busy_before = snapshot(database)
        attempts = [(["controller", "backup", "--data-dir", str(data), "--output", str(data / "busy-backup.json")], None),
                    (["controller", "restore", "--data-dir", str(data), "--input", str(personal_backup), "--force"], None),
                    (recovery, replacement + "\n")]
        for arguments, password in attempts:
            output = run(arguments, password, expected=2)
            require("already in use" in output[1], "offline_command_bypassed_live_controller_lease")
            captures.extend(output)
        busy_after = snapshot(database)
        require(all(busy_before[t] == busy_after[t] for t in ("admin_auth_state", "admin_accounts", "admin_credentials")), "busy_offline_operation_changed_auth")
        require(not (data / "busy-backup.json").exists(), "busy_backup_created_output")
    captures.extend(run(["controller", "restore", "--data-dir", str(data), "--input", str(personal_backup), "--force"]))
    restored = snapshot(database)
    for table in ("admin_accounts", "admin_credentials", "agents", "agent_identities", "admin_tokens"):
        require(restored[table] == saved[table], "native_restore_did_not_preserve_backup_history")
    require(all(row in restored["audit_events"] for row in saved["audit_events"]), "native_restore_lost_backup_audit")
    require(restored["admin_auth_state"][0][1] == "personal" and restored["admin_auth_state"][0][2] != epoch, "native_restore_human_epoch_not_fresh")
    with sqlite3.connect(database) as connection:
        after_delivery = connection.execute("SELECT namespace,store_epoch FROM controller_delivery_identity WHERE id=1").fetchone()
        require(after_delivery[0] == delivery[0] and after_delivery[1] != delivery[1], "native_restore_delivery_boundary_invalid")
        require(connection.execute("SELECT count(*) FROM admin_credentials WHERE epoch=(SELECT epoch FROM admin_auth_state WHERE id=1)").fetchone() == (0,),
                "restored_lookup_bindings_not_stale")
    require(tuple((data / "controller" / name).read_bytes() for name in ("controller_public.key", "controller_private.key")) == keys, "native_restore_changed_signing_identity")
    with controller(data, captures) as base:
        protected_read(base, token, expected=401)
    legacy_target = data / "legacy-restored"
    captures.extend(run(["controller", "restore", "--data-dir", str(legacy_target), "--input", str(legacy_backup)]))
    legacy_database = legacy_target / "controller/fleet.db"
    with sqlite3.connect(legacy_database) as connection:
        require(connection.execute("SELECT mode FROM admin_auth_state WHERE id=1").fetchone() == ("local_setup_required",), "old_backup_revived_shared_auth")
        require(connection.execute("SELECT count(*) FROM admin_accounts").fetchone() == (0,), "old_backup_invented_owner")
    old_snapshot = snapshot(legacy_database)
    for table in ("agents", "agent_identities", "admin_tokens"):
        require(old_snapshot[table] == saved[table], "old_backup_changed_agent_or_legacy_history")
    require(tuple((legacy_target / "controller" / name).read_bytes() for name in ("controller_public.key", "controller_private.key")) == keys,
            "old_backup_changed_original_signing_identity")
    with controller(legacy_target, captures) as base:
        protected_read(base, token, expected=401)
    captures.extend(run(["controller", "admin", "init-owner", "--data-dir", str(legacy_target),
                         "--username", "restored-owner", "--password-stdin"], replacement + "\n"))
    with sqlite3.connect(legacy_database) as connection:
        require(connection.execute("SELECT mode FROM admin_auth_state WHERE id=1").fetchone() == ("personal",), "restored_local_setup_cannot_initialize_owner")
    for secret in (replacement, keys[1].decode().strip()):
        require(all(secret not in output for output in captures), "raw_recovery_material_in_output")
    require(replacement.encode() not in database.read_bytes(), "raw_recovery_password_persisted")
    for archive in (legacy_backup, personal_backup, invalid_backup, fault_backup, safety_backup):
        require(stat.S_IMODE(archive.stat().st_mode) == 0o600, "backup_archive_not_private")
    require(not any(p.name.startswith(".fleet-restore-") for p in data.iterdir()), "unexpected_restore_staging_left")
    return {"native_recovery_replaced_target_verifier_and_revoked_credentials": True,
            "native_backup_dry_run_preserved_bytes_and_epochs": True,
            "native_restore_corruption_and_audit_fault_preserved_target": True,
            "native_offline_commands_rejected_live_controller_lease": True,
            "native_restore_rotated_independent_epochs_preserved_backup_history_keys": True,
            "native_old_backup_requires_local_setup_never_revives_shared_token": True,
            "native_restored_local_setup_can_initialize_owner": True,
            "rollback_reverted_post_backup_password_change_but_kept_credentials_stale": True,
            "validated_pre_restore_safety_backup_retained": True,
            "four_purpose_binding_rows": "synthetic_seeds_stale_after_native_restore; actual_file_to_Application_rejection_passes_Rust_tests; native_personal_HTTP_pending"}


def rehearse(data):
    captures = []
    password = "Cedar-" + secrets.token_urlsafe(32)
    owner_args = ["controller", "admin", "init-owner", "--data-dir", str(data),
                  "--username", "fixture-owner", "--password-stdin"]
    output, _ = run(["controller", "init", "--data-dir", str(data)])
    match = re.search(r"^admin token: (\S+)$", output, re.MULTILINE)
    require(match is not None and match[1] != "already", "one_time_legacy_token_missing")
    token = match[1]
    database = data / "controller/fleet.db"
    enrollment, _ = run(["enroll-token", "create", "--data-dir", str(data), "--expires-in-seconds", "600"])
    enrollment = enrollment.strip()
    require(enrollment.startswith("enroll-"), "fixture_enrollment_token_missing")
    public = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    with controller(data, captures) as base:
        status, body = request(base, "/api/agents/enroll", body={
            "token": enrollment, "agent_id": "agent-iam-fixture", "name": "iam-fixture",
            "public_key": public, "fingerprint": hashlib.sha256(bytes.fromhex(public)).hexdigest(), "labels": [],
        })
        require_response(status, body, 201)
        protected_read(base, token)
    legacy_backup = data / "legacy-backup.json"
    captures.extend(run(["controller", "backup", "--data-dir", str(data), "--output", str(legacy_backup)]))
    before = snapshot(database)
    keys = tuple((data / "controller" / name).read_bytes() for name in ("controller_public.key", "controller_private.key"))
    waiting = subprocess.Popen([str(BINARY), *owner_args], cwd=ROOT, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    waiting_reaped = False
    try:
        wait_for_held_lease(data, waiting)
        busy = run(owner_args, password + "\n", expected=2)
        require("already in use" in busy[1], "concurrent_owner_not_rejected_by_lease")
        captures.extend(busy)
        require(snapshot(database) == before, "busy_owner_mutated_database")
        captures.extend(stop(waiting, kill=True))
        waiting_reaped = True
        require(waiting.returncode == -signal.SIGKILL, "owner_crash_not_injected")
    finally:
        if not waiting_reaped:
            captures.extend(stop(waiting, kill=True))
    require(snapshot(database) == before, "precommit_crash_changed_canonical_state")
    with controller(data, captures) as base:
        protected_read(base, token)
    before_fault = snapshot(database)
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TRIGGER iam_smoke_audit_fault BEFORE INSERT ON audit_events "
                           "WHEN NEW.action='admin_owner_initialized' BEGIN "
                           "SELECT RAISE(ABORT,'fixture identity audit failure'); END")
    try:
        captures.extend(run(owner_args, password + "\n", expected=2))
        require(snapshot(database) == before_fault, "audit_fault_did_not_roll_back_cutover")
    finally:
        with sqlite3.connect(database) as connection:
            connection.execute("DROP TRIGGER iam_smoke_audit_fault")
    with controller(data, captures) as base:
        protected_read(base, token)
    before_commit = snapshot(database)
    help_output = run(["controller", "admin", "init-owner", "--help"], wrapper=True)
    require("--password-stdin" in help_output[0], "actual_wrapper_did_not_reach_owner_cli")
    captures.extend(help_output)
    winner = subprocess.Popen([str(BINARY), *owner_args], cwd=ROOT, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    winner_reaped = False
    try:
        wait_for_held_lease(data, winner)
        loser = run(owner_args, password + "\n", expected=2)
        require("already in use" in loser[1], "concurrent_cutover_contender_not_rejected")
        captures.extend(loser)
        captures.extend(winner.communicate(password + "\n", timeout=35))
        winner_reaped = True
        require(winner.returncode == 0, "exclusive_cutover_winner_failed")
    finally:
        if not winner_reaped:
            captures.extend(stop(winner, kill=True))
    with sqlite3.connect(database) as connection:
        require(connection.execute("SELECT mode FROM admin_auth_state WHERE id=1").fetchone() == ("personal",), "cutover_mode_not_personal")
        require(connection.execute("SELECT count(*) FROM admin_accounts WHERE role='owner' AND status='active' AND password_profile='argon2id-v19-m19456-t2-p1'").fetchone() == (1,), "valid_owner_missing_after_commit")
        require(connection.execute("SELECT count(*) FROM audit_events WHERE action='admin_owner_initialized'").fetchone() == (1,), "owner_audit_not_exactly_once")
    after_commit = snapshot(database)
    for table in ("agents", "agent_identities", "admin_tokens"):
        require(after_commit[table] == before_commit[table], "legacy_history_or_agent_identity_changed")
    require(after_commit["audit_events"][:len(before_commit["audit_events"])] == before_commit["audit_events"], "prior_audit_history_changed")
    require(tuple((data / "controller" / name).read_bytes() for name in ("controller_public.key", "controller_private.key")) == keys, "signing_identity_changed")
    with controller(data, captures) as base:
        protected_read(base, token, expected=401)
    recovery_proof = rehearse_recovery_restore(data, captures, token, keys, legacy_backup)
    for secret in (password, token, enrollment):
        require(all(secret not in captured for captured in captures), "raw_credential_in_operational_output")
        require(secret.encode() not in database.read_bytes(), "raw_credential_in_database")
    return {**recovery_proof, "legacy_positive_read_before_cutover": True, "synthetic_agent_identity_preserved": True,
            "concurrent_owner_rejected": True, "concurrent_cutover_exactly_one_success": True,
            "actual_controller_wrapper_reaches_owner_cli": True, "precommit_sigkill_preserved_state": True,
            "lease_released_after_crash": True, "audit_fault_rolled_back_cutover": True,
            "postcommit_active_owner_durable": True, "old_bearer_rejected_after_restart": True,
            "legacy_and_audit_history_preserved": True, "signing_identity_preserved": True,
            "raw_credentials_absent_from_operational_output_and_db": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true", help="rebuild the fixed debug binary and record source/asset provenance")
    parser.add_argument("--reset-fixture", action="store_true")
    args = parser.parse_args()
    if args.build:
        build_current_binary()
    build = json.loads((ROOT / "target/iam-rehearsal/fleet-binary-build.json").read_text())
    require(all(path in build.get("sources", {}) for path in EMBEDDED_CONTRACTS), "embedded_contract_build_evidence_required")
    require(build["status"] == "rebuilt-current" and build["after"]["sha256"] == digest(BINARY), "fresh_official_binary_evidence_required")
    for group in ("sources", "assets"):
        require(all(digest(ROOT / path) == expected for path, expected in build[group].items()), "source_or_embedded_assets_changed_since_build")
    with fixture_lease(args.reset_fixture) as data:
        try:
            proof = rehearse(data)
            require(digest(BINARY) == build["after"]["sha256"], "wrapper_changed_official_binary_baseline")
            proof.update({"status": "pass", "purpose": PURPOSE, "owner_uid": os.geteuid(),
                          "binary_sha256": digest(BINARY), "harness_sha256": digest(Path(__file__)),
                          "personal_login_acceptance": "pending_tasks_0016_0017", "processes": "stopped"})
            write_proof(proof)
        except BaseException as error:
            write_proof({"status": "failed", "purpose": PURPOSE, "owner_uid": os.geteuid(),
                         "harness_sha256": digest(Path(__file__)),
                         "cause": str(error) if isinstance(error, RehearsalFailure) else type(error).__name__})
            raise
    print("local owner/recovery/restore rehearsal PASS; owned processes stopped; fixture preserved; personal-login acceptance pending")


if __name__ == "__main__":
    try:
        main()
    except RehearsalFailure as error:
        print("local owner rehearsal FAILED: " + str(error), file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print("local owner rehearsal FAILED: unexpected " + type(error).__name__, file=sys.stderr)
        sys.exit(1)
