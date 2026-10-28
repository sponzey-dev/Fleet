#!/usr/bin/env python3
"""Exercise durable Command recovery across service and host interruptions.

This manual gate runs only on a disposable Linux VM. It creates approved
commands that write a private marker under the configured Fleet data directory,
then checks API status, stored output, and marker counts after interruption.
The admin token is requested without echo and is never written to disk.
"""

import argparse
import getpass
import ipaddress
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


CONFIRMATION_ENV = "FLEET_MANUAL_DISPOSABLE_CONFIRMATION"
CONFIRMATION_VALUE = "YES"
EXPECTED_SCENARIOS = {
    "controller-restart": (["SMOKE_STARTED", "SMOKE_FINISHED"], True),
    "agent-restart": (["SMOKE_STARTED"], False),
    "host-reboot": (["SMOKE_STARTED"], False),
}


def recovery_expectation(scenario, job, output_text, marker_lines):
    """Return contract mismatches for a recovered Command and its side effect."""
    if scenario not in EXPECTED_SCENARIOS:
        raise ValueError("unknown recovery scenario")

    expected_markers, should_succeed = EXPECTED_SCENARIOS[scenario]
    expected_job_status = "success" if should_succeed else "failed"
    expected_assignment_status = "succeeded" if should_succeed else "failed"
    targets = job.get("target_agents")
    if not isinstance(targets, list) or len(targets) != 1:
        return ("job does not contain exactly one target assignment",)

    target = targets[0]
    issues = []
    if job.get("status") != expected_job_status:
        issues.append("job status differs from the recovery contract")
    if target.get("assignment_status") != expected_assignment_status:
        issues.append("assignment status differs from the recovery contract")
    if should_succeed:
        if target.get("last_error"):
            issues.append("successful assignment unexpectedly has an error")
        for marker in expected_markers:
            if output_text.count(marker) != 1:
                issues.append("stored output does not contain each marker exactly once")
                break
    else:
        # Controller G2 writes the reason alone; an Agent restart final passes
        # through task_result_last_error with its synthetic exit code. Accept
        # only these exact existing representations, not substring matches.
        if target.get("last_error") not in (
            "execution_outcome_unknown",
            "exit_code=-1,reason=execution_outcome_unknown",
        ):
            issues.append("interrupted assignment is not marked execution_outcome_unknown")
        if output_text.count("SMOKE_STARTED") != 1:
            issues.append("stored output does not contain the start marker exactly once")
        if "SMOKE_FINISHED" in output_text:
            issues.append("interrupted Command unexpectedly reported completion output")

    if marker_lines != expected_markers:
        issues.append("marker side effects differ from the expected single execution")
    return tuple(issues)


def build_command_request(job_id, marker_path, scenario):
    """Build one approved shell probe with a unique, harmless filesystem marker."""
    if scenario not in EXPECTED_SCENARIOS:
        raise ValueError("unknown recovery scenario")
    if not Path(marker_path).is_absolute():
        raise ValueError("marker path must be absolute")

    sleep_seconds = {
        "controller-restart": 120,
        "agent-restart": 300,
        "host-reboot": 600,
    }[scenario]
    shell_command = (
        "printf 'SMOKE_STARTED\\n' | tee -a "
        + shlex.quote(str(marker_path))
        + "; sync; sleep "
        + str(sleep_seconds)
        + "; printf 'SMOKE_FINISHED\\n' | tee -a "
        + shlex.quote(str(marker_path))
        + "; sync"
    )
    timeout_seconds = sleep_seconds + 60
    return {
        "job_id": job_id,
        "target_agent_ids": [],
        "selector": "agent:local-agent",
        "program": "/bin/sh",
        "args": ["-c", shell_command],
        "timeout_seconds": timeout_seconds,
        "confirmed_high_risk": True,
        "confirmed_by": "task056-manual-recovery-smoke",
        "expires_in_seconds": timeout_seconds + 900,
        "nonce_prefix": "nonce-" + job_id,
    }


class LoopbackApi:
    """Small no-redirect JSON client that keeps the admin token in memory only."""

    def __init__(self, base_url, admin_token):
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise RuntimeError("controller URL must be an HTTP(S) loopback URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise RuntimeError("controller URL must not contain credentials or extra data")
        if parsed.path not in ("", "/"):
            raise RuntimeError("controller URL must not contain a path prefix")
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = parsed.hostname.lower() == "localhost"
        if not loopback:
            raise RuntimeError("manual recovery smoke refuses non-loopback controller URLs")
        self.base_url = base_url.rstrip("/")
        self.admin_token = admin_token

    def request(self, method, path, body=None, authenticated=True):
        headers = {"Accept": "application/json"}
        data = None
        if authenticated:
            headers["Authorization"] = "Bearer " + self.admin_token
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path, data=data, headers=headers, method=method
        )
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirectHandler()
        )
        try:
            with opener.open(request, timeout=10) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            raise RuntimeError(
                "controller returned HTTP {} for {} {}".format(
                    error.code, method, path
                )
            ) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise RuntimeError("controller request failed for {} {}".format(method, path)) from None
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError("controller returned an invalid JSON response") from None


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def run_command(argv, expected_success=True):
    try:
        completed = subprocess.run(
            argv,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("required host command failed: {}".format(argv[0])) from None
    if expected_success and completed.returncode != 0:
        raise RuntimeError("host command failed: {}".format(" ".join(argv)))
    return completed


def parse_systemd_agent_state(output):
    """Parse the systemd fields used to prove an automatic Agent restart."""
    properties = {}
    for line in output.splitlines():
        name, separator, value = line.partition("=")
        if separator:
            properties[name] = value

    try:
        active_state = properties["ActiveState"]
        sub_state = properties["SubState"]
        main_pid = int(properties["MainPID"])
        restart_count = int(properties["NRestarts"])
    except (KeyError, ValueError):
        raise RuntimeError("could not inspect Agent systemd restart status") from None
    if main_pid < 0 or restart_count < 0:
        raise RuntimeError("Agent systemd restart status contains an invalid count")
    return {
        "active_state": active_state,
        "sub_state": sub_state,
        "main_pid": main_pid,
        "restart_count": restart_count,
    }


def read_systemd_agent_state():
    result = run_command(
        [
            "systemctl",
            "show",
            "--property=ActiveState",
            "--property=SubState",
            "--property=MainPID",
            "--property=NRestarts",
            "fleet-agent.service",
        ]
    )
    return parse_systemd_agent_state(result.stdout)


def agent_restart_completed(previous, current):
    """Require systemd to report a running process after an automatic restart."""
    return (
        current["active_state"] == "active"
        and current["sub_state"] == "running"
        and current["main_pid"] > 0
        and current["restart_count"] > previous["restart_count"]
    )


def require_host(mode):
    if platform.system() != "Linux":
        raise RuntimeError("manual task recovery smoke requires Linux")
    if os.geteuid() != 0:
        raise RuntimeError("manual task recovery smoke requires root")
    if not shutil.which("systemctl"):
        raise RuntimeError("manual task recovery smoke requires systemctl")
    if mode != "verify-reboot" and os.environ.get(CONFIRMATION_ENV) != CONFIRMATION_VALUE:
        raise RuntimeError(
            "set {}=YES only on a disposable Linux VM".format(CONFIRMATION_ENV)
        )
    for unit in ("fleet-controller.service", "fleet-agent.service"):
        result = run_command(["systemctl", "is-active", "--quiet", unit], False)
        if result.returncode != 0:
            raise RuntimeError("{} must be active before this test".format(unit))
    kill_mode = run_command(
        ["systemctl", "show", "--property=KillMode", "--value", "fleet-agent.service"]
    ).stdout.strip()
    if kill_mode != "control-group":
        raise RuntimeError("Agent systemd KillMode must be control-group")


def require_operator_confirmation(prompt, expected):
    if not sys.stdin.isatty():
        raise RuntimeError("interactive confirmation requires a terminal")
    print(prompt)
    if input("Type {} to continue: ".format(expected)).strip() != expected:
        raise RuntimeError("operator confirmation did not match")


def read_admin_token():
    if not sys.stdin.isatty():
        raise RuntimeError("admin token must be entered through an interactive terminal")
    token = getpass.getpass("Admin token (input is hidden): ").strip()
    if not token:
        raise RuntimeError("admin token is required")
    return token


def ensure_private_work_dir(data_dir, create=True):
    if not data_dir.is_absolute() or data_dir == Path("/") or data_dir.is_symlink():
        raise RuntimeError("FLEET_DATA_DIR must be an absolute, non-root, non-symlink path")
    if not data_dir.is_dir():
        raise RuntimeError("Fleet data directory must already exist")
    if data_dir.stat().st_uid != 0:
        raise RuntimeError("Fleet data directory must be owned by root for this manual gate")
    work_dir = data_dir / "task056-recovery-smoke"
    if work_dir.is_symlink():
        raise RuntimeError("recovery smoke directory must not be a symlink")
    if create:
        work_dir.mkdir(mode=0o700, exist_ok=True)
        if work_dir.stat().st_uid != 0:
            raise RuntimeError("recovery smoke directory must be owned by root")
        os.chmod(work_dir, 0o700)
    else:
        if not work_dir.is_dir() or work_dir.stat().st_uid != 0:
            raise RuntimeError("recovery smoke state directory is missing or not root-owned")
        if work_dir.stat().st_mode & 0o077:
            raise RuntimeError("recovery smoke state directory must be owner-only")
    return work_dir


def atomic_write_state(state_path, state):
    payload = json.dumps(state, separators=(",", ":")).encode("utf-8")
    temporary = state_path.with_name(state_path.name + ".tmp-" + uuid.uuid4().hex)
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(str(temporary), str(state_path))
        directory_descriptor = os.open(
            str(state_path.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_reboot_state(state_path):
    if state_path.is_symlink() or not state_path.is_file():
        raise RuntimeError("reboot smoke state is missing or unsafe")
    state_metadata = state_path.stat()
    if state_metadata.st_uid != os.geteuid() or state_metadata.st_mode & 0o077:
        raise RuntimeError("reboot smoke state must belong to the current user and be owner-only")
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise RuntimeError("reboot smoke state is missing or invalid") from None
    if not isinstance(state, dict) or set(state) != {"job_id", "marker_path"}:
        raise RuntimeError("reboot smoke state contains unexpected fields")
    return state


def create_approved_job(api, scenario, marker_path):
    job_id = "task056-{}-{}".format(scenario, uuid.uuid4().hex[:12])
    marker_path.touch(mode=0o600, exist_ok=False)
    request = build_command_request(job_id, marker_path, scenario)
    response = api.request("POST", "/api/jobs/command", request)
    if not isinstance(response, dict) or response.get("job_id") != job_id:
        raise RuntimeError("Controller did not create the expected single test job")
    if response.get("target_count") != 1 or response.get("assignment_count") != 1:
        raise RuntimeError("test selector must resolve to exactly one Agent")
    approval_id = response.get("approval_request_id")
    if response.get("status") != "pending_approval" or not approval_id:
        raise RuntimeError("high-risk recovery test must require explicit approval")
    api.request(
        "POST",
        "/api/approvals/{}/approve".format(urllib.parse.quote(approval_id, safe="")),
        {"reason": "approved disposable task056 recovery smoke"},
    )
    return job_id


def get_job_and_output(api, job_id):
    safe_job_id = urllib.parse.quote(job_id, safe="")
    job = api.request("GET", "/api/jobs/" + safe_job_id)
    output = api.request("GET", "/api/jobs/{}/output".format(safe_job_id))
    if not isinstance(job, dict) or not isinstance(output, list):
        raise RuntimeError("Controller returned an unexpected job or output shape")
    output_text = "".join(
        item.get("data", "") for item in output if isinstance(item, dict)
    )
    return job, output_text


def wait_until(predicate, description, timeout_seconds):
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.5)
    raise RuntimeError("timed out waiting for {}".format(description))


def wait_for_started(api, job_id, marker_path, timeout_seconds=45):
    def started():
        job, _ = get_job_and_output(api, job_id)
        targets = job.get("target_agents", [])
        return (
            len(targets) == 1
            and targets[0].get("assignment_status") == "started"
            and marker_path.exists()
            and marker_path.read_text(encoding="utf-8").splitlines()
            == ["SMOKE_STARTED"]
        )

    wait_until(started, "the test Command to start and write its marker", timeout_seconds)


def wait_for_controller(api):
    def healthy():
        try:
            api.request("GET", "/healthz", authenticated=False)
            return True
        except RuntimeError:
            return False

    wait_until(healthy, "Controller health after restart", 45)


def wait_for_terminal(api, job_id, expected_status, timeout_seconds):
    latest = {}

    def terminal():
        nonlocal latest
        latest, _ = get_job_and_output(api, job_id)
        return latest.get("status") == expected_status

    wait_until(terminal, "job status {}".format(expected_status), timeout_seconds)
    return latest


def verify_scenario(api, scenario, job_id, marker_path, timeout_seconds):
    expected_status = "success" if scenario == "controller-restart" else "failed"
    wait_for_terminal(api, job_id, expected_status, timeout_seconds)
    job, output_text = get_job_and_output(api, job_id)
    marker_lines = marker_path.read_text(encoding="utf-8").splitlines()
    issues = recovery_expectation(scenario, job, output_text, marker_lines)
    if issues:
        raise RuntimeError("recovery evidence failed: {}".format("; ".join(issues)))
    print("PASS scenario={} job_id={} marker={}".format(scenario, job_id, marker_path))


def run_restart_scenario(api, work_dir, scenario):
    if scenario == "controller-restart":
        require_operator_confirmation(
            "This will restart fleet-controller.service during an approved test Command.\n"
            "FLEET_DATA_DIR={}".format(work_dir.parent),
            "RESTART-CONTROLLER",
        )
    else:
        require_operator_confirmation(
            "This will SIGKILL fleet-agent.service during an approved test Command.\n"
            "FLEET_DATA_DIR={}".format(work_dir.parent),
            "KILL-AGENT",
        )
    marker = work_dir / (scenario + "-" + uuid.uuid4().hex + ".marker")
    job_id = create_approved_job(api, scenario, marker)
    wait_for_started(api, job_id, marker)
    if scenario == "controller-restart":
        run_command(["systemctl", "restart", "fleet-controller.service"])
        wait_for_controller(api)
        verify_scenario(api, scenario, job_id, marker, 240)
    else:
        previous_agent_state = read_systemd_agent_state()
        if (
            previous_agent_state["active_state"] != "active"
            or previous_agent_state["sub_state"] != "running"
            or previous_agent_state["main_pid"] <= 0
        ):
            raise RuntimeError("Agent service is not running before SIGKILL")
        run_command(
            [
                "systemctl",
                "kill",
                "--signal=SIGKILL",
                "--kill-whom=all",
                "fleet-agent.service",
            ]
        )
        wait_until(
            lambda: agent_restart_completed(
                previous_agent_state, read_systemd_agent_state()
            ),
            "Agent systemd automatic restart",
            45,
        )
        verify_scenario(api, scenario, job_id, marker, 120)


def prepare_reboot(api, work_dir, state_path):
    marker = work_dir / ("host-reboot-" + uuid.uuid4().hex + ".marker")
    job_id = create_approved_job(api, "host-reboot", marker)
    wait_for_started(api, job_id, marker)
    atomic_write_state(state_path, {"job_id": job_id, "marker_path": str(marker)})
    print("PASS preparation job_id={} marker={}".format(job_id, marker))
    print("Now reboot this disposable VM manually. After it returns, run:")
    print(
        "  sudo env FLEET_DATA_DIR={} python3 scripts/manual_task_recovery_smoke.py verify-reboot".format(
            data_dir_from_work_dir(work_dir)
        )
    )


def data_dir_from_work_dir(work_dir):
    return work_dir.parent


def verify_reboot(api, work_dir, state_path):
    state = read_reboot_state(state_path)
    marker_path = Path(state["marker_path"])
    if (
        marker_path.parent != work_dir
        or marker_path.is_symlink()
        or not marker_path.is_file()
    ):
        raise RuntimeError("reboot marker is missing or outside the private smoke directory")
    for unit in ("fleet-controller.service", "fleet-agent.service"):
        run_command(["systemctl", "is-enabled", "--quiet", unit])
        run_command(["systemctl", "is-active", "--quiet", unit])
    verify_scenario(api, "host-reboot", state["job_id"], marker_path, 120)
    state_path.unlink()


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode",
        choices=("controller-restart", "agent-restart", "prepare-reboot", "verify-reboot"),
    )
    parser.add_argument("--data-dir", default=os.environ.get("FLEET_DATA_DIR", "/var/lib/fleet"))
    parser.add_argument(
        "--controller-url",
        default=os.environ.get("FLEET_CONTROLLER_URL", "http://127.0.0.1:7700"),
    )
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        require_host(args.mode)
        data_dir = Path(args.data_dir)
        work_dir = ensure_private_work_dir(data_dir, create=args.mode != "verify-reboot")
        state_path = work_dir / "host-reboot-state.json"
        if args.mode == "verify-reboot":
            token = read_admin_token()
            api = LoopbackApi(args.controller_url, token)
            verify_reboot(api, work_dir, state_path)
            return 0
        token = read_admin_token()
        api = LoopbackApi(args.controller_url, token)
        if args.mode in ("controller-restart", "agent-restart"):
            run_restart_scenario(api, work_dir, args.mode)
        else:
            require_operator_confirmation(
                "This will create an approved long-running Command; it will not reboot automatically.\n"
                "FLEET_DATA_DIR={}".format(data_dir),
                "PREPARE-REBOOT",
            )
            prepare_reboot(api, work_dir, state_path)
    except (RuntimeError, OSError, ValueError) as error:
        print("manual task recovery smoke failed: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
