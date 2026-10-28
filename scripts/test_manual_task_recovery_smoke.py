import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import manual_task_recovery_smoke as smoke


class RecoveryExpectationTests(unittest.TestCase):
    def test_controller_restart_requires_one_successful_effect_and_complete_output(self):
        issues = smoke.recovery_expectation(
            "controller-restart",
            {
                "status": "success",
                "target_agents": [
                    {"assignment_status": "succeeded", "last_error": ""}
                ],
            },
            "SMOKE_STARTED\nSMOKE_FINISHED\n",
            ["SMOKE_STARTED", "SMOKE_FINISHED"],
        )

        self.assertEqual(issues, ())

    def test_controller_restart_rejects_duplicate_side_effects(self):
        issues = smoke.recovery_expectation(
            "controller-restart",
            {
                "status": "success",
                "target_agents": [
                    {"assignment_status": "succeeded", "last_error": ""}
                ],
            },
            "SMOKE_STARTED\nSMOKE_FINISHED\n",
            ["SMOKE_STARTED", "SMOKE_STARTED", "SMOKE_FINISHED"],
        )

        self.assertIn("marker side effects differ from the expected single execution", issues)

    def test_agent_restart_requires_unknown_outcome_without_reexecution(self):
        issues = smoke.recovery_expectation(
            "agent-restart",
            {
                "status": "failed",
                "target_agents": [
                    {
                        "assignment_status": "failed",
                        "last_error": "execution_outcome_unknown",
                    }
                ],
            },
            "SMOKE_STARTED\n",
            ["SMOKE_STARTED"],
        )

        self.assertEqual(issues, ())

    def test_reboot_recovery_rejects_missing_persisted_output(self):
        issues = smoke.recovery_expectation(
            "host-reboot",
            {
                "status": "failed",
                "target_agents": [
                    {
                        "assignment_status": "failed",
                        "last_error": "execution_outcome_unknown",
                    }
                ],
            },
            "",
            ["SMOKE_STARTED"],
        )

        self.assertIn("stored output does not contain the start marker exactly once", issues)

    def test_interrupted_recovery_accepts_agent_reported_unknown_final(self):
        for scenario in ("agent-restart", "host-reboot"):
            with self.subTest(scenario=scenario):
                issues = smoke.recovery_expectation(
                    scenario,
                    {
                        "status": "failed",
                        "target_agents": [{
                            "assignment_status": "failed",
                            "last_error": "exit_code=-1,reason=execution_outcome_unknown",
                        }],
                    },
                    "SMOKE_STARTED\n",
                    ["SMOKE_STARTED"],
                )

                self.assertEqual(issues, ())

    def test_interrupted_recovery_rejects_other_or_malformed_final_reasons(self):
        for reason in (
            "",
            "agent_interrupted_before_start",
            "exit_code=-1,reason=agent_interrupted_before_start",
            "exit_code=0,reason=execution_outcome_unknown",
            "exit_code=1,reason=execution_outcome_unknown",
            "exit_code=-1,reason=execution_outcome_unknown_extra",
            "exit_code=-1,reason=execution_outcome_unknown,extra=1",
            "prefix_execution_outcome_unknown",
        ):
            with self.subTest(reason=reason):
                issues = smoke.recovery_expectation(
                    "agent-restart",
                    {
                        "status": "failed",
                        "target_agents": [{
                            "assignment_status": "failed",
                            "last_error": reason,
                        }],
                    },
                    "SMOKE_STARTED\n",
                    ["SMOKE_STARTED"],
                )

                self.assertIn(
                    "interrupted assignment is not marked execution_outcome_unknown", issues
                )

    def test_unknown_scenario_is_rejected(self):
        with self.assertRaises(ValueError):
            smoke.recovery_expectation("unknown", {}, "", [])


class SmokeInputTests(unittest.TestCase):
    def test_agent_restart_requires_a_new_active_systemd_process(self):
        previous = {
            "active_state": "active",
            "sub_state": "running",
            "main_pid": 310,
            "restart_count": 2,
        }
        restarted = {
            "active_state": "active",
            "sub_state": "running",
            "main_pid": 415,
            "restart_count": 3,
        }

        self.assertTrue(smoke.agent_restart_completed(previous, restarted))

    def test_agent_restart_does_not_accept_the_old_active_process(self):
        previous = {
            "active_state": "active",
            "sub_state": "running",
            "main_pid": 310,
            "restart_count": 2,
        }

        self.assertFalse(smoke.agent_restart_completed(previous, dict(previous)))

    def test_agent_restart_waits_until_the_new_process_is_running(self):
        previous = {
            "active_state": "active",
            "sub_state": "running",
            "main_pid": 310,
            "restart_count": 2,
        }
        activating = {
            "active_state": "activating",
            "sub_state": "start-pre",
            "main_pid": 415,
            "restart_count": 3,
        }

        self.assertFalse(smoke.agent_restart_completed(previous, activating))

    def test_systemd_agent_state_parses_restart_identity(self):
        state = smoke.parse_systemd_agent_state(
            "ActiveState=active\nSubState=running\nMainPID=415\nNRestarts=3\n"
        )

        self.assertEqual(
            state,
            {
                "active_state": "active",
                "sub_state": "running",
                "main_pid": 415,
                "restart_count": 3,
            },
        )

    def test_systemd_agent_state_requires_all_restart_fields(self):
        with self.assertRaises(RuntimeError):
            smoke.parse_systemd_agent_state("ActiveState=active\nMainPID=310\n")

    def test_command_request_targets_one_named_agent_and_uses_only_test_markers(self):
        request = smoke.build_command_request(
            "task056-agent-restart-test", "/var/lib/fleet-smoke/marker", "agent-restart"
        )

        self.assertEqual(request["selector"], "agent:local-agent")
        self.assertEqual(request["target_agent_ids"], [])
        self.assertEqual(request["program"], "/bin/sh")
        self.assertEqual(request["args"][0], "-c")
        self.assertIn("SMOKE_STARTED", request["args"][1])
        self.assertIn("sync; sleep 300", request["args"][1])
        self.assertNotIn("admin_token", request)

    def test_generated_probe_emits_each_marker_once_to_stdout_and_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            # Only the wall-clock delay and global sync are stubbed. Execute the
            # generated shell, quoting and real marker/output writes unchanged.
            for utility in ("sleep", "sync"):
                executable = fake_bin / utility
                executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                executable.chmod(0o700)
            for scenario in smoke.EXPECTED_SCENARIOS:
                with self.subTest(scenario=scenario):
                    marker = root / (scenario + " marker's file")
                    request = smoke.build_command_request("probe-unit", marker, scenario)
                    result = subprocess.run(
                        [request["program"], *request["args"]],
                        env={"PATH": str(fake_bin) + os.pathsep + os.defpath},
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(
                        result.stdout.splitlines(), ["SMOKE_STARTED", "SMOKE_FINISHED"]
                    )
                    self.assertEqual(
                        marker.read_text(encoding="utf-8").splitlines(),
                        ["SMOKE_STARTED", "SMOKE_FINISHED"],
                    )

    def test_api_refuses_non_loopback_controller_url(self):
        with self.assertRaises(RuntimeError):
            smoke.LoopbackApi("http://192.0.2.10:7700", "admin-test")

    def test_api_refuses_url_credentials_and_path_prefix(self):
        for url in (
            "http://admin-test@127.0.0.1:7700",
            "http://127.0.0.1:7700/prefix",
        ):
            with self.subTest(url=url):
                with self.assertRaises(RuntimeError):
                    smoke.LoopbackApi(url, "admin-test")

    def test_reboot_state_contains_only_job_and_marker_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            smoke.atomic_write_state(
                path,
                {"job_id": "job-test", "marker_path": "/tmp/marker"},
            )

            state = smoke.read_reboot_state(path)
            mode = path.stat().st_mode & 0o777

        self.assertEqual(state, {"job_id": "job-test", "marker_path": "/tmp/marker"})
        self.assertEqual(mode, 0o600)
        self.assertNotIn("admin_token", state)


if __name__ == "__main__":
    unittest.main()
