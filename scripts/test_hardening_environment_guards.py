#!/usr/bin/env python3
"""Exercise the environment guards in an owned minimal copy of the audit script.

Allowed fixtures must reach the next, deliberately missing gate; this is not a
substitute for running the full hardening audit on the actual repository.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest


class EnvironmentGuardTests(unittest.TestCase):
    def audit(self, relative, statement):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "scripts/hardening_audit.sh"
            script.parent.mkdir()
            script.write_bytes(Path(__file__).with_name("hardening_audit.sh").read_bytes())
            source = root / relative
            source.parent.mkdir(parents=True)
            source.write_text(statement)
            return subprocess.run(["sh", str(script)], text=True, capture_output=True, timeout=10)

    def test_known_child_fixtures_pass_environment_guard_only(self):
        for relative, variable in [
            ("crates/fleet-cli/src/controller_snapshot_tests.rs", "FLEET_TEST_RESTORE_ROOT"),
            ("crates/fleet-cli/src/controller_snapshot_tests.rs", "FLEET_TEST_RESTORE_AFTER"),
            ("crates/fleet-core/src/controller_data.rs", "FLEET_CORE_LEASE_PROBE_DIR"),
            ("crates/fleet-core/src/controller_data.rs", "FLEET_CORE_LEASE_PROBE_EXPECT"),
        ]:
            with self.subTest(relative=relative, variable=variable):
                result = self.audit(relative, f'#[test]\nfn child_fixture() {{ let input=std::env::var_os("{variable}"); }}')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("read environment outside bootstrap", result.stderr)
                self.assertIn("remote HTTP agent warning-policy test is missing", result.stderr)

    def test_fixture_names_do_not_exempt_production_files(self):
        for variable in ("FLEET_TEST_RESTORE_ROOT", "FLEET_CORE_LEASE_PROBE_DIR"):
            with self.subTest(variable=variable):
                result = self.audit("crates/fleet-controller/src/lib.rs", f'fn production() {{ std::env::var_os("{variable}"); }}')
                self.assertIn("read environment outside bootstrap", result.stderr)

    def test_unknown_fixture_read_and_any_environment_mutation_are_rejected(self):
        result = self.audit("crates/fleet-cli/src/controller_snapshot_tests.rs", 'std::env::var("UNAPPROVED_FIXTURE_SETTING");')
        self.assertIn("read environment outside bootstrap", result.stderr)
        result = self.audit("crates/fleet-cli/src/controller_snapshot_tests.rs", 'std::env::set_var("FLEET_TEST_RESTORE_ROOT", "fake");')
        self.assertIn("must not mutate process environment", result.stderr)


if __name__ == "__main__":
    unittest.main()
