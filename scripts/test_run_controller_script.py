#!/usr/bin/env python3
"""Check wrapper routing with a no-op Cargo and fixture-only argument recorder."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class ControllerWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fleet wrapper ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        scripts = self.root / "scripts"
        scripts.mkdir()
        self.script = scripts / "run_controller.sh"
        shutil.copyfile(Path(__file__).with_name("run_controller.sh"), self.script)
        self.tools = self.root / "tools"
        self.tools.mkdir()
        cargo = self.tools / "cargo"
        cargo.write_text("#!/bin/sh\nexit 0\n")
        cargo.chmod(0o700)
        binary = self.root / "target/debug/fleet"
        binary.parent.mkdir(parents=True)
        binary.write_text("#!/usr/bin/env python3\nimport json, sys\nprint(json.dumps(sys.argv[1:]))\n")
        binary.chmod(0o700)
        self.env = os.environ.copy()
        self.env["PATH"] = str(self.tools) + os.pathsep + self.env["PATH"]
        self.data = self.root / "private data"

    def forwarded(self, args):
        result = subprocess.run(
            ["sh", str(self.script), *args], cwd=self.root, env=self.env,
            text=True, capture_output=True, timeout=5, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_admin_explicit_and_shorthand_bypass_start_only_preflight(self):
        metadata = ["init-owner", "--username", "fixture-owner", "--data-dir", str(self.data), "--password-stdin"]
        for prefix in [["controller", "admin"], ["admin"]]:
            with self.subTest(prefix=prefix):
                self.assertEqual(self.forwarded(prefix + metadata), ["controller", "admin", *metadata])
        self.assertFalse(self.data.exists())

    def test_explicit_controller_subcommands_and_nested_help_are_preserved(self):
        for args in [["admin", "--help"], ["backup", "--output", "fixture.json"], ["signing-rotation-status", "--help"]]:
            with self.subTest(args=args):
                self.assertEqual(self.forwarded(["controller", *args]), ["controller", *args])

    def test_init_custom_database_and_controller_help_are_preserved(self):
        options = ["--data-dir", str(self.data), "--db", "sqlite://custom fixture.db"]
        for prefix in [["controller", "init"], ["init"]]:
            self.assertEqual(self.forwarded(prefix + options), ["controller", "init", *options])
        self.assertEqual(self.forwarded(["controller", "--help"]), ["controller", "--help"])
        self.assertEqual(self.forwarded(["--help"]), ["controller", "start", "--help"])

    def test_start_explicit_shorthand_and_options_keep_initialized_preflight(self):
        controller = self.data / "controller"
        controller.mkdir(parents=True)
        for name in ["controller_public.key", "controller_private.key"]:
            (controller / name).write_text("fixture-only")
        options = ["--host", "127.0.0.1", "--port", "7700", "--data-dir", str(self.data)]
        for prefix in [["controller", "start"], ["start"], []]:
            self.assertEqual(self.forwarded(prefix + options), ["controller", "start", *options])


if __name__ == "__main__":
    unittest.main()
