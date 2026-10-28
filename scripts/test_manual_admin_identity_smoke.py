#!/usr/bin/env python3
"""Test reset authority and binary provenance using only private temporary fixtures."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("iam_smoke", Path(__file__).with_name("manual_admin_identity_smoke.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class FixtureResetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.original = smoke.FIXTURE
        self.addCleanup(setattr, smoke, "FIXTURE", self.original)
        smoke.FIXTURE = Path(self.temporary.name) / "owned"
        smoke.FIXTURE.mkdir(mode=0o700)
        with smoke.private_file(smoke.FIXTURE / "fixture-owner.json") as stream:
            json.dump({"purpose": smoke.PURPOSE, "owner_uid": os.geteuid()}, stream)
        smoke.write_proof({"status": "existing-proof"})
        self.data = smoke.FIXTURE / "data"
        self.data.mkdir(mode=0o700)
        with smoke.private_file(self.data / ".controller.lock"):
            pass
        (self.data / "preserved").write_bytes(b"owned database fixture")
        self.proof = (smoke.FIXTURE / "proof.json").read_bytes()

    def unchanged(self):
        self.assertEqual((self.data / "preserved").read_bytes(), b"owned database fixture")
        self.assertEqual((smoke.FIXTURE / "proof.json").read_bytes(), self.proof)

    def test_implicit_reset_preserves_data_and_proof(self):
        with self.assertRaises(smoke.RehearsalFailure):
            with smoke.fixture_lease(False):
                self.fail("implicit reset yielded")
        self.unchanged()

    def test_explicit_reset_removes_only_owned_data_child(self):
        sibling = smoke.FIXTURE / "unrelated"
        sibling.write_bytes(b"preserved sibling")
        with smoke.fixture_lease(True) as data:
            self.assertEqual(data, self.data)
            self.assertFalse(data.exists())
        self.assertEqual(sibling.read_bytes(), b"preserved sibling")
        self.assertTrue((smoke.FIXTURE / "fixture-owner.json").is_file())

    def test_live_nested_controller_blocks_reset_before_proof_or_data_changes(self):
        nested = self.data / "legacy-restored"
        nested.mkdir(mode=0o700)
        with smoke.private_file(nested / ".controller.lock") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                with smoke.fixture_lease(True):
                    self.fail("reset bypassed nested Controller lease")
        self.unchanged()

    def test_nested_symlink_is_not_an_owned_reset_boundary(self):
        foreign = Path(self.temporary.name) / "foreign"
        foreign.mkdir(mode=0o700)
        (foreign / "preserved").write_bytes(b"foreign fixture")
        (self.data / "legacy-restored").symlink_to(foreign, target_is_directory=True)
        with self.assertRaises(smoke.RehearsalFailure):
            with smoke.fixture_lease(True):
                self.fail("foreign nested root accepted")
        self.unchanged()
        self.assertEqual((foreign / "preserved").read_bytes(), b"foreign fixture")


class BinaryBuildProvenanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for path in ("Cargo.toml", "Cargo.lock", "crates/example/Cargo.toml", "crates/example/src/lib.rs",
                     "web-admin/api-client.js", "docs/openapi.json", "docs/swagger-ui.html", "target/debug/fleet"):
            file = self.root / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text("synthetic build input")
        for name, value in (("ROOT", self.root), ("BINARY", self.root / "target/debug/fleet")):
            patch = mock.patch.object(smoke, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def fake_build(self, *_args, **_kwargs):
        smoke.BINARY.write_bytes(b"synthetic rebuilt binary")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def test_embedded_contract_change_during_build_cannot_be_reported_current(self):
        for relative in ("docs/openapi.json", "docs/swagger-ui.html"):
            with self.subTest(relative=relative):
                def changed(*args, **kwargs):
                    (self.root / relative).write_text("changed during synthetic build")
                    return self.fake_build(*args, **kwargs)
                with mock.patch.object(smoke.subprocess, "run", side_effect=changed):
                    with self.assertRaisesRegex(smoke.RehearsalFailure, "source_changed_during_build"):
                        smoke.build_current_binary()

    def test_successful_build_records_embedded_contract_digests(self):
        with mock.patch.object(smoke.subprocess, "run", side_effect=self.fake_build):
            smoke.build_current_binary()
        record = json.loads((self.root / "target/iam-rehearsal/fleet-binary-build.json").read_text())
        self.assertEqual(record["status"], "rebuilt-current")
        for relative in ("docs/openapi.json", "docs/swagger-ui.html"):
            self.assertEqual(record["sources"].get(relative), smoke.digest(self.root / relative))

    def test_missing_embedded_contract_evidence_is_rejected_before_fixture_access(self):
        with mock.patch.object(smoke.subprocess, "run", side_effect=self.fake_build):
            smoke.build_current_binary()
        path = self.root / "target/iam-rehearsal/fleet-binary-build.json"
        record = json.loads(path.read_text())
        record["sources"].pop("docs/openapi.json", None)
        path.write_text(json.dumps(record))
        with mock.patch.object(smoke.argparse.ArgumentParser, "parse_args", return_value=SimpleNamespace(build=False, reset_fixture=False)):
            with mock.patch.object(smoke, "fixture_lease", side_effect=AssertionError("fixture must not be accessed")):
                with self.assertRaisesRegex(smoke.RehearsalFailure, "embedded_contract_build_evidence_required"):
                    smoke.main()


if __name__ == "__main__":
    unittest.main()
