from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.validate_hermes_skill import accepted, child_environment, selected_environment


class HermesNativeProbeTests(unittest.TestCase):
    """No Hermes import, provider, real configuration or installation in unittest."""

    def test_environment_drops_secrets_and_python_startup_overrides(self):
        result = child_environment({
            "SystemRoot": "windows", "USERPROFILE": "unchanged-os-home",
            "API_KEY": "synthetic-not-a-secret", "HERMES_HOME": "real-profile",
            "PYTHONPATH": "outside", "PATH": "outside", "PYTHONSTARTUP": "outside",
        }, Path("temporary-home"))
        self.assertEqual(result, {"SystemRoot": "windows", "USERPROFILE": "unchanged-os-home",
                                  "HERMES_HOME": "temporary-home"})

    def fixture(self, root, *, version="3.14.7", outside=False):
        repo = (root / "hermes-agent").resolve()
        repo.mkdir()
        key = hashlib.sha256(str(repo).encode()).hexdigest()[:16]
        install = root / "installs" / key
        environments = install / "environments"
        environments.mkdir(parents=True)
        venv = root / "outside" if outside else environments / "committed" / "venv"
        (venv / "Lib/site-packages").mkdir(parents=True)
        (venv / "pyvenv.cfg").write_text("version_info = " + version + "\n", encoding="utf-8")
        facts = install / "facts.json"
        raw = json.dumps({"packages": {"venv": {"environment": str(venv)}}}).encode()
        facts.write_bytes(raw)
        return repo, facts, raw, venv

    def temporary(self):
        parent = Path(__file__).resolve().parents[1] / "tests/.test-temp"
        parent.mkdir(exist_ok=True)
        return tempfile.TemporaryDirectory(prefix="hermes-probe-contract-", dir=parent)

    def test_existing_pm_selection_is_read_without_modification(self):
        with self.temporary() as folder:
            repo, facts, raw, venv = self.fixture(Path(folder))
            selected, unchanged, site = selected_environment(repo, (3, 14, 7))
            self.assertEqual(selected, facts)
            self.assertEqual(unchanged, raw)
            self.assertEqual(site, (venv / "Lib/site-packages").resolve())
            self.assertEqual(facts.read_bytes(), raw)

    def test_runtime_abi_mismatch_is_rejected(self):
        with self.temporary() as folder:
            repo, *_ = self.fixture(Path(folder), version="3.12.14")
            with self.assertRaisesRegex(ValueError, "runtime_dependency_version_mismatch"):
                selected_environment(repo, (3, 14, 7))

    def test_selection_outside_committed_environments_is_rejected(self):
        with self.temporary() as folder:
            repo, *_ = self.fixture(Path(folder), outside=True)
            with self.assertRaisesRegex(ValueError, "runtime_environment_outside_install"):
                selected_environment(repo, (3, 14, 7))

    def test_oversized_facts_are_rejected_before_parsing(self):
        with self.temporary() as folder:
            repo, facts, *_ = self.fixture(Path(folder))
            facts.write_bytes(b" " * (1024 * 1024 + 1))
            with self.assertRaisesRegex(ValueError, "invalid_runtime_facts"):
                selected_environment(repo, (3, 14, 7))

    def complete_report(self):
        return dict.fromkeys((
            "full_module_imported", "guard_write_rejected", "home_isolated", "skill_view_success",
            "exact_skill_body", "native_yaml_parser", "preprocessed_view_success",
            "preprocessed_plain_body_equal", "temporary_cleaned", "runtime_selection_unchanged",
        ), True) | {"readiness_status": "available", "setup_needed": False,
                   "native_traversal_rejections": [True, True, True], "bootstrap_modules": [], "child_exit_code": 0}

    def test_complete_library_report_is_accepted(self):
        self.assertTrue(accepted(self.complete_report()))

    def test_every_missing_or_false_check_rejects_report(self):
        report = self.complete_report()
        for key in report:
            with self.subTest(key=key):
                self.assertFalse(accepted({name: value for name, value in report.items() if name != key}))
        for key, value in report.items():
            if value is True:
                with self.subTest(false_key=key):
                    self.assertFalse(accepted({**report, key: False}))

    def test_child_failure_bootstrap_and_traversal_regression_reject(self):
        report = self.complete_report()
        for override in ({"child_exit_code": 1}, {"bootstrap_modules": ["hermes_bootstrap"]},
                         {"native_traversal_rejections": [True, False, True]},
                         {"error": "PermissionError"}, {"setup_needed": True}):
            with self.subTest(override=override):
                self.assertFalse(accepted({**report, **override}))


if __name__ == "__main__":
    unittest.main()
