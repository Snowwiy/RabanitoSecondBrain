from __future__ import annotations

import json
import ast
import unittest
from pathlib import Path

from scripts.publication_audit import inspect_text


class PublicationTests(unittest.TestCase):
    def test_generated_and_private_paths_are_rejected_even_if_tracked(self) -> None:
        for path in ("data/metadata.json", "knowledge/private.md", "config/settings.json",
                     "tests/.test-temp/note.md", "config/.env", "other/index.sqlite3-wal"):
            with self.subTest(path=path):
                self.assertIn("forbidden_path", {i["rule"] for i in inspect_text(path, b"{}")})

    def test_detector_does_not_print_credential_values(self) -> None:
        candidate = "gh" + "p_" + "Z" * 36
        issues = inspect_text("rabanito/example.py", candidate.encode())
        self.assertEqual(issues[0]["rule"], "github_token")
        self.assertNotIn(candidate, json.dumps(issues))

    def test_reviewed_fixture_is_not_a_file_wide_exemption(self) -> None:
        candidate = "-----BEGIN " + "PRIVATE KEY-----"
        for path in ("tests/test_core.py", "tests/test_dependencies.py", "tests/test_security_releases.py"):
            with self.subTest(path=path):
                issues = inspect_text(path, repr(candidate).encode())
                self.assertIn("private_key", {i["rule"] for i in issues})

    def test_new_literal_on_reviewed_fixture_line_is_still_reported(self) -> None:
        from scripts.publication_audit import REVIEWED_TEST_LITERALS
        import hashlib
        candidate = "-----BEGIN " + "PRIVATE KEY-----"
        for relative, fingerprints in REVIEWED_TEST_LITERALS.items():
            path = Path(__file__).resolve().parents[1] / relative
            approved = next(node.value for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
                            if isinstance(node, ast.Constant) and isinstance(node.value, str)
                            and hashlib.sha256(node.value.encode()).hexdigest() in fingerprints)
            with self.subTest(path=relative):
                payload = (repr(approved) + "; " + repr(candidate)).encode()
                issues = inspect_text(relative, payload)
                self.assertEqual(len(issues), 1)
                self.assertEqual(issues[0]["rule"], "private_key")

    def test_binary_oversize_and_unreviewed_types_are_rejected(self) -> None:
        for path, payload, expected in (("web/a.js", b"a\x00b", "binary_content"),
                                        ("docs/a.md", b"a" * (2 * 1024 * 1024 + 1), "oversize"),
                                        ("web/a.bin", b"abc", "unreviewed_file_type")):
            self.assertIn(expected, {i["rule"] for i in inspect_text(path, payload)})

    def test_example_configuration_has_only_local_portable_sources(self) -> None:
        root = Path(__file__).resolve().parents[1]
        example = json.loads((root / "config/settings.example.json").read_text(encoding="utf-8"))
        self.assertEqual(example["project_root"], ".")
        self.assertEqual(example["dashboard_host"], "127.0.0.1")
        self.assertEqual(example["additional_sources"], [])
        self.assertFalse(example["cyber"]["cadence"]["enabled"])
        for key in ("vault_root", "projects_root", "database_path", "knowledge_dir", "data_dir"):
            self.assertFalse(Path(example[key]).is_absolute())
