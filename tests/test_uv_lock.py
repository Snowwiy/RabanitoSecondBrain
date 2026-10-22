from __future__ import annotations

import contextlib
import base64
import hashlib
import io
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlunsplit

from rabanito.cli import main
from rabanito.config import Settings
from rabanito.db import Database, restore_database
from rabanito.dependencies import inspect_manifest
from rabanito.dependency_memory import snapshot_inventory
from rabanito.knowledge_graph import graph_page, sync_graph
from rabanito.knowledge_graph.projection import dependency_id
from rabanito.uv_lock import parse_uv_lock
from scripts import validate_uv_lock as research
from tests import test_dependencies as fixtures


def package(name="parser", version="1.0", source=None, markers=None):
    lines = ["[[package]]"]
    if name is not None: lines.append("name = " + json.dumps(name))
    if version is not None: lines.append("version = " + json.dumps(version))
    source = {"registry": "https://pypi.org/simple"} if source is None else source
    values = [json.dumps(k) + " = " + json.dumps(v) for k, v in source.items()]
    lines.append("source = { " + ", ".join(values) + " }")
    if markers is not None: lines.append("resolution-markers = " + json.dumps(markers))
    return "\n".join(lines) + "\n"


def lock(*entries, revision=5, extra=""):
    return 'version = 1\n' + ("revision = " + str(revision) + "\n" if revision is not None else "") + 'requires-python = ">=3.11"\n' + extra + "\n" + "\n".join(entries)


class UvLockTests(unittest.TestCase):
    setUp = fixtures.DependencyTests.setUp
    tearDown = fixtures.DependencyTests.tearDown
    register = fixtures.DependencyTests.register
    seed = fixtures.DependencyTests.seed

    def write(self, raw=None):
        self.path = self.project / "uv.lock"
        self.path.write_text(raw if raw is not None else lock(package()), encoding="utf-8")
        return self.path

    def inspect(self):
        return inspect_manifest(self.settings, self.project.name, self.path.relative_to(self.project).as_posix())

    def test_pypi_candidate_has_toml_provenance_and_hash_without_network_or_writes(self):
        self.seed(); self.write()
        original = self.path.read_bytes()
        before = hashlib.sha256(self.settings.database_path.read_bytes()).hexdigest()
        with patch("socket.socket", side_effect=AssertionError("offline")), patch("subprocess.Popen", side_effect=AssertionError("no package tools")):
            report = self.inspect()
        self.assertEqual(report["summary"], {"potentially_affected": 1})
        self.assertEqual(report["source"]["sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(report["findings"][0]["component_pointer"], "/package/0")
        self.assertEqual(report["components"][0]["locator_kind"], "parsed_toml_tree")
        self.assertTrue(report["findings"][0]["citation"].startswith("https://api.osv.dev/"))
        self.assertIn("not_evaluated", report["coverage"]["selection"])
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(hashlib.sha256(self.settings.database_path.read_bytes()).hexdigest(), before)
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertIsNone(db.one("SELECT 1 FROM sqlite_master WHERE name='dependency_migrations'"))

    def test_sources_do_not_turn_private_git_local_or_ambiguous_packages_into_pypi(self):
        self.seed()
        sources = [{"registry": "https://private.invalid/simple?token=secret-sentinel"}, {"registry": "../private-wheels"},
                   {"git": "https://private.invalid/project#secret-sentinel"}, {"url": "https://private.invalid/archive"},
                   {"path": "../../outside"}, {"directory": "private/dir"}, {"editable": "."}, {"virtual": "."},
                   {"registry": "https://pypi.org/simple", "git": "private"}, {"new-source": "private"}]
        self.write(lock(*(package(source=s) for s in sources)))
        report = self.inspect()
        self.assertEqual(report["summary"], {"needs_review": len(sources)})
        self.assertEqual(report["findings"], [])
        self.assertTrue(all(not c["ecosystem"] for c in report["components"]))
        for secret in ("private.invalid", "secret-sentinel", "outside", "private-wheels"):
            self.assertNotIn(secret, json.dumps(report))

    def test_credentials_wheels_metadata_and_commands_are_never_echoed_or_followed(self):
        self.seed()
        credentials = urlunsplit(("https", "fixture-user:" + "example-password@private.invalid", "/simple", "", ""))
        raw = lock(package(source={"registry": credentials})) + '\n[package.metadata]\ncommand = "untrusted-command-sentinel"\n'
        raw += '\n[package.sdist]\nurl = "https://private.invalid/?token=hidden-query-sentinel"\n'
        self.write(raw)
        with patch("socket.socket", side_effect=AssertionError("offline")), patch("subprocess.Popen", side_effect=AssertionError("untrusted commands")):
            report = self.inspect()
        for value in (credentials, "private.invalid", "example-password", "untrusted-command-sentinel", "hidden-query-sentinel"):
            self.assertNotIn(value, json.dumps(report))

    def test_universal_marker_forks_remain_distinct_without_evaluating_python(self):
        self.seed()
        self.write(lock(package(version="1.0", markers=["python_version < '3.10'"]),
                        package(version="2.0", markers=["python_version >= '3.10'"])))
        report = self.inspect()
        self.assertEqual(report["component_count"], 2)
        self.assertEqual(len({c["conditions_sha256"] for c in report["components"]}), 2)
        self.assertTrue(all(c["environment_selection"] == "universal_lock_entry_not_evaluated" for c in report["components"]))
        self.assertNotIn("python_version", json.dumps(report["components"]))

    def test_duplicate_known_coordinates_keep_additional_locations_but_not_distinct_forks(self):
        self.write(lock(package("Parser"), package("parser"), package("parser", markers=["sys_platform == 'win32'"])))
        report = self.inspect()
        self.assertEqual((report["component_count"], report["duplicates_removed"]), (2, 1))
        self.assertEqual(report["components"][0]["additional_locations"], ["/package/1"])
        self.assertNotEqual(dependency_id(1, report["components"][0]), dependency_id(1, report["components"][1]))

    def test_public_registry_trailing_slash_is_same_declared_identity(self):
        self.write(lock(package(), package(source={"registry": "https://pypi.org/simple/"})))
        self.assertEqual(self.inspect()["duplicates_removed"], 1)

    def test_unknown_names_versions_and_dynamic_local_packages_are_not_invented(self):
        token = "gh" + "p_" + "Z" * 36
        self.write(lock(package(name=None), package(version=None), package(name=token), package(version=token),
                        package(version=None, source={"virtual": "."}), package(version="password:private-value")))
        report = self.inspect()
        self.assertEqual(report["summary"], {"needs_review": 6})
        self.assertEqual(report["findings"], [])
        self.assertNotIn(token, json.dumps(report))
        self.assertNotIn("private-value", json.dumps(report))
        self.assertTrue(all(c["identity_issue"] for c in report["components"]))

    def test_python_epochs_prereleases_post_and_dev_use_public_ordering(self):
        self.seed()
        self.write(lock(*(package(version=v) for v in ("1.8rc1", "1!1.0", "1.0.post1", "1.0.dev1"))))
        self.assertEqual(self.inspect()["summary"], {"potentially_affected": 3, "outside_observed_ranges": 1})

    def test_unsupported_major_or_future_revision_is_rejected_instead_of_guessed(self):
        for replacement in ("version = 2", 'version = "1"', "version = true", "version = 1.0"):
            with self.subTest(version=replacement), self.assertRaisesRegex(ValueError, "unsupported_uv"):
                parse_uv_lock(lock(package()).replace("version = 1\n", replacement + "\n", 1), 10)
        for revision in (-1, 6, 100):
            with self.subTest(revision=revision), self.assertRaisesRegex(ValueError, "unsupported_uv"):
                parse_uv_lock(lock(package(), revision=revision), 10)

    def test_reviewed_revisions_zero_through_five_and_empty_locks_are_explicit(self):
        for revision in (None, 0, 1, 2, 3, 4, 5):
            with self.subTest(revision=revision):
                format_name, result, _, _ = parse_uv_lock(lock(package(), revision=revision), 10)
                self.assertEqual(len(result), 1)
                self.assertIn("revision " + str(revision or 0), format_name)
        self.assertEqual(parse_uv_lock(lock(), 10)[1], [])

    def test_malformed_duplicate_or_nonfinite_toml_has_static_sanitized_errors(self):
        for raw in ('version = 1\nversion = 2\n', 'private = "secret-line-sentinel', lock(extra="value = nan\n"),
                    lock(extra="value = inf\n"), '{"version":1}'):
            with self.subTest(), self.assertRaisesRegex(ValueError, "^malformed_uv_lock$") as caught:
                parse_uv_lock(raw, 10)
            self.assertNotIn("secret-line-sentinel", str(caught.exception))

    def test_invalid_structures_markers_and_python_requirements_fail_closed(self):
        for raw in (lock(extra="package = false\n"), lock(extra="package = [42]\n"),
                    lock(package()).replace('requires-python = ">=3.11"', 'requires-python = 3'),
                    lock(package()).replace('requires-python = ">=3.11"\n', ""),
                    lock(package(markers=["x"])).replace('["x"]', '"x"')):
            with self.subTest(raw=raw[:50]), self.assertRaises(ValueError): parse_uv_lock(raw, 10)

    def test_count_bytes_depth_and_marker_budgets_are_enforced(self):
        with self.assertRaisesRegex(ValueError, "uv_packages"): parse_uv_lock(lock(package(), package()), 1)
        with self.assertRaisesRegex(ValueError, "structure_limit"):
            parse_uv_lock(lock(extra="unknown = " + "[" * 66 + "0" + "]" * 66 + "\n"), 10)
        with self.assertRaisesRegex(ValueError, "structure_limit"):
            parse_uv_lock(lock(extra="unknown = [" + "0," * 100001 + "]\n"), 10)
        with self.assertRaisesRegex(ValueError, "uv_markers"):
            parse_uv_lock(lock(package(markers=["m" * 4096] * 17)), 10)
        self.write()
        self.settings.raw["dependency_analysis"] = {"max_sbom_bytes": 10}
        with self.assertRaisesRegex(ValueError, "size_limit"): self.inspect()

    def test_toml_multiline_fake_header_does_not_fabricate_source_line_numbers(self):
        self.write(lock(package()) + '\n[package.metadata]\ncomment = """\n[[package]]\nname = "fake"\n"""\n')
        report = self.inspect()
        self.assertEqual(report["component_count"], 1)
        self.assertEqual(report["components"][0]["pointer"], "/package/0")
        self.assertNotIn("line_number", report["components"][0])

    def test_only_selected_file_is_read_not_pyproject_or_local_sources(self):
        self.write(lock(package(source={"editable": "../not-followed"})))
        from rabanito import source_files
        from contextlib import contextmanager
        actual_open = source_files._native_open
        opened = []
        @contextmanager
        def selected_only(path, *args, **kwargs):
            opened.append(path)
            if path != self.path: raise AssertionError("unexpected file read")
            with actual_open(path, *args, **kwargs) as stream:
                yield stream
        with patch.object(source_files, '_native_open', selected_only), patch.object(Path, 'open', side_effect=AssertionError('unpinned file read')):
            report = self.inspect()
        self.assertEqual(opened, [self.path])
        self.assertEqual(report["summary"], {"needs_review": 1})

    def test_unicode_relative_paths_and_exclusions_keep_existing_permissions(self):
        path = self.project / "Documentación á/uv.lock"
        path.parent.mkdir(); path.write_text(lock(package()), encoding="utf-8"); self.path = path
        self.assertEqual(self.inspect()["source"]["relative_path"], "Documentación á/uv.lock")
        self.settings.raw["source_policy"]["projects"]["exclude_extensions"] = [".lock"]
        with self.assertRaisesRegex(ValueError, "excluded"): self.inspect()

    def test_parent_project_cannot_read_another_registered_project_lock(self):
        child = self.project / "Nested"
        child.mkdir(); self.register(child)
        self.path = child / "uv.lock"; self.path.write_text(lock(package()), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "another_project"): self.inspect()

    def test_unauthorized_names_traversal_and_reparse_are_not_new_connectors(self):
        self.write()
        for relative in ("poetry.lock", "pylock.toml", "../uv.lock", "uv.lock:stream", "private/uv.lock"):
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                inspect_manifest(self.settings, self.project.name, relative)
        with patch("rabanito.dependencies.contains_reparse_component", return_value=True):
            with self.assertRaises(ValueError): self.inspect()

    def test_saved_analysis_reuse_avoids_parsing_and_source_changes_invalidate_it(self):
        self.seed(); self.write()
        saved = snapshot_inventory(self.settings, str(self.project), "uv.lock", kind="manifest", save=True)["report"]
        with patch("rabanito.uv_lock.parse_uv_lock", side_effect=AssertionError("must reuse validated saved analysis")):
            report = self.inspect()
        self.assertEqual(report["cache"]["status"], "reused_saved_analysis")
        self.assertEqual(report["analysis_id"], saved["analysis_id"])
        stamp = self.path.stat()
        self.path.write_text(lock(package(version="1.1")), encoding="utf-8")
        os.utime(self.path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        current = self.inspect()
        self.assertEqual(current["cache"]["status"], "computed")
        self.assertNotEqual(current["analysis_id"], saved["analysis_id"])

    def test_engine_bump_does_not_reuse_an_engine_three_report(self):
        self.write()
        with patch("rabanito.dependencies.ENGINE_VERSION", 3):
            old = snapshot_inventory(self.settings, str(self.project), "uv.lock", kind="manifest", save=True)["report"]
        report = self.inspect()
        self.assertEqual(report["engine_version"], 6)
        self.assertEqual(report["cache"]["status"], "computed")
        self.assertNotEqual(report["analysis_id"], old["analysis_id"])

    def test_snapshot_restore_and_graph_preserve_sources_without_fabricating_equivalence(self):
        self.seed()
        self.write(lock(package(), package(source={"registry": "https://one.invalid/simple"}),
                        package(source={"registry": "https://two.invalid/simple"})))
        saved = snapshot_inventory(self.settings, str(self.project), "uv.lock", kind="manifest", save=True)["report"]
        self.assertEqual(len({dependency_id(1, c) for c in saved["components"]}), 3)
        self.assertEqual(sync_graph(self.settings, max_inputs=2000)["status"], "ok")
        nodes = graph_page(self.settings, kind="dependency", project=str(self.project), limit=10)["nodes"]
        self.assertEqual(len(nodes), 3)
        self.assertTrue(all(n["data"]["environment_selection"] == "universal_lock_entry_not_evaluated" for n in nodes))
        self.assertNotIn("one.invalid", json.dumps(nodes))
        backup, target = self.root / "uv-backup.db", self.root / "uv-restored.db"
        with Database(self.settings.database_path, read_only=True) as db: db.backup(backup)
        restore_database(backup, target)
        settings = Settings(self.root, {**self.settings.raw, "database_path": str(target)})
        recovered = inspect_manifest(settings, str(self.project), "uv.lock")
        self.assertEqual(recovered["analysis_id"], saved["analysis_id"])
        self.assertEqual(recovered["cache"]["status"], "reused_saved_analysis")

    def test_cli_uses_the_same_local_memory_with_explicit_manifest(self):
        self.seed(); self.write()
        output = io.StringIO()
        with patch("rabanito.cli.load_settings", return_value=self.settings), contextlib.redirect_stdout(output):
            main(["dependency", "inspect", "--project", self.project.name, "--manifest", "uv.lock"])
        report = json.loads(output.getvalue())
        self.assertEqual(report["summary"], {"potentially_affected": 1})
        self.assertIn("uv.lock v1", report["source"]["format"])

    def test_no_local_advisory_never_becomes_a_safe_or_installed_claim(self):
        self.write()
        report = self.inspect()
        self.assertEqual(report["summary"], {"no_local_advisory": 1})
        self.assertEqual(report["coverage"]["remote_requests"], 0)
        self.assertIn("not_installed_state", report["coverage"]["scope"])

    def capture(self, transform=None):
        body = lock(package()).encode()
        blob = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
        payload = {"sha": blob, "size": len(body), "encoding": "base64", "content": base64.b64encode(body).decode()}
        if transform: payload = transform(payload)
        class Opener:
            def open(self, request, timeout):
                return io.BytesIO(json.dumps(payload).encode())
        settings = Settings(research.ROOT, {**self.settings.raw, "data_dir": str(self.root / "research-data"),
                                            "database_path": str(self.settings.database_path)})
        with patch.object(research, "build_opener", return_value=Opener()):
            return settings, research.capture(settings, blob)

    def test_public_capture_rehearsal_is_offline_and_does_not_replace_live_database(self):
        self.seed()
        settings, captured = self.capture()
        before = hashlib.sha256(self.settings.database_path.read_bytes()).hexdigest()
        with patch("socket.socket", side_effect=AssertionError("offline rehearsal")):
            result = research.rehearse(settings, captured["manifest"])
        self.assertTrue(result["temporary_copy_cleaned"])
        self.assertTrue(result["restored_analysis_id_equal"])
        self.assertFalse(result["live_database_replaced"])
        self.assertEqual(hashlib.sha256(self.settings.database_path.read_bytes()).hexdigest(), before)

    def test_public_capture_rejects_wrong_blob_metadata_or_hash(self):
        for transform in (lambda d: {**d, "sha": "a" * 40}, lambda d: {**d, "size": True},
                          lambda d: {**d, "size": 999}, lambda d: {**d, "encoding": "text"},
                          lambda d: {**d, "content": "invalid base64"}):
            with self.subTest(), self.assertRaises((ValueError, base64.binascii.Error)): self.capture(transform)

    def test_failed_capture_metadata_write_cleans_only_its_new_body(self):
        settings, first = self.capture()
        with patch.object(research, "write_json_atomic", side_effect=OSError("fixture failure")):
            with self.assertRaises(OSError): self.capture()
        folder = research.folder(settings)
        self.assertEqual(len(list(folder.glob("*.uv.lock"))), 1)
        self.assertTrue((folder / first["body"]).is_file())

    def test_research_manifest_scope_types_and_hash_are_verified_before_rehearsal(self):
        settings, captured = self.capture()
        path = research.folder(settings) / captured["manifest"]
        original = json.loads(path.read_text(encoding="utf-8"))
        for value in ([], {**original, "body": "../private"}, {**original, "blob_sha1": 1},
                      {**original, "repository": "other/repository"}, {**original, "sha256": "a" * 64}):
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.subTest(), self.assertRaises(ValueError): research.rehearse(settings, captured["manifest"])
        path.write_text(json.dumps(original), encoding="utf-8")
        with patch.object(research, "contains_reparse_component", side_effect=lambda p: Path(p) == research.ROOT / "tests/.test-temp"):
            with self.assertRaisesRegex(ValueError, "unsafe_uv_rehearsal_temporary_directory"):
                research.rehearse(settings, captured["manifest"])
