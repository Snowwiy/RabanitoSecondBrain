from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import unittest
from unittest.mock import patch
from urllib.parse import urlunsplit

from rabanito import dependencies
from rabanito.cli import main
from rabanito.config import Settings
from rabanito.db import Database, restore_database
from rabanito.dependencies import inspect_manifest
from rabanito.dependency_memory import snapshot_inventory
from rabanito.knowledge_graph import graph_page, sync_graph
from rabanito.knowledge_graph.projection import dependency_id
from rabanito.pylock import is_pylock_name, parse_pylock
from tests import test_dependencies as fixtures


def artifact(**extra):
    return {"url": "https://files.pythonhosted.org/packages/fixture/parser-1.0-py3-none-any.whl", "hashes": {"sha256": "a" * 64}, **extra}


def package(name="parser", version="1.0", **extra):
    result = {"name": name, "version": version, "wheels": [artifact()], **extra}
    return {k: v for k, v in result.items() if v is not None}


def _toml(value):
    if isinstance(value, dict): return "{" + ", ".join(json.dumps(k) + " = " + _toml(v) for k, v in value.items()) + "}"
    if isinstance(value, list): return "[" + ", ".join(_toml(v) for v in value) + "]"
    return json.dumps(value, ensure_ascii=False)


def lock(*entries, **extra):
    header = {"lock-version": "1.0", "created-by": "fixture-only", **extra}
    if not entries: header["packages"] = []
    return "\n".join(json.dumps(k) + " = " + _toml(v) for k, v in header.items()) + "\n" + "\n".join(
        "[[packages]]\n" + "\n".join(json.dumps(k) + " = " + _toml(v) for k, v in p.items()) for p in entries) + "\n"


class PylockTests(unittest.TestCase):
    setUp = fixtures.DependencyTests.setUp
    tearDown = fixtures.DependencyTests.tearDown
    register = fixtures.DependencyTests.register
    seed = fixtures.DependencyTests.seed

    def write(self, raw=None, name="pylock.toml"):
        self.path = self.project / name; self.path.parent.mkdir(exist_ok=True, parents=True)
        self.path.write_text(raw if raw is not None else lock(package()), encoding="utf-8")
        return self.path

    def inspect(self):
        return inspect_manifest(self.settings, str(self.project), self.path.relative_to(self.project).as_posix())

    def test_public_artifact_has_citation_and_toml_pointer_without_network_or_writes(self):
        self.seed(); self.write(); original = self.path.read_bytes()
        before = hashlib.sha256(self.settings.database_path.read_bytes()).hexdigest()
        with patch("socket.socket", side_effect=AssertionError("offline")), patch("subprocess.Popen", side_effect=AssertionError("no commands")):
            report = self.inspect()
        self.assertEqual(report["summary"], {"potentially_affected": 1})
        self.assertEqual(report["findings"][0]["component_pointer"], "/packages/0")
        self.assertEqual(report["findings"][0]["affected_pointer"], "/affected/0")
        self.assertTrue(report["findings"][0]["citation"].startswith("https://api.osv.dev/"))
        self.assertEqual(report["components"][0]["locator_kind"], "parsed_toml_tree")
        self.assertNotIn("line_number", report["components"][0])
        self.assertEqual(report["source"]["sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(hashlib.sha256(self.settings.database_path.read_bytes()).hexdigest(), before)
        self.assertFalse(report["cache"]["writes"])
        self.assertNotIn(str(self.root), json.dumps(report))

    def test_public_index_and_sdist_wheels_origins_are_explicit_not_attested(self):
        self.write(lock(package(index="https://pypi.org/simple/", sdist=artifact()), package(wheels=None, sdist=artifact())))
        report = self.inspect()
        self.assertEqual(report["component_count"], 2)
        self.assertEqual([c["artifact_count"] for c in report["components"]], [2, 1])
        self.assertEqual([c["source_kind"] for c in report["components"]], ["pypi_index_declared", "pypi_artifacts_declared"])
        self.assertTrue(all(c["artifact_integrity"] == "declared_hashes_not_verified" for c in report["components"]))
        self.assertIn("no_attestation_verification", report["coverage"]["artifacts"])

    def test_private_index_vcs_directory_archive_and_missing_sources_are_unverified(self):
        self.seed()
        self.write(lock(package(index="https://private.invalid/simple"), package(wheels=None, vcs={"type": "git", "url": "https://private.invalid/code", "commit-id": "fixture"}),
                        package(wheels=None, directory={"path": "../../outside"}), package(wheels=None, archive={"url": "https://private.invalid/archive", "hashes": {"sha256": "a" * 64}}), package(wheels=None)))
        report = self.inspect()
        self.assertEqual(report["summary"], {"needs_review": 5})
        self.assertFalse(report["findings"])
        self.assertTrue(all(not c["ecosystem"] for c in report["components"]))
        self.assertEqual(report["components"][3]["artifact_count"], 1)
        self.assertNotIn("private.invalid", json.dumps(report)); self.assertNotIn("outside", json.dumps(report))

    def test_path_precedence_and_conflicting_sources_never_assume_public_pypi(self):
        self.seed(); self.write(lock(package(wheels=[artifact(path="../../outside.whl")]),
                                    package(directory={"path": "."}), package(wheels=None, directory={"path": "."}, vcs={"type": "git"})))
        report = self.inspect()
        self.assertEqual(report["summary"], {"needs_review": 3})
        self.assertEqual([c["source_kind"] for c in report["components"]], ["artifact_path_unverified", "conflicting_sources", "conflicting_sources"])

    def test_credentials_tool_attestations_and_marker_values_are_not_echoed_or_followed(self):
        credentials = urlunsplit(("https", "fixture-user:" + "example-password@private.invalid", "/simple", "", ""))
        self.write(lock(package(index=credentials, marker="private-marker-sentinel", tool={"command": "untrusted-command-sentinel"},
                                **{"attestation-identities": [{"kind": "private-attestation-sentinel"}]}),
                        **{"created-by": "private-creator-sentinel", "tool": {"command": "untrusted-global-sentinel"}}))
        with patch("socket.socket", side_effect=AssertionError("offline")), patch("subprocess.Popen", side_effect=AssertionError("untrusted")):
            report = self.inspect()
        for secret in (credentials, "private.invalid", "example-password", "private-marker-sentinel", "untrusted-command-sentinel", "private-attestation-sentinel", "private-creator-sentinel", "untrusted-global-sentinel"):
            self.assertNotIn(secret, json.dumps(report))

    def test_conditions_and_artifact_forks_stay_distinct_without_evaluating_environment(self):
        self.write(lock(package(marker="sys_platform == 'win32'"), package(marker="sys_platform == 'linux'"), package(wheels=[artifact(hashes={"sha256": "b" * 64})]),
                        **{"environments": ["python_version >= '3.11'"], "dependency-groups": ["private-group"], "default-groups": ["default-private"], "extras": ["private-extra"]}))
        report = self.inspect()
        self.assertEqual(report["component_count"], 3)
        self.assertEqual(len({c["inventory_scope_sha256"] for c in report["components"]}), 3)
        self.assertTrue(all(c["environment_selection"] == "pylock_entry_conditions_not_evaluated" for c in report["components"]))
        for literal in ("sys_platform", "python_version", "private-group", "default-private", "private-extra"):
            self.assertNotIn(literal, json.dumps(report))

    def test_deduplication_keeps_additional_locators_but_not_unverified_identity(self):
        self.write(lock(package("Parser"), package("parser"), *[package(index="https://private.invalid/simple")] * 2))
        report = self.inspect()
        self.assertEqual(report["duplicates_removed"], 1); self.assertEqual(report["component_count"], 3)
        self.assertEqual(report["components"][0]["additional_locations"], ["/packages/1"])

    def test_named_unicode_lockfiles_are_explicit_and_pyproject_is_not_a_lock(self):
        for name in ("pylock.toml", "pylock.ci.toml", "PYLOCK.CI.TOML", "pylock.Producción á.toml"):
            with self.subTest(name=name):
                self.assertTrue(is_pylock_name(name)); self.write(name=name); self.assertEqual(self.inspect()["component_count"], 1)
        for name in ("pylock..toml", "pylock.a.b.toml", "pyproject.toml", "poetry.lock", "pylock.toml.bak", "pylock. .toml", "pylock.x:secret.toml"):
            self.assertFalse(is_pylock_name(name))
            with self.assertRaises(ValueError): inspect_manifest(self.settings, str(self.project), name)

    def test_versions_required_metadata_and_future_formats_fail_closed(self):
        for version in ("2.0", "1.1", "0.1", 1, True, 1.0):
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "unsupported_pylock_version"):
                parse_pylock(lock(package(), **{"lock-version": version}), 10)
        for raw in (lock().replace('"created-by" = "fixture-only"\n', ''), lock(**{"created-by": 1}), lock(**{"requires-python": False}), lock(**{"environments": "private"})):
            with self.assertRaises(ValueError): parse_pylock(raw, 10)
        self.assertEqual(parse_pylock(lock(), 10)[1], [])

    def test_malformed_toml_duplicate_keys_and_nonfinite_errors_never_echo_source(self):
        for raw in ('lock-version="1.0"\nlock-version="1.0"', 'secret-line-sentinel = "unterminated', lock(**{"tool": {"number": float("nan")}}).replace("NaN", "nan")):
            with self.assertRaisesRegex(ValueError, "^malformed_pylock$") as caught: parse_pylock(raw, 10)
            self.assertNotIn("secret-line-sentinel", str(caught.exception))

    def test_structure_depth_count_and_marker_budgets_are_enforced(self):
        for raw in (lock(**{"tool": {"deep": [0]}}).replace("[0]", "[" * 66 + "0" + "]" * 66),
                    lock(**{"tool": {"wide": [0]}}).replace("[0]", "[" + "0," * 100001 + "]")):
            with self.assertRaisesRegex(ValueError, "structure_limit"): parse_pylock(raw, 10)
        with self.assertRaisesRegex(ValueError, "pylock_packages"): parse_pylock(lock(package(), package()), 1)
        with self.assertRaisesRegex(ValueError, "pylock_conditions"): parse_pylock(lock(**{"environments": ["x" * 4096] * 17}), 10)
        for cap in (True, 0, 10001):
            with self.assertRaisesRegex(ValueError, "inventory_budget"): parse_pylock(lock(), cap)
        self.write(); self.settings.raw["dependency_analysis"] = {"max_sbom_bytes": 10}
        with self.assertRaisesRegex(ValueError, "size_limit"): self.inspect()

    def test_unknown_semantic_keys_and_malformed_package_shapes_fail_closed(self):
        for raw in (lock(**{"unknown-field": "private"}), lock(package(**{"new-source": "private"})),
                    lock(package(marker=3)), lock(package(index=[])), lock(package(dependencies="bad")), lock(package(wheels="bad"))):
            with self.assertRaises(ValueError): parse_pylock(raw, 10)

    def test_invalid_hash_sizes_unknown_artifact_fields_and_types_are_not_public_matches(self):
        self.seed()
        examples = [artifact(hashes={}), artifact(hashes={"sha256": "x" * 64}), artifact(hashes={"sha256": "a" * 63}), artifact(size=True), artifact(size=-1), artifact(**{"new-source": "private"}), {"hashes": {"sha256": "a" * 64}}]
        self.write(lock(*(package(wheels=[a]) for a in examples)))
        self.assertEqual(self.inspect()["summary"], {"needs_review": len(examples)})

    def test_public_host_spoofing_credentials_queries_and_protocols_stay_unverified(self):
        urls = ["http://files.pythonhosted.org/packages/x", "https://files.pythonhosted.org.private.invalid/packages/x", "https://files.pythonhosted.org/other/x", "https://files.pythonhosted.org/packages/x?private=hidden-query-sentinel", "https://files.pythonhosted.org:444/packages/x", "https://files.pythonhosted.org:invalid/packages/x", "file:///outside.whl"]
        self.write(lock(*(package(wheels=[artifact(url=u)]) for u in urls)))
        report = self.inspect(); self.assertEqual(report["summary"], {"needs_review": len(urls)})
        self.assertNotIn("hidden-query-sentinel", json.dumps(report))

    def test_unknown_token_names_unresolved_versions_and_local_packages_are_not_invented(self):
        token = "gh" + "p_" + "Z" * 36
        self.write(lock(package(name=None), package(name=token), package(version=token), package(version=None), package(version="password:private-value")))
        report = self.inspect(); self.assertEqual(report["summary"], {"needs_review": 5})
        self.assertNotIn(token, json.dumps(report)); self.assertNotIn("private-value", json.dumps(report))

    def test_attestation_and_dependencies_do_not_create_new_confirmed_relations(self):
        self.write(lock(package(dependencies=[{"name": "not-a-declared-package"}], **{"attestation-identities": [{"kind": "GitHub", "repository": "private-name"}]})))
        report = self.inspect(); self.assertEqual(report["component_count"], 1)
        self.assertEqual(report["components"][0]["artifact_integrity"], "declared_hashes_not_verified")
        self.assertNotIn("not-a-declared-package", json.dumps(report)); self.assertNotIn("private-name", json.dumps(report))

    def test_package_and_global_condition_changes_update_only_their_scoped_identity(self):
        self.write(lock(package())); original = self.inspect()["components"][0]
        self.write(lock(package(**{"requires-python": ">=3.12"}))); scoped = self.inspect()["components"][0]
        self.assertNotEqual(dependency_id(1, original), dependency_id(1, scoped))
        self.write(lock(package(), **{"environments": ["os_name == 'nt'"]})); global_scoped = self.inspect()["components"][0]
        self.assertNotEqual(original["conditions_sha256"], global_scoped["conditions_sha256"])

    def test_unicode_paths_project_exclusions_extensions_and_traversal_guards(self):
        self.write(name="Documentación á/pylock.Producción.toml")
        self.assertEqual(self.inspect()["source"]["relative_path"], "Documentación á/pylock.Producción.toml")
        for value in ("../pylock.toml", "C:/pylock.toml", "pylock.toml:secret"):
            with self.assertRaises(ValueError): inspect_manifest(self.settings, str(self.project), value)
        self.settings.raw["source_policy"]["projects"]["exclude_extensions"] = [".toml"]
        with self.assertRaises(ValueError): self.inspect()
        self.settings.raw["source_policy"]["projects"]["exclude_extensions"] = []
        self.settings.raw["excluded_projects"] = [self.project.name]
        with self.assertRaises(ValueError): self.inspect()

    def test_nested_project_and_reparse_components_are_rejected(self):
        child = self.project / "nested"; child.mkdir(); self.register(child)
        self.write(name="nested/pylock.toml")
        with self.assertRaises(ValueError): self.inspect()
        self.write()
        with patch("rabanito.dependencies.contains_reparse_component", return_value=True), self.assertRaises(ValueError): self.inspect()

    def test_cli_returns_the_same_bounded_report_and_citation(self):
        self.seed(); self.write(); output = io.StringIO()
        with patch("rabanito.cli.load_settings", return_value=self.settings), contextlib.redirect_stdout(output):
            main(["dependency", "inspect", "--project", str(self.project), "--manifest", "pylock.toml"])
        report = json.loads(output.getvalue()); self.assertEqual(report["summary"], {"potentially_affected": 1})
        self.assertEqual(report["findings"][0]["component_pointer"], "/packages/0")
        self.assertEqual(report["coverage"]["remote_requests"], 0)

    def test_engine_five_and_equal_mtime_content_changes_cannot_reuse_stale_reports(self):
        self.write()
        with patch.object(dependencies, "ENGINE_VERSION", 5):
            old = snapshot_inventory(self.settings, str(self.project), "pylock.toml", kind="manifest", save=True)["report"]
        current = self.inspect(); self.assertEqual(current["engine_version"], 6)
        self.assertEqual(current["cache"]["status"], "computed"); self.assertNotEqual(old["analysis_id"], current["analysis_id"])
        snapshot_inventory(self.settings, str(self.project), "pylock.toml", kind="manifest", save=True)
        self.assertEqual(self.inspect()["cache"]["status"], "reused_saved_analysis")
        stamp = self.path.stat(); self.write(lock(package(version="1.1"))); os.utime(self.path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        self.assertNotEqual(self.inspect()["analysis_id"], current["analysis_id"])

    def test_snapshot_backup_restore_and_graph_preserve_source_variants(self):
        self.seed(); self.write(lock(package(), package(marker="os_name == 'nt'"), package(index="https://private.invalid/simple")))
        saved = snapshot_inventory(self.settings, str(self.project), "pylock.toml", kind="manifest", save=True)["report"]
        for _ in range(10):
            batch = sync_graph(self.settings, max_inputs=2000)
            self.assertFalse(batch["errors"])
            if batch["status"] == "ok": break
        else: self.fail("graph did not converge")
        self.assertEqual(len(graph_page(self.settings, kind="dependency", project=str(self.project), limit=20)["nodes"]), 3)
        backup = self.root / "data" / "saved.db"; restored = self.root / "data" / "restored.db"
        with Database(self.settings.database_path, read_only=True) as db: db.backup(backup)
        restore_database(backup, restored)
        recovered = Settings(self.root, {**self.settings.raw, "database_path": str(restored)})
        report = inspect_manifest(recovered, str(self.project), "pylock.toml")
        self.assertEqual(report["analysis_id"], saved["analysis_id"])
        with Database(restored, read_only=True) as db:
            self.assertEqual(db.one("PRAGMA integrity_check")[0], "ok"); self.assertFalse(db.query("PRAGMA foreign_key_check"))

    def test_toml_timestamps_are_hashed_without_serialization_or_source_leaks(self):
        raw = lock(package()).replace('"hashes" =', '"upload-time" = 2025-01-25T11:30:10Z, "hashes" =')
        self.write(raw); self.assertEqual(self.inspect()["component_count"], 1)
        self.assertNotIn("2025-01-25", json.dumps(self.inspect()))

    def test_sha256_is_declared_not_verified_and_weak_hash_is_not_a_security_claim(self):
        self.write(lock(package(wheels=[artifact(hashes={"md5": "a" * 32})])))
        report = self.inspect()
        self.assertEqual(report["components"][0]["artifact_integrity"], "declared_hashes_not_verified")
        self.assertEqual(report["coverage"]["remote_requests"], 0)
        self.assertEqual(report["summary"], {"no_local_advisory": 1})


if __name__ == "__main__":
    unittest.main()
