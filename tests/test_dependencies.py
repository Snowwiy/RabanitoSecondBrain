from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rabanito.cli import main
from rabanito.config import Settings
from rabanito.cyber.sync import sync_source
from rabanito.db import Database
from rabanito.dependencies import inspect_manifest, inspect_sbom, package_key, parse_purl, python_release_key, semver_key, version_evidence
from rabanito.utils import path_key
from tests.test_cyber import FakeClient, GHSA, NOW, osv


def component(name="parser", version="1.0", kind="pypi"):
    return {"type": "library", "name": name, "version": version, "purl": f"pkg:{kind}/{name}@{version}"}


class DependencyTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parent / ".test-temp"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="dependencies-ñ-", dir=parent)
        self.root = Path(self.temporary.name)
        self.settings = Settings(self.root, {"database_path": "data/test.db", "data_dir": "data", "knowledge_dir": "knowledge",
                                           "vault_root": "vault", "projects_root": "projects", "source_policy": {
                                               "projects": {"exclude_dirs": ["secrets", "node_modules"], "exclude_names": ["credentials.json"]}}})
        self.project = self.root / "projects" / "Prueba Unicode á"
        self.project.mkdir(parents=True)
        self.register(self.project)
        self.path = self.project / "inventario ñ.json"

    def tearDown(self):
        self.temporary.cleanup()

    def register(self, root, status="active"):
        with Database(self.settings.database_path) as db:
            db.execute("INSERT INTO projects(name,root_path,path_key,first_seen,last_seen,status) VALUES (?,?,?,?,?,?)",
                       (root.name, str(root), path_key(root), NOW.isoformat(), NOW.isoformat(), status))
            db.commit()

    def seed(self, payload=None):
        result = sync_source(self.settings, "osv", [GHSA], client=FakeClient([payload or osv()]), now=NOW)
        self.assertEqual(result["status"], "ok")

    def write(self, components=None, payload=None):
        self.path.write_text(json.dumps(payload or {"bomFormat": "CycloneDX", "specVersion": "1.6", "components":
                                                  components if components is not None else [component()]}, ensure_ascii=False), encoding="utf-8")

    def inspect(self):
        return inspect_sbom(self.settings, self.project.name, self.path.name)

    def test_exact_osv_version_has_citation_but_does_not_assert_deployment(self):
        self.seed()
        self.write()
        original = self.path.read_bytes()
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            report = self.inspect()
        self.assertEqual(report["summary"], {"potentially_affected": 1})
        finding = report["findings"][0]
        self.assertEqual(finding["evidence"], ["explicit_affected_version"])
        self.assertEqual(finding["affected_pointer"], "/affected/0")
        self.assertTrue(finding["citation"].startswith("https://api.osv.dev/"))
        self.assertEqual(report["source"]["relative_path"], self.path.name)
        self.assertEqual(report["coverage"]["remote_requests"], 0)
        self.assertIn("not_installed_state", report["coverage"]["scope"])
        self.assertNotIn(str(self.root), json.dumps(report))
        self.assertEqual(self.path.read_bytes(), original)

    def test_same_package_name_in_other_ecosystem_does_not_match(self):
        self.seed()
        self.write([component(kind="npm")])
        self.assertEqual(self.inspect()["summary"], {"no_local_advisory": 1})

    def test_unsupported_python_prerelease_and_missing_version_require_review(self):
        self.seed()
        missing = component()
        missing.pop("version")
        missing["purl"] = "pkg:pypi/parser"
        self.write([component(version="1.8rc1"), missing])
        report = self.inspect()
        self.assertEqual(report["summary"], {"needs_review": 2})
        self.assertEqual(report["findings"][0]["evidence"], ["unsupported_or_invalid_version_range"])

    def test_identity_conflicts_never_emit_positive_matches(self):
        self.seed()
        bad_version = component()
        bad_version["purl"] = "pkg:pypi/parser@2.0"
        bad_name = component()
        bad_name["name"] = "another"
        self.write([bad_version, bad_name])
        report = self.inspect()
        self.assertEqual(report["summary"], {"needs_review": 2})
        self.assertFalse(report["findings"])

    def test_duplicate_packages_and_nested_components_have_json_pointers(self):
        self.seed()
        parent = component("parent", "1.0.0", "npm")
        parent["components"] = [component(), component()]
        self.write([parent])
        report = self.inspect()
        self.assertEqual(report["duplicates_removed"], 1)
        self.assertEqual(report["component_count"], 2)
        self.assertTrue(report["findings"][0]["component_pointer"].startswith("/components/0/components/"))

    def test_spdx_purl_and_pypi_normalization(self):
        payload = osv()
        payload["affected"][0]["package"]["name"] = "parser-name"
        self.seed(payload)
        self.write(payload={"spdxVersion": "SPDX-2.3", "packages": [{"name": "Parser_Name", "versionInfo": "1.0",
                   "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                     "referenceLocator": "pkg:pypi/Parser_Name@1.0"}]}]})
        self.assertEqual(self.inspect()["summary"], {"potentially_affected": 1})

    def test_withdrawn_osv_advisory_not_promoted_to_active_finding(self):
        payload = osv()
        payload["withdrawn"] = "2026-10-16T00:00:00Z"
        self.seed(payload)
        self.write()
        report = self.inspect()
        self.assertFalse(report["findings"])
        self.assertEqual(report["coverage"]["examined"], 1)

    def test_empty_local_database_is_honestly_scoped_without_schema_write(self):
        self.write()
        report = self.inspect()
        self.assertEqual(report["coverage"]["total_local_observations"], 0)
        self.assertEqual(report["summary"], {"no_local_advisory": 1})
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertIsNone(db.one("SELECT 1 FROM sqlite_master WHERE name='cyber_migrations'"))

    def test_fingerprints_change_only_when_source_or_local_advisories_change(self):
        self.seed()
        self.write()
        first = self.inspect()["analysis_id"]
        self.assertEqual(first, self.inspect()["analysis_id"])
        payload = osv()
        payload["affected"][0]["versions"] = ["1.1"]
        self.seed(payload)
        second = self.inspect()["analysis_id"]
        self.assertNotEqual(first, second)
        self.write([component(version="1.1")])
        self.assertNotEqual(second, self.inspect()["analysis_id"])

    def test_project_exclusions_missing_and_nested_project_isolation(self):
        self.write()
        self.settings.raw["excluded_projects"] = [self.project.name]
        with self.assertRaisesRegex(ValueError, "active_authorized"):
            self.inspect()
        self.settings.raw["excluded_projects"] = []
        nested = self.project / "nested"
        nested.mkdir()
        self.register(nested, status="excluded")
        (nested / "sbom.json").write_bytes(self.path.read_bytes())
        with self.assertRaisesRegex(ValueError, "another_project"):
            inspect_sbom(self.settings, self.project.name, "nested/sbom.json")
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE projects SET status='missing'")
            db.commit()
        with self.assertRaisesRegex(ValueError, "active_authorized"):
            self.inspect()

    def test_sensitive_excluded_paths_traversal_and_alternate_streams_rejected(self):
        self.write()
        for relative in ("../x.json", str(self.path), "x.json:stream", ".env.json", "secrets/bom.json",
                         "private/bom.json", "credentials.json", "node_modules/bom.json", "a/./b.json", "a\x00.json"):
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                inspect_sbom(self.settings, self.project.name, relative)

    def test_reparse_guard_fails_closed(self):
        self.write()
        with patch("rabanito.dependencies.contains_reparse_component", return_value=True), self.assertRaisesRegex(ValueError, "unsafe"):
            self.inspect()

    def test_size_count_and_configuration_limits(self):
        self.write([component(), component()])
        for config, code in (({"max_sbom_bytes": 10}, "size_limit"), ({"max_components": 1}, "component_limit"),
                             ({"max_components": True}, "invalid_dependency_limit")):
            self.settings.raw["dependency_analysis"] = config
            with self.subTest(config=config), self.assertRaisesRegex(ValueError, code):
                self.inspect()

    def test_malformed_and_duplicate_json_never_accepted(self):
        for raw in ('{"bomFormat":"CycloneDX","bomFormat":"other"}', '{"x":NaN}', '{"x":', '[]'):
            self.path.write_text(raw, encoding="utf-8")
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.inspect()
        self.write(payload={"bomFormat": "CycloneDX", "specVersion": "99", "components": []})
        with self.assertRaisesRegex(ValueError, "unsupported_sbom_format"):
            self.inspect()

    def test_local_advisory_and_findings_limits_are_explicit(self):
        self.seed()
        second = osv()
        second["id"] = "GHSA-2222-3333-4444"
        result = sync_source(self.settings, "osv", [second["id"]], client=FakeClient([second]), now=NOW)
        self.assertEqual(result["status"], "ok")
        self.write()
        self.settings.raw["dependency_analysis"] = {"max_local_advisories": 1}
        report = self.inspect()
        self.assertFalse(report["coverage"]["local_snapshot_complete"])
        self.assertEqual(report["coverage"]["examined"], 1)
        self.settings.raw["dependency_analysis"] = {"max_findings": 1}
        self.assertTrue(self.inspect()["coverage"]["findings_truncated"])

    def test_cli_inspect_uses_same_memory_and_returns_compact_structured_report(self):
        self.seed()
        self.write()
        output = io.StringIO()
        with patch("rabanito.cli.load_settings", return_value=self.settings), contextlib.redirect_stdout(output):
            main(["dependency", "inspect", "--project", self.project.name, "--sbom", self.path.name])
        report = json.loads(output.getvalue())
        self.assertEqual(report["summary"], {"potentially_affected": 1})
        self.assertNotIn(str(self.root), output.getvalue())

    def test_requirements_pins_have_source_lines_and_no_secret_url_or_include_egress(self):
        self.seed()
        requirements = self.project / "requirements.txt"
        requirements.write_text("# synthetic only\nParser==1.0\nparser==1.0\n-r secrets.txt\n--index-url https://fixture-user:secret-sentinel@example.invalid/simple\nother>=1.0\n", encoding="utf-8")
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            report = inspect_manifest(self.settings, self.project.name, requirements.name)
        self.assertEqual(report["component_count"], 1)
        self.assertEqual(report["duplicates_removed"], 1)
        self.assertEqual(report["summary"], {"potentially_affected": 1})
        self.assertEqual(report["components"][0]["line_number"], 2)
        self.assertEqual(report["findings"][0]["component_pointer"], "line:2")
        self.assertEqual(report["coverage"]["ignored_inventory_entries"], 3)
        self.assertNotIn("secret-sentinel", json.dumps(report))
        self.assertNotIn("example.invalid", json.dumps(report))

    def test_requirements_markers_wildcards_and_prereleases_do_not_claim_known_applicability(self):
        self.seed()
        path = self.project / "requirements-dev.txt"
        path.write_text('parser==1.0; python_version < "3.10"\nparser==1.*\nparser==1.8rc1\n', encoding="utf-8")
        report = inspect_manifest(self.settings, self.project.name, path.name)
        self.assertEqual(report["summary"], {"needs_review": 3})
        self.assertFalse(any(f["assessment"] == "potentially_affected" for f in report["findings"]))

    def test_npm_lockfiles_support_transitive_scopes_dedupe_and_do_not_emit_resolved_credentials(self):
        payload = osv()
        payload["affected"][0]["package"] = {"name": "@scope/parser", "ecosystem": "npm"}
        payload["affected"][0]["versions"] = ["1.0.0"]
        self.seed(payload)
        path = self.project / "package-lock.json"
        for version in (2, 3):
            data = {"lockfileVersion": version, "packages": {"": {"name": "root-private"},
                "node_modules/@scope/parser": {"version": "1.0.0", "dev": True, "resolved": "https://user:secret-sentinel@private.invalid/file"},
                "node_modules/parent/node_modules/@scope/parser": {"version": "1.0.0"},
                "packages/local-workspace": {"version": "1.0.0"}}}
            path.write_text(json.dumps(data), encoding="utf-8")
            report = inspect_manifest(self.settings, self.project.name, path.name)
            self.assertEqual(report["summary"], {"potentially_affected": 1})
            self.assertEqual(report["duplicates_removed"], 1)
            self.assertEqual(report["coverage"]["ignored_inventory_entries"], 1)
            self.assertEqual(report["components"][0]["declared_scopes"], ["development", "non_development"])
            self.assertEqual(len(report["components"][0]["additional_locations"]), 1)
            self.assertIn("node_modules~1@scope~1parser", report["findings"][0]["component_pointer"])
            self.assertNotIn("secret-sentinel", json.dumps(report))
            self.assertNotIn("private.invalid", json.dumps(report))

    def test_npm_alias_links_unresolved_versions_and_unsafe_locations_are_not_guessed(self):
        path = self.project / "package-lock.json"
        path.write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/parser": {"version": "1.0", "name": "another"},
            "node_modules/local": {"link": True, "version": "1.0.0"},
            "node_modules/unresolved": {"version": "git+https://private.invalid/code"},
            "C:/secret/node_modules/pkg": {"version": "1.0.0"}}}), encoding="utf-8")
        report = inspect_manifest(self.settings, self.project.name, path.name)
        self.assertEqual(report["summary"], {"needs_review": 3})
        self.assertEqual(report["coverage"]["ignored_inventory_entries"], 1)
        self.assertNotIn("C:/secret", json.dumps(report))
        self.assertNotIn("private.invalid", json.dumps(report))

    def test_manifest_interface_reuses_exclusions_and_rejects_unsupported_names_or_schemas(self):
        for name in (".env", "credentials.json", "package.json", "not-a-lock.txt"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                inspect_manifest(self.settings, self.project.name, name)
        path = self.project / "package-lock.json"
        path.write_text('{"lockfileVersion":1,"dependencies":{}}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unsupported_npm_lockfile_version"):
            inspect_manifest(self.settings, self.project.name, path.name)
        self.settings.raw["excluded_projects"] = [self.project.name]
        with self.assertRaisesRegex(ValueError, "active_authorized"):
            inspect_manifest(self.settings, self.project.name, path.name)

    def test_manifest_cli_selects_requirements_without_creating_a_fake_sbom(self):
        self.seed()
        path = self.project / "requirements.txt"
        path.write_text("parser==1.0\n", encoding="utf-8")
        output = io.StringIO()
        with patch("rabanito.cli.load_settings", return_value=self.settings), contextlib.redirect_stdout(output):
            main(["dependency", "inspect", "--project", self.project.name, "--manifest", path.name])
        report = json.loads(output.getvalue())
        self.assertIn("pip requirements", report["source"]["format"])
        self.assertEqual(report["summary"], {"potentially_affected": 1})


class VersionTests(unittest.TestCase):
    def test_pypi_final_numeric_releases_use_pep440_zero_padding_not_text_order(self):
        self.assertEqual(python_release_key("1.0"), python_release_key("1.0.0"))
        self.assertLess(python_release_key("1.9"), python_release_key("1.10"))
        self.assertEqual(python_release_key("01.0"), python_release_key("1"))
        for unknown in ("1.0rc1", "1!1.0", "1.0+private", "1.0.post1", "1.0.dev1"):
            self.assertIsNone(python_release_key(unknown))
        affected = {"ecosystem": "PyPI", "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.9"}, {"fixed": "1.10"}]}]}
        self.assertEqual(version_evidence("1.9.0", affected)[0], "potentially_affected")
        self.assertEqual(version_evidence("1.10", affected)[0], "outside_observed_ranges")
        self.assertEqual(version_evidence("1.9rc1", affected)[0], "needs_review")
        self.assertEqual(version_evidence("1.0.0", {"ecosystem": "PyPI", "versions": ["1.0"]})[1], ["pep440_numeric_release_equivalence"])
    def test_semver_ordering_prerelease_and_build_metadata(self):
        ordered = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "2.0.0"]
        self.assertEqual(sorted(reversed(ordered), key=semver_key), ordered)
        self.assertEqual(semver_key("1.0.0+one"), semver_key("1.0.0+two"))
        for bad in ("v1.0.0", "01.0.0", "1.0", "1.0.0-01", "1.0.0+", None):
            self.assertIsNone(semver_key(bad))

    def test_osv_semver_boundaries_multiple_intervals_and_limits(self):
        def assess(version, events):
            return version_evidence(version, {"ranges": [{"type": "SEMVER", "events": events}]})[0]
        for key, boundary_affected in (("fixed", False), ("limit", False), ("last_affected", True)):
            events = [{"introduced": "0"}, {key: "1.2.0"}]
            self.assertEqual(assess("1.2.0", events), "potentially_affected" if boundary_affected else "outside_observed_ranges")
            self.assertEqual(assess("1.1.9", events), "potentially_affected")
        events = [{"introduced": "1.0.0"}, {"fixed": "1.1.0"}, {"introduced": "2.0.0"}]
        self.assertEqual(assess("1.5.0", events), "outside_observed_ranges")
        self.assertEqual(assess("2.0.1", events), "potentially_affected")
        self.assertEqual(assess("0.9.0", events), "outside_observed_ranges")

    def test_malformed_range_requires_review_even_if_early_segment_would_match(self):
        for events in ([{"fixed": "2.0.0"}], [{"introduced": "0"}, {"introduced": "1.0.0"}],
                       [{"introduced": "2.0.0"}, {"fixed": "1.0.0"}],
                       [{"introduced": "0"}, {"fixed": "2.0.0"}, {"unknown": "3.0.0"}]):
            self.assertEqual(version_evidence("1.0.0", {"ranges": [{"type": "SEMVER", "events": events}]})[0], "needs_review")
        self.assertEqual(version_evidence("1.0.0", {"ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]})[0], "needs_review")

    def test_purl_scope_type_qualifiers_and_identity_are_not_guessed(self):
        self.assertEqual(parse_purl("pkg:npm/%40scope/parser@1.2.3"), ("npm", "@scope/parser", "1.2.3"))
        self.assertEqual(parse_purl("pkg:maven/org.example/parser@1.0"), ("Maven", "org.example:parser", "1.0"))
        self.assertEqual(package_key("PyPI", "Parser.Name_test"), ("PyPI", "parser-name-test"))
        for bad in ("pkg:generic/parser@1.0", "pkg:pypi/parser@1.0?distro=private", "pkg:npm/%2fparser@1.0", "pkg:npm/parser@%GG", "https://private/token"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_purl(bad)


if __name__ == "__main__":
    unittest.main()
