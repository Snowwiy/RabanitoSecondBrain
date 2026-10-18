from __future__ import annotations

import contextlib
import hashlib
import io
import json
import unittest
from unittest.mock import patch

from rabanito import dependencies
from rabanito.cli import main
from rabanito.db import Database, restore_database
from rabanito.dependencies import inspect_manifest, inspect_sbom, parse_purl, python_release_key, version_evidence
from rabanito.dependency_memory import snapshot_inventory
from rabanito.pep440 import parse_version
from tests import test_dependencies as fixtures
from tests.test_uv_lock import lock, package


def assessment(version, events, **extra):
    return version_evidence(version, {"ecosystem": "PyPI", "ranges": [{"type": "ECOSYSTEM", "events": events}], **extra})


class Pep440Tests(unittest.TestCase):
    def test_documented_suffix_order_is_strict_across_all_pairs(self):
        ordered = ["1.dev0", "1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12.dev456", "1.0a12",
                   "1.0b1.dev456", "1.0b2", "1.0b2.post345.dev456", "1.0b2.post345", "1.0rc1.dev456",
                   "1.0rc1", "1.0", "1.0+abc.5", "1.0+abc.7", "1.0+5", "1.0.post456.dev34",
                   "1.0.post456", "1.0.15", "1.1.dev1"]
        for i, left in enumerate(ordered):
            for right in ordered[i + 1:]:
                with self.subTest(left=left, right=right):
                    self.assertLess(parse_version(left).key, parse_version(right).key)

    def test_normalization_aliases_case_separators_and_implicit_numbers(self):
        examples = [("V01.002RC_003", "1.2rc3"), ("1.1alpha1", "1.1a1"), ("1.1beta2", "1.1b2"),
                    ("1.1c3", "1.1rc3"), ("1.1pre3", "1.1rc3"), ("1.1preview3", "1.1rc3"),
                    ("1.1.a1", "1.1a1"), ("1.1-a.1", "1.1a1"), ("1.1_a_1", "1.1a1"),
                    ("1.2a", "1.2a0"), ("1.0rc-", "1.0rc0"), ("1.0-dev_", "1.0.dev0"), ("1.0post-", "1.0.post0"),
                    ("1.2-post2", "1.2.post2"), ("1.2post2", "1.2.post2"),
                    ("1.2.post-2", "1.2.post2"), ("1.0-r4", "1.0.post4"), ("1.0rev4", "1.0.post4"),
                    ("1.2.post", "1.2.post0"), ("1.0-1", "1.0.post1"), ("1.2-dev2", "1.2.dev2"),
                    ("1.2dev2", "1.2.dev2"), ("1.2.dev", "1.2.dev0"), ("1.2DEV_2", "1.2.dev2"),
                    ("1.0+ABC_01-foo0100", "1.0+abc.1.foo0100"), ("0!1.00", "1.0"),
                    ("V01!001.002-pre_03-r_04-dev_05+ABC_01", "1!1.2rc3.post4.dev5+abc.1")]
        for literal, canonical in examples:
            with self.subTest(literal=literal):
                parsed = parse_version(literal)
                self.assertEqual(parsed.normalized, canonical)
                self.assertEqual(parsed.key, parse_version(canonical).key)
                self.assertEqual(parse_version(parsed.normalized), parsed)

    def test_ascii_outer_whitespace_normalizes_but_internal_or_unicode_does_not(self):
        self.assertEqual(parse_version(" \t\n\r\f\v1.0 \t\n\r\f\v").normalized, "1.0")
        for bad in ("1 .0", "1.0\npost1", "1.0\u00a0", "\u200b1.0", "１.0", "1.0+K", "1.0\x00"):
            with self.subTest(bad=bad): self.assertIsNone(parse_version(bad))

    def test_release_segments_zero_padding_without_eight_component_ceiling(self):
        self.assertEqual(python_release_key("01.0"), python_release_key("1.0.0.0.0.0.0.0.0.0"))
        self.assertLess(python_release_key("1.0.0.0.0.0.0.0.0.1"), python_release_key("1.0.0.0.0.0.0.0.0.2"))
        self.assertEqual(python_release_key("0"), python_release_key("0.0.0"))
        self.assertLess(python_release_key("1.9"), python_release_key("1.10"))

    def test_epoch_precedes_release_and_suffix_ordering(self):
        ordered = ["2014.04", "1!0.dev0", "1!1.0", "1!1.1", "2!0.dev0", "10!0"]
        self.assertEqual(sorted(reversed(ordered), key=python_release_key), ordered)
        self.assertEqual(python_release_key("01!01.00"), python_release_key("1!1"))

    def test_local_ordering_is_defined_without_claiming_public_applicability(self):
        ordered = ["1", "1+aaa", "1+abc", "1+abc.foo", "1+abc.1", "1+abc.2", "1+1", "1+2", "1.post0"]
        self.assertEqual(sorted(reversed(ordered), key=lambda v: parse_version(v).key), ordered)
        self.assertEqual(parse_version("1+ABC_01").key, parse_version("1+abc.1").key)
        self.assertTrue(parse_version("1+abc").has_local)
        self.assertIsNone(python_release_key("1+abc"))

    def test_invalid_and_legacy_syntax_is_not_guessed(self):
        for bad in (None, 1, True, {}, [], "", "v", "vv1.0", "!1.0", "1!!1.0", "-1", "1.-1", "1..0", "1.",
                    "1.0-", "1.0+", "1.0++abc", "1.0+abc..1", "1.0+abc_", "1.0rc--", "1.0dev..",
                    "1.0.post1.rc1", "1.0.dev1.post1", "1.0a1b2", "1.0previewpreview1", "1.0legacy",
                    "1.0~rc1", "1.0:*", "1.0.*", "==1.0", ">=1.0", "1.0,2.0", "https://example.invalid/v1"):
            with self.subTest(bad=bad): self.assertIsNone(parse_version(bad))

    def test_parser_budgets_bound_integers_segments_and_suffix_work(self):
        self.assertIsNotNone(parse_version("9" * 200))
        self.assertIsNone(parse_version("9" * 201))
        self.assertIsNotNone(parse_version("1." * 99 + "1"))
        self.assertIsNone(parse_version("1" * 196 + "post"))  # Canonical expansion must also fit.
        self.assertIsNone(parse_version("1" * 196 + "dev"))  # Implicit number adds a dot and zero.
        self.assertEqual(assessment("1" * 196 + "post", [{"introduced": "0"}, {"fixed": "2"}])[0], "needs_review")
        for bad in ("1" + "." * 199, "1+" + "a" * 199, " " * 201, "1!" + "0" * 199):
            self.assertIsNone(parse_version(bad))

    def test_fixed_limit_last_affected_and_introduced_boundaries(self):
        for end, inclusive in (("fixed", False), ("limit", False), ("last_affected", True)):
            events = [{"introduced": "1.0rc1"}, {end: "1.0.post1"}]
            self.assertEqual(assessment("1.0rc1", events)[0], "potentially_affected")
            self.assertEqual(assessment("1.0rc0", events)[0], "outside_observed_ranges")
            self.assertEqual(assessment("1.0.post1", events)[0], "potentially_affected" if inclusive else "outside_observed_ranges")
            self.assertEqual(assessment("1.0.post2", events)[0], "outside_observed_ranges")

    def test_zero_introduced_sentinel_and_epochs_use_order_not_string(self):
        self.assertEqual(assessment("0.dev0", [{"introduced": "0"}, {"fixed": "0"}])[0], "potentially_affected")
        events = [{"introduced": "2014.04"}, {"fixed": "1!1.0"}]
        self.assertEqual(assessment("1!0.9", events)[0], "potentially_affected")
        self.assertEqual(assessment("2!0", events)[0], "outside_observed_ranges")

    def test_osv_interval_is_not_a_pip_exclusive_specifier(self):
        self.assertEqual(assessment("1.0rc1", [{"introduced": "0"}, {"fixed": "1.0"}])[0], "potentially_affected")
        self.assertEqual(assessment("1.0.post1", [{"introduced": "1.0"}])[0], "potentially_affected")

    def test_disjoint_public_intervals_and_alias_boundaries(self):
        events = [{"introduced": "1a"}, {"fixed": "1.0RC_1"}, {"introduced": "1.post0"}, {"last_affected": "1.post2"}]
        for version, status in (("1a0", "potentially_affected"), ("1.0rc1", "outside_observed_ranges"),
                                ("1", "outside_observed_ranges"), ("1.post2", "potentially_affected"), ("1.post3", "outside_observed_ranges")):
            self.assertEqual(assessment(version, events)[0], status)

    def test_local_component_and_boundaries_stay_review_except_literal_positive(self):
        events = [{"introduced": "0"}, {"fixed": "2.0"}]
        for local in ("1.0+backport.1", "2.0+patched", "3.0+custom"):
            self.assertEqual(assessment(local, events), ("needs_review", ["local_build_applicability_not_verified"]))
        self.assertEqual(assessment("1+abc", events, versions=["1+abc"])[1], ["explicit_affected_version"])
        self.assertEqual(assessment("1+ABC", events, versions=["1+abc"])[0], "needs_review")
        for end in ("fixed", "limit", "last_affected"):
            self.assertEqual(assessment("9.0", [{"introduced": "0"}, {end: "1+local"}])[0], "needs_review")

    def test_explicit_equivalence_covers_public_aliases_but_not_legacy_or_local(self):
        for left, right in (("1.0RC01", "1.0rc1"), ("1.0-1", "1.post1"), ("v1.0dev", "1.0.dev0"), ("01!01", "1!1.0")):
            self.assertEqual(version_evidence(left, {"ecosystem": "PyPI", "versions": [right]})[1], ["pep440_public_version_equivalence"])
        self.assertEqual(version_evidence("1.0.0", {"ecosystem": "PyPI", "versions": ["1.0"]})[1], ["pep440_numeric_release_equivalence"])
        for bad in ("1.0legacy", "1.0+local"):
            self.assertEqual(version_evidence(bad, {"ecosystem": "PyPI", "versions": ["1.0"]})[0], "needs_review")
        self.assertEqual(version_evidence("legacy", {"ecosystem": "PyPI", "versions": ["legacy"]})[1], ["explicit_affected_version"])

    def test_invalid_complete_stream_never_returns_an_early_positive(self):
        for events in ([{"introduced": "0"}, {"fixed": "1rc1"}, {"fixed": "2"}],
                       [{"introduced": "2"}, {"fixed": "1"}], [{"introduced": "0"}, {"fixed": "2"}, {"introduced": "1"}],
                       [{"introduced": "0"}, {"fixed": "2"}, {"new": "3"}], [{"fixed": "2"}],
                       [{"introduced": "0"}, {"fixed": None}], [{"introduced": "0"}, {"fixed": "1.0legacy"}],
                       [{"introduced": "0"}, {"fixed": "2", "last_affected": "1"}]):
            self.assertEqual(assessment("1.0.dev1", events)[0], "needs_review")

    def test_unhandled_range_types_or_ecosystems_do_not_gain_pep440_semantics(self):
        for kind in ("GIT", "SEMVER", "NEW"):
            self.assertEqual(version_evidence("1.0rc1", {"ecosystem": "PyPI", "ranges": [{"type": kind, "events": [{"introduced": "0"}]}]})[0], "needs_review")
        for ecosystem in ("npm", "Maven", "NuGet", "crates.io", ""):
            self.assertEqual(version_evidence("1.0rc1", {"ecosystem": ecosystem, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]})[0], "needs_review")

    def test_explicit_equivalence_budget_never_silently_drops_late_positive(self):
        events = [{"introduced": "2"}, {"fixed": "3"}]
        versions = ["9"] * 19999 + ["1.0rc1"]
        self.assertEqual(assessment("v1.0RC01", events, versions=versions)[1], ["pep440_public_version_equivalence"])
        self.assertEqual(assessment("v1.0RC01", events, versions=versions + ["9"]), ("needs_review", ["oversized_affected_versions"]))


class Pep440InventoryTests(unittest.TestCase):
    setUp = fixtures.DependencyTests.setUp
    tearDown = fixtures.DependencyTests.tearDown
    register = fixtures.DependencyTests.register
    seed = fixtures.DependencyTests.seed

    def test_epoch_purl_and_sbom_references_offline_no_original_or_db_writes(self):
        self.seed(); self.path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [fixtures.component(version="1!1.0")]}), encoding="utf-8")
        self.assertEqual(parse_purl("pkg:pypi/parser@1%211.0"), ("PyPI", "parser", "1!1.0"))
        before = [hashlib.sha256(p.read_bytes()).hexdigest() for p in (self.path, self.settings.database_path)]
        with patch("socket.socket", side_effect=AssertionError("offline")), patch("subprocess.Popen", side_effect=AssertionError("no installers")):
            report = inspect_sbom(self.settings, self.project.name, self.path.name)
        self.assertEqual(report["summary"], {"outside_observed_ranges": 1})
        self.assertEqual(report["findings"][0]["affected_pointer"], "/affected/0")
        self.assertTrue(report["findings"][0]["citation"].startswith("https://api.osv.dev/"))
        self.assertEqual(before, [hashlib.sha256(p.read_bytes()).hexdigest() for p in (self.path, self.settings.database_path)])
        self.assertNotIn(str(self.root), json.dumps(report))

    def test_requirements_public_prerelease_candidates_are_distinct_from_conditionals_and_local(self):
        self.seed(); path = self.project / "requirements.txt"
        path.write_text('parser==1.8RC1\nparser==1!0.1\nparser==1.0+local\nparser==1.0; os_name == "nt"\n', encoding="utf-8")
        report = inspect_manifest(self.settings, self.project.name, path.name)
        self.assertEqual(report["summary"], {"potentially_affected": 1, "outside_observed_ranges": 1, "needs_review": 2})
        self.assertEqual(report["findings"][0]["component_pointer"], "line:1")
        self.assertEqual(report["findings"][2]["evidence"], ["local_build_applicability_not_verified"])

    def test_uv_private_source_is_never_promoted_by_version_normalization(self):
        self.seed(); path = self.project / "uv.lock"
        path.write_text(lock(package(version="1.0RC1"), package(version="1.0RC1", source={"registry": "https://private.invalid/simple"}),
                             package(version="1!0.1"), package(version="1.0+local")), encoding="utf-8")
        report = inspect_manifest(self.settings, self.project.name, path.name)
        self.assertEqual(report["summary"], {"potentially_affected": 1, "needs_review": 2, "outside_observed_ranges": 1})
        self.assertNotIn("private.invalid", json.dumps(report))
        self.assertTrue(report["coverage"]["selection"].startswith("all_lock_entries"))

    def test_engine_four_snapshot_is_not_reused_but_remains_recoverable(self):
        self.seed(); path = self.project / "requirements.txt"; path.write_text("parser==1.0rc1\n", encoding="utf-8")
        with patch.object(dependencies, "ENGINE_VERSION", 4):
            old = snapshot_inventory(self.settings, self.project.name, path.name, kind="manifest", save=True)["report"]
        current = inspect_manifest(self.settings, self.project.name, path.name)
        self.assertEqual(current["engine_version"], 6)
        self.assertEqual(current["cache"]["status"], "computed")
        self.assertNotEqual(old["analysis_id"], current["analysis_id"])
        saved = snapshot_inventory(self.settings, self.project.name, path.name, kind="manifest", save=True)["report"]
        self.assertEqual(inspect_manifest(self.settings, self.project.name, path.name)["cache"]["status"], "reused_saved_analysis")
        backup = self.root / "data" / "saved-analysis.db"
        with Database(self.settings.database_path, read_only=True) as db:
            db.backup(backup)
        restored = self.root / "data" / "restored.db"
        restore_database(backup, restored)
        with Database(restored, read_only=True) as db:
            self.assertEqual(db.one("PRAGMA integrity_check")[0], "ok")
            self.assertFalse(db.query("PRAGMA foreign_key_check"))
            ids = {r[0] for r in db.query("SELECT analysis_id FROM dependency_analyses")}
        self.assertTrue({old["analysis_id"], saved["analysis_id"]} <= ids)

    def test_cli_preserves_public_ordering_result_and_citation(self):
        self.seed(); path = self.project / "requirements.txt"; path.write_text("parser==1.0rc1\n", encoding="utf-8")
        output = io.StringIO()
        with patch("rabanito.cli.load_settings", return_value=self.settings), contextlib.redirect_stdout(output):
            main(["dependency", "inspect", "--project", self.project.name, "--manifest", path.name])
        report = json.loads(output.getvalue())
        self.assertEqual(report["summary"], {"potentially_affected": 1})
        self.assertEqual(report["coverage"]["remote_requests"], 0)
        self.assertEqual(report["findings"][0]["component_pointer"], "line:1")
        self.assertNotIn(str(self.root), output.getvalue())


if __name__ == "__main__":
    unittest.main()
