from __future__ import annotations

import copy
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from urllib.request import Request, urlopen

from rabanito.cli import main
from rabanito.config import Settings
from rabanito.cyber.model import InvalidFeed
from rabanito.security import get_security_entry, index_security_catalog, search_security, security_context, validate_catalog
from tests import test_cyber as http_fixtures
from tests import test_security as fixtures


class SecurityReleaseTests(unittest.TestCase):
    setUp = fixtures.SecurityKnowledgeTests.setUp
    tearDown = fixtures.SecurityKnowledgeTests.tearDown
    save_catalog = fixtures.SecurityKnowledgeTests.save_catalog
    server = http_fixtures.CyberTests.server

    def test_reviewed_source_versions_are_structured_without_claiming_byte_pinning(self):
        entries, _, _ = validate_catalog(self.catalog)
        csf = [e for e in entries if e.get("source_release", {}).get("id") == "NIST-CSF-2.0"]
        self.assertEqual(len(csf), 27)
        self.assertEqual({e["source_release"]["version"] for e in csf}, {"2.0"})
        self.assertEqual({e["source_release"]["published_on"] for e in csf}, {"2024-02-26"})
        self.assertTrue(all(e["source_release"]["pinning"] == "publisher_version_reference" for e in csf))
        self.assertTrue(all("sha256" not in e["source_release"] for e in csf))

    def test_all_six_csf_functions_have_outcomes_and_explicit_parent_relations(self):
        entries, relations, _ = validate_catalog(self.catalog)
        controls = [e for e in entries if e["kind"] == "control"]
        self.assertEqual(len(controls), 26)
        self.assertEqual({e["id"].split("/")[1][:2] for e in controls}, {"GV", "ID", "PR", "DE", "RS", "RC"})
        parents = {(r["source"], r["target"]) for r in relations if r["type"] == "part_of"}
        self.assertTrue(all((e["id"], "NIST-CSF-2.0") in parents for e in controls))

    def test_rolling_reference_remains_separate_from_a_reviewed_version(self):
        index_security_catalog(self.settings)
        rolling = get_security_entry(self.settings, "MITRE-ATTACK")
        fixed = get_security_entry(self.settings, "MITRE-ATTACK-20.0")
        self.assertEqual(rolling["edition_status"], "rolling")
        self.assertNotIn("source_release", rolling)
        self.assertEqual(fixed["source_release"]["version"], "20.0")
        self.assertEqual(fixed["source_url"], "https://attack.mitre.org/versions/v20/")
        self.assertTrue(any(r["relation_type"] == "edition_of" for r in fixed["relations"]))

    def test_release_filters_and_paging_query_only_local_index(self):
        index_security_catalog(self.settings)
        with patch("socket.socket", side_effect=AssertionError("offline only")):
            page = search_security(self.settings, release="NIST-CSF-2.0", kind="control", limit=4, offset=4)
            self.assertEqual((page["total"], len(page["results"])), (26, 4))
            self.assertTrue(page["truncated"])
            self.assertEqual(search_security(self.settings, release="MITRE-ATTACK-20.0")["total"], 1)
            self.assertEqual(search_security(self.settings, release="missing")["total"], 0)

    def test_context_keeps_edition_release_and_locator_with_a_bounded_passage(self):
        index_security_catalog(self.settings)
        result = security_context(self.settings, "respaldo", release="NIST-CSF-2.0", kind="control", max_chars=31)
        self.assertGreater(result["total_matches"], 0)
        self.assertEqual(result["used_chars"], 31)
        item = result["fragments"][0]
        self.assertEqual(item["edition"], "2.0")
        self.assertEqual(item["framework"], "NIST-CSF-2.0")
        self.assertEqual(item["source_release"]["verified_on"], "2026-10-17")
        self.assertTrue(item["locator"].startswith("Apéndice A"))

    def test_new_review_does_not_redate_unreviewed_legacy_entries(self):
        index_security_catalog(self.settings)
        self.assertEqual(get_security_entry(self.settings, "NIST-800-63B-4")["reviewed_on"], "2026-10-16")
        self.assertEqual(get_security_entry(self.settings, "NIST-CSF-2.0")["reviewed_on"], "2026-10-17")
        self.assertEqual(get_security_entry(self.settings, "LOCAL-ZT-POLICY")["reviewed_on"], "2026-10-16")

    def test_legacy_catalog_without_release_metadata_remains_compatible(self):
        legacy = copy.deepcopy(self.catalog)
        del legacy["source_releases"]
        for entry in legacy["entries"]:
            entry.pop("release_id", None)
        entries, _, _ = validate_catalog(legacy)
        self.assertEqual(len(entries), 72)
        self.assertTrue(all("source_release" not in e for e in entries))

    def test_metadata_limits_dates_and_fields_reject_false_pinning_or_credentials(self):
        base = self.catalog["source_releases"]["NIST-CSF-2.0"]
        for key, value in (("version", ""), ("version", "x" * 81), ("published_on", "2026-02-29"),
                           ("verified_on", "2023-01-01"), ("verified_on", "2026-10-17T00:00:00"),
                           ("pinning", "sha256_verified"), ("reference_url", "https://evil.example/x"),
                           ("reference_url", "https://person:secret@www.nist.gov/"),
                           ("reference_url", "https://www.nist.gov:8443/"), ("reference_url", "file:///private")):
            data = copy.deepcopy(self.catalog)
            data["source_releases"]["NIST-CSF-2.0"] = {**base, key: value}
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): validate_catalog(data)
        data = copy.deepcopy(self.catalog)
        data["source_releases"]["NIST-CSF-2.0"]["sha256"] = "a" * 64
        with self.assertRaises(ValueError): validate_catalog(data)
        for url in ("https://www.nist.gov/?token=synthetic", "https://www.nist.gov/#private-fragment"):
            data = copy.deepcopy(self.catalog)
            data["source_releases"]["NIST-CSF-2.0"]["reference_url"] = url
            with self.subTest(url=url), self.assertRaises(ValueError): validate_catalog(data)

    def test_registry_and_unknown_release_do_not_write_an_index(self):
        for raw in ([], None, {str(i): {} for i in range(101)}):
            data = {**self.catalog, "source_releases": raw}
            with self.assertRaises(ValueError): validate_catalog(data)
        self.catalog["entries"][0]["release_id"] = "unknown"
        self.save_catalog()
        with self.assertRaises(ValueError): index_security_catalog(self.settings)
        self.assertFalse(self.settings.database_path.exists())

    def test_rolling_entry_cannot_silently_claim_a_fixed_release(self):
        data = copy.deepcopy(self.catalog)
        entry = next(e for e in data["entries"] if e["id"] == "MITRE-ATTACK")
        entry["release_id"] = "MITRE-ATTACK-20.0"
        with self.assertRaisesRegex(ValueError, "rolling"): validate_catalog(data)

    def test_duplicate_json_keys_are_not_accepted_even_if_last_value_is_valid(self):
        path = self.root / "config/security_catalog.json"
        path.write_text('{"catalog_version":"hidden","catalog_version":' + json.dumps(self.catalog["catalog_version"]) +
                        ',"reviewed_on":"2026-10-16","entries":' + json.dumps(self.catalog["entries"]) + '}', encoding="utf-8")
        with self.assertRaisesRegex(InvalidFeed, "duplicate_json_key"): index_security_catalog(self.settings)
        self.assertFalse(self.settings.database_path.exists())

    def test_release_reference_change_updates_only_referencing_entries(self):
        index_security_catalog(self.settings)
        self.catalog["source_releases"]["NIST-CSF-2.0"]["verified_on"] = "2026-10-18"
        self.save_catalog()
        result = index_security_catalog(self.settings)
        self.assertEqual((result["modified"], result["unchanged"]), (27, 45))

    def test_invalid_query_release_is_rejected_and_reads_do_not_create_schema(self):
        with self.assertRaises(ValueError): search_security(self.settings, release="../../secret")
        self.assertEqual(search_security(self.settings, release="NIST-CSF-2.0")["total"], 0)
        self.assertEqual(security_context(self.settings, "backup", release="NIST-CSF-2.0")["fragments"], [])
        self.assertFalse(self.settings.database_path.exists())

    def test_write_outputs_outside_the_configured_workspace_are_rejected_before_creation(self):
        for field in ("database_path", "data_dir"):
            value = "../" + self.root.name + "-outside" + (".db" if field == "database_path" else "")
            settings = Settings(self.root, {**self.settings.raw, field: value})
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "unsafe_security_catalog_output"):
                index_security_catalog(settings)
        self.assertFalse(self.settings.database_path.exists())

    def test_cli_release_context_and_http_search_return_actual_filtered_index(self):
        index_security_catalog(self.settings)
        output = io.StringIO()
        with patch("rabanito.cli.load_settings", return_value=self.settings), redirect_stdout(output):
            main(["security", "context", "respaldo", "--release", "NIST-CSF-2.0", "--kind", "control", "--max-chars", "50"])
        context = json.loads(output.getvalue())
        self.assertTrue(context["fragments"])
        self.assertLessEqual(context["used_chars"], 50)
        with self.server() as origin:
            request = Request(origin + "/api/security/search", data=json.dumps({"release": "MITRE-ATTACK-20.0"}).encode(),
                              headers={"Origin": origin, "Content-Type": "application/json"}, method="POST")
            with urlopen(request) as response:
                result = json.load(response)
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["results"][0]["id"], "MITRE-ATTACK-20.0")
