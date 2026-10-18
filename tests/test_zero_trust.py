from __future__ import annotations

import copy
import io
import json
import sqlite3
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from urllib.request import Request, urlopen

from rabanito.cli import main
from rabanito.config import Settings
from rabanito.db import Database, restore_database
from rabanito.knowledge_graph import graph_page, sync_graph
from rabanito.security import get_security_entry, index_security_catalog, search_security, security_context, validate_catalog
from rabanito.security_releases import publication_date, validate_releases
from tests import test_security as fixtures
from tests import test_cyber as http_fixtures
from scripts import validate_security_catalog as research


NIST = "NIST-800-207-2020"
CISA = "CISA-ZTMM-2.0"


class ZeroTrustTests(unittest.TestCase):
    setUp = fixtures.SecurityKnowledgeTests.setUp
    tearDown = fixtures.SecurityKnowledgeTests.tearDown
    save_catalog = fixtures.SecurityKnowledgeTests.save_catalog
    server = http_fixtures.CyberTests.server

    def test_seven_tenets_are_local_concepts_not_official_control_ids(self):
        entries, relations, _ = validate_catalog(self.catalog)
        tenets = [e for e in entries if e["id"].startswith("LOCAL-ZT-TENET-")]
        self.assertEqual({e["id"] for e in tenets}, {"LOCAL-ZT-TENET-" + str(i).zfill(2) for i in range(1, 8)})
        self.assertTrue(all(e["kind"] == "concept" and e["source_release"]["id"] == NIST and "2.1" in e["locator"] for e in tenets))
        self.assertTrue(all(any(r["source"] == e["id"] and r["target"] == "NIST-800-207" and r["type"] == "part_of" for r in relations) for e in tenets))
        self.assertEqual(len([e for e in entries if e["kind"] == "control"]), 26)

    def test_policy_components_have_exact_sections_and_no_implementation_claim(self):
        entries, _, _ = validate_catalog(self.catalog)
        components = [e for e in entries if e["id"] in {"LOCAL-ZT-PE", "LOCAL-ZT-PA", "LOCAL-ZT-PEP"}]
        self.assertEqual(len(components), 3)
        self.assertTrue(all(e["kind"] == "concept" and "Sección 3" in e["locator"] and "PDF" in e["locator"] for e in components))
        self.assertTrue(all("installed" not in e and "implementation_status" not in e for e in components))

    def test_five_pillars_three_cross_capabilities_and_four_stages_stay_distinct(self):
        entries, relations, _ = validate_catalog(self.catalog)
        new = [e for e in entries if e["id"].startswith("LOCAL-ZTMM-")]
        for prefix, count in (("PILLAR", 5), ("CROSS", 3), ("STAGE", 4)):
            self.assertEqual(len([e for e in new if e["id"].startswith("LOCAL-ZTMM-" + prefix + "-")]), count)
        self.assertTrue(all(e["kind"] == "concept" and e["framework"] == CISA for e in new))
        stages = [e for e in new if "-STAGE-" in e["id"]]
        self.assertTrue(all("no califica este entorno" in e["summary"] and "p.9" in e["locator"] for e in stages))
        self.assertTrue(all(any(r["source"] == e["id"] and r["target"] == CISA and r["validation"] == "source_documented" for r in relations) for e in new))

    def test_month_precision_does_not_invent_a_first_day_or_byte_pin(self):
        entries, _, _ = validate_catalog(self.catalog)
        item = next(e for e in entries if e["id"] == CISA)
        release = item["source_release"]
        self.assertEqual(release["published_on"], "2023-04")
        self.assertEqual(release["published_on_precision"], "month")
        self.assertEqual(release["pinning"], "publisher_version_reference")
        self.assertNotIn("sha256", release)
        self.assertNotIn("2023-04-01", json.dumps(item))
        daily = next(e for e in entries if e["id"] == "NIST-CSF-2.0")["source_release"]
        self.assertNotIn("published_on_precision", daily)  # Existing daily JSON stays unchanged.
        self.assertEqual(publication_date("2024-02-29"), ("2024-02-29", "day"))

    def test_invalid_partial_publication_dates_are_rejected(self):
        for value in (None, 202304, "2023", "2023-4", "2023-00", "2023-13", "0000-04", "2023-04-31", "2026-02-29", "2023-04-private"):
            with self.subTest(value=value), self.assertRaises(ValueError): publication_date(value)
        release = self.catalog["source_releases"][CISA]
        for key, value in (("verified_on", "2023-04"), ("verified_on", "2023-03-31"), ("published_on", "2027-01")):
            bad = copy.deepcopy(self.catalog)
            bad["source_releases"][CISA] = {**release, key: value}
            with self.assertRaises(ValueError): validate_catalog(bad)

    def test_same_month_review_preserves_precision_without_inferred_chronology(self):
        data = copy.deepcopy(self.catalog)
        data["source_releases"][CISA]["verified_on"] = "2023-04-01"
        entries, _, _ = validate_catalog(data)
        self.assertEqual(next(e for e in entries if e["id"] == CISA)["source_release"]["published_on"], "2023-04")
        data["source_releases"][CISA]["published_on_precision"] = "day"
        with self.assertRaisesRegex(ValueError, "release_fields"): validate_catalog(data)

    def test_offline_release_filters_paging_and_context_are_cited_and_bounded(self):
        index_security_catalog(self.settings)
        with patch("socket.socket", side_effect=AssertionError("offline")), patch("subprocess.Popen", side_effect=AssertionError("no instructions")):
            self.assertEqual(search_security(self.settings, release=NIST, kind="concept")["total"], 10)
            page = search_security(self.settings, "pilar", release=CISA, limit=2, offset=2)
            self.assertEqual((page["total"], len(page["results"])), (5, 2))
            context = security_context(self.settings, "madurez", release=CISA, max_chars=31)
        self.assertTrue(context["fragments"]); self.assertLessEqual(context["used_chars"], 31)
        self.assertTrue(all(f["source_release"]["published_on"] == "2023-04" and f["source_release"]["published_on_precision"] == "month" and f["locator"] for f in context["fragments"]))
        self.assertTrue(all(f["citation"].startswith("https://www.cisa.gov/") for f in context["fragments"]))

    def test_legacy_dates_and_editorial_mappings_are_not_implicitly_renewed(self):
        index_security_catalog(self.settings)
        self.assertEqual(get_security_entry(self.settings, "LOCAL-ZT-POLICY")["reviewed_on"], "2026-10-16")
        entry = get_security_entry(self.settings, "NIST-800-207")
        self.assertEqual(entry["source_release"]["published_on"], "2020-08-11")
        self.assertTrue(any(r["validation"] == "unvalidated_editorial" for r in entry["relations"]))

    def _old_catalog(self):
        old = copy.deepcopy(self.catalog)
        old["catalog_version"] = "2026-10-17.1"
        old["entries"] = old["entries"][:50]
        ids = {e["id"] for e in old["entries"]}
        old["relations"] = [r for r in old["relations"] if r["source"] in ids and r["target"] in ids]
        for key in (NIST, CISA): old["source_releases"].pop(key)
        for e in old["entries"]:
            if e["id"] in {"NIST-800-207", CISA}:
                e.pop("release_id"); e.pop("reviewed_on")
            if e["id"] == CISA: e["locator"] = "Version 2.0"
        return old

    def test_upgrading_existing_fifty_preserves_ids_and_changes_only_two_parents(self):
        current = self.catalog; self.catalog = self._old_catalog(); self.save_catalog()
        self.assertEqual(index_security_catalog(self.settings)["added"], 50)
        self.catalog = current; self.save_catalog(); first = index_security_catalog(self.settings)
        self.assertEqual(tuple(first[k] for k in ("added", "modified", "unchanged", "retired")), (22, 2, 48, 0))
        second = index_security_catalog(self.settings)
        self.assertEqual(tuple(second[k] for k in ("added", "modified", "unchanged", "retired")), (0, 0, 72, 0))

    def test_publication_failure_rolls_back_new_concepts_fts_and_dates(self):
        current = self.catalog; self.catalog = self._old_catalog(); self.save_catalog(); index_security_catalog(self.settings)
        self.catalog = current; self.save_catalog()
        with patch.object(Database, "executemany", side_effect=sqlite3.OperationalError("fixture rollback")), self.assertRaises(sqlite3.OperationalError): index_security_catalog(self.settings)
        self.assertEqual(search_security(self.settings)["total"], 50)
        self.assertEqual(search_security(self.settings, release=CISA)["total"], 0)
        self.assertIsNone(get_security_entry(self.settings, "LOCAL-ZTMM-STAGE-OPTIMAL"))

    def test_graph_keeps_concepts_separate_from_controls_and_editorial_suggestions(self):
        index_security_catalog(self.settings)
        for _ in range(10):
            batch = sync_graph(self.settings, max_inputs=2000)
            self.assertFalse(batch["errors"])
            if batch["status"] == "ok": break
        else: self.fail("graph did not converge")
        concepts = graph_page(self.settings, kind="security_concept", limit=100)["nodes"]
        self.assertEqual(len(concepts), 25)
        self.assertEqual(len(graph_page(self.settings, kind="control", limit=100)["nodes"]), 26)
        self.assertTrue(all(n["data"]["entry_kind"] == "concept" for n in concepts))

    def test_restore_preserves_month_precision_and_relationships(self):
        index_security_catalog(self.settings); original = get_security_entry(self.settings, CISA)
        backup = self.root / "data" / "snapshot.db"; target = self.root / "data" / "restored.db"
        with Database(self.settings.database_path, read_only=True) as db: db.backup(backup)
        restore_database(backup, target)
        restored = Settings(self.root, {**self.settings.raw, "database_path": str(target)})
        self.assertEqual(get_security_entry(restored, CISA), original)
        self.assertEqual(search_security(restored, release=CISA, kind="concept")["total"], 12)

    def test_cli_and_http_keep_month_precision_without_remote_lookup(self):
        index_security_catalog(self.settings); output = io.StringIO()
        with patch("rabanito.cli.load_settings", return_value=self.settings), redirect_stdout(output):
            main(["security", "context", "madurez", "--release", CISA, "--max-chars", "40"])
        result = json.loads(output.getvalue()); self.assertTrue(result["fragments"])
        self.assertEqual(result["fragments"][0]["source_release"]["published_on_precision"], "month")
        with self.server() as origin:
            request = Request(origin + "/api/security/search", data=json.dumps({"release": CISA, "kind": "concept", "limit": 100}).encode(), headers={"Origin": origin, "Content-Type": "application/json"}, method="POST")
            with urlopen(request) as response: result = json.load(response)
        self.assertEqual(result["total"], 12)
        self.assertTrue(all(r["source_release"]["published_on"] == "2023-04" for r in result["results"]))

    def test_rehearsal_rejects_unsafe_temporary_root_before_copy(self):
        index_security_catalog(self.settings)
        def unsafe(path): return str(path).replace("\\", "/").endswith("tests/.test-temp")
        with patch.object(research, "ROOT", self.root), patch.object(research, "load_settings", return_value=self.settings), patch.object(research, "contains_reparse_component", side_effect=unsafe):
            with self.assertRaisesRegex(ValueError, "unsafe_security_rehearsal_temporary"): research.rehearse()


if __name__ == "__main__": unittest.main()
