from __future__ import annotations

import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rabanito.config import Settings
from rabanito.db import Database, restore_database
from rabanito.security import get_security_entry, index_security_catalog, search_security, security_context, validate_catalog


PROJECT = Path(__file__).resolve().parents[1]


class SecurityKnowledgeTests(unittest.TestCase):
    def setUp(self):
        temporary_root = PROJECT / "tests" / ".test-temp"
        temporary_root.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="security-", dir=temporary_root)
        self.root = Path(self.temporary.name)
        (self.root / "config").mkdir()
        self.catalog = json.loads((PROJECT / "config" / "security_catalog.json").read_text(encoding="utf-8"))
        self.settings = Settings(self.root, {"database_path": "data/brain.db", "data_dir": "data", "knowledge_dir": "knowledge",
                                          "vault_root": "vault", "projects_root": "projects"})
        self.save_catalog()

    def save_catalog(self):
        (self.root / "config" / "security_catalog.json").write_text(json.dumps(self.catalog, ensure_ascii=False), encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def test_curated_catalog_has_official_sources_and_no_equivalence_claims(self):
        entries, relations, version = validate_catalog(self.catalog)
        self.assertEqual(len(entries), 28)
        self.assertEqual(version, "2026-10-16.2")
        self.assertTrue(all(x["source_url"].startswith("https://") and x["locator"] for x in entries))
        self.assertTrue(all(x["validation"] == "unvalidated_editorial" for x in relations if x["type"] == "editorial_overlap"))
        self.assertTrue(any(x["edition_status"] == "historical" for x in entries))

    def test_offline_index_search_control_reference_and_context(self):
        with patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("No network")):
            self.assertEqual(index_security_catalog(self.settings)["added"], 28)
            found = search_security(self.settings, "Zero Trust")
            self.assertGreater(found["total"], 0)
            self.assertTrue(all(x["knowledge_type"] == "own_summary_of_cited_source" for x in found["results"]))
            control = get_security_entry(self.settings, "NIST-CSF-2.0/PR.AA-05")
            self.assertIn("mínimo privilegio", control["summary"])
            self.assertTrue(any(x["relation_type"] == "part_of" for x in control["relations"]))
            context = security_context(self.settings, "Zero Trust", max_chars=23)
            self.assertEqual(context["used_chars"], 23)
            self.assertTrue(context["fragments"][0]["citation"].startswith("https://"))

    def test_incremental_index_changes_one_summary_and_preserves_others(self):
        index_security_catalog(self.settings)
        self.assertEqual(index_security_catalog(self.settings)["unchanged"], 28)
        self.catalog["entries"][0]["summary"] += " Nueva revisión editorial documentada."
        self.save_catalog()
        result = index_security_catalog(self.settings)
        self.assertEqual((result["modified"], result["unchanged"]), (1, 27))

    def test_absent_entry_is_retired_without_destroying_record(self):
        index_security_catalog(self.settings)
        self.catalog["entries"] = [x for x in self.catalog["entries"] if x["id"] != "MITRE-ATTACK"]
        self.save_catalog()
        self.assertEqual(index_security_catalog(self.settings)["retired"], 1)
        self.assertIsNone(get_security_entry(self.settings, "MITRE-ATTACK"))
        with Database(self.settings.database_path) as db:
            self.assertEqual(db.one("SELECT active FROM security_entries WHERE entry_id='MITRE-ATTACK'")["active"], 0)

    def test_duplicate_identifiers_invalid_sources_and_dangling_edges_fail_before_write(self):
        index_security_catalog(self.settings)
        variants = []
        duplicate = copy.deepcopy(self.catalog); duplicate["entries"].append(duplicate["entries"][0]); variants.append(duplicate)
        bad_url = copy.deepcopy(self.catalog); bad_url["entries"][0]["source_url"] = "https://evil.example/private"; variants.append(bad_url)
        missing = copy.deepcopy(self.catalog); missing["relations"][0]["target"] = "missing"; variants.append(missing)
        empty = copy.deepcopy(self.catalog); empty["entries"] = []; variants.append(empty)
        for variant in variants:
            self.catalog = variant; self.save_catalog()
            with self.assertRaises(ValueError): index_security_catalog(self.settings)
            self.assertEqual(search_security(self.settings)["total"], 28)

    def test_transaction_rolls_back_changed_entries_fts_and_metadata_on_relation_conflict(self):
        index_security_catalog(self.settings)
        original = get_security_entry(self.settings, "NIST-800-207")["summary"]
        self.catalog["entries"][0]["summary"] = "Transaction sentinel phrase"
        self.catalog["relations"].append(self.catalog["relations"][0])
        self.save_catalog()
        with self.assertRaises(sqlite3.IntegrityError): index_security_catalog(self.settings)
        self.assertEqual(get_security_entry(self.settings, "NIST-800-207")["summary"], original)
        self.assertEqual(search_security(self.settings, "sentinel")["total"], 0)

    def test_paging_filters_historical_and_zero_budget_are_explicit(self):
        index_security_catalog(self.settings)
        self.assertEqual(search_security(self.settings, edition_status="historical")["total"], 2)
        self.assertEqual(search_security(self.settings, kind="control")["total"], 5)
        page = search_security(self.settings, limit=3, offset=3)
        self.assertEqual((len(page["results"]), page["total"]), (3, 28))

    def test_catalog_covers_identity_cloud_dfir_monitoring_and_platform_hardening(self):
        index_security_catalog(self.settings)
        for term, expected in (("MFA", "NIST-800-63B-4"), ("cloud", "NIST-800-210"),
                               ("DFIR", "NIST-800-86"), ("SOC", "NIST-800-137"),
                               ("Windows", "MICROSOFT-WINDOWS-BASELINES"), ("Linux", "REDHAT-RHEL9-HARDENING")):
            with self.subTest(term=term):
                self.assertIn(expected, {x["id"] for x in search_security(self.settings, term)["results"]})
        self.assertEqual(get_security_entry(self.settings, "MICROSOFT-WINDOWS-BASELINES")["edition_status"], "rolling")
        self.assertIn("5.2.0", get_security_entry(self.settings, "NIST-800-53R5")["edition"])
        self.assertEqual(security_context(self.settings, "Zero Trust", max_chars=0)["fragments"], [])

    def test_backup_restores_catalog_and_public_citations(self):
        index_security_catalog(self.settings)
        backup, target = self.root / "backup.db", self.root / "restored.db"
        with Database(self.settings.database_path) as db: db.backup(backup)
        restore_database(backup, target)
        restored = Settings(self.root, {**self.settings.raw, "database_path": str(target)})
        self.assertEqual(search_security(restored, "Zero Trust")["total"], search_security(self.settings, "Zero Trust")["total"])

    def test_no_schema_queries_do_not_seed_catalog_implicitly(self):
        self.assertEqual(search_security(self.settings)["total"], 0)
        self.assertIsNone(get_security_entry(self.settings, "NIST-800-207"))
