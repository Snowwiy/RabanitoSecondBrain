from __future__ import annotations

import copy
import math
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rabanito.config import Settings
from rabanito.cyber.model import normalize_epss, normalize_nvd, normalize_osv
from rabanito.cyber.store import apply_records, ensure_schema, get_vulnerability, vulnerability_context
from rabanito.cyber.sync import EPSS_URL, NVD_URL, OSV_URL, sync_source
from rabanito.db import Database
from tests.test_cyber import CVE, OTHER, GHSA, NOW, FakeClient, epss, nvd, osv

STAMP = "2026-10-19T03:00:00+00:00"


class SpyDatabase(Database):
    def __init__(self, *args, **kwargs):
        self.fts_deletes = []
        super().__init__(*args, **kwargs)

    def execute(self, sql, params=()):
        values = tuple(params)
        if sql.startswith("DELETE FROM cyber_fts "):
            self.fts_deletes.append((sql, values))
        return super().execute(sql, values)


class CyberFtsBatchTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parent / ".test-temp"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="cyber-fts-batch-", dir=parent)
        self.root = Path(self.temporary.name)
        self.settings = Settings(self.root, {"data_dir": "data", "database_path": "data/test.db",
            "knowledge_dir": "knowledge", "vault_root": "vault", "projects_root": "projects"})
        for path in (self.settings.knowledge_root, self.settings.vault_root, self.settings.projects_root):
            path.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def publish(self, records, *, source="nvd", stamp=STAMP, binding_limit=None, **options):
        with SpyDatabase(self.settings.database_path) as db:
            ensure_schema(db)
            if binding_limit is not None:
                db.connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, binding_limit)
            db.execute("BEGIN IMMEDIATE")
            result = apply_records(db, source, records, [], retrieved_at=stamp, **options)
            calls = list(db.fts_deletes)
        return result, calls

    def rows(self, sql, params=()):
        with Database(self.settings.database_path, read_only=True) as db:
            return [tuple(r) for r in db.query(sql, params)]

    def canonical(self):
        queries = {
            "records": "SELECT * FROM cyber_records ORDER BY source,source_id",
            "aliases": "SELECT * FROM cyber_aliases ORDER BY source,source_id,vulnerability_id",
            "entities": "SELECT * FROM cyber_entities ORDER BY vulnerability_id",
            "fts": "SELECT * FROM cyber_fts ORDER BY vulnerability_id",
            "revisions": "SELECT * FROM cyber_revisions ORDER BY revision_id",
            "identifiers": "SELECT * FROM cyber_revision_identifiers ORDER BY revision_id,identifier",
        }
        return {name: self.rows(sql) for name, sql in queries.items()}

    def test_large_window_clears_fts_in_bounded_batches_not_per_entity(self):
        ids = tuple(f"CVE-2024-{10000 + i}" for i in range(501))
        records = normalize_nvd(nvd(ids), NVD_URL)
        counts, calls = self.publish(records)
        self.assertEqual(counts["added"], 501)
        self.assertEqual(len(calls), 2)
        self.assertEqual(sorted(v for _, values in calls for v in values), sorted(ids))
        self.assertTrue(all(" IN (" in sql and len(values) <= 500 for sql, values in calls))
        self.assertEqual(self.rows("SELECT COUNT(*),COUNT(DISTINCT vulnerability_id) FROM cyber_fts"), [(501, 501)])

    def test_connection_variable_budget_is_respected(self):
        ids = tuple(f"CVE-2024-{11000 + i}" for i in range(61))
        counts, calls = self.publish(normalize_nvd(nvd(ids), NVD_URL), binding_limit=20)
        self.assertEqual(counts["added"], 61)
        self.assertEqual(len(calls), math.ceil(len(ids) / 20))
        self.assertTrue(all(len(values) <= 20 for _, values in calls))

    def test_unchanged_refresh_updates_dates_without_false_revisions_or_duplicates(self):
        records = normalize_nvd(nvd((CVE, OTHER)), NVD_URL)
        self.publish(records)
        before = self.rows("SELECT * FROM cyber_revisions ORDER BY revision_id")
        counts, calls = self.publish(records, stamp="2026-10-19T04:00:00+00:00")
        self.assertEqual(counts, {"added": 0, "modified": 0, "unchanged": 2, "retired": 0})
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.rows("SELECT * FROM cyber_revisions ORDER BY revision_id"), before)
        context = vulnerability_context(self.settings, CVE, source="nvd", max_chars=100)
        self.assertEqual(context["fragments"][0]["retrieved_at"], "2026-10-19T04:00:00+00:00")
        self.assertEqual(self.rows("SELECT COUNT(*),COUNT(DISTINCT vulnerability_id) FROM cyber_fts"), [(2, 2)])

    def test_untouched_fts_rows_keep_rowids_and_text(self):
        third = "CVE-2024-99999"
        self.publish(normalize_nvd(nvd((CVE, OTHER, third)), NVD_URL))
        before = self.rows("SELECT rowid,* FROM cyber_fts WHERE vulnerability_id=?", (third,))
        changed = nvd((CVE, OTHER))
        for item in changed["vulnerabilities"]:
            item["cve"]["descriptions"][0]["value"] = "Updated fixture Unicode café."
        counts, calls = self.publish(normalize_nvd(changed, NVD_URL))
        self.assertEqual(counts["modified"], 2)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.rows("SELECT rowid,* FROM cyber_fts WHERE vulnerability_id=?", (third,)), before)
        self.assertEqual(self.rows("SELECT COUNT(*) FROM cyber_fts WHERE description LIKE '%café%'"), [(2,)])

    def test_existing_duplicate_fts_rows_are_removed_only_for_touched_ids(self):
        self.publish(normalize_nvd(nvd((CVE, OTHER)), NVD_URL))
        with Database(self.settings.database_path, initialize=False) as db:
            db.execute("INSERT INTO cyber_fts SELECT * FROM cyber_fts WHERE vulnerability_id=?", (CVE,))
            db.execute("INSERT INTO cyber_fts VALUES (?,?,?,?)", ("untouched') OR 1=1 --", "literal", "other", ""))
        untouched = self.rows("SELECT rowid,* FROM cyber_fts WHERE vulnerability_id!=?", (CVE,))
        self.publish(normalize_nvd(nvd((CVE,)), NVD_URL))
        self.assertEqual(self.rows("SELECT COUNT(*) FROM cyber_fts WHERE vulnerability_id=?", (CVE,)), [(1,)])
        self.assertEqual(self.rows("SELECT rowid,* FROM cyber_fts WHERE vulnerability_id!=?", (CVE,)), untouched)

    def test_alias_remapping_removes_last_observation_of_old_entity(self):
        self.publish(normalize_osv(osv((CVE,)), OSV_URL + GHSA), source="osv")
        self.publish(normalize_osv(osv((OTHER,)), OSV_URL + GHSA), source="osv")
        self.assertEqual(self.rows("SELECT vulnerability_id FROM cyber_fts"), [(OTHER,)])
        self.assertEqual(self.rows("SELECT vulnerability_id FROM cyber_entities"), [(OTHER,)])

    def test_legacy_alias_is_bound_as_literal_while_clearing_touched_rows(self):
        self.publish(normalize_nvd(nvd((CVE, OTHER)), NVD_URL))
        legacy = "old') OR 1=1 --"
        with Database(self.settings.database_path, initialize=False) as db:
            db.execute("INSERT INTO cyber_aliases VALUES (?,?,?)", ("nvd", CVE, legacy))
            db.execute("INSERT INTO cyber_fts VALUES (?,?,?,?)", (legacy, "literal", "legacy", ""))
        untouched = self.rows("SELECT rowid,* FROM cyber_fts WHERE vulnerability_id=?", (OTHER,))
        _, calls = self.publish(normalize_nvd(nvd(), NVD_URL))
        self.assertTrue(any(legacy in values for _, values in calls))
        self.assertFalse(any(legacy in sql for sql, _ in calls))
        self.assertEqual(self.rows("SELECT COUNT(*) FROM cyber_fts WHERE vulnerability_id=?", (legacy,)), [(0,)])
        self.assertEqual(self.rows("SELECT rowid,* FROM cyber_fts WHERE vulnerability_id=?", (OTHER,)), untouched)

    def test_retiring_last_observation_removes_fts_and_entity(self):
        self.publish(normalize_epss(epss(), EPSS_URL), source="epss")
        counts, calls = self.publish([], source="epss", retire_ids=[CVE])
        self.assertEqual(counts["retired"], 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.rows("SELECT COUNT(*) FROM cyber_fts"), [(0,)])
        self.assertEqual(self.rows("SELECT COUNT(*) FROM cyber_entities"), [(0,)])

    def test_snapshot_retirement_keeps_other_provider_observation(self):
        self.publish(normalize_nvd(nvd((CVE, OTHER)), NVD_URL))
        self.publish(normalize_epss(epss(), EPSS_URL), source="epss")
        counts, _ = self.publish(normalize_nvd(nvd((OTHER,)), NVD_URL), snapshot=True)
        self.assertEqual(counts["retired"], 1)
        self.assertEqual(self.rows("SELECT COUNT(*),COUNT(DISTINCT vulnerability_id) FROM cyber_fts"), [(2, 2)])
        self.assertEqual([r["source"] for r in get_vulnerability(self.settings, CVE)["observations"]], ["epss"])
        # An EPSS-only observation has metrics but no descriptive prose.
        self.assertEqual(vulnerability_context(self.settings, CVE, max_chars=100)["fragments"], [])

    def test_empty_delta_does_not_clear_any_fts_row(self):
        self.publish(normalize_nvd(nvd(), NVD_URL))
        before = self.canonical()
        counts, calls = self.publish([])
        self.assertEqual(counts, {"added": 0, "modified": 0, "unchanged": 0, "retired": 0})
        self.assertEqual(calls, [])
        self.assertEqual(self.canonical(), before)

    def test_failure_after_bulk_clear_rolls_back_records_history_and_fts(self):
        self.assertEqual(sync_source(self.settings, "nvd", [CVE, OTHER],
            client=FakeClient([nvd((CVE,)), nvd((OTHER,))]), now=NOW)["status"], "ok")
        before = self.canonical()
        changed = copy.deepcopy(nvd((CVE,)))
        changed["vulnerabilities"][0]["cve"]["descriptions"][0]["value"] = "A changed fixture, never production."
        with patch("rabanito.cyber.store._merge_entity", side_effect=ValueError("fixture failure")):
            result = sync_source(self.settings, "nvd", [CVE], client=FakeClient([changed]), now=NOW)
        self.assertEqual(result["status"], "error")
        self.assertEqual(self.canonical(), before)
        with Database(self.settings.database_path, initialize=False) as db:
            db.execute("INSERT INTO cyber_fts(cyber_fts) VALUES('integrity-check')")
            self.assertEqual(db.one("PRAGMA integrity_check")[0], "ok")
            self.assertEqual(db.query("PRAGMA foreign_key_check"), [])
