from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import sqlite3
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

from rabanito.cli import main
from rabanito.config import Settings
from rabanito.cyber.history import DDL_3, vulnerability_history
from rabanito.cyber.store import DDL, schema_version
from rabanito.cyber.pending import DDL_2
from rabanito.cyber.sync import sync_source
from rabanito.db import Database, restore_database
from rabanito.server import RabanitoHandler
from tests import test_cyber as fixtures
from tests.test_cyber import CVE, OTHER, GHSA, NOW, FakeClient, kev, nvd, osv


class CyberHistoryTests(unittest.TestCase):
    setUp = fixtures.CyberTests.setUp
    tearDown = fixtures.CyberTests.tearDown
    sync = fixtures.CyberTests.sync

    def history(self, value=CVE, **kwargs):
        return vulnerability_history(self.settings, value, **kwargs)

    def legacy(self):
        self.sync("osv", [osv()], [GHSA])
        with Database(self.settings.database_path) as db:
            # Generated fixture only: model a real v2 ledger/current observation.
            db.execute("DROP TABLE cyber_revision_identifiers")
            db.execute("DROP TABLE cyber_revisions")
            db.execute("DELETE FROM cyber_migrations WHERE version=3")

    def test_query_before_first_sync_is_read_only_without_history_claim(self):
        result = self.history()
        self.assertFalse(result["history_available"])
        self.assertIsNone(result["activated_at"])
        self.assertFalse(self.settings.database_path.exists())

    def test_corrupt_database_fails_safely_without_exposing_path(self):
        self.settings.database_path.write_bytes(b"generated corrupt database fixture")
        with self.assertRaisesRegex(ValueError, "^cyber_history_storage_unavailable$"):
            self.history()

    def test_first_observation_and_unchanged_refresh_do_not_duplicate_history(self):
        self.sync("nvd", [nvd()], [CVE])
        first = self.history()
        self.assertEqual(first["total"], 1)
        self.assertEqual(first["results"][0]["event"], "observed")
        self.sync("nvd", [nvd()], [CVE])
        self.assertEqual(self.history()["total"], 1)
        self.assertNotIn("data_json", first["results"][0])
        self.assertNotIn(str(self.root), json.dumps(first))

    def test_modified_observation_preserves_previous_revision_and_source_dates(self):
        self.sync("osv", [osv()], [GHSA])
        changed = osv()
        changed["modified"] = "2026-10-16T11:00:00Z"
        changed["summary"] = "Revised public fixture"
        self.sync("osv", [changed], [GHSA])
        result = self.history(source="osv")
        self.assertEqual([r["event"] for r in result["results"]], ["modified", "observed"])
        self.assertNotEqual(result["results"][0]["fingerprint"], result["results"][1]["fingerprint"])
        self.assertEqual(result["results"][0]["source_modified"], "2026-10-16T11:00:00Z")
        self.assertTrue(result["results"][0]["recorded_at"])
        self.assertTrue(result["results"][0]["retrieved_at"])

    def test_v2_upgrade_backs_up_and_lazily_captures_known_baseline_not_fake_past(self):
        self.legacy()
        self.assertFalse(self.history()["history_available"])
        with Database(self.settings.database_path, read_only=True) as db:
            old = dict(db.one("SELECT * FROM cyber_records WHERE source='osv'"))
            ledger = [(r["version"], r["checksum"]) for r in db.query("SELECT * FROM cyber_migrations ORDER BY version")]
        self.assertEqual([checksum for _, checksum in ledger], [hashlib.sha256(d.encode()).hexdigest() for d in (DDL, DDL_2)])
        changed = osv()
        changed["details"] = "Actual new fixture observation"
        updated = self.sync("osv", [changed], [GHSA])
        self.assertTrue((self.settings.data_dir / "backups" / updated["migration_backup"]).exists())
        result = self.history()
        self.assertEqual([r["event"] for r in result["results"]], ["modified", "baseline_captured"])
        self.assertEqual(result["results"][1]["fingerprint"], old["fingerprint"])
        self.assertEqual(result["results"][1]["retrieved_at"], old["retrieved_at"])
        self.assertEqual(result["results"][1]["recorded_at"], result["results"][0]["recorded_at"])
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(schema_version(db), 3)
            self.assertEqual([(r["version"], r["checksum"]) for r in db.query("SELECT * FROM cyber_migrations WHERE version<3 ORDER BY version")], ledger)

    def test_retirement_and_reactivation_keep_distinct_observed_states(self):
        self.assertEqual(self.sync("kev", [kev()])["status"], "ok")
        self.assertEqual(self.sync("kev", [kev((OTHER,))])["status"], "ok")
        retired = self.history(source="kev")["results"][0]
        self.assertEqual(retired["event"], "retired")
        self.assertEqual(retired["active"], 0)
        self.assertEqual(self.sync("kev", [kev((CVE, OTHER))])["status"], "ok")
        self.assertEqual([r["event"] for r in self.history()["results"]], ["reactivated", "retired", "observed"])

    def test_changed_aliases_preserve_historical_reference_without_equating_cves(self):
        self.sync("osv", [osv((CVE, OTHER))], [GHSA])
        changed = osv((CVE,))
        changed["modified"] = "2026-10-16T11:00:00Z"
        self.sync("osv", [changed], [GHSA])
        self.assertEqual(self.history(OTHER)["total"], 1)
        self.assertEqual(self.history(CVE)["total"], 2)
        self.assertEqual(self.history(OTHER)["results"][0]["matched_by"], "provider_alias")
        self.assertEqual(self.history(OTHER)["results"][0]["source_id"], GHSA)
        self.assertIn("not equivalence", self.history(OTHER)["association"])

    def test_failed_publication_rolls_back_revision_and_current_record(self):
        self.sync("osv", [osv()], [GHSA])
        previous = self.history()["results"]
        changed = osv()
        changed["summary"] = "Should never publish"
        with patch("rabanito.cyber.store._merge_entity", side_effect=ValueError("fixture failure")):
            self.assertEqual(self.sync("osv", [changed], [GHSA])["status"], "error")
        self.assertEqual(self.history()["results"], previous)

    def test_pending_pages_have_no_revisions_until_atomic_window_publication(self):
        self.settings.raw["cyber"].update(max_pages=1, nvd_window_minutes=1)
        first = self.sync("nvd", [nvd((CVE,), 2)])
        self.assertEqual(first["status"], "partial")
        self.assertEqual(self.history()["results"], [])
        self.assertTrue(self.history()["history_available"])
        self.assertEqual(self.sync("nvd", [nvd((OTHER,), 2, 1)])["status"], "ok")
        self.assertEqual(self.history()["total"], 1)
        self.assertEqual(self.history(OTHER)["total"], 1)

    def test_older_pending_record_does_not_create_a_false_revision(self):
        self.settings.raw["cyber"].update(max_pages=1, nvd_window_minutes=1)
        self.sync("nvd", [nvd((CVE,), 2)])
        newer = nvd()
        newer["vulnerabilities"][0]["cve"]["lastModified"] = "2026-10-16T11:00:00Z"
        self.sync("nvd", [newer], [CVE])
        previous = self.history()["results"]
        resumed = self.sync("nvd", [nvd((OTHER,), 2, 1)])
        self.assertEqual(resumed["retained_newer"], 1)
        self.assertEqual(self.history()["results"], previous)

    def test_cursor_pagination_filters_and_strict_input_limits(self):
        self.sync("kev", [kev()])
        self.sync("nvd", [nvd()], [CVE])
        first = self.history(limit=1)
        self.assertTrue(first["truncated"])
        second = self.history(limit=1, before=first["next_before"])
        self.assertNotEqual(first["results"][0]["revision_id"], second["results"][0]["revision_id"])
        self.assertFalse(second["truncated"])
        self.assertEqual(self.history(source="kev")["total"], 1)
        self.assertEqual(self.history(limit=0)["results"], [])
        for kwargs in ({"limit": True}, {"limit": 51}, {"before": 0}, {"before": 10 ** 100}, {"source": []}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.history(**kwargs)

    def test_failed_migration_preserves_legacy_schema_and_observations(self):
        self.legacy()
        with patch("rabanito.cyber.store.DDL_3", DDL_3 + "\nTHIS IS INVALID SQL;"):
            with self.assertRaises(sqlite3.OperationalError):
                self.sync("kev", [kev()])
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(schema_version(db), 2)
            self.assertIsNone(db.one("SELECT 1 FROM sqlite_master WHERE name='cyber_revisions'"))
            self.assertEqual(db.one("SELECT count(*) n FROM cyber_records")["n"], 1)
            self.assertEqual(db.one("PRAGMA integrity_check")[0], "ok")

    def test_restore_preserves_revision_history_and_rejects_tampered_migration(self):
        self.sync("osv", [osv()], [GHSA])
        backup, restored = self.settings.data_dir / "history-backup.db", self.settings.data_dir / "restored.db"
        with Database(self.settings.database_path, read_only=True) as db:
            db.backup(backup)
        restore_database(backup, restored)
        config = Settings(self.root, {**self.settings.raw, "database_path": str(restored)})
        self.assertEqual(vulnerability_history(config, CVE)["total"], 1)
        with Database(restored) as db:
            db.execute("UPDATE cyber_migrations SET checksum='invalid' WHERE version=3")
        with self.assertRaisesRegex(ValueError, "migration"):
            vulnerability_history(config, CVE)

    def test_cli_returns_bounded_metadata_without_raw_provider_payload(self):
        self.sync("osv", [osv()], [GHSA])
        config = self.root / "settings.json"
        config.write_text(json.dumps({**self.settings.raw, "project_root": str(self.root)}), encoding="utf-8")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            main(["--config", str(config), "cyber", "history", CVE, "--limit", "1"])
        result = json.loads(output.getvalue())
        self.assertEqual(len(result["results"]), 1)
        self.assertNotIn("data_json", output.getvalue())

    def test_http_history_requires_local_json_post_and_preserves_privacy_contract(self):
        self.sync("osv", [osv()], [GHSA])
        class Handler(RabanitoHandler):
            settings = self.settings
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        try:
            headers = {"Origin": origin, "Content-Type": "application/json"}
            with urlopen(Request(origin + "/api/cyber/history", data=json.dumps({"id": CVE}).encode(), headers=headers)) as response:
                self.assertEqual(json.load(response)["total"], 1)
            for method, payload, extra, status in (("GET", {}, {}, 405),
                    ("POST", {"id": CVE}, {"Origin": "https://external.invalid"}, 403),
                    ("POST", {"id": CVE, "limit": None}, {}, 400)):
                with self.subTest(method=method, status=status), self.assertRaises(HTTPError) as caught:
                    request = Request(origin + "/api/cyber/history", data=None if method == "GET" else json.dumps(payload).encode(),
                                      headers=headers | extra, method=method)
                    urlopen(request).close()
                self.assertEqual(caught.exception.code, status)
                caught.exception.close()
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)
