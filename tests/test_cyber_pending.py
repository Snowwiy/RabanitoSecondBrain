from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from rabanito.config import Settings
from rabanito.cyber.pending import discard_pending_window
from rabanito.cyber.store import DDL, SCHEMA_VERSION, cyber_status, ensure_schema, get_vulnerability, schema_version
from rabanito.cyber.sync import sync_source
from rabanito.cyber.transport import FetchError
from rabanito.db import Database, restore_database
from tests.test_cyber import CVE, OTHER, NOW, FakeClient, nvd


class CyberPendingTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parent / ".test-temp"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="cyber-pending-", dir=parent)
        self.root = Path(self.temporary.name)
        self.settings = Settings(self.root, {"database_path": "data/test.db", "data_dir": "data", "knowledge_dir": "knowledge",
                                           "vault_root": "vault", "projects_root": "projects", "cyber": {
                                               "nvd_page_size": 1, "max_pages": 1, "nvd_window_minutes": 1}})

    def tearDown(self):
        self.temporary.cleanup()

    def sync(self, payloads, ids=None):
        return sync_source(self.settings, "nvd", ids, client=FakeClient(payloads), now=NOW)

    def stage(self):
        result = self.sync([nvd((CVE,), 2)])
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["scope"]["resumable"])
        return result

    def snapshot(self):
        with Database(self.settings.database_path, read_only=True) as db:
            return {"entities": db.one("SELECT count(*) FROM cyber_entities")[0],
                    "cache": db.one("SELECT count(*) FROM cyber_http_cache")[0],
                    "fts": db.one("SELECT count(*) FROM cyber_fts")[0],
                    "watermark": db.one("SELECT watermark FROM cyber_sync_state WHERE source='nvd'")[0],
                    "pending": db.one("SELECT count(*) FROM cyber_pending_windows")[0]}

    def test_pages_are_unpublished_until_resume_completes_the_same_window(self):
        first = self.stage()
        self.assertEqual(self.snapshot(), {"entities": 0, "cache": 0, "fts": 0, "watermark": None, "pending": 1})
        client = FakeClient([nvd((OTHER,), 2, 1)])
        second = sync_source(self.settings, "nvd", client=client, now=NOW)
        self.assertEqual(second["status"], "ok")
        self.assertEqual(second["added"], 2)
        query = parse_qs(urlsplit(client.calls[0][0]).query)
        self.assertEqual(query["startIndex"], ["1"])
        self.assertEqual(second["scope"]["end"], first["scope"]["end"])
        self.assertEqual(self.snapshot(), {"entities": 2, "cache": 2, "fts": 2, "watermark": first["scope"]["end"], "pending": 0})

    def test_multiple_partial_calls_extend_checkpoint_not_the_public_index(self):
        first = self.sync([nvd((CVE,), 3)])
        second = self.sync([nvd((OTHER,), 3, 1)])
        self.assertEqual((first["status"], second["status"]), ("partial", "partial"))
        self.assertEqual(second["scope"]["next_offset"], 2)
        self.assertEqual(self.snapshot()["entities"], 0)
        third_id = "CVE-2024-99999"
        third = self.sync([nvd((third_id,), 3, 2)])
        self.assertEqual((third["status"], third["added"]), ("ok", 3))
        self.assertIsNotNone(get_vulnerability(self.settings, third_id))

    def test_network_failure_preserves_checkpoint_and_published_records(self):
        self.sync([nvd((OTHER,))], [OTHER])
        self.stage()
        before = self.snapshot()
        result = self.sync([FetchError("network_error")])
        self.assertEqual(result["status"], "error")
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.sync([nvd((OTHER,), 2, 1)])["status"], "ok")

    def test_provider_total_change_discards_only_unpublished_checkpoint(self):
        self.sync([nvd((OTHER,))], [OTHER])
        self.stage()
        result = self.sync([nvd((OTHER,), 3, 1)])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error_code"], "changing_pagination_total")
        state = self.snapshot()
        self.assertEqual(state["entities"], 1)
        self.assertEqual(state["pending"], 0)
        self.assertIsNone(state["watermark"])
        self.assertEqual(self.sync([nvd(())])["status"], "ok")

    def test_cross_page_duplicate_discards_staging_without_publishing_fake_coverage(self):
        self.stage()
        result = self.sync([nvd((CVE,), 2, 1)])
        self.assertEqual(result["error_code"], "duplicate_page_records")
        self.assertEqual(self.snapshot()["entities"], 0)
        self.assertEqual(self.snapshot()["pending"], 0)

    def test_invalid_feed_preserves_previous_staging_for_retry(self):
        self.stage()
        before = self.snapshot()
        result = self.sync([{"unexpected": "fixture"}])
        self.assertEqual(result["status"], "error")
        self.assertEqual(self.snapshot(), before)

    def test_empty_incomplete_page_is_retryable_without_destroying_previous_staging(self):
        self.stage()
        before = self.snapshot()
        self.assertEqual(self.sync([nvd((), 2, 1)])["error_code"], "empty_incomplete_page")
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.sync([nvd((OTHER,), 2, 1)])["status"], "ok")

    def test_concurrent_writers_serialize_staging_and_resume_without_duplicate_publication(self):
        entered, release = threading.Event(), threading.Event()
        class BlockingClient(FakeClient):
            def get(self, *args, **kwargs):
                entered.set()
                if not release.wait(5):
                    raise AssertionError("fixture coordination timeout")
                return super().get(*args, **kwargs)
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(sync_source, self.settings, "nvd", client=BlockingClient([nvd((CVE,), 2)]), now=NOW)
            self.assertTrue(entered.wait(5))
            second = executor.submit(sync_source, self.settings, "nvd", client=FakeClient([nvd((OTHER,), 2, 1)]), now=NOW)
            release.set()
            self.assertEqual(first.result(timeout=10)["status"], "partial")
            self.assertEqual(second.result(timeout=10)["status"], "ok")
        self.assertEqual(self.snapshot()["entities"], 2)
        self.assertEqual(self.snapshot()["pending"], 0)

    def test_final_publish_rollback_keeps_the_previous_checkpoint(self):
        self.stage()
        before = self.snapshot()
        with patch("rabanito.cyber.sync.apply_records", side_effect=sqlite3.IntegrityError("fixture publication failure")):
            result = self.sync([nvd((OTHER,), 2, 1)])
        self.assertEqual(result["status"], "error")
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.sync([nvd((OTHER,), 2, 1)])["added"], 2)

    def test_pending_byte_limit_does_not_mutate_published_or_old_checkpoint(self):
        self.stage()
        before = self.snapshot()
        # Change the fixture's persisted total only through an independently prepared three-record window.
        with Database(self.settings.database_path) as db:
            db.execute("DELETE FROM cyber_pending_windows")
            db.commit()
        self.sync([nvd((CVE,), 3)])
        before = self.snapshot()
        with patch("rabanito.cyber.pending.MAX_PENDING_BYTES", 50):
            result = self.sync([nvd((OTHER,), 3, 1)])
        self.assertEqual(result["status"], "error")  # load fails closed at the artificial size cap
        self.assertEqual(self.snapshot(), before)

    def test_first_checkpoint_size_limit_publishes_nothing_and_advances_no_cursor(self):
        with patch("rabanito.cyber.pending.MAX_PENDING_BYTES", 50):
            result = self.sync([nvd((CVE,), 2)])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["error_code"], "pending_window_checkpoint_limit_or_error")
        self.assertEqual(self.snapshot(), {"entities": 0, "cache": 0, "fts": 0, "watermark": None, "pending": 0})

    def test_newer_point_observation_is_not_overwritten_by_an_older_staged_record(self):
        self.stage()
        newer = nvd()
        newer["vulnerabilities"][0]["cve"]["lastModified"] = "2026-10-16T14:00:00Z"
        newer["vulnerabilities"][0]["cve"]["descriptions"][0]["value"] = "Newer verified fixture revision"
        self.sync([newer], [CVE])
        result = self.sync([nvd((OTHER,), 2, 1)])
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["retained_newer"], 1)
        self.assertIn("Newer verified fixture", get_vulnerability(self.settings, CVE)["description"])

    def test_staged_observation_preserves_its_real_fetch_time_after_final_publication(self):
        first_client = FakeClient([nvd((CVE,), 2)])
        response = first_client.get
        def first_get(*args, **kwargs):
            value = response(*args, **kwargs)
            value.fetched_at = "2026-10-16T09:00:00+00:00"
            return value
        first_client.get = first_get
        sync_source(self.settings, "nvd", client=first_client, now=NOW)
        self.sync([nvd((OTHER,), 2, 1)])
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(db.one("SELECT retrieved_at FROM cyber_records WHERE source_id=?", (CVE,))[0], "2026-10-16T09:00:00+00:00")

    def test_staged_window_backup_restore_resumes_after_process_restart(self):
        first = self.stage()
        backup, restored = self.root / "backup.db", self.root / "restored.db"
        with Database(self.settings.database_path) as db:
            db.backup(backup)
        restore_database(backup, restored)
        settings = Settings(self.root, self.settings.raw | {"database_path": str(restored)})
        result = sync_source(settings, "nvd", client=FakeClient([nvd((OTHER,), 2, 1)]), now=NOW)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["scope"]["end"], first["scope"]["end"])
        self.assertEqual(cyber_status(settings)["entities"], 2)
        self.assertEqual(self.snapshot()["entities"], 0)

    def test_point_lookup_does_not_delete_pending_window_or_advance_coverage(self):
        self.stage()
        self.sync([nvd((OTHER,))], [OTHER])
        self.assertEqual(self.snapshot()["pending"], 1)
        self.assertIsNone(self.snapshot()["watermark"])
        self.assertEqual(self.sync([nvd((OTHER,), 2, 1)])["status"], "ok")

    def test_pending_checksum_tampering_is_detected_without_network_or_publication(self):
        self.stage()
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE cyber_pending_windows SET checksum='tampered'")
            db.commit()
        client = FakeClient([])
        result = sync_source(self.settings, "nvd", client=client, now=NOW)
        self.assertEqual(result["status"], "error")
        self.assertEqual(client.calls, [])
        self.assertEqual(self.snapshot()["entities"], 0)

    def test_recovery_preview_is_read_only_and_explicit_discard_is_backed_up_and_restorable(self):
        self.stage()
        before = self.snapshot()
        preview = discard_pending_window(self.settings)
        self.assertTrue(preview["requires_explicit_approval"])
        self.assertFalse(preview["discarded"])
        self.assertEqual(self.snapshot(), before)
        result = discard_pending_window(self.settings, approve=True)
        self.assertTrue(result["discarded"])
        self.assertEqual(self.snapshot()["pending"], 0)
        self.assertIsNone(self.snapshot()["watermark"])
        restored = self.root / "recovered.db"
        restore_database(self.settings.data_dir / "backups" / result["backup"], restored)
        with Database(restored, read_only=True) as db:
            self.assertEqual(db.one("SELECT next_offset FROM cyber_pending_windows")[0], 1)
            self.assertEqual(db.one("SELECT count(*) FROM cyber_entities")[0], 0)

    def test_schema1_upgrade_is_additive_backed_up_and_queries_do_not_upgrade_it(self):
        with Database(self.settings.database_path) as db:
            db.connection.executescript(DDL)
            db.execute("INSERT INTO cyber_migrations VALUES (1,?,?)", (hashlib.sha256(DDL.encode()).hexdigest(), NOW.isoformat()))
            db.commit()
        self.assertEqual(cyber_status(self.settings)["schema_version"], 1)
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertIsNone(db.one("SELECT 1 FROM sqlite_master WHERE name='cyber_pending_windows'"))
        result = self.sync([nvd(())])
        self.assertIsNotNone(result["migration_backup"])
        self.assertTrue((self.settings.data_dir / "backups" / result["migration_backup"]).is_file())
        self.assertEqual(cyber_status(self.settings)["schema_version"], SCHEMA_VERSION)

    def test_migration_failure_rolls_back_without_changing_legacy_ledger(self):
        with Database(self.settings.database_path) as db:
            db.connection.executescript(DDL)
            checksum = hashlib.sha256(DDL.encode()).hexdigest()
            db.execute("INSERT INTO cyber_migrations VALUES (1,?,?)", (checksum, NOW.isoformat()))
            db.execute("CREATE TABLE cyber_pending_windows(marker TEXT)")
            db.commit()
            with self.assertRaises(sqlite3.OperationalError):
                ensure_schema(db)
            self.assertEqual(schema_version(db), 1)
            self.assertEqual(db.one("SELECT checksum FROM cyber_migrations")[0], checksum)
            self.assertEqual(db.one("PRAGMA integrity_check")[0], "ok")


if __name__ == "__main__":
    unittest.main()
