from __future__ import annotations

import hashlib
import json
import os
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import patch

from rabanito.db import Database, restore_database
from rabanito.config import Settings
from rabanito.dependencies import inspect_manifest, inspect_sbom
from rabanito.dependency_memory import snapshot_inventory
from rabanito.cyber.sync import sync_source
from tests import test_dependencies as fixtures
from tests.test_cyber import FakeClient, NOW, osv


class DependencyCacheTests(unittest.TestCase):
    setUp = fixtures.DependencyTests.setUp
    tearDown = fixtures.DependencyTests.tearDown
    register = fixtures.DependencyTests.register
    seed = fixtures.DependencyTests.seed
    write = fixtures.DependencyTests.write

    def inspect(self):
        return inspect_sbom(self.settings, str(self.project), self.path.name)

    def save(self):
        return snapshot_inventory(self.settings, str(self.project), self.path.name, save=True)

    def prepared(self):
        self.seed(); self.write()
        return self.save()["report"]

    def test_unsaved_queries_never_create_cache_or_migrate(self):
        self.seed(); self.write()
        before = hashlib.sha256(self.settings.database_path.read_bytes()).hexdigest()
        self.assertEqual(self.inspect()["cache"]["status"], "computed")
        self.assertEqual(self.inspect()["cache"]["status"], "computed")
        self.assertEqual(hashlib.sha256(self.settings.database_path.read_bytes()).hexdigest(), before)
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertIsNone(db.one("SELECT 1 FROM sqlite_master WHERE name='dependency_migrations'"))

    def test_hit_skips_inventory_parsing_and_version_evaluation_without_writes(self):
        saved = self.prepared()
        before = hashlib.sha256(self.settings.database_path.read_bytes()).hexdigest()
        with patch("rabanito.dependencies._components", side_effect=AssertionError("reparsed inventory")), \
             patch("rabanito.dependencies.version_evidence", side_effect=AssertionError("reevaluated ranges")), \
             patch("socket.socket", side_effect=AssertionError("network prohibited")):
            hit = self.inspect()
        self.assertEqual(hit["analysis_id"], saved["analysis_id"])
        self.assertEqual(hit["analyzed_at"], saved["analyzed_at"])
        self.assertEqual(hit["findings"], saved["findings"])
        self.assertEqual(hit["cache"]["status"], "reused_saved_analysis")
        self.assertEqual(hashlib.sha256(self.settings.database_path.read_bytes()).hexdigest(), before)
        self.assertNotIn(str(self.root), json.dumps(hit))

    def test_same_size_and_mtime_inventory_changes_invalidate_hit(self):
        saved = self.prepared()
        before = self.path.stat()
        self.path.write_bytes(self.path.read_bytes().replace(b"1.0", b"1.1"))
        os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(self.path.stat().st_size, before.st_size)
        current = self.inspect()
        self.assertEqual(current["cache"]["status"], "computed")
        self.assertNotEqual(current["analysis_id"], saved["analysis_id"])
        self.assertEqual(current["components"][0]["version"], "1.1")

    def test_modified_and_withdrawn_osv_records_invalidate(self):
        old = self.prepared()
        payload = osv()
        payload["affected"][0]["versions"] = ["9.0"]
        payload["affected"][0]["ranges"] = []
        self.seed(payload)
        changed = self.inspect()
        self.assertNotEqual(changed["analysis_id"], old["analysis_id"])
        self.assertEqual(changed["cache"]["status"], "computed")
        self.save()
        payload["withdrawn"] = NOW.isoformat()
        self.seed(payload)
        retired = self.inspect()
        self.assertEqual(retired["cache"]["status"], "computed")
        self.assertEqual(retired["findings"], [])

    def test_osv_retrieval_dates_and_coverage_changes_are_not_stale_on_hit(self):
        saved = self.prepared()
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE cyber_records SET retrieved_at=? WHERE source='osv'", ((NOW + timedelta(days=1)).isoformat(),))
        current = self.inspect()
        self.assertNotEqual(current["analysis_id"], saved["analysis_id"])
        self.assertEqual(current["coverage"]["latest_retrieved_at"], (NOW + timedelta(days=1)).isoformat())

    def test_new_record_after_capped_prefix_changes_completeness_and_identity(self):
        self.settings.raw["dependency_analysis"] = {"max_local_advisories": 1}
        saved = self.prepared()
        self.assertTrue(saved["coverage"]["local_snapshot_complete"])
        payload = osv()
        payload["id"] = "PYSEC-2099-999999"
        sync_source(self.settings, "osv", [payload["id"]], client=FakeClient([payload]), now=NOW)
        current = self.inspect()
        self.assertEqual(current["coverage"]["examined"], 1)
        self.assertEqual(current["coverage"]["total_local_observations"], 2)
        self.assertFalse(current["coverage"]["local_snapshot_complete"])
        self.assertNotEqual(saved["analysis_id"], current["analysis_id"])

    def test_engine_and_limit_changes_do_not_reuse_old_results(self):
        saved = self.prepared()
        from rabanito import dependencies
        with patch.object(dependencies, "ENGINE_VERSION", dependencies.ENGINE_VERSION + 1):
            upgraded = self.inspect()
        self.assertEqual(upgraded["cache"]["status"], "computed")
        self.assertNotEqual(upgraded["analysis_id"], saved["analysis_id"])
        self.settings.raw["dependency_analysis"] = {"max_findings": 1}
        changed = self.inspect()
        self.assertEqual(changed["cache"]["status"], "computed")
        self.assertNotEqual(changed["analysis_id"], saved["analysis_id"])

    def test_current_exclusions_and_missing_file_override_saved_report(self):
        self.prepared()
        self.settings.raw["excluded_projects"] = [str(self.project)]
        with self.assertRaisesRegex(ValueError, "active_authorized"):
            self.inspect()
        self.settings.raw["excluded_projects"] = []
        self.settings.raw["source_policy"]["projects"]["exclude_extensions"] = [".json"]
        with self.assertRaisesRegex(ValueError, "path_excluded"):
            self.inspect()
        self.settings.raw["source_policy"]["projects"]["exclude_extensions"] = []
        self.path.unlink()
        with self.assertRaisesRegex(ValueError, "unavailable"):
            self.inspect()

    def test_corrupted_saved_result_is_recomputed_not_trusted_or_silently_overwritten(self):
        saved = self.prepared()
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE dependency_analyses SET report_json=json_set(report_json,'$.summary.potentially_affected',0)")
        computed = self.inspect()
        self.assertEqual(computed["cache"]["status"], "computed")
        self.assertEqual(computed["summary"], saved["summary"])
        with self.assertRaisesRegex(ValueError, "not_reusable_review_required"):
            self.save()
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(db.one("SELECT json_extract(report_json,'$.summary.potentially_affected') FROM dependency_analyses")[0], 0)

    def test_unknown_migrations_fail_closed_before_cache_reuse(self):
        self.prepared()
        for table in ("cyber_migrations", "dependency_migrations"):
            with self.subTest(table=table):
                with Database(self.settings.database_path) as db:
                    old = db.query(f"SELECT version,checksum FROM {table}")
                    db.execute(f"UPDATE {table} SET checksum='invalid'")
                with self.assertRaisesRegex(ValueError, "migration"):
                    self.inspect()
                with Database(self.settings.database_path) as db:
                    db.executemany(f"UPDATE {table} SET checksum=? WHERE version=?", [(r["checksum"], r["version"]) for r in old])

    def test_concurrent_reads_and_saves_keep_one_snapshot(self):
        self.prepared()
        with ThreadPoolExecutor(max_workers=3) as pool:
            reports = list(pool.map(lambda _: self.save()["report"], range(3)))
        self.assertTrue(all(r["cache"]["status"] == "reused_saved_analysis" for r in reports))
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(db.one("SELECT count(*) FROM dependency_analyses")[0], 1)
            self.assertEqual(db.query("PRAGMA foreign_key_check"), [])

    def test_manifest_cache_and_restore_use_same_local_memory(self):
        self.seed()
        self.path = self.project / "requirements.txt"
        self.path.write_text("parser==1.0\n", encoding="utf-8")
        snapshot_inventory(self.settings, str(self.project), self.path.name, kind="manifest", save=True)
        with patch("rabanito.dependencies._requirements", side_effect=AssertionError("reparsed manifest")):
            report = inspect_manifest(self.settings, str(self.project), self.path.name)
        self.assertEqual(report["cache"]["status"], "reused_saved_analysis")
        backup, restored = self.settings.data_dir / "cache-backup.db", self.settings.data_dir / "cache-restore.db"
        with Database(self.settings.database_path, read_only=True) as db:
            db.backup(backup)
        restore_database(backup, restored)
        settings = Settings(self.root, {**self.settings.raw, "database_path": str(restored)})
        recovered = inspect_manifest(settings, str(self.project), self.path.name)
        self.assertEqual(recovered["cache"]["status"], "reused_saved_analysis")
        self.assertEqual(recovered["analysis_id"], report["analysis_id"])

    def test_osv_publication_during_read_cannot_mix_metadata_and_payload_revisions(self):
        self.seed(); self.write()
        original = self.inspect()
        payload = osv()
        payload["affected"][0]["versions"] = ["9.0"]
        payload["affected"][0]["ranges"] = []
        def publish(*args, **kwargs):
            self.seed(payload)
            return None
        with patch("rabanito.dependencies.reuse_saved", side_effect=publish):
            snapshot = self.inspect()
        self.assertEqual(snapshot["analysis_id"], original["analysis_id"])
        self.assertEqual(snapshot["findings"], original["findings"])
        following = self.inspect()
        self.assertNotEqual(following["analysis_id"], snapshot["analysis_id"])
        # A non-matching explicit versions list without a supported range is
        # inconclusive, never proof that the version is outside all affected releases.
        self.assertEqual(following["components"][0]["assessment"], "needs_review")

    def test_root_relocation_does_not_reuse_another_provenance(self):
        old = self.prepared()
        moved = self.settings.projects_root / "Another authorized root ñ"
        moved.mkdir()
        target = moved / self.path.name
        target.write_bytes(self.path.read_bytes())
        from rabanito.utils import path_key
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE projects SET root_path=?,name=?,path_key=? WHERE root_path=?", (str(moved), moved.name, path_key(moved), str(self.project)))
        self.project, self.path = moved, target
        current = self.inspect()
        self.assertEqual(current["cache"]["status"], "computed")
        self.assertNotEqual(current["analysis_id"], old["analysis_id"])
        self.assertEqual(current["project"], moved.name)

    def test_oversized_saved_report_is_not_loaded_for_reuse(self):
        self.prepared()
        with patch("rabanito.dependency_cache.MAX_REPORT_BYTES", 32):
            report = self.inspect()
        self.assertEqual(report["cache"]["status"], "computed")
        self.assertEqual(report["summary"], {"potentially_affected": 1})

    def test_vex_review_never_suppresses_original_cached_candidate(self):
        from tests import test_dependency_memory as memory_fixtures
        from rabanito.dependency_memory import review_inventory, reviewed_inventory
        args = memory_fixtures.DependencyMemoryTests.setup_review(self)
        # setup_review publishes the fixture OSV observation. Snapshot after
        # that publication so crossing a wall-clock second cannot alter inputs.
        saved = self.save()["report"]
        preview = review_inventory(self.settings, **args)
        review_inventory(self.settings, **args, approve_digest=preview["approval_digest"])
        view = reviewed_inventory(self.settings, str(self.project), self.path.name, now=NOW)
        self.assertEqual(view["report"]["cache"]["status"], "reused_saved_analysis")
        self.assertEqual(view["report"]["findings"][0]["assessment"], "potentially_affected")
        self.assertEqual(view["reviews"][0]["effective_state"], "current")
        self.assertEqual(view["analysis_result_sha256"], saved["result_sha256"])
        self.assertNotIn("result_sha256", view["report"])
