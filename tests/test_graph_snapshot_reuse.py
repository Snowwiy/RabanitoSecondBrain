from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rabanito.config import Settings
from rabanito.cyber.sync import sync_source
from rabanito.db import Database
from rabanito.indexer import index_all
from rabanito.knowledge_graph import graph_neighbors, graph_page, sync_graph
from rabanito.knowledge_graph import query, store
from tests.test_cyber import CVE, OTHER, NOW, FakeClient, kev


class GraphSnapshotReuseTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parent / ".test-temp"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="graph-snapshot-", dir=parent)
        self.root = Path(self.temporary.name)
        self.settings = Settings(self.root, {"data_dir": "data", "database_path": "data/test.db",
            "knowledge_dir": "knowledge", "vault_root": "vault", "projects_root": "projects",
            "source_policy": {kind: {"extensions": [".md"]} for kind in ("obsidian", "projects", "internal")}})
        for path in (self.settings.knowledge_root, self.settings.vault_root, self.settings.projects_root):
            path.mkdir()
        (self.settings.vault_root / "Local.md").write_text(
            "---\ntitle: Local fixture\n---\n# Local fixture\nSelected documentation.\n", encoding="utf-8")
        for name in ("Alpha", "Beta"):
            folder = self.settings.projects_root / name
            folder.mkdir()
            (folder / "README.md").write_text(f"# {name}\nDocumented fixture architecture.\n", encoding="utf-8")
        self.assertEqual(sync_source(self.settings, "kev", client=FakeClient([kev((CVE, OTHER))]), now=NOW)["status"], "ok")
        self.assertEqual(index_all(self.settings)["status"], "ok")
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(db.one("SELECT COUNT(*) FROM documents WHERE source_kind='obsidian' AND status='active'")[0], 1)
            self.assertGreaterEqual(db.one("SELECT COUNT(*) FROM documents WHERE source_kind='projects' AND status='active'")[0], 2)
        for _ in range(4):
            if sync_graph(self.settings, max_inputs=1000)["status"] == "ok":
                break
        else:
            self.fail("Fixture projection did not complete")
        self.real_configure = query.configure
        self.fingerprints = []

    def tearDown(self):
        with query._PROOF_LOCK:
            query._CLEAN_PROOFS.clear()
        self.temporary.cleanup()

    def counted_configure(self, db, settings):
        result = self.real_configure(db, settings)
        def fingerprint(*values):
            self.fingerprints.append(values)
            return store.fingerprint("kg-projection", store.ENGINE_VERSION, *values)
        db.connection.create_function("kg_fp", -1, fingerprint, deterministic=True)
        return result

    def cold(self, function=graph_page, **options):
        with query._PROOF_LOCK:
            query._CLEAN_PROOFS.clear()
        self.fingerprints = []
        with patch.object(query, "configure", self.counted_configure):
            result = function(self.settings, **options)
        return result, len(self.fingerprints)

    def proof_calls(self):
        result, calls = self.cold(kind="vulnerability", limit=0)
        return result, calls

    def test_clean_persisted_epoch_proof_skips_descriptor_scan_for_page(self):
        result, calls = self.cold(kind="vulnerability", limit=50)
        self.assertEqual(calls, 0)
        self.assertEqual(result["coverage"]["source_validation"], "epoch_validated_fingerprints")
        self.assertFalse(result["coverage"]["requires_sync"])
        self.assertEqual({n["id"] for n in result["nodes"]}, {"vulnerability:" + CVE, "vulnerability:" + OTHER})

    def test_cleared_persisted_version_forces_global_live_validation(self):
        with Database(self.settings.database_path, initialize=False) as db:
            db.execute("UPDATE kg_state SET value='' WHERE key='last_complete_source_version'")
        result, calls = self.cold(kind="vulnerability", limit=50)
        self.assertGreater(calls, 0)
        self.assertEqual(result["coverage"]["source_validation"], "live_fingerprint_scan")
        self.assertFalse(result["coverage"]["requires_sync"])
        self.assertEqual({n["id"] for n in result["nodes"]}, {"vulnerability:" + CVE, "vulnerability:" + OTHER})
        # A public kind filter still validates local and project inputs globally.
        self.assertTrue(any("Local fixture" in args for args in self.fingerprints))
        self.assertTrue(any("Alpha" in args for args in self.fingerprints))

    def test_clean_persisted_epoch_proof_skips_descriptor_scan_for_neighbors(self):
        result, calls = self.cold(graph_neighbors, node_id="vulnerability:" + CVE, limit=50)
        self.assertEqual(calls, 0)
        self.assertTrue(result["anchor_visible"])
        self.assertTrue(result["edges"])
        self.assertEqual(result["coverage"]["source_validation"], "epoch_validated_fingerprints")

    def test_missing_watchers_still_force_fingerprints_and_require_sync(self):
        with Database(self.settings.database_path, initialize=False) as db:
            name = db.one("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'kg_watch_%' LIMIT 1")[0]
            db.execute('DROP TRIGGER "' + name + '"')
        _, expected = self.proof_calls()
        for _ in range(2):
            result, calls = self.cold(kind="vulnerability", limit=50)
            self.assertEqual(calls, expected)
            self.assertTrue(result["coverage"]["requires_sync"])
            self.assertFalse(result["coverage"]["watcher_coverage_complete"])
            self.assertEqual(result["coverage"]["source_validation"], "live_fingerprint_scan")

    def test_dirty_input_keeps_fingerprint_join_and_hides_stale_claims(self):
        with Database(self.settings.database_path, initialize=False) as db:
            db.execute("UPDATE cyber_records SET retrieved_at=? WHERE source='kev' AND source_id=?", ("2026-10-19T06:00:00+00:00", CVE))
        _, expected = self.proof_calls()
        result, calls = self.cold(kind="vulnerability", limit=50)
        self.assertGreater(calls, expected)
        self.assertGreater(result["coverage"]["missing_or_stale_inputs"], 0)
        self.assertEqual({n["id"] for n in result["nodes"]}, {"vulnerability:" + OTHER})

    def test_obsolete_input_cannot_take_clean_shortcut(self):
        with Database(self.settings.database_path, initialize=False) as db:
            db.execute("UPDATE cyber_records SET active=0 WHERE source='kev' AND source_id=?", (CVE,))
        _, expected = self.proof_calls()
        result, calls = self.cold(kind="vulnerability", limit=50)
        self.assertGreater(calls, expected)
        self.assertGreater(result["coverage"]["obsolete_inputs"], 0)
        self.assertNotIn("vulnerability:" + CVE, {n["id"] for n in result["nodes"]})

    def test_project_exclusion_is_revalidated_before_canonical_nodes(self):
        with Database(self.settings.database_path, read_only=True) as db:
            pid = db.one("SELECT project_id FROM projects WHERE name='Alpha'")[0]
        before, _ = self.cold(limit=200)
        self.assertIn("project:" + str(pid), {n["id"] for n in before["nodes"]})
        self.settings.raw["excluded_projects"] = ["Alpha"]
        result, _ = self.cold(limit=200)
        self.assertNotIn("project:" + str(pid), {n["id"] for n in result["nodes"]})
        self.assertTrue(all(n["contributor_project_id"] != pid for n in result["nodes"]))
        self.assertTrue(result["coverage"]["requires_sync"])

    def test_persisted_proof_remains_valid_across_separate_read_connections(self):
        first, _ = self.cold(kind="vulnerability", limit=50)
        self.fingerprints = []
        with patch.object(query, "configure", self.counted_configure):
            second = graph_page(self.settings, kind="vulnerability", limit=50)
        self.assertEqual(first["nodes"], second["nodes"])
        self.assertEqual(first["coverage"]["source_validation"], "epoch_validated_fingerprints")
        self.assertEqual(second["coverage"]["source_validation"], "epoch_validated_fingerprints")
        self.assertEqual(self.fingerprints, [])

    def test_schema_checks_are_not_bypassed_by_a_clean_proof(self):
        self.cold(kind="vulnerability", limit=50)
        with Database(self.settings.database_path, initialize=False) as db:
            db.execute("UPDATE cyber_migrations SET checksum='fixture-invalid' WHERE version=3")
        with self.assertRaises(ValueError):
            graph_page(self.settings, kind="vulnerability", limit=50)
