from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rabanito.config import Settings
from rabanito.db import Database
import sqlite3
from rabanito.cyber.sync import sync_source
from rabanito.public_graph import public_graph
from rabanito.security import index_security_catalog
from tests.test_cyber import CVE, GHSA, NOW, FakeClient, kev, nvd, osv


class PublicGraphTests(unittest.TestCase):
    def test_withdrawn_root_keeps_its_citation_and_status_without_active_package_edges(self):
        payload = osv()
        payload["withdrawn"] = "2026-10-16T00:00:00Z"
        sync_source(self.settings, "osv", [GHSA], client=FakeClient([payload]), now=NOW)
        graph = public_graph(self.settings, "cyber", limit=20)
        self.assertEqual(len(graph["nodes"]), 1)
        self.assertEqual(graph["nodes"][0]["record_status"], "withdrawn")
        self.assertIn("withdrawn", graph["nodes"][0]["summary"])
        self.assertTrue(graph["nodes"][0]["reference_url"].startswith("https://"))
        self.assertFalse(graph["edges"])

    def setUp(self):
        self.project = Path(__file__).resolve().parents[1]
        parent = self.project / "tests" / ".test-temp"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="public-graph-", dir=parent)
        self.root = Path(self.temporary.name)
        self.settings = Settings(self.root, {"database_path": "data/brain.db", "data_dir": "data", "knowledge_dir": "knowledge",
                                           "vault_root": "vault", "projects_root": "projects"})

    def tearDown(self):
        self.temporary.cleanup()

    def seed_cyber(self):
        for source, payload, ids in (("kev", kev(), None), ("nvd", nvd(), [CVE]), ("osv", osv(), [GHSA])):
            result = sync_source(self.settings, source, ids, client=FakeClient([payload]), now=NOW)
            self.assertEqual(result["status"], "ok")

    def test_public_graph_has_real_typed_edges_safe_ids_and_source_citations(self):
        self.seed_cyber()
        graph = public_graph(self.settings, "cyber", limit=100)
        self.assertTrue(graph["nodes"] and graph["edges"])
        self.assertEqual({n["entity_kind"] for n in graph["nodes"]}, {"vulnerability", "technology", "weakness"})
        ids = {n["document_id"] for n in graph["nodes"]}
        self.assertTrue(all(-2**53 < value < 0 for value in ids))
        self.assertTrue(all(e["source"] in ids and e["target"] in ids and e["citation"].startswith("https://") for e in graph["edges"]))
        self.assertTrue(any("not_project_applicability" in e["relation_type"] for e in graph["edges"]))
        self.assertTrue(any(e["relation_type"] == "advisory_reports_package" for e in graph["edges"]))
        self.assertNotIn(str(self.root), json.dumps(graph))

    def test_limits_determinism_and_degree_filter_do_not_create_dangling_edges(self):
        self.seed_cyber()
        for cap in (0, 1, 2, 3, 5, 100):
            with self.subTest(cap=cap):
                first = public_graph(self.settings, "cyber", limit=cap)
                second = public_graph(self.settings, "cyber", limit=cap)
                self.assertEqual(first, second)
                self.assertLessEqual(len(first["nodes"]), cap)
                ids = {n["document_id"] for n in first["nodes"]}
                self.assertTrue(all(e["source"] in ids and e["target"] in ids for e in first["edges"]))
        self.assertEqual(public_graph(self.settings, "cyber", min_degree=100)["nodes"], [])

    def test_queries_and_provider_filters_use_local_real_records(self):
        self.seed_cyber()
        self.assertEqual(public_graph(self.settings, "cyber", query="nonexistent-needle")["nodes"], [])
        self.assertEqual(public_graph(self.settings, "cyber", source="epss")["nodes"], [])
        self.assertEqual(public_graph(self.settings, "cyber", query=CVE)["root_total_matches"], 1)

    def test_read_only_database_connection_cannot_mutate_or_create_a_database(self):
        self.seed_cyber()
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertIsNotNone(db.one("SELECT 1 FROM cyber_entities LIMIT 1"))
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("DELETE FROM cyber_entities")
        absent = self.root / "not-created" / "missing.db"
        with self.assertRaises(sqlite3.OperationalError): Database(absent, read_only=True)
        self.assertFalse(absent.parent.exists())

    def test_security_graph_keeps_editorial_crosswalks_separate_from_source_relations(self):
        config = self.root / "config"
        config.mkdir()
        (config / "security_catalog.json").write_bytes((self.project / "config" / "security_catalog.json").read_bytes())
        index_security_catalog(self.settings)
        graph = public_graph(self.settings, "security", limit=100)
        self.assertEqual(len(graph["nodes"]), 28)
        self.assertEqual(len(graph["edges"]), 17)
        self.assertTrue(any(e["kind"] == "suggested" and e["validation"] == "unvalidated_editorial" for e in graph["edges"]))
        self.assertTrue(all(e["kind"] == "explicit" for e in graph["edges"] if e["relation_type"] == "part_of"))
