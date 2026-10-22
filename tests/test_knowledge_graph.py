from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import sqlite3
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

from rabanito.cli import main
from rabanito.config import Settings
from rabanito.cyber.sync import sync_source
from rabanito.cyber.store import apply_records, ensure_schema
from rabanito.cyber.model import normalize_nvd
from rabanito.db import Database, restore_database
from rabanito.dependency_memory import review_inventory, snapshot_inventory
from rabanito.indexer import index_all
from rabanito.knowledge_graph import graph_neighbors, graph_page, sync_graph
from rabanito.security import index_security_catalog
from rabanito.server import RabanitoHandler
from tests import test_coding_retrieval as fixtures
from tests.test_cyber import CVE, GHSA, NOW, FakeClient, kev, nvd, osv


class KnowledgeGraphTests(unittest.TestCase):
    setUp = fixtures.CodingMemoryTests.setUp
    tearDown = fixtures.CodingMemoryTests.tearDown
    memory = fixtures.CodingMemoryTests.memory

    def seed(self):
        (self.settings.vault_root / "Graph Ñ.md").write_text("# Graph Ñ\n\nA local synthetic note.\n", encoding="utf-8")
        (self.alpha / "README.md").write_text("# Alpha fixture\n\n[[Graph Ñ]]\n\n[CVE](https://nvd.nist.gov/vuln/detail/" + CVE + ")\n\n[ZT](https://csrc.nist.gov/pubs/sp/800/207/final)\n", encoding="utf-8")
        (self.alpha / "pyproject.toml").write_text('[project]\nname="graph-fixture"\ndependencies=["parser==1.0"]\n', encoding="utf-8")
        self.memory(evidence=["project:README.md", "obsidian:Graph Ñ.md"])
        self.memory(self.beta)
        index_all(self.settings)
        for source, payload, ids in (("kev", kev(), None), ("nvd", nvd(), [CVE]), ("osv", osv(), [GHSA])):
            self.assertEqual(sync_source(self.settings, source, ids, client=FakeClient([payload]), now=NOW)["status"], "ok")
        catalog = self.root / "config/security_catalog.json"
        catalog.parent.mkdir(exist_ok=True)
        catalog.write_bytes((Path(__file__).resolve().parents[1] / "config/security_catalog.json").read_bytes())
        index_security_catalog(self.settings)
        inventory = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
            {"type": "library", "name": "parser", "version": "1.0", "purl": "pkg:pypi/parser@1.0"}]}
        (self.alpha / "inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
        snapshot_inventory(self.settings, str(self.alpha), "inventory.json", save=True)
        args = dict(project=str(self.alpha), relative_path="inventory.json", advisory=GHSA, component_pointer="/components/0",
                    status="under_investigation", reviewer="Fixture Reviewer", reason="Fixture applicability requires review",
                    expires=(datetime.now(timezone.utc).date() + timedelta(days=30)).isoformat(), evidence=["README.md"])
        preview = review_inventory(self.settings, **args)
        review_inventory(self.settings, **args, approve_digest=preview["approval_digest"])

    def sync(self, limit=5000):
        for _ in range(100):
            result = sync_graph(self.settings, max_inputs=limit)
            if result["status"] == "ok":
                return result
            self.assertEqual(result["errors"], 0, result)
        self.fail("Generated graph sync failed to converge")

    def pages(self, **options):
        result, cursor = [], None
        for _ in range(500):
            page = graph_page(self.settings, cursor=cursor, **options)
            result += page["nodes"]
            if not page["has_more"]:
                return result
            self.assertTrue(page["next_cursor"])
            self.assertNotEqual(cursor, page["next_cursor"])
            cursor = page["next_cursor"]
        self.fail("Graph pagination failed to terminate")

    def test_read_before_projection_never_migrates_or_writes(self):
        before = hashlib.sha256(self.settings.database_path.read_bytes()).hexdigest()
        self.assertFalse(graph_page(self.settings)["projection_available"])
        self.assertFalse(graph_neighbors(self.settings, "project:1")["projection_available"])
        self.assertEqual(hashlib.sha256(self.settings.database_path.read_bytes()).hexdigest(), before)
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertIsNone(db.one("SELECT 1 FROM sqlite_master WHERE name='kg_migrations'"))

    def test_real_fixture_domains_and_cited_typed_connections(self):
        self.seed(); self.sync()
        nodes = self.pages(limit=25)
        kinds = {n["kind"] for n in nodes}
        self.assertTrue({"document", "project", "decision", "solution", "vulnerability", "observation", "package", "weakness",
                         "standard", "control", "security_concept", "snapshot", "dependency", "review", "technology", "dependency_declaration"} <= kinds)
        self.assertNotIn(str(self.root), json.dumps(nodes))
        all_ids = {n["id"] for n in nodes}
        for node in nodes:
            self.assertTrue(node["citation"])
        alpha = next(n for n in nodes if n["kind"] == "project" and n["title"] == self.alpha.name)
        near = graph_neighbors(self.settings, alpha["id"], limit=200)
        self.assertTrue(near["edges"])
        self.assertTrue(all(e["citation"] and e["source"] in all_ids and e["target"] in all_ids for e in near["edges"]))

    def test_small_sync_batches_converge_and_unchanged_cycle_does_not_duplicate(self):
        self.seed()
        first = sync_graph(self.settings, max_inputs=1)
        self.assertEqual(first["status"], "partial")
        self.assertTrue(first["next_key"])
        result = self.sync(limit=3)
        self.assertEqual(result["missing_or_stale_inputs"], 0)
        before = self.pages(limit=50)
        unchanged = self.sync()
        self.assertEqual(unchanged["changed"], 0)
        self.assertGreater(unchanged["unchanged"], 0)
        self.assertEqual(before, self.pages(limit=50))

    def test_keyset_pages_reach_nodes_outside_initial_visual_cap(self):
        for i in range(260):
            (self.settings.vault_root / f"Node-{i:03}.md").write_text(f"# Node {i}\n\n[[Node-000]]\n", encoding="utf-8")
        index_all(self.settings); self.sync()
        nodes = self.pages(kind="document", limit=17)
        self.assertGreaterEqual(len(nodes), 264)
        self.assertEqual(len(nodes), len({n["id"] for n in nodes}))
        self.assertTrue(any(n["title"] == "Node 259" for n in nodes))
        anchor = next(n for n in nodes if n["title"] == "Node 0")
        cursor, ids = None, set()
        for _ in range(100):
            page = graph_neighbors(self.settings, anchor["id"], limit=11, cursor=cursor)
            ids.update(e["id"] for e in page["edges"])
            if not page["has_more"]:
                break
            cursor = page["next_cursor"]
        self.assertGreaterEqual(len(ids), 259)

    def test_exclusions_and_missing_projects_apply_without_sync(self):
        self.seed(); self.sync()
        self.settings.raw["excluded_projects"] = [str(self.beta)]
        nodes = self.pages(limit=50)
        self.assertFalse(any(n["title"] == self.beta.name for n in nodes))
        with self.assertRaises(ValueError):
            graph_page(self.settings, project=str(self.beta))
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE projects SET status='missing' WHERE name=?", (self.alpha.name,))
        self.assertEqual(graph_page(self.settings, kind="project")["nodes"], [])

    def test_project_scope_keeps_other_private_nodes_out_and_only_lists_direct_public_references(self):
        self.seed(); self.sync()
        nodes = self.pages(project=str(self.alpha), limit=50)
        self.assertFalse(any(n["title"] == self.beta.name for n in nodes))
        self.assertTrue(any(n["id"] == "vulnerability:" + CVE for n in nodes))
        self.assertTrue(any(n["title"] == "Graph Ñ" for n in nodes))
        global_nodes = self.pages(kind="project", limit=50)
        beta = next(n for n in global_nodes if n["title"] == self.beta.name)
        self.assertFalse(graph_neighbors(self.settings, beta["id"], project=str(self.alpha))["anchor_visible"])

    def test_cursors_bind_filters_permissions_generation_and_api_operation(self):
        self.seed(); self.sync()
        page = graph_page(self.settings, limit=1)
        cursor = page["next_cursor"]
        with self.assertRaisesRegex(ValueError, "scope_mismatch"):
            graph_page(self.settings, limit=1, query="different", cursor=cursor)
        with self.assertRaisesRegex(ValueError, "scope_mismatch"):
            graph_neighbors(self.settings, page["nodes"][0]["id"], limit=1, cursor=cursor)
        self.settings.raw["excluded_projects"] = [self.beta.name]
        with self.assertRaisesRegex(ValueError, "scope_mismatch"):
            graph_page(self.settings, limit=1, cursor=cursor)

    def test_upstream_changes_are_hidden_until_explicit_sync_and_deleted_sources_retire(self):
        self.seed(); self.sync()
        node = graph_page(self.settings, kind="document", query="Alpha fixture")["nodes"][0]
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE documents SET title='Changed fixture title' WHERE document_id=?", (node["data"]["document_id"],))
        stale = graph_page(self.settings, query="Alpha fixture")
        self.assertEqual(stale["nodes"], [])
        self.assertTrue(stale["coverage"]["requires_sync"])
        self.sync()
        self.assertTrue(graph_page(self.settings, query="Changed fixture title")["nodes"])
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE documents SET status='deleted' WHERE document_id=?", (node["data"]["document_id"],))
        self.assertFalse(graph_neighbors(self.settings, node["id"])["anchor_visible"])
        retired = self.sync()
        self.assertGreaterEqual(retired["retired"], 1)

    def test_reviewed_solutions_revalidate_source_and_evidence_on_read(self):
        self.seed(); self.sync()
        solution = graph_page(self.settings, kind="solution", project=str(self.alpha))["nodes"][0]
        with Database(self.settings.database_path, read_only=True) as db:
            path = Path(db.one("SELECT absolute_path FROM documents WHERE document_id=?", (solution["data"]["document_id"],))[0])
        path.write_text(path.read_text(encoding="utf-8") + "\nUnindexed change\n", encoding="utf-8")
        page = graph_page(self.settings, kind="solution", project=str(self.alpha))
        self.assertEqual(page["nodes"], [])
        self.assertEqual(page["coverage"]["unverifiable_solutions_skipped"], 0)
        self.assertTrue(page['coverage']['requires_sync'])

    def test_saved_inventory_candidates_and_review_claims_never_become_confirmed_vulnerability(self):
        self.seed(); self.sync()
        dependency = graph_page(self.settings, kind="dependency", project=str(self.alpha))["nodes"][0]
        near = graph_neighbors(self.settings, dependency["id"], project=str(self.alpha), limit=200)
        candidate = next(e for e in near["edges"] if e["relation_type"] == "saved_inventory_applicability_candidate")
        self.assertEqual(candidate["kind"], "inferred")
        self.assertIn("not_current_or_installed", candidate["data"]["validation"])
        claim = next(e for e in near["edges"] if e["relation_type"] == "review_claim_about_version")
        self.assertEqual(claim["kind"], "reviewed_claim")
        self.assertFalse(any(e["relation_type"] == "project_is_vulnerable" for e in near["edges"]))

    def test_risk_date_source_category_and_unicode_filters(self):
        self.seed(); self.sync()
        page = graph_page(self.settings, risk="known_exploited", since="2026-10-01", until="2026-10-31", source="nvd")
        self.assertEqual([n["id"] for n in page["nodes"]], ["vulnerability:" + CVE])
        self.assertEqual(graph_page(self.settings, risk="high_prediction")["nodes"], [])
        self.assertTrue(graph_page(self.settings, query="GRAPH ñ")["nodes"])
        self.assertEqual(graph_page(self.settings, query="%_wildcard")["nodes"], [])
        self.assertTrue(graph_page(self.settings, kind="control", category="NIST")["nodes"])

    def test_errors_limits_zero_reads_and_no_remote_calls(self):
        self.seed(); self.sync()
        with patch("socket.socket", side_effect=AssertionError("Network prohibited")):
            self.assertEqual(graph_page(self.settings, limit=0)["nodes"], [])
            self.assertTrue(graph_page(self.settings, kind="project")["nodes"])
        for kwargs in ({"limit": True}, {"limit": 201}, {"kind": []}, {"risk": "safe"}, {"since": "bad"},
                       {"since": "2026-10-20", "until": "2026-10-01"}, {"query": []}, {"cursor": "malformed!"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                graph_page(self.settings, **kwargs)

    def test_atomic_failure_retains_previous_projection_and_safe_originals(self):
        self.seed(); self.sync()
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE projects SET last_seen='2026-10-17T00:00:00Z'")
            db.execute("CREATE TRIGGER kg_abort_fixture BEFORE INSERT ON kg_nodes BEGIN SELECT RAISE(ABORT,'fixture abort'); END")
            before = db.one("SELECT count(*) FROM kg_nodes")[0]
        with self.assertRaises(sqlite3.IntegrityError):
            sync_graph(self.settings)
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(db.one("SELECT count(*) FROM kg_nodes")[0], before)
            self.assertEqual(db.one("PRAGMA integrity_check")[0], "ok")

    def test_backup_restore_and_schema_checksum(self):
        self.seed(); self.sync()
        backup, restored = self.settings.data_dir / "kg-backup.db", self.settings.data_dir / "kg-restored.db"
        with Database(self.settings.database_path, read_only=True) as db:
            db.backup(backup)
        restore_database(backup, restored)
        settings = Settings(self.root, {**self.settings.raw, "database_path": str(restored)})
        self.assertTrue(graph_page(settings)["nodes"])
        with Database(restored) as db:
            db.execute("UPDATE kg_migrations SET checksum='invalid'")
        with self.assertRaisesRegex(ValueError, "migration"):
            graph_page(settings)

    def test_http_and_cli_preserve_contract_and_do_not_implicitly_write(self):
        self.seed()
        class Handler(RabanitoHandler):
            settings = self.settings
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        headers = {"Origin": origin, "Content-Type": "application/json"}
        def post(path, value, extra=None):
            return urlopen(Request(origin + path, data=json.dumps(value).encode(), headers=headers | (extra or {})))
        try:
            with post("/api/knowledge-graph", {}) as response:
                self.assertFalse(json.load(response)["projection_available"])
            with post("/api/knowledge-graph/sync", {"confirm_graph_sync": True, "max_inputs": 5000}) as response:
                self.assertEqual(json.load(response)["status"], "ok")
            with post("/api/knowledge-graph", {"kind": "project"}) as response:
                project = json.load(response)["nodes"][0]
            with post("/api/knowledge-graph/neighbors", {"id": project["id"], "project_id": project["contributor_project_id"]}) as response:
                self.assertTrue(json.load(response)["anchor_visible"])
            for path, payload, extra, status in (("/api/knowledge-graph/sync", {}, {}, 400),
                    ("/api/knowledge-graph", {"limit": None}, {}, 400), ("/api/knowledge-graph", {"unknown": 1}, {}, 400),
                    ("/api/knowledge-graph", {}, {"Origin": "https://external.invalid"}, 403)):
                with self.subTest(path=path), self.assertRaises(HTTPError) as caught:
                    post(path, payload, extra).close()
                self.assertEqual(caught.exception.code, status); caught.exception.close()
            with self.assertRaises(HTTPError) as caught:
                urlopen(origin + "/api/knowledge-graph").close()
            self.assertEqual(caught.exception.code, 405); caught.exception.close()
            duplicate = Request(origin + "/api/knowledge-graph", data=b'{"limit":1,"limit":2}', headers=headers)
            with self.assertRaises(HTTPError) as caught:
                urlopen(duplicate).close()
            self.assertEqual(caught.exception.code, 400); caught.exception.close()
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)
        config = self.root / "settings.json"
        config.write_text(json.dumps({**self.settings.raw, "project_root": str(self.root)}), encoding="utf-8")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            main(["--config", str(config), "knowledge-graph", "page", "--kind", "project"])
        self.assertTrue(json.loads(output.getvalue())["nodes"])

    def test_suggestions_are_opt_in_for_project_roots_and_neighbor_expansion(self):
        self.seed()
        (self.settings.vault_root / "Only suggested.md").write_text("# Only suggested\n", encoding="utf-8")
        index_all(self.settings)
        with Database(self.settings.database_path) as db:
            left = db.one("SELECT document_id FROM documents WHERE title='Alpha fixture'")[0]
            right = db.one("SELECT document_id FROM documents WHERE title='Only suggested'")[0]
            db.execute("INSERT INTO link_suggestions(source_document_id,target_document_id,score,reason,status,created_at) VALUES (?,?,.7,'Synthetic candidate','suggested',?)",
                       (left, right, NOW.isoformat()))
        self.sync()
        self.assertFalse(any(n["id"] == f"document:{right}" for n in self.pages(project=str(self.alpha), limit=100)))
        self.assertTrue(any(n["id"] == f"document:{right}" for n in self.pages(project=str(self.alpha), suggestions=True, limit=100)))
        default = graph_neighbors(self.settings, f"document:{left}", limit=200)
        included = graph_neighbors(self.settings, f"document:{left}", suggestions=True, limit=200)
        self.assertFalse(any(e["kind"] == "suggested" for e in default["edges"]))
        self.assertTrue(any(e["kind"] == "suggested" for e in included["edges"]))

    def test_changed_source_root_immediately_hides_old_cached_documents(self):
        self.seed(); self.sync()
        replacement = self.root / "new-vault"
        replacement.mkdir()
        self.settings.raw["vault_root"] = str(replacement)
        self.assertEqual(graph_page(self.settings, source="obsidian")["nodes"], [])
        self.assertTrue(graph_page(self.settings)["coverage"]["requires_sync"])

    def test_new_path_exclusions_hide_documents_and_saved_inventory_without_reindex(self):
        self.seed(); self.sync()
        self.settings.raw["source_policy"]["obsidian"].setdefault("exclude_names", []).append("Graph Ñ.md")
        self.settings.raw["source_policy"]["projects"].setdefault("exclude_names", []).append("inventory.json")
        self.assertEqual(graph_page(self.settings, source="obsidian", query="Graph Ñ")["nodes"], [])
        self.assertEqual(graph_page(self.settings, kind="snapshot")["nodes"], [])
        self.assertEqual(graph_page(self.settings, kind="review")["nodes"], [])

    def test_projection_engine_upgrade_hides_old_transform_and_resyncs_without_changing_node_ids(self):
        from rabanito.knowledge_graph import store
        self.seed(); self.sync()
        original = {n["id"] for n in self.pages(limit=100)}
        with patch.object(store, "ENGINE_VERSION", store.ENGINE_VERSION + 1):
            old = graph_page(self.settings)
            self.assertEqual(old["nodes"], [])
            self.assertTrue(old["coverage"]["requires_sync"])
            self.sync()
            self.assertEqual({n["id"] for n in self.pages(limit=100)}, original)

    def test_withdrawn_advisories_are_retained_but_not_ranked_as_published_risk(self):
        payload = osv()
        payload["withdrawn"] = "2026-10-16T12:00:00Z"
        sync_source(self.settings, "osv", [GHSA], client=FakeClient([payload]), now=NOW)
        self.sync()
        node = graph_page(self.settings, kind="vulnerability")["nodes"][0]
        self.assertEqual(node["data"]["record_status"], "withdrawn")
        self.assertIsNone(node["data"]["risk"])
        self.assertEqual(graph_page(self.settings, risk="published")["nodes"], [])

    def test_partial_cycle_restarts_after_upstream_generation_changes(self):
        self.seed()
        first = sync_graph(self.settings, max_inputs=1)
        self.assertEqual(first["next_key"], "document:1")
        (self.alpha / "README.md").write_text("# New upstream state\n", encoding="utf-8")
        index_all(self.settings)
        second = sync_graph(self.settings, max_inputs=1)
        self.assertEqual(second["next_key"], "document:1")
        self.assertEqual(second["changed"], 1)
        self.sync()
        self.assertTrue(graph_page(self.settings, query="New upstream state")["nodes"])

    def test_rejected_input_remains_partial_without_hiding_the_error_or_original(self):
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE documents SET title=? WHERE document_id=1", ("password=" + "synthetic_fixture_value",))
        result = sync_graph(self.settings)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["errors"], 1)
        self.assertTrue(graph_page(self.settings)["coverage"]["requires_sync"])
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(db.one("SELECT count(*) FROM documents")[0], 4)

    def test_concurrent_sync_resumes_the_same_cycle_without_overwriting_progress(self):
        from concurrent.futures import ThreadPoolExecutor
        self.seed()
        with ThreadPoolExecutor(max_workers=2) as pool:
            runs = list(pool.map(lambda _: sync_graph(self.settings, max_inputs=1), range(2)))
        self.assertEqual(len({r["next_key"] for r in runs}), 2)
        self.sync()
        self.assertFalse(graph_page(self.settings)["coverage"]["requires_sync"])

    def test_large_public_graph_queries_use_one_connection_and_reach_late_roots(self):
        total = 2050
        with Database(self.settings.database_path) as db:
            ensure_schema(db)
            for offset in range(0, total, 500):
                ids = tuple(f"CVE-2099-{10000+i}" for i in range(offset, min(offset+500,total)))
                records = normalize_nvd(nvd(ids), "https://services.nvd.nist.gov/rest/json/cves/2.0")
                db.execute("BEGIN IMMEDIATE")
                apply_records(db, "nvd", records, [], retrieved_at=NOW.isoformat())
                db.commit()
        self.sync()
        from rabanito.knowledge_graph import query as reader
        opened, statements = [], [0]
        def connection(*args, **kwargs):
            db = Database(*args, **kwargs)
            opened.append(1)
            db.connection.set_trace_callback(lambda _: statements.__setitem__(0, statements[0]+1))
            return db
        with patch.object(reader, "Database", side_effect=connection):
            page = graph_page(self.settings, kind="vulnerability", query="CVE-2099-12049", limit=5)
        self.assertEqual([n["id"] for n in page["nodes"]], ["vulnerability:CVE-2099-12049"])
        self.assertEqual(len(opened), 1)
        self.assertLess(statements[0], 45)
        roots = self.pages(kind="vulnerability", limit=200)
        self.assertEqual(len(roots), total)

    def test_warm_proof_is_invalidated_by_committed_native_change(self):
        self.sync()
        first = graph_page(self.settings, limit=1)
        warmed = graph_page(self.settings, limit=1)
        self.assertEqual(first["coverage"]["source_validation"], "live_fingerprint_scan")
        self.assertEqual(warmed["coverage"]["source_validation"], "epoch_validated_fingerprints")
        with Database(self.settings.database_path) as db:
            before = db.one("SELECT value FROM kg_epoch")[0]
            db.execute("UPDATE documents SET title='Committed native change' WHERE document_id=1")
            self.assertEqual(db.one("SELECT value FROM kg_epoch")[0], before + 1)
        changed = graph_page(self.settings, limit=1)
        self.assertEqual(changed["coverage"]["source_validation"], "live_fingerprint_scan")
        self.assertTrue(changed["coverage"]["requires_sync"])
        self.assertFalse(any(n["id"] == "document:1" for n in self.pages(limit=50)))
        with self.assertRaisesRegex(ValueError, "scope_mismatch"):
            graph_page(self.settings, limit=1, cursor=warmed["next_cursor"])
        self.sync()
        self.assertTrue(graph_page(self.settings, query="Committed native change")["nodes"])

    def test_source_rollback_also_rolls_back_epoch(self):
        self.sync()
        graph_page(self.settings)
        with Database(self.settings.database_path) as db:
            before = db.one("SELECT value FROM kg_epoch")[0]
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE documents SET title='Never committed' WHERE document_id=1")
            self.assertGreater(db.one("SELECT value FROM kg_epoch")[0], before)
            db.connection.rollback()
            self.assertEqual(db.one("SELECT value FROM kg_epoch")[0], before)
        result = graph_page(self.settings)
        self.assertFalse(result["coverage"]["requires_sync"])
        self.assertEqual(graph_page(self.settings, query="Never committed")["nodes"], [])

    def test_missing_watcher_disables_proof_and_sync_repairs_it(self):
        self.sync()
        graph_page(self.settings); graph_page(self.settings)
        with Database(self.settings.database_path) as db:
            db.execute("DROP TRIGGER kg_watch_documents_update")
            db.execute("UPDATE documents SET title='Changed without watcher' WHERE document_id=1")
        result = graph_page(self.settings)
        self.assertEqual(result["coverage"]["source_validation"], "live_fingerprint_scan")
        self.assertFalse(result["coverage"]["watcher_coverage_complete"])
        self.assertTrue(result["coverage"]["requires_sync"])
        self.assertFalse(any(n["id"] == "document:1" for n in result["nodes"]))
        self.sync()
        repaired = graph_page(self.settings)
        self.assertTrue(repaired["coverage"]["watcher_coverage_complete"])
        self.assertFalse(repaired["coverage"]["requires_sync"])

    def test_modified_watcher_is_not_silently_replaced(self):
        self.sync()
        with Database(self.settings.database_path) as db:
            db.execute("DROP TRIGGER kg_watch_documents_update")
            db.execute("CREATE TRIGGER kg_watch_documents_update AFTER UPDATE ON documents BEGIN SELECT 1; END")
        self.assertFalse(graph_page(self.settings)["coverage"]["watcher_coverage_complete"])
        with self.assertRaisesRegex(ValueError, "modified_knowledge_graph_watcher"):
            sync_graph(self.settings)
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertIn("SELECT 1", db.one("SELECT sql FROM sqlite_master WHERE name='kg_watch_documents_update'")[0])

    def test_new_native_namespace_is_readable_but_not_memoized_until_explicit_sync(self):
        self.sync()
        graph_page(self.settings)
        sync_source(self.settings, "nvd", [CVE], client=FakeClient([nvd()]), now=NOW)
        before = graph_page(self.settings)
        self.assertTrue(before["coverage"]["requires_sync"])
        self.assertFalse(before["coverage"]["watcher_coverage_complete"])
        self.sync()
        graph_page(self.settings)
        warmed = graph_page(self.settings, kind="vulnerability")
        self.assertEqual(warmed["coverage"]["source_validation"], "epoch_validated_fingerprints")
        self.assertEqual(len(warmed["nodes"]), 1)

    def test_proof_is_bounded_and_not_shared_between_database_copies(self):
        from rabanito.knowledge_graph import query as reader
        self.sync()
        graph_page(self.settings); graph_page(self.settings)
        copied = self.settings.data_dir / "proof-copy.db"
        with Database(self.settings.database_path, read_only=True) as db:
            db.backup(copied)
        other = Settings(self.root, {**self.settings.raw, "database_path": str(copied)})
        self.assertEqual(graph_page(other)["coverage"]["source_validation"], "live_fingerprint_scan")
        self.assertEqual(graph_page(other)["coverage"]["source_validation"], "epoch_validated_fingerprints")
        with reader._PROOF_LOCK:
            self.assertLessEqual(len(reader._CLEAN_PROOFS), 16)
            self.assertTrue(all(len(k) == 64 and v is True for k, v in reader._CLEAN_PROOFS.items()))

    def test_unknown_source_schema_is_rejected_on_read_and_sync(self):
        self.seed(); self.sync()
        graph_page(self.settings); graph_page(self.settings)
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE security_migrations SET checksum='invalid'")
        for action in (graph_page, sync_graph):
            with self.subTest(action=action.__name__), self.assertRaisesRegex(ValueError, "source_migration"):
                action(self.settings)

    def test_alias_relationship_changes_are_incremental_without_record_text_change(self):
        self.seed(); self.sync()
        anchor = "observation:nvd:" + CVE
        self.assertTrue(graph_neighbors(self.settings, anchor)["edges"])
        with Database(self.settings.database_path) as db:
            db.execute("DELETE FROM cyber_aliases WHERE source='nvd' AND source_id=?", (CVE,))
        self.assertFalse(graph_neighbors(self.settings, anchor)["anchor_visible"])
        result = self.sync()
        self.assertGreater(result["changed"], 0)
        remaining = graph_neighbors(self.settings, anchor)["edges"]
        self.assertFalse(any(e["relation_type"] == "observation_references_identifier_not_equivalence" for e in remaining))
        self.assertTrue(any(e["relation_type"] == "provider_product_or_configuration_condition" for e in remaining))

    def test_security_link_target_changes_rebuild_only_affected_assertions(self):
        self.seed(); self.sync()
        doc = graph_page(self.settings, kind="document", query="Alpha fixture")["nodes"][0]
        original = graph_neighbors(self.settings, doc["id"], limit=200)
        citation_edges = [e for e in original["edges"] if e["relation_type"] == "cites_security_publication_not_compliance"]
        self.assertTrue(citation_edges)
        target = citation_edges[0]["target"].removeprefix("security:")
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE security_entries SET active=0 WHERE entry_id=?", (target,))
        self.sync()
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(db.one("SELECT count(*) FROM kg_edges WHERE source=? AND target=? AND relation='cites_security_publication_not_compliance'", (doc["id"], "security:" + target))[0], 0)

    def test_reviewed_evidence_path_map_changes_update_relationship_fingerprint(self):
        self.seed(); self.sync()
        with Database(self.settings.database_path) as db:
            memory = db.one("SELECT document_id FROM documents WHERE source_kind='internal' AND json_extract(frontmatter_json,'$.kind')='verified-memory' ORDER BY document_id LIMIT 1")[0]
            evidence = db.one("SELECT document_id FROM documents WHERE source_kind='obsidian' AND title='Graph Ñ'")[0]
            before = db.one("SELECT fingerprint FROM kg_inputs WHERE input_key=?", (f"document:{memory}",))[0]
            db.execute("UPDATE documents SET status='deleted' WHERE document_id=?", (evidence,))
        self.sync()
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertNotEqual(db.one("SELECT fingerprint FROM kg_inputs WHERE input_key=?", (f"document:{memory}",))[0], before)
        docs = graph_page(self.settings, kind="document", project=str(self.alpha))["nodes"]
        for node in docs:
            if node["source"] == "projects":
                self.assertTrue(node["citation"].startswith("projects:" + str(node["contributor_project_id"]) + ":"))
