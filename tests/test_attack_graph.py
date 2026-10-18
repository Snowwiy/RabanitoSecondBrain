from __future__ import annotations

import copy
import io
import json
import sqlite3
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from rabanito.attack_capture import capture_release
from rabanito.attack_store import index_capture
from rabanito.cli import main
from rabanito.config import Settings
from rabanito.db import Database, restore_database
from rabanito.knowledge_graph import graph_neighbors, graph_page, sync_graph
from rabanito.knowledge_graph import store
from rabanito.knowledge_graph.attack import node_id
from tests.attack_fixture import COMMIT, DOMAIN, Opener, blob, bundle, sid
from tests import test_coding_retrieval as fixtures
from tests import test_cyber as http_fixtures


class AttackGraphTests(unittest.TestCase):
    setUp = fixtures.CodingMemoryTests.setUp
    tearDown = fixtures.CodingMemoryTests.tearDown
    server = http_fixtures.CyberTests.server

    def publish(self, value=None, commit=COMMIT, domain=DOMAIN):
        value = copy.deepcopy(value if value is not None else bundle())
        for item in value["objects"]:
            item["x_mitre_domains"] = [domain]
        value["objects"][0]["name"] = {"enterprise-attack": "Enterprise ATT&CK", "mobile-attack": "Mobile ATT&CK"}[domain]
        value["objects"][0]["x_mitre_contents"] = [{"object_ref": x["id"], "object_modified": x["modified"]} for x in value["objects"][1:]]
        raw = json.dumps(value, ensure_ascii=False).encode()
        result = capture_release(self.settings, domain, value["objects"][0]["x_mitre_version"], commit, blob(raw), len(raw), opener=Opener(raw))
        return index_capture(self.settings, result["manifest"])

    def sync(self, limit=5000):
        totals = {k: 0 for k in ("examined", "changed", "unchanged", "retired", "errors")}
        for _ in range(100):
            result = sync_graph(self.settings, max_inputs=limit)
            for key in totals:
                totals[key] += result[key]
            self.assertEqual(result["errors"], 0)
            if result["status"] == "ok":
                return totals
        self.fail("Graph did not converge within the fixture budget")

    def page(self, **options):
        return graph_page(self.settings, source="attack", **options)

    def test_typed_public_nodes_citations_and_no_false_project_or_cve_edges(self):
        published = self.publish()
        self.sync()
        page = self.page(include_inactive=True)
        self.assertEqual({n["kind"] for n in page["nodes"]}, {"attack_collection", "attack_technique"})
        self.assertEqual(len(page["nodes"]), 3)
        for node in page["nodes"]:
            self.assertIsNone(node["contributor_project_id"])
            self.assertEqual(node["data"]["release_id"], published["release_id"])
            self.assertEqual(node["data"]["privacy"], "public")
            self.assertEqual(node["category"], DOMAIN)
            self.assertIn(COMMIT, node["citation"])
        self.assertNotIn(str(self.root), json.dumps(page))
        nearby = graph_neighbors(self.settings, node_id(DOMAIN, sid("attack-pattern", 1)), include_inactive=True)
        self.assertTrue(all(e["validation"] == "source_documented" for e in nearby["edges"]))
        self.assertTrue(all(e["source"].startswith("attack:") and e["target"].startswith("attack:") for e in nearby["edges"]))
        self.assertNotIn("vulnerability", {n["kind"] for n in nearby["nodes"]})

    def test_default_hides_revoked_and_deprecated_and_filter_must_be_boolean(self):
        data = bundle()
        data["objects"][2].update(revoked=False, x_mitre_deprecated=True)
        self.publish(data)
        self.sync()
        self.assertEqual(len(self.page(kind="attack_technique")["nodes"]), 1)
        old = node_id(DOMAIN, sid("attack-pattern", 2))
        self.assertFalse(graph_neighbors(self.settings, old)["anchor_visible"])
        result = graph_neighbors(self.settings, old, include_inactive=True)
        self.assertTrue(result["anchor_visible"])
        self.assertTrue(result["nodes"][0]["data"]["deprecated"])
        for value in (None, 1, "true", []):
            with self.assertRaises(ValueError):
                self.page(include_inactive=value)

    def test_revoked_sro_with_current_endpoints_is_hidden_by_default(self):
        data = bundle()
        data["objects"][2]["revoked"] = False
        data["objects"][3].update(revoked=True, relationship_type="uses")
        self.publish(data)
        self.sync()
        anchor = node_id(DOMAIN, sid("attack-pattern", 1))
        self.assertFalse(any(e["relation_type"]=="uses" for e in graph_neighbors(self.settings, anchor)["edges"]))
        full = graph_neighbors(self.settings, anchor, include_inactive=True)
        edge = next(e for e in full["edges"] if e["relation_type"]=="uses")
        self.assertTrue(edge["data"]["revoked"])
        self.assertFalse(edge["data"]["source_state"]["revoked"])

    def test_sro_direction_identity_and_endpoint_state_are_preserved(self):
        self.publish()
        self.sync()
        anchor = node_id(DOMAIN, sid("attack-pattern", 1))
        result = graph_neighbors(self.settings, anchor, include_inactive=True)
        sro = next(e for e in result["edges"] if e["relation_type"] == "revoked-by")
        self.assertEqual(sro["source"], node_id(DOMAIN, sid("attack-pattern", 2)))
        self.assertEqual(sro["target"], anchor)
        self.assertEqual(sro["data"]["stix_id"], sid("relationship", 3))
        self.assertTrue(sro["data"]["source_state"]["revoked"])
        self.assertEqual(sro["data"]["locator"], "/objects/3")

    def test_same_external_id_does_not_merge_stix_objects_or_domains(self):
        data = bundle()
        data["objects"][2]["external_references"] = copy.deepcopy(data["objects"][1]["external_references"])
        self.publish(data)
        self.publish(data, domain="mobile-attack")
        self.sync()
        nodes = self.page(kind="attack_technique", query="T1000", include_inactive=True)["nodes"]
        self.assertEqual(len(nodes), 4)
        self.assertEqual(len({n["id"] for n in nodes}), 4)
        self.assertEqual(len(self.page(kind="attack_technique", category=DOMAIN, include_inactive=True)["nodes"]), 2)

    def test_no_rewrite_unchanged_cycle_and_small_batch_resume(self):
        self.publish()
        first = sync_graph(self.settings, max_inputs=1)
        self.assertEqual(first["status"], "partial")
        self.assertTrue(first["next_key"])
        self.sync(limit=2)
        with Database(self.settings.database_path, read_only=True) as db:
            counts = tuple(db.one("SELECT (SELECT count(*) FROM kg_nodes),(SELECT count(*) FROM kg_edges)"))
        next_cycle = self.sync(limit=2)
        self.assertEqual(next_cycle["changed"], 0)
        self.assertEqual(next_cycle["retired"], 0)
        self.assertFalse(self.page()["coverage"]["requires_sync"])
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(tuple(db.one("SELECT (SELECT count(*) FROM kg_nodes),(SELECT count(*) FROM kg_edges)")), counts)

    def test_new_commit_changes_provenance_but_node_and_sro_ids_stay_stable(self):
        self.publish()
        self.sync()
        anchor = node_id(DOMAIN, sid("attack-pattern", 1))
        before = graph_neighbors(self.settings, anchor, include_inactive=True)
        self.publish(commit="b"*40)
        stale = self.page(include_inactive=True)
        self.assertTrue(stale["coverage"]["requires_sync"])
        self.assertEqual(stale["nodes"], [])
        self.sync()
        after = graph_neighbors(self.settings, anchor, include_inactive=True)
        self.assertEqual({n["id"] for n in before["nodes"]}, {n["id"] for n in after["nodes"]})
        self.assertEqual({e["id"] for e in before["edges"]}, {e["id"] for e in after["edges"]})
        self.assertTrue(all("b"*40 in n["citation"] for n in after["nodes"]))

    def test_removed_head_members_hidden_before_sync_and_retired_after_complete_cycle(self):
        self.publish()
        self.sync()
        absent = bundle()
        absent["objects"][0].update(x_mitre_version="20.1", modified="2026-10-14T00:00:00Z")
        absent["objects"] = [absent["objects"][0], absent["objects"][2]]
        self.publish(absent, "b"*40)
        self.assertFalse(graph_neighbors(self.settings, node_id(DOMAIN, sid("attack-pattern", 1)), include_inactive=True)["anchor_visible"])
        totals = self.sync(limit=1)
        self.assertEqual(totals["retired"], 2)
        self.assertEqual(self.page(kind="attack_technique", include_inactive=True)["nodes"][0]["data"]["stix_id"], sid("attack-pattern", 2))

    def test_changed_endpoint_invalidates_sro_descriptor_and_old_cursor(self):
        self.publish()
        self.sync()
        first = self.page(include_inactive=True, limit=1)
        graph_page(self.settings); graph_page(self.settings)
        changed = bundle()
        changed["objects"][0].update(x_mitre_version="20.1", modified="2026-10-14T00:00:00Z")
        changed["objects"][2].update(revoked=False, modified="2026-10-14T00:00:00Z")
        self.publish(changed, "b"*40)
        with self.assertRaisesRegex(ValueError, "scope_mismatch"):
            self.page(include_inactive=True, limit=1, cursor=first["next_cursor"])
        self.sync()
        near = graph_neighbors(self.settings, node_id(DOMAIN, sid("attack-pattern", 1)))
        edge = next(e for e in near["edges"] if e["relation_type"]=="revoked-by")
        self.assertFalse(edge["data"]["source_state"]["revoked"])

    def test_query_flags_bind_cursor_scope_and_pages_do_not_overlap(self):
        self.publish()
        self.sync()
        first = self.page(include_inactive=True, limit=1)
        second = self.page(include_inactive=True, limit=1, cursor=first["next_cursor"])
        self.assertFalse({n["id"] for n in first["nodes"]} & {n["id"] for n in second["nodes"]})
        with self.assertRaisesRegex(ValueError, "scope_mismatch"):
            self.page(include_inactive=False, limit=1, cursor=first["next_cursor"])

    def test_graph_migration_checks_attack_schema_on_reads_and_sync(self):
        self.publish()
        self.sync()
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE attack_migrations SET checksum='modified'")
        for action in (lambda: self.page(), lambda: self.sync()):
            with self.assertRaisesRegex(ValueError, "source_migration"):
                action()

    def test_namespace_appears_without_implicit_writes_then_sync_installs_watchers(self):
        self.sync()
        self.publish()
        before = self.page()
        self.assertFalse(before["coverage"]["watcher_coverage_complete"])
        self.assertTrue(before["coverage"]["requires_sync"])
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertIsNone(db.one("SELECT 1 FROM sqlite_master WHERE name='kg_watch_attack_heads_update'"))
        self.sync()
        graph_page(self.settings)
        warmed = self.page()
        self.assertTrue(warmed["coverage"]["watcher_coverage_complete"])
        self.assertEqual(warmed["coverage"]["source_validation"], "epoch_validated_fingerprints")

    def test_missing_or_altered_attack_watcher_does_not_allow_memoized_stale_data(self):
        self.publish()
        self.sync()
        graph_page(self.settings); graph_page(self.settings)
        with Database(self.settings.database_path) as db:
            db.execute("DROP TRIGGER kg_watch_attack_members_update")
        self.assertFalse(self.page()["coverage"]["watcher_coverage_complete"])
        self.sync()
        self.assertTrue(self.page()["coverage"]["watcher_coverage_complete"])
        with Database(self.settings.database_path) as db:
            db.execute("DROP TRIGGER kg_watch_attack_heads_update")
            db.execute("CREATE TRIGGER kg_watch_attack_heads_update AFTER UPDATE ON attack_heads BEGIN SELECT 1; END")
        with self.assertRaisesRegex(ValueError, "modified_knowledge_graph_watcher"):
            self.sync()

    def test_attack_source_transaction_rollback_rolls_back_epoch(self):
        self.publish()
        self.sync()
        with Database(self.settings.database_path) as db:
            epoch = db.one("SELECT value FROM kg_epoch")[0]
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE attack_heads SET release_id=release_id")
            self.assertEqual(db.one("SELECT value FROM kg_epoch")[0], epoch+1)
            db.connection.rollback()
            self.assertEqual(db.one("SELECT value FROM kg_epoch")[0], epoch)

    def test_project_filter_does_not_invent_associations_to_public_attack(self):
        self.publish()
        self.sync()
        page = self.page(project=str(self.alpha))
        self.assertEqual(page["nodes"], [])
        anchor = node_id(DOMAIN, sid("attack-pattern", 1))
        near = graph_neighbors(self.settings, anchor, project=str(self.beta), include_inactive=True)
        self.assertTrue(near["anchor_visible"])
        self.assertTrue(all(n["contributor_project_id"] is None for n in near["nodes"]))
        self.assertTrue(all(e["source"].startswith("attack:") and e["target"].startswith("attack:") for e in near["edges"]))

    def test_restore_preserves_graph_ids_flags_and_source_checksums(self):
        self.publish()
        self.sync()
        before = self.page(include_inactive=True)
        saved, restored = self.root/"graph-saved.db", self.root/"graph-restored.db"
        with Database(self.settings.database_path, read_only=True) as db:
            db.backup(saved)
        restore_database(saved, restored)
        settings = Settings(self.root, {**self.settings.raw, "database_path": str(restored)})
        after = graph_page(settings, source="attack", include_inactive=True)
        self.assertEqual(before["nodes"], after["nodes"])
        with Database(restored, read_only=True) as db:
            store.check_source_schemas(db)
            self.assertTrue(store.schema(db))
            self.assertEqual(db.query("PRAGMA foreign_key_check"), [])

    def test_cli_and_http_flag_and_new_kinds_use_the_existing_graph_contract(self):
        self.publish()
        self.sync()
        output = io.StringIO()
        with patch("rabanito.cli.load_settings", return_value=self.settings), redirect_stdout(output):
            main(["knowledge-graph", "page", "--kind", "attack_technique", "--query", "T1000", "--include-inactive"])
        self.assertEqual(len(json.loads(output.getvalue())["nodes"]), 1)
        with self.server() as origin:
            for payload, expected in (({"kind": "attack_technique", "source": "attack", "include_inactive": True}, 200),
                                      ({"include_inactive": 1}, 400)):
                request = Request(origin+"/api/knowledge-graph", data=json.dumps(payload).encode(),
                                  headers={"Origin": origin, "Content-Type": "application/json"}, method="POST")
                try:
                    with urlopen(request) as response:
                        self.assertEqual(response.status, expected)
                        self.assertEqual(len(json.load(response)["nodes"]), 2)
                except HTTPError as exc:
                    try:
                        self.assertEqual(exc.code, expected)
                    finally:
                        exc.close()
