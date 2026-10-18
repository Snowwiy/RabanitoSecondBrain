from __future__ import annotations

import copy
import io
import json
import socket
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from rabanito.attack_capture import capture_release
from rabanito.attack_store import index_capture, schema
from rabanito.attack_query import search_attack, get_attack_object, attack_context, attack_relations, attack_history, attack_status
from rabanito.cli import main
from rabanito.config import Settings
from rabanito.db import Database, restore_database
from rabanito.indexer import _index_lock
from tests.attack_fixture import DOMAIN, VERSION, COMMIT, Opener, blob, bundle, sid
from tests import test_cyber as http_fixtures


class AttackStoreTests(unittest.TestCase):
    server = http_fixtures.CyberTests.server

    def setUp(self):
        parent = Path(__file__).resolve().parent / ".test-temp"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="attack-index-ñ-", dir=parent)
        self.root = Path(self.temporary.name)
        self.settings = Settings(self.root, {"data_dir": "data", "database_path": "data/brain.db", "knowledge_dir": "knowledge",
                                          "index_lock_timeout_seconds": 0.05})

    def tearDown(self):
        self.temporary.cleanup()

    def capture(self, value=None, commit=COMMIT):
        data = copy.deepcopy(value if value is not None else bundle())
        data["objects"][0]["x_mitre_contents"] = [{"object_ref": x["id"], "object_modified": x["modified"]}
                                                    for x in data["objects"][1:]]
        raw = json.dumps(data, ensure_ascii=False).encode()
        return capture_release(self.settings, DOMAIN, data["objects"][0]["x_mitre_version"], commit, blob(raw), len(raw),
                               opener=Opener(raw))["manifest"]

    def publish(self, value=None, commit=COMMIT):
        return index_capture(self.settings, self.capture(value, commit))

    def next_collection(self, day=14, version="20.1"):
        data = bundle()
        data["objects"][0].update(modified=f"2026-10-{day:02d}T00:00:00Z", x_mitre_version=version)
        return data

    def counts(self):
        with Database(self.settings.database_path, read_only=True) as db:
            return {t: db.one("SELECT count(*) FROM "+t)[0] for t in ("attack_releases", "attack_records", "attack_members", "attack_revisions", "attack_fts")}

    def test_reads_do_not_create_database_or_schema(self):
        self.assertEqual(search_attack(self.settings)["total"], 0)
        self.assertEqual(get_attack_object(self.settings, "T1000")["matches"], [])
        self.assertEqual(attack_status(self.settings)["releases"], 0)
        self.assertEqual(attack_relations(self.settings, sid("attack-pattern", 1))["relations"], [])
        self.assertEqual(attack_history(self.settings, sid("attack-pattern", 1))["revisions"], [])
        self.assertFalse(self.settings.database_path.exists())
        with Database(self.settings.database_path):
            pass
        self.assertEqual(search_attack(self.settings)["total"], 0)
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertFalse(schema(db))

    def test_publication_is_offline_and_reuses_unchanged_revision_and_fts(self):
        manifest = self.capture()
        with patch.object(socket, "socket", side_effect=AssertionError("no network")):
            first = index_capture(self.settings, manifest)
            counts = self.counts()
            with patch("rabanito.attack_store._revision", side_effect=AssertionError("must not rewrite revisions")):
                second = index_capture(self.settings, manifest)
        self.assertEqual((first["added"], second["unchanged"]), (3, 3))
        self.assertTrue(second["content_reused"])
        self.assertEqual(self.counts(), counts)
        self.assertEqual(counts["attack_fts"], 3)

    def test_new_commit_equal_content_adds_membership_not_fts(self):
        self.publish()
        before = self.counts()
        result = self.publish(commit="b"*40)
        self.assertEqual((result["added"], result["modified"], result["unchanged"]), (0, 0, 3))
        self.assertEqual(self.counts()["attack_fts"], before["attack_fts"])
        self.assertEqual(self.counts()["attack_revisions"], before["attack_revisions"])
        self.assertEqual(self.counts()["attack_members"], 6)
        self.assertEqual(get_attack_object(self.settings, "T1000")["matches"][0]["source_commit"], "b"*40)

    def test_incremental_modified_object_and_historical_edition_retrieval(self):
        self.publish()
        data = self.next_collection()
        data["objects"][1].update(description="Changed documented solution", modified="2026-10-14T00:00:00Z")
        result = self.publish(data, "b"*40)
        self.assertEqual((result["modified"], result["unchanged"]), (1, 2))
        self.assertEqual(self.counts()["attack_fts"], 4)
        self.assertEqual(search_attack(self.settings, "Changed")["total"], 1)
        self.assertEqual(search_attack(self.settings, "Changed", release="20.0")["total"], 0)
        old = get_attack_object(self.settings, "T1000", release="20.0")["matches"][0]
        current = get_attack_object(self.settings, "T1000")["matches"][0]
        self.assertNotEqual(old["description"], current["description"])
        self.assertEqual(old["source_commit"], COMMIT)

    def test_retirement_is_observed_absence_not_revocation(self):
        first = self.publish()
        data = self.next_collection()
        data["objects"] = [data["objects"][0], data["objects"][2]]
        result = self.publish(data, "b"*40)
        self.assertEqual((result["retired"], result["unchanged"]), (2, 1))
        self.assertEqual(get_attack_object(self.settings, "T1000")["matches"], [])
        self.assertEqual(get_attack_object(self.settings, "T1000", release="20.0")["total"], 1)
        history = attack_history(self.settings, sid("attack-pattern", 1))
        item = history["revisions"][0]
        self.assertEqual(item["event"], "retired")
        self.assertFalse(item["present"])
        self.assertFalse(item["revoked"])
        self.assertEqual(item["citation"]["release_id"], first["release_id"])
        self.assertNotEqual(item["release_id"], first["release_id"])
        self.assertEqual(attack_status(self.settings)["retired"], 2)

    def test_reactivation_keeps_history_and_does_not_duplicate_identity(self):
        self.publish()
        absent = self.next_collection()
        absent["objects"] = [absent["objects"][0], absent["objects"][2]]
        self.publish(absent, "b"*40)
        result = self.publish(self.next_collection(15, "20.2"), "c"*40)
        self.assertEqual((result["reactivated"], result["unchanged"]), (2, 1))
        self.assertEqual(self.counts()["attack_records"], 3)
        self.assertEqual(attack_history(self.settings, sid("attack-pattern", 1))["total"], 3)
        self.assertEqual(attack_status(self.settings)["retired"], 0)

    def test_source_order_updates_locator_not_content_revision(self):
        first = self.publish()
        before = get_attack_object(self.settings, "T1000")["matches"][0]
        data = bundle()
        data["objects"][1:] = reversed(data["objects"][1:])
        result = self.publish(data, "b"*40)
        after = get_attack_object(self.settings, "T1000")["matches"][0]
        self.assertEqual(result["unchanged"], 3)
        self.assertEqual(before["revision_id"], after["revision_id"])
        self.assertNotEqual(before["locator"], after["locator"])
        self.assertNotEqual(first["release_id"], after["release_id"])

    def test_unprojected_source_change_still_records_revision(self):
        self.publish()
        data = self.next_collection()
        data["objects"][1]["x_mitre_extra"] = "updated source metadata"
        self.assertEqual(self.publish(data, "b"*40)["modified"], 1)
        self.assertEqual(attack_history(self.settings, sid("attack-pattern", 1))["total"], 2)

    def test_invalid_capture_cannot_change_schema_head_history_or_fts(self):
        self.publish()
        counts = self.counts()
        manifest = self.capture(self.next_collection(), "b"*40)
        path = self.settings.data_dir/"attack-captures"/manifest
        metadata = json.loads(path.read_text(encoding="utf-8"))
        (path.parent/metadata["body"]).write_bytes(b"corrupt")
        with self.assertRaises(ValueError):
            index_capture(self.settings, manifest)
        self.assertEqual(self.counts(), counts)

    def test_transaction_rolls_back_release_members_history_and_fts(self):
        self.publish()
        counts = self.counts()
        head = attack_status(self.settings)["head"]
        data = self.next_collection()
        data["objects"][1]["description"] = "changed"
        manifest = self.capture(data, "b"*40)
        with patch("rabanito.attack_store._revision", side_effect=sqlite3.OperationalError("injected write failure")):
            with self.assertRaises(sqlite3.Error):
                index_capture(self.settings, manifest)
        self.assertEqual(self.counts(), counts)
        self.assertEqual(attack_status(self.settings)["head"], head)

    def test_stale_edition_collection_object_and_superseded_release_rejected(self):
        old = self.capture()
        index_capture(self.settings, old)
        data = self.next_collection()
        data["objects"][1]["modified"] = "2026-10-14T00:00:00Z"
        self.publish(data, "b"*40)
        counts = self.counts()
        with self.assertRaisesRegex(ValueError, "stale_attack_collection"):
            index_capture(self.settings, old)
        data = self.next_collection(15, "20.2")
        with self.assertRaisesRegex(ValueError, "stale_attack_object"):
            self.publish(data, "c"*40)
        self.assertEqual(self.counts(), counts)
        data["objects"][0]["modified"] = "2026-10-13T18:00:00Z"
        with self.assertRaisesRegex(ValueError, "stale_attack_collection"):
            self.publish(data, "c"*40)

    def test_equal_version_previous_capture_cannot_be_silently_reactivated(self):
        old = self.capture()
        index_capture(self.settings, old)
        self.publish(commit="b"*40)
        with self.assertRaisesRegex(ValueError, "already_superseded"):
            index_capture(self.settings, old)

    def test_schema_checksum_tampering_fails_read_and_write(self):
        self.publish()
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE attack_migrations SET checksum='changed'")
        with self.assertRaisesRegex(ValueError, "migration"):
            attack_status(self.settings)
        with self.assertRaisesRegex(ValueError, "migration"):
            self.publish()

    def test_existing_database_gets_pre_migration_backup_and_real_restore(self):
        with Database(self.settings.database_path) as db:
            db.execute("INSERT INTO meta VALUES ('fixture','preserved')")
        first = self.publish()
        self.assertTrue(first["migration_backup"])
        pre = self.settings.data_dir/"backups"/first["migration_backup"]
        with Database(pre, read_only=True) as db:
            self.assertFalse(schema(db))
            self.assertEqual(db.one("SELECT value FROM meta WHERE key='fixture'")[0], "preserved")
        saved, restored = self.root/"saved.db", self.root/"restored.db"
        with Database(self.settings.database_path, read_only=True) as db:
            db.backup(saved)
        restore_database(saved, restored)
        settings = Settings(self.root, {**self.settings.raw, "database_path": str(restored)})
        self.assertEqual(get_attack_object(settings, "T1000"), get_attack_object(self.settings, "T1000"))
        with Database(restored) as db:
            self.assertEqual(db.one("PRAGMA integrity_check")[0], "ok")
            self.assertEqual(db.query("PRAGMA foreign_key_check"), [])
            db.execute("INSERT INTO attack_fts(attack_fts) VALUES ('integrity-check')")
            self.assertIn("MITRE", db.one("SELECT license_text FROM attack_releases")[0])

    def test_queries_are_offline_bounded_and_never_execute_stored_text(self):
        self.publish()
        with patch.object(socket, "socket", side_effect=AssertionError("no network")):
            result = search_attack(self.settings, "memoria unicode", limit=1)
            context = attack_context(self.settings, "T1000", max_chars=19)
            self.assertEqual(result["total"], 1)
            self.assertEqual(context["used_chars"], 19)
            self.assertTrue(context["fragments"][0]["text_truncated"])
        fragment = context["fragments"][0]
        self.assertEqual(fragment["source_commit"], COMMIT)
        self.assertEqual(fragment["locator"], "/objects/1")
        self.assertTrue(fragment["untrusted_data"])
        self.assertTrue(fragment["citation"].startswith("https://raw.githubusercontent.com/mitre-attack/"))

    def test_active_filters_and_explicit_id_show_revoked_separately(self):
        self.publish()
        self.assertEqual(search_attack(self.settings)["total"], 1)
        self.assertEqual(search_attack(self.settings, include_inactive=True)["total"], 2)
        self.assertTrue(get_attack_object(self.settings, "T1001")["matches"][0]["revoked"])
        self.assertEqual(search_attack(self.settings, kind="relationship", include_inactive=True)["total"], 1)

    def test_external_ids_are_disambiguated_not_merged(self):
        data = bundle()
        data["objects"][2]["external_references"] = copy.deepcopy(data["objects"][1]["external_references"])
        self.publish(data)
        result = get_attack_object(self.settings, "T1000")
        self.assertTrue(result["ambiguous"])
        self.assertEqual(result["total"], 2)
        self.assertNotEqual(result["matches"][0]["id"], result["matches"][1]["id"])

    def test_relationships_filter_inactive_endpoints_and_preserve_direction(self):
        self.publish()
        identity = sid("attack-pattern", 1)
        self.assertEqual(attack_relations(self.settings, identity)["total"], 0)
        relations = attack_relations(self.settings, identity, include_inactive=True, direction="incoming")
        self.assertEqual(relations["total"], 1)
        edge = relations["relations"][0]
        self.assertEqual(edge["source"]["id"], sid("attack-pattern", 2))
        self.assertTrue(edge["source"]["revoked"])
        self.assertEqual(edge["validation"], "source_documented")
        self.assertEqual(attack_relations(self.settings, identity, include_inactive=True, direction="outgoing")["total"], 0)

    def test_search_and_relation_offset_history_keyset_pagination(self):
        self.publish()
        all_records = search_attack(self.settings, include_inactive=True, limit=1)
        second = search_attack(self.settings, include_inactive=True, limit=1, offset=1)
        self.assertTrue(all_records["truncated"])
        self.assertNotEqual(all_records["results"][0]["id"], second["results"][0]["id"])
        data = self.next_collection()
        data["objects"][1]["description"] = "changed"
        self.publish(data, "b"*40)
        first = attack_history(self.settings, sid("attack-pattern", 1), limit=1)
        next_page = attack_history(self.settings, sid("attack-pattern", 1), limit=1, before=first["next_before"])
        self.assertEqual(first["revisions"][0]["event"], "modified")
        self.assertEqual(next_page["revisions"][0]["event"], "added")
        self.assertIsNone(next_page["next_before"])
        self.assertNotIn("data_json", first["revisions"][0])
        self.assertEqual(attack_relations(self.settings, sid("attack-pattern", 1), include_inactive=True, offset=1)["relations"], [])

    def test_stix_id_search_and_exact_attack_id_rank_above_description_mentions(self):
        data = bundle()
        data["objects"][2].update(revoked=False, description="T1000 T1000")
        self.publish(data)
        self.assertEqual(search_attack(self.settings, "T1000")["results"][0]["id"], sid("attack-pattern", 1))
        self.assertEqual(search_attack(self.settings, sid("attack-pattern", 1))["results"][0]["id"], sid("attack-pattern", 1))

    def test_failed_initial_migration_is_transactional_and_backup_is_retained(self):
        manifest = self.capture()
        execute = Database.execute
        def injected(db, sql, params=()):
            if sql.startswith("INSERT INTO attack_migrations"):
                raise sqlite3.OperationalError("injected migration failure")
            return execute(db, sql, params)
        with patch.object(Database, "execute", injected):
            with self.assertRaises(sqlite3.Error):
                index_capture(self.settings, manifest)
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertFalse(schema(db))
            self.assertEqual(db.query("SELECT name FROM sqlite_master WHERE name LIKE 'attack_%'"), [])
        self.assertEqual(len(list((self.settings.data_dir/"backups").glob("pre-attack-schema1-*.db"))), 1)

    def test_domain_and_release_filters_do_not_mix_memories(self):
        first = self.publish()
        self.assertEqual(search_attack(self.settings, domain="mobile-attack")["total"], 0)
        self.assertEqual(search_attack(self.settings, release="99.0")["total"], 0)
        self.assertEqual(get_attack_object(self.settings, "T1000", release=first["release_id"])["total"], 1)

    def test_query_input_limits_are_strict_before_sqlite_access(self):
        for options in ({"limit": True}, {"limit": 101}, {"offset": -1}, {"domain": None}, {"kind": []},
                        {"release": "../private"}, {"include_inactive": 1}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                search_attack(self.settings, **options)
        for query in (";", [], "x"*501):
            with self.assertRaises(ValueError):
                search_attack(self.settings, query)
        with self.assertRaises(ValueError):
            attack_context(self.settings, "T1000", max_chars=True)
        with self.assertRaises(ValueError):
            attack_history(self.settings, sid("attack-pattern", 1), before=True)
        with self.assertRaises(ValueError):
            attack_relations(self.settings, "T1000")

    def test_output_path_guards_reject_before_read_or_creation(self):
        unsafe = Settings(self.root, {**self.settings.raw, "database_path": "../outside-attack.db"})
        with self.assertRaisesRegex(ValueError, "unsafe_attack_index_output"):
            index_capture(unsafe, "not-read")
        with patch("rabanito.attack_store.contains_reparse_component", return_value=True):
            with self.assertRaisesRegex(ValueError, "unsafe_attack_index_output"):
                index_capture(self.settings, "not-read")

    def test_shared_writer_lock_protects_publication(self):
        import threading
        manifest = self.capture()
        errors = []
        def attempt():
            try:
                index_capture(self.settings, manifest)
            except TimeoutError:
                errors.append("locked")
        with _index_lock(self.settings):
            thread = threading.Thread(target=attempt)
            thread.start()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, ["locked"])
        self.assertFalse(self.settings.database_path.exists())

    def test_cli_queries_use_the_shared_index_and_capture_mode_remains_compatible(self):
        manifest = self.capture()
        for argv in (["index", "--capture", manifest], ["status"], ["search", "memoria"], ["get", "T1000"],
                     ["context", "T1000", "--max-chars", "27"], ["history", sid("attack-pattern", 1)],
                     ["relations", sid("attack-pattern", 1), "--include-inactive"]):
            output = io.StringIO()
            with patch("rabanito.cli.load_settings", return_value=self.settings), redirect_stdout(output):
                main(["attack", *argv])
            self.assertIsInstance(json.loads(output.getvalue()), dict)

    def test_http_read_contracts_and_strict_fields_no_capture_or_index_endpoint(self):
        self.publish()
        with self.server() as origin:
            for endpoint, payload in (("status", {}), ("search", {"q": "memoria"}), ("get", {"id": "T1000"}),
                    ("context", {"q": "T1000", "max_chars": 29}), ("relations", {"id": sid("attack-pattern", 1), "include_inactive": True}),
                    ("history", {"id": sid("attack-pattern", 1)})):
                request = Request(origin+"/api/attack/"+endpoint, data=json.dumps(payload).encode(),
                                  headers={"Origin": origin, "Content-Type": "application/json"}, method="POST")
                with urlopen(request) as response:
                    self.assertEqual(response.status, 200)
                    result = json.load(response)
                self.assertEqual(result["requests"], 0)
                self.assertNotIn(str(self.root), json.dumps(result))
            for path, raw, expected in (("search", b'{"q":"a","q":"b"}', 400),
                    ("search", b'{"limit":true}', 400), ("context", b'{"q":"a","capture":"x"}', 400),
                    ("index", b'{}', 404), ("capture", b'{}', 404), ("get", b'{"id":"T9999"}', 404)):
                request = Request(origin+"/api/attack/"+path, data=raw,
                                  headers={"Origin": origin, "Content-Type": "application/json"}, method="POST")
                with self.assertRaises(HTTPError) as caught:
                    urlopen(request)
                self.assertEqual(caught.exception.code, expected)
                caught.exception.close()
            with self.assertRaises(HTTPError) as caught:
                urlopen(origin+"/api/attack/search?q=ignored")
            self.assertEqual(caught.exception.code, 405)
            caught.exception.close()
