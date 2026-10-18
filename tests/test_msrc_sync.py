from __future__ import annotations

import copy
import io
import json
import sqlite3
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from rabanito.cli import main
from rabanito.cyber.cadence import run_cyber_watch
from rabanito.cyber.history import vulnerability_history
from rabanito.cyber.model import InvalidFeed
from rabanito.cyber.msrc import document_url
from rabanito.cyber.msrc_capture import capture_month
from rabanito.cyber.msrc_state import schema
from rabanito.cyber.store import cyber_status, get_vulnerability, search_vulnerabilities, vulnerability_context
from rabanito.cyber.sync import sync_source
from rabanito.cyber.transport import FetchError, validate_endpoint
from rabanito.db import Database
from rabanito.knowledge_graph import graph_page, sync_graph
from rabanito.indexer import _index_lock
from tests import test_cyber as fixtures
from tests.test_msrc import cvrf
from tests.test_msrc_capture import Opener


MONTH = "2026-Oct"
CVE = "CVE-2099-10000"


def summary(month=MONTH, modified="2026-10-16T07:00:00Z"):
    return {"value": [{"ID": month, "CurrentReleaseDate": modified,
                       "CvrfUrl": document_url(month).split("?", 1)[0]}]}


class MsrcSyncTests(unittest.TestCase):
    setUp = fixtures.CyberTests.setUp
    tearDown = fixtures.CyberTests.tearDown
    server = fixtures.CyberTests.server

    def capture(self, data=None, month=MONTH):
        return capture_month(self.settings, month, opener=Opener(json.dumps(data if data is not None else cvrf()).encode()))["manifest"]

    def sync(self, data=None, payload=None, month=MONTH, manifest=None):
        return sync_source(self.settings, "msrc", month=month, capture_manifest=manifest or self.capture(data, month),
                           client=fixtures.FakeClient([payload or summary(month)]))

    def values(self):
        with Database(self.settings.database_path, read_only=True) as db:
            return {table: [tuple(r) for r in db.query("SELECT * FROM " + table + " ORDER BY 1,2")]
                    for table in ("cyber_records", "cyber_aliases", "cyber_entities", "cyber_fts", "cyber_revisions", "msrc_documents")}

    def test_real_capture_pipeline_publishes_cited_searchable_fts_and_history(self):
        result = self.sync()
        self.assertEqual(result["status"], "ok")
        self.assertEqual((result["added"], result["requests"]), (1, 1))
        self.assertFalse(result["scope"]["body_downloaded"])
        found = search_vulnerabilities(self.settings, "Fixture", source="msrc")
        self.assertEqual(found["total"], 1)
        self.assertEqual(found["results"][0]["id"], CVE)
        context = vulnerability_context(self.settings, CVE, max_chars=100)
        self.assertLessEqual(context["used_chars"], 100)
        self.assertEqual(context["fragments"][0]["citation"], document_url(MONTH))
        self.assertEqual(context["fragments"][0]["locator"], "/Vulnerability/0")
        history = vulnerability_history(self.settings, CVE, source="msrc")
        self.assertTrue(history["results"])
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(db.one("PRAGMA integrity_check")[0], "ok")
            self.assertEqual(db.query("PRAGMA foreign_key_check"), [])
            self.assertLess(len(db.one("SELECT body_json FROM cyber_http_cache")[0]), 1000)

    def test_unchanged_summary_skips_body_preserves_retrieval_and_history(self):
        self.sync()
        before = self.values()
        with patch("rabanito.cyber.msrc_sync.capture_month", side_effect=AssertionError("no large download")), patch(
                "rabanito.cyber.msrc_sync.read_capture", side_effect=AssertionError("no reparse")):
            client = fixtures.FakeClient([summary()])
            result = sync_source(self.settings, "msrc", month=MONTH, client=client)
        self.assertEqual((result["status"], result["unchanged"], result["requests"]), ("ok", 1, 1))
        self.assertTrue(result["scope"]["incremental_skip"])
        after = self.values()
        for table in before.keys() - {"msrc_documents"}:
            self.assertEqual(before[table], after[table], table)
        state = next(s for s in cyber_status(self.settings)["connectors"] if s["source"] == "msrc")
        self.assertFalse(state["coverage"]["global_coverage"])
        self.assertEqual(len(state["coverage"]["months"]), 1)

    def test_updated_version_records_revision_and_retires_only_same_month(self):
        data = cvrf(); extra = copy.deepcopy(data["Vulnerability"][0]); extra["CVE"] = "CVE-2099-10001"
        data["Vulnerability"].append(extra)
        self.assertEqual(self.sync(data)["added"], 2)
        sep = cvrf(); sep["DocumentTracking"]["Identification"]["ID"]["Value"] = "2026-Sep"
        self.assertEqual(self.sync(sep, month="2026-Sep")["added"], 1)
        revised = cvrf(); revised["DocumentTracking"]["CurrentReleaseDate"] = "2026-10-17T07:00:00"
        revised["Vulnerability"][0]["Title"]["Value"] = "Revised fixture title"
        result = self.sync(revised, payload=summary(modified="2026-10-17T07:00:00Z"))
        self.assertEqual((result["status"], result["modified"], result["retired"]), ("ok", 1, 1))
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(db.one("SELECT active FROM cyber_records WHERE source_id=?", ("MSRC-2026-Sep-" + CVE,))[0], 1)
        events = vulnerability_history(self.settings, CVE, source="msrc")["results"]
        self.assertIn("modified", {e["event"] for e in events})

    def test_capture_version_mismatch_preserves_all_published_state(self):
        self.sync(); before = self.values()
        result = self.sync(payload=summary(modified="2026-10-17T07:00:00Z"))
        self.assertEqual(result["error_code"], "msrc_capture_version_mismatch")
        self.assertEqual(self.values(), before)

    def test_summary_regression_is_not_applied(self):
        self.sync(); before = self.values()
        result = self.sync(payload=summary(modified="2026-10-15T07:00:00Z"))
        self.assertEqual(result["error_code"], "msrc_summary_regressed")
        self.assertEqual(self.values(), before)

    def test_empty_valid_document_does_not_retire_previous_records(self):
        self.sync(); before = self.values()
        data = cvrf(); data["Vulnerability"] = []
        data["DocumentTracking"]["CurrentReleaseDate"] = "2026-10-17T07:00:00"
        result = self.sync(data, payload=summary(modified="2026-10-17T07:00:00Z"))
        self.assertEqual(result["error_code"], "unexpected_empty_msrc_document")
        self.assertEqual(self.values(), before)

    def test_publication_failure_rolls_back_records_fts_history_and_ledger(self):
        self.sync(); before = self.values()
        data = cvrf(); data["DocumentTracking"]["CurrentReleaseDate"] = "2026-10-17T07:00:00"
        data["Vulnerability"][0]["Title"]["Value"] = "Atomic revised fixture"
        from rabanito.cyber.store import apply_records
        def fail(*args, **kwargs):
            apply_records(*args, **kwargs)
            raise sqlite3.OperationalError("synthetic interruption after FTS/history writes")
        with patch("rabanito.cyber.msrc_sync.apply_records", side_effect=fail):
            result = self.sync(data, payload=summary(modified="2026-10-17T07:00:00Z"))
        self.assertEqual(result["error_code"], "OperationalError")
        self.assertEqual(self.values(), before)

    def test_same_version_repairs_missing_observation_instead_of_false_skip(self):
        manifest = self.capture(); self.sync(manifest=manifest)
        with Database(self.settings.database_path) as db:
            db.execute("DELETE FROM cyber_records WHERE source='msrc'")
        result = self.sync(manifest=manifest)
        self.assertEqual((result["added"], result["scope"]["incremental_skip"]), (1, False))

    def test_changed_summary_during_download_does_not_publish(self):
        manifest = self.capture()
        with patch("rabanito.cyber.msrc_sync.capture_month", return_value={"manifest": manifest}) as capture:
            result = sync_source(self.settings, "msrc", month=MONTH, client=fixtures.FakeClient([
                summary(), summary(modified="2026-10-17T07:00:00Z")]))
        self.assertEqual(result["error_code"], "msrc_summary_changed_during_capture")
        self.assertEqual(cyber_status(self.settings)["records"], 0)
        self.assertEqual(result["requests"], 3)
        self.assertEqual(capture.call_args.kwargs["max_seconds"], 300)

    def test_fresh_capture_is_published_only_after_second_summary_check(self):
        manifest = self.capture()
        with patch("rabanito.cyber.msrc_sync.capture_month", return_value={"manifest": manifest}):
            result = sync_source(self.settings, "msrc", month=MONTH, client=fixtures.FakeClient([summary(), summary()]))
        self.assertEqual((result["status"], result["requests"]), ("ok", 3))
        self.assertTrue(result["scope"]["body_downloaded"])

    def test_advisory_and_vendor_exploitation_are_not_fabricated_as_kev(self):
        data = cvrf(); adv = copy.deepcopy(data["Vulnerability"][0]); adv["CVE"] = "ADV260001"
        data["Vulnerability"].append(adv)
        data["Vulnerability"][0]["Threats"][0]["Description"]["Value"] = "Exploited:Yes;"
        self.assertEqual(self.sync(data)["status"], "ok")
        record = get_vulnerability(self.settings, CVE)
        self.assertEqual(record["priority"], "known_exploited")
        self.assertFalse(record["kev"])
        advisory = get_vulnerability(self.settings, "MSRC-2026-Oct-ADV260001")
        self.assertEqual(advisory["record_kind"], "security_advisory")
        self.assertIsNone(advisory["priority"])
        self.assertEqual(advisory["status"], "advisory")
        while sync_graph(self.settings, max_inputs=2000)["status"] != "ok":
            self.fail("Tiny fixture should sync in one batch")
        nodes = graph_page(self.settings, kind="security_advisory")["nodes"]
        self.assertEqual(len(nodes), 1)
        self.assertIsNone(nodes[0]["data"]["risk"])
        risk = graph_page(self.settings, risk="known_exploited")["nodes"]
        self.assertEqual(len(risk), 1)
        self.assertFalse(risk[0]["data"]["kev"])

    def test_retry_after_blocks_next_run_without_network(self):
        result = sync_source(self.settings, "msrc", month=MONTH, client=fixtures.FakeClient([FetchError("rate_limited", 429, 120)]))
        self.assertEqual(result["status"], "error")
        client = fixtures.FakeClient([])
        result = sync_source(self.settings, "msrc", month=MONTH, client=client)
        self.assertEqual((result["status"], result["requests"]), ("deferred", 0))
        self.assertEqual(client.calls, [])

    def test_vendor_observed_exploitation_ranks_before_prediction_without_false_kev(self):
        data = cvrf(); data["Vulnerability"][0]["Threats"][0]["Description"]["Value"] = "Exploited:Yes;"
        self.assertEqual(self.sync(data)["status"], "ok")
        predicted = "CVE-2099-10001"
        sync_source(self.settings, "epss", [predicted], client=fixtures.FakeClient([fixtures.epss([predicted], score="0.99")]))
        results = search_vulnerabilities(self.settings, sort="risk")["results"]
        self.assertEqual(results[0]["id"], CVE)
        self.assertFalse(results[0]["kev"])
        self.assertEqual(results[1]["priority"], "high_prediction")

    def test_interrupt_records_safe_state_and_can_retry(self):
        class Interrupted:
            def get(self, *args): raise KeyboardInterrupt
        result = sync_source(self.settings, "msrc", month=MONTH, client=Interrupted())
        self.assertEqual(result["status"], "interrupted")
        self.assertEqual(self.sync()["status"], "ok")

    def test_parallel_writer_is_rejected_before_database_or_provider_access(self):
        acquired, release = threading.Event(), threading.Event()
        self.settings.raw["index_lock_timeout_seconds"] = .01
        def writer():
            with _index_lock(self.settings):
                acquired.set()
                release.wait(5)
        thread = threading.Thread(target=writer)
        thread.start()
        try:
            self.assertTrue(acquired.wait(3))
            client = fixtures.FakeClient([])
            with self.assertRaises(TimeoutError):
                sync_source(self.settings, "msrc", month=MONTH, client=client)
            self.assertEqual(client.calls, [])
            self.assertFalse(self.settings.database_path.exists())
        finally:
            release.set(); thread.join(5)

    def test_corrupt_data_with_same_stored_fingerprint_cannot_false_skip(self):
        manifest = self.capture(); self.sync(manifest=manifest)
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE cyber_records SET data_json=json_set(data_json,'$.title','corrupt fixture') WHERE source='msrc'")
        result = self.sync(manifest=manifest)
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["scope"]["incremental_skip"])
        self.assertEqual(get_vulnerability(self.settings, CVE)["title"], "Fixture vulnerability")

    def test_invalid_or_private_month_and_capture_paths_are_rejected_before_io(self):
        for month in (None, "all", "../../.env", "2026-oct", "2026-Oct?private=1", "C:\\private"):
            with self.subTest(month=month), self.assertRaises((InvalidFeed, ValueError)):
                sync_source(self.settings, "msrc", month=month, client=fixtures.FakeClient([]))
        for manifest in ("../../.env", "2026-Oct-" + "a" * 32 + ".json", "2026-Sep-" + "a" * 32 + ".metadata.json"):
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                sync_source(self.settings, "msrc", month=MONTH, capture_manifest=manifest)
        self.assertFalse(self.settings.database_path.exists())

    def test_other_providers_do_not_accept_msrc_scope_options(self):
        with self.assertRaises(ValueError):
            sync_source(self.settings, "kev", month=MONTH)
        with self.assertRaises(ValueError):
            sync_source(self.settings, "msrc", [CVE], month=MONTH)

    def test_transport_only_allows_exact_public_summary_not_arbitrary_urls(self):
        prefix = "https://api.msrc.microsoft.com/cvrf/v3.0/updates/"
        self.assertEqual(validate_endpoint(prefix + MONTH + "?api-version=2023-11-01"), "api.msrc.microsoft.com")
        for path in (MONTH, MONTH + "?api-version=2023-11-01&private=x", MONTH + "/extra?api-version=2023-11-01", "all?api-version=2023-11-01"):
            with self.subTest(path=path), self.assertRaises(ValueError): validate_endpoint(prefix + path)
        with self.assertRaises(ValueError): validate_endpoint(document_url(MONTH))

    def test_wrong_summary_identity_or_url_or_date_fails_without_large_download(self):
        for key, value in (("ID", "2026-Sep"), ("CvrfUrl", "https://evil.example/"), ("CurrentReleaseDate", "0001-01-01")):
            data = summary(); data["value"][0][key] = value
            with self.subTest(key=key), patch("rabanito.cyber.msrc_sync.capture_month", side_effect=AssertionError("no download")):
                result = sync_source(self.settings, "msrc", month=MONTH, client=fixtures.FakeClient([data]))
                self.assertEqual(result["status"], "error")

    def test_migration_backup_and_tampered_checksum_are_enforced(self):
        result = self.sync()
        self.assertEqual(len(result["migration_backups"]), 1)
        backup = self.settings.data_dir / "backups" / result["migration_backups"][0]
        with Database(backup, read_only=True) as db:
            self.assertFalse(schema(db))
            self.assertEqual(db.one("PRAGMA integrity_check")[0], "ok")
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE msrc_migrations SET checksum='tampered'")
        with self.assertRaisesRegex(ValueError, "unsupported_msrc_migration"):
            self.sync()

    def test_manual_only_cadence_and_cli_month_options(self):
        self.settings.raw["cyber"]["cadence"] = {"sources": ["msrc"]}
        with self.assertRaisesRegex(ValueError, "manual-only"):
            run_cyber_watch(self.settings, start=True, cycles=1)
        with patch("rabanito.cli.load_settings", return_value=self.settings), patch(
                "rabanito.cli.sync_source", return_value={"status": "ok"}) as sync, redirect_stdout(io.StringIO()):
            main(["cyber", "sync", "--source", "msrc", "--month", MONTH])
        self.assertEqual(sync.call_args.kwargs["month"], MONTH)

    def test_http_accepts_explicit_month_but_not_local_capture_paths(self):
        with self.server() as origin, patch("rabanito.server.sync_source", return_value={"status": "ok"}) as sync:
            payload = {"source": "msrc", "month": MONTH, "confirm_public_sync": True}
            def request(data):
                return Request(origin + "/api/cyber/sync", data=json.dumps(data).encode(),
                               headers={"Origin": origin, "Content-Type": "application/json"}, method="POST")
            with urlopen(request(payload)) as response:
                self.assertEqual(json.load(response)["status"], "ok")
            sync.assert_called_once_with(self.settings, "msrc", None, month=MONTH)
            for key in ("capture", "capture_manifest"):
                with self.assertRaises(HTTPError) as caught:
                    urlopen(request({**payload, key: "private.json"}))
                self.assertEqual(caught.exception.code, 400)
                caught.exception.close()
            self.assertEqual(sync.call_count, 1)
