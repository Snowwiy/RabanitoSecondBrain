from __future__ import annotations

import copy
import io
import json
import sqlite3
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from contextlib import closing, contextmanager
from http.server import ThreadingHTTPServer
from threading import Thread
from urllib.request import Request, urlopen
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

from rabanito.config import Settings
from rabanito.cyber.model import InvalidFeed, normalize_epss, normalize_kev, normalize_nvd, normalize_osv
from rabanito.cyber.model import identifier
from rabanito.cyber.store import cyber_status, ensure_schema, get_vulnerability, search_vulnerabilities
from rabanito.cyber.store import vulnerability_context
from rabanito.cyber.sync import EPSS_URL, KEV_URL, NVD_URL, OSV_URL, sync_source
from rabanito.cyber.transport import FetchError, PublicHttpClient, Response, validate_endpoint
from rabanito.db import Database, restore_database
from rabanito.server import RabanitoHandler


CVE = "CVE-2024-12345"
OTHER = "CVE-2024-54321"
GHSA = "GHSA-jfh8-c2jp-5v3q"
NOW = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)


def kev(cves=(CVE,)):
    return {"catalogVersion": "2026.10.16", "dateReleased": "2026-10-16T10:00:00Z", "count": len(cves),
            "vulnerabilities": [{"cveID": c, "vendorProject": "Fixture Vendor", "product": "Test App",
                "vulnerabilityName": "Deterministic Unicode parser", "shortDescription": "A synthetic fixture only.",
                "dateAdded": "2026-10-15", "dueDate": "2026-11-01", "requiredAction": "Follow the vendor advisory.",
                "knownRansomwareCampaignUse": "Unknown", "cwes": ["CWE-20"]} for c in cves]}


def nvd(cves=(CVE,), total=None, offset=0):
    return {"resultsPerPage": len(cves), "startIndex": offset, "totalResults": len(cves) if total is None else total,
            "vulnerabilities": [{"cve": {"id": c, "published": "2024-10-01T00:00:00.000", "lastModified": "2026-10-15T12:00:00.000",
                "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "Fixture Unicode parser buffer issue."}],
                "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
                "configurations": [{"operator": "AND", "nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:fixture:parser:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0"}]}]}],
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-120"}]}],
                "references": [{"url": "https://example.com/advisory", "tags": ["Patch"]}]}} for c in cves]}


def epss(cves=(CVE,), score="0.42", offset=0, total=None):
    return {"status": "OK", "total": len(cves) if total is None else total, "offset": offset,
            "data": [{"cve": c, "epss": score, "percentile": "0.95", "date": "2026-10-15"} for c in cves]}


def osv(aliases=(CVE,)):
    return {"id": GHSA, "aliases": list(aliases), "summary": "Synthetic parser advisory", "details": "Fixture vulnerability details.",
            "published": "2024-10-01T00:00:00Z", "modified": "2026-10-15T00:00:00Z",
            "affected": [{"package": {"name": "parser", "ecosystem": "PyPI"}, "versions": ["1.0"],
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}],
            "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/" + GHSA}],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, cache=None):
        self.calls.append((url, cache))
        data = self.responses.pop(0)
        if isinstance(data, Exception):
            raise data
        return Response(copy.deepcopy(data), url, '"fixture-etag"', "Fri, 16 Oct 2026 12:00:00 GMT")


class CyberTests(unittest.TestCase):
    def test_nvd_identifier_lookup_does_not_claim_global_freshness_without_a_window(self):
        self.sync("nvd", [nvd()], [CVE])
        state = next(x for x in cyber_status(self.settings)["connectors"] if x["source"] == "nvd")
        self.assertTrue(state["stale"])
        self.assertTrue(state["coverage"]["backlog"])
        self.assertIsNone(state["coverage"]["covered_until"])
        self.assertEqual(state["coverage"]["kind"], "identifier_lookups_only_or_none")

    def test_nvd_lookup_cannot_hide_previously_recorded_window_backlog(self):
        result = self.sync("nvd", [nvd()])
        self.assertTrue(result["scope"]["backlog"])
        self.sync("nvd", [nvd()], [CVE])
        state = next(x for x in cyber_status(self.settings)["connectors"] if x["source"] == "nvd")
        self.assertEqual(state["scope"]["type"], "public_identifiers")
        self.assertTrue(state["coverage"]["backlog"])
        self.assertTrue(state["stale"])
        self.assertEqual(state["coverage"]["covered_until"], result["scope"]["end"])

    def test_status_reports_configured_foreground_permission_not_a_running_scheduler(self):
        self.settings.raw["cyber"]["cadence"] = {"enabled": True}
        status = cyber_status(self.settings)
        self.assertTrue(status["periodic_enabled"])
        self.assertEqual(status["cadence_mode"], "foreground_only")
        self.assertFalse(status["background_process_managed"])
        self.settings.raw["cyber"]["cadence"]["enabled"] = "true"
        self.assertFalse(cyber_status(self.settings)["periodic_enabled"])

    def setUp(self):
        root = Path(__file__).resolve().parent / ".test-temp"
        root.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="cyber-ñ-", dir=root)
        self.root = Path(self.temporary.name)
        self.settings = Settings(self.root, {"data_dir": "data", "database_path": "data/test.db", "knowledge_dir": "knowledge",
            "vault_root": "vault", "projects_root": "projects", "cyber": {"nvd_page_size": 1}})
        for p in (self.settings.data_dir, self.settings.vault_root, self.settings.projects_root, self.settings.knowledge_root):
            p.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.temporary.cleanup()

    def sync(self, source, data, ids=None):
        return sync_source(self.settings, source, ids, client=FakeClient(data), now=NOW)

    def test_local_queries_before_first_sync_have_no_network_or_migration(self):
        with patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Network forbidden")):
            self.assertEqual(cyber_status(self.settings)["entities"], 0)
            self.assertEqual(search_vulnerabilities(self.settings)["total"], 0)
            self.assertIsNone(get_vulnerability(self.settings, CVE))
        with Database(self.settings.database_path) as db:
            self.assertIsNone(db.one("SELECT 1 FROM sqlite_master WHERE name='cyber_migrations'"))

    def test_real_source_shapes_normalize_without_inventing_unknowns(self):
        k = normalize_kev(kev(), KEV_URL)[0]
        self.assertIsNone(k["published"])
        self.assertEqual(k["metrics"], [])
        self.assertEqual(k["affected"][0]["version_scope"], "not_specified")
        n = normalize_nvd(nvd(), NVD_URL)[0]
        self.assertEqual(n["metrics"][0]["score"], 9.8)
        self.assertEqual(n["configuration_logic"][0]["operator"], "AND")
        self.assertEqual(n["affected"][0]["versionEndExcluding"], "2.0")
        o = normalize_osv(osv(), OSV_URL + GHSA)[0]
        self.assertIsNone(o["metrics"][0]["score"])
        self.assertEqual(o["fixes"][0]["version"], "2.0")

    def test_four_sources_merge_one_cve_and_keep_all_provenance(self):
        for source, payload, ids in (("kev", kev(), None), ("nvd", nvd(), [CVE]), ("epss", epss(), [CVE]), ("osv", osv(), [GHSA])):
            self.assertEqual(self.sync(source, [payload], ids)["status"], "ok")
        record = get_vulnerability(self.settings, CVE)
        self.assertEqual(record["sources"], ["epss", "kev", "nvd", "osv"])
        self.assertEqual(record["exploitation"], "known_exploited")
        self.assertEqual(record["cvss"]["score"], 9.8)
        self.assertEqual(record["epss"]["score"], .42)
        self.assertTrue(all(o["source_url"].startswith("https://") and o["retrieved_at"] for o in record["observations"]))
        result = search_vulnerabilities(self.settings, "Unicode parser", source="kev", kev_only=True)
        self.assertEqual(result["total"], 1)
        self.assertNotIn("observations", result["results"][0])
        self.assertEqual(cyber_status(self.settings)["records"], 4)

    def test_idempotency_and_source_changes_update_only_affected(self):
        first = self.sync("kev", [kev((CVE, OTHER))])
        same = self.sync("kev", [kev((CVE, OTHER))])
        changed = kev((CVE, OTHER))
        changed["vulnerabilities"][0]["requiredAction"] = "New documented mitigation"
        last = self.sync("kev", [changed])
        self.assertEqual((first["added"], same["unchanged"], last["modified"], last["unchanged"]), (2, 2, 1, 1))
        self.assertEqual(cyber_status(self.settings)["entities"], 2)

    def test_full_kev_snapshot_retires_missing_without_deleting_history(self):
        self.sync("kev", [kev((CVE, OTHER))])
        result = self.sync("kev", [kev((CVE,))])
        self.assertEqual(result["retired"], 1)
        self.assertIsNone(get_vulnerability(self.settings, OTHER))
        with Database(self.settings.database_path) as db:
            self.assertEqual(db.one("SELECT active FROM cyber_records WHERE source_id=?", (OTHER,))["active"], 0)

    def test_invalid_catalog_rolls_back_and_does_not_poison_cache(self):
        self.sync("kev", [kev()])
        bad = kev((OTHER,))
        bad["count"] = 100
        result = self.sync("kev", [bad])
        self.assertEqual(result["status"], "error")
        self.assertIsNotNone(get_vulnerability(self.settings, CVE))
        self.assertIsNone(get_vulnerability(self.settings, OTHER))
        with Database(self.settings.database_path) as db:
            cached = db.one("SELECT body_json FROM cyber_http_cache WHERE url=?", (KEV_URL,))
            self.assertEqual(json.loads(cached["body_json"])["count"], 1)

    def test_pagination_complete_advances_watermark_only_after_last_page(self):
        result = self.sync("nvd", [nvd((CVE,), 2), nvd((OTHER,), 2, 1)])
        self.assertEqual(result["added"], 2)
        self.assertEqual(result["requests"], 2)
        state = next(s for s in cyber_status(self.settings)["connectors"] if s["source"] == "nvd")
        self.assertEqual(state["watermark"], result["scope"]["end"])
        self.assertTrue(result["scope"]["backlog"])
        self.assertEqual(result["scope"]["type"], "modified_window")

    def test_page_budget_partial_is_not_published_or_checkpointed(self):
        self.settings.raw["cyber"]["max_pages"] = 1
        self.settings.raw["cyber"]["nvd_window_minutes"] = 1
        result = self.sync("nvd", [nvd((CVE,), 2)])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(cyber_status(self.settings)["entities"], 0)
        state = next(s for s in cyber_status(self.settings)["connectors"] if s["source"] == "nvd")
        self.assertIsNone(state["watermark"])
        with Database(self.settings.database_path) as db:
            self.assertEqual(db.one("SELECT count(*) n FROM cyber_http_cache")["n"], 0)

    def test_second_page_network_failure_preserves_previous_records(self):
        self.sync("nvd", [nvd()], [CVE])
        result = self.sync("nvd", [nvd((OTHER,), 2), FetchError("network_error")])
        self.assertEqual(result["status"], "error")
        self.assertEqual(cyber_status(self.settings)["entities"], 1)
        self.assertIsNotNone(get_vulnerability(self.settings, CVE))

    def test_duplicate_pages_and_changed_totals_are_rejected(self):
        for pages in ([nvd((CVE,), 2), nvd((CVE,), 2, 1)], [nvd((CVE,), 2), nvd((OTHER,), 3, 1)]):
            with self.subTest(pages=pages):
                self.assertEqual(self.sync("nvd", pages)["status"], "error")
                self.assertEqual(cyber_status(self.settings)["entities"], 0)

    def test_oversized_nvd_page_reduces_page_size_before_retrying_same_offset(self):
        self.settings.raw["cyber"]["nvd_page_size"] = 500
        client = FakeClient([FetchError("response_too_large"), nvd()])
        result = sync_source(self.settings, "nvd", [CVE], client=client, now=NOW)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(parse_qs(urlsplit(client.calls[0][0]).query)["resultsPerPage"], ["500"])
        self.assertEqual(parse_qs(urlsplit(client.calls[1][0]).query)["resultsPerPage"], ["250"])

    def test_window_narrows_after_page_budget_and_publishes_only_complete_scope(self):
        self.settings.raw["cyber"]["max_pages"] = 1
        client = FakeClient([nvd((OTHER,), 2), nvd((CVE,), 1)])
        result = sync_source(self.settings, "nvd", client=client, now=NOW)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["scope"]["window_minutes"], 30)
        self.assertIsNone(get_vulnerability(self.settings, OTHER))
        self.assertIsNotNone(get_vulnerability(self.settings, CVE))

    def test_nvd_resumes_a_successful_narrow_window_even_after_a_point_lookup(self):
        self.settings.raw["cyber"]["max_pages"] = 1
        first = self.sync("nvd", [nvd((OTHER,), 2), nvd()])
        self.assertEqual(first["scope"]["window_minutes"], 30)
        self.sync("nvd", [nvd()], [CVE])
        second = self.sync("nvd", [nvd(())])
        self.assertEqual(second["scope"]["window_minutes"], 30)
        self.assertEqual(second["requests"], 1)
        self.assertGreater(second["scope"]["end"], first["scope"]["end"])

    def test_default_window_can_narrow_to_one_minute_without_publishing_partial_scopes(self):
        self.settings.raw["cyber"]["max_pages"] = 1
        result = self.sync("nvd", [nvd((OTHER,), 2)] * 5 + [nvd()])
        self.assertEqual(result["scope"]["window_minutes"], 1)
        self.assertEqual(result["requests"], 6)
        self.assertEqual(result["status"], "ok")
        self.assertIsNone(get_vulnerability(self.settings, OTHER))

    def test_nvd_grows_adaptive_window_only_after_three_light_completed_windows(self):
        self.settings.raw["cyber"]["max_pages"] = 1
        first = self.sync("nvd", [nvd((OTHER,), 2), nvd()])
        self.assertEqual(first["scope"]["window_minutes"], 30)
        for quiet in (1, 2, 3):
            result = self.sync("nvd", [nvd(())])
            self.assertEqual(result["scope"]["light_windows"], quiet)
            self.assertEqual(result["scope"]["window_minutes"], 30)
        expanded = self.sync("nvd", [nvd(())])
        self.assertEqual(expanded["scope"]["window_minutes"], 60)
        self.assertEqual(expanded["scope"]["light_windows"], 1)

    def test_one_minute_window_watermark_moves_forward_despite_overlap(self):
        self.settings.raw["cyber"]["nvd_window_minutes"] = 1
        first = self.sync("nvd", [nvd(())])
        second = self.sync("nvd", [nvd(())])
        self.assertGreater(second["scope"]["end"], first["scope"]["end"])

    def test_empty_valid_nvd_window_succeeds_and_empty_kev_fails_closed(self):
        self.assertEqual(self.sync("nvd", [nvd(())])["status"], "ok")
        self.assertEqual(self.sync("kev", [kev(())])["status"], "error")

    def test_scoped_nvd_lookup_does_not_move_incremental_watermark(self):
        self.sync("nvd", [nvd()], [CVE])
        state = next(s for s in cyber_status(self.settings)["connectors"] if s["source"] == "nvd")
        self.assertIsNone(state["watermark"])

    def test_kev_official_mirror_fallback_only_for_forbidden_or_missing(self):
        result = self.sync("kev", [FetchError("http_error", 403), kev()])
        self.assertEqual(result["status"], "ok")
        self.assertIn("cisagov", result["scope"]["endpoint"])
        result = self.sync("kev", [FetchError("rate_limited", 429)])
        self.assertEqual(result["requests"], 1)

    def test_osv_advisory_does_not_merge_distinct_cves(self):
        self.sync("osv", [osv((CVE, OTHER))], [GHSA])
        self.assertEqual(cyber_status(self.settings)["entities"], 2)
        advisory = get_vulnerability(self.settings, GHSA)
        self.assertEqual(advisory["related_cves"], [CVE, OTHER])

    def test_osv_ghsa_case_is_preserved_for_case_sensitive_public_endpoint(self):
        self.assertEqual(identifier(GHSA.upper()), GHSA)
        client = FakeClient([osv()])
        self.assertEqual(sync_source(self.settings, "osv", [GHSA], client=client, now=NOW)["status"], "ok")
        self.assertEqual(client.calls[0][0], OSV_URL + GHSA)

    def test_rate_limit_cooldown_is_preserved_between_syncs(self):
        self.sync("kev", [FetchError("rate_limited", 429, 120)])
        client = FakeClient([])
        deferred = sync_source(self.settings, "kev", client=client, now=NOW)
        self.assertEqual(deferred["status"], "deferred")
        self.assertEqual(client.calls, [])

    def test_absent_epss_score_on_successful_target_refresh_is_not_kept_as_current(self):
        self.sync("epss", [epss()], [CVE])
        result = self.sync("epss", [epss(())], [CVE])
        self.assertEqual(result["retired"], 1)
        self.assertIsNone(get_vulnerability(self.settings, CVE))

    def test_epss_probability_is_not_evidence_of_observed_exploitation(self):
        self.sync("epss", [epss(score="0.99")], [CVE])
        record = get_vulnerability(self.settings, CVE)
        self.assertEqual(record["exploitation"], "not_established")
        self.assertEqual(record["priority"], "high_prediction")
        self.assertIsNone(record["cvss"])

    def test_invalid_epss_scores_and_invalid_identifiers_rejected(self):
        for value in ("NaN", "Infinity", "1.1", "-0.1", True):
            with self.subTest(value=value), self.assertRaises(InvalidFeed):
                normalize_epss(epss(score=value), EPSS_URL)
        for value in ("../../etc/passwd", "CVE-2024-12345?token=secret", "file:///a", "CVE-2024-12345\n"):
            with self.assertRaises(ValueError):
                sync_source(self.settings, "osv", [value], client=FakeClient([]))

    def test_queries_offline_limits_filters_and_safe_fts(self):
        self.sync("kev", [kev((CVE, OTHER))])
        with patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("network")):
            self.assertEqual(search_vulnerabilities(self.settings, CVE)["results"][0]["id"], CVE)
            self.assertEqual(search_vulnerabilities(self.settings, '" OR NOT *', limit=0)["results"], [])
            result = search_vulnerabilities(self.settings, limit=1, offset=1)
            self.assertEqual((len(result["results"]), result["total"]), (1, 2))
            self.assertEqual(search_vulnerabilities(self.settings, source="epss")["total"], 0)

    def test_schema_checksum_and_future_version_fail_closed(self):
        self.sync("kev", [kev()])
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE cyber_migrations SET checksum='tampered'")
            db.commit()
            with self.assertRaises(ValueError):
                ensure_schema(db)

    def test_database_backup_restore_includes_cyber_and_fts(self):
        self.sync("kev", [kev()])
        backup, restored = self.root / "backup.db", self.root / "restored.db"
        with Database(self.settings.database_path) as db:
            db.backup(backup)
        restore_database(backup, restored)
        restored_settings = Settings(self.root, {**self.settings.raw, "database_path": str(restored)})
        self.assertEqual(search_vulnerabilities(restored_settings, "Unicode")["total"], 1)
        with closing(sqlite3.connect(restored)) as connection:
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_existing_private_sources_are_not_read_or_transmitted(self):
        sentinel = self.settings.vault_root / "private.md"
        sentinel.write_text("DO NOT TRANSMIT - PRIVATE", encoding="utf-8")
        original = sentinel.read_bytes()
        client = FakeClient([kev()])
        with patch("pathlib.Path.read_text", side_effect=AssertionError("Must not read notes")):
            result = sync_source(self.settings, "kev", client=client, now=NOW)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(original, sentinel.read_bytes())
        self.assertNotIn("PRIVATE", repr(client.calls))

    def test_bounded_context_has_provider_citations_and_is_offline(self):
        self.sync("kev", [kev()])
        for maximum in (0, 7, 1000):
            result = vulnerability_context(self.settings, CVE, max_chars=maximum)
            self.assertLessEqual(sum(len(x["text"]) for x in result["fragments"]), maximum)
            self.assertTrue(all(x["citation"].startswith("https://") and x["retrieved_at"] for x in result["fragments"]))

    def test_cli_pipe_emits_utf8_even_if_windows_default_encoding_is_cp1252(self):
        payload = kev()
        payload["vulnerabilities"][0]["vulnerabilityName"] = "Ráfaga Unicode"
        self.sync("kev", [payload])
        config = self.root / "settings.json"
        config.write_text(json.dumps({"project_root": str(self.root), **self.settings.raw}), encoding="utf-8")
        result = subprocess.run([sys.executable, "-B", "-m", "rabanito", "--config", str(config), "cyber", "search", CVE],
                                cwd=Path(__file__).resolve().parents[1], env={**os.environ, "PYTHONIOENCODING": "cp1252"},
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Ráfaga".encode("utf-8"), result.stdout)
        self.assertEqual(json.loads(result.stdout.decode("utf-8"))["results"][0]["title"], "Ráfaga Unicode")

    @contextmanager
    def server(self):
        handler = type("CyberFixtureHandler", (RabanitoHandler,), {"settings": self.settings, "log_message": lambda *a: None})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_address[1]}"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)

    def test_http_local_search_detail_status_and_no_network_on_reads(self):
        self.sync("kev", [kev()])
        with self.server() as origin, patch("rabanito.server.sync_source", side_effect=AssertionError("no synchronization")):
            with urlopen(origin + "/api/cyber/status") as response:
                self.assertEqual(json.load(response)["kev"], 1)
            for endpoint, body in (("search", {"q": CVE}), ("get", {"id": CVE})):
                request = Request(origin + "/api/cyber/" + endpoint, data=json.dumps(body).encode(),
                                  headers={"Origin": origin, "Content-Type": "application/json"}, method="POST")
                with urlopen(request) as response:
                    result = json.load(response)
                self.assertNotIn(str(self.root), json.dumps(result))
                self.assertTrue(result)

    def test_http_rejects_forged_origin_get_mutation_and_missing_explicit_sync(self):
        with self.server() as origin, patch("rabanito.server.sync_source") as sync:
            for method, headers, data, expected in (("GET", {}, None, 405),
                ("POST", {"Origin": "https://evil.example", "Content-Type": "application/json"}, b'{}', 403),
                ("POST", {"Origin": origin, "Content-Type": "application/json"}, b'{"source":"kev"}', 400)):
                request = Request(origin + "/api/cyber/sync", data=data, headers=headers, method=method)
                with self.assertRaises(HTTPError) as caught:
                    urlopen(request)
                self.assertEqual(caught.exception.code, expected)
                caught.exception.close()
            sync.assert_not_called()

    def test_http_sync_calls_only_fixed_connector_with_explicit_payload(self):
        with self.server() as origin, patch("rabanito.server.sync_source", return_value={"status": "ok", "source": "kev"}) as sync:
            request = Request(origin + "/api/cyber/sync", data=b'{"source":"kev","confirm_public_sync":true}',
                              headers={"Origin": origin, "Content-Type": "application/json"}, method="POST")
            with urlopen(request) as response:
                self.assertEqual(json.load(response)["status"], "ok")
            sync.assert_called_once_with(self.settings, "kev", None)

    def test_http_public_graph_rejects_false_project_applicability_scope(self):
        self.sync("kev", [kev()])
        with self.server() as origin:
            request = Request(origin + "/api/graph", data=b'{"domain":"cyber","project_id":1}',
                              headers={"Origin": origin, "Content-Type": "application/json"}, method="POST")
            with self.assertRaises(HTTPError) as caught: urlopen(request)
            self.assertEqual(caught.exception.code, 400)
            caught.exception.close()
            request = Request(origin + "/api/graph", data=b'{"domain":"cyber","limit":20}',
                              headers={"Origin": origin, "Content-Type": "application/json"}, method="POST")
            with urlopen(request) as response:
                graph = json.load(response)
            self.assertEqual(graph["domain"], "cyber")
            self.assertNotIn(str(self.root), json.dumps(graph))

    def test_interrupted_fetch_records_recoverable_state_without_publishing(self):
        self.sync("kev", [kev()])
        class Interrupted:
            def get(self, *args): raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            sync_source(self.settings, "kev", client=Interrupted(), now=NOW)
        state = next(s for s in cyber_status(self.settings)["connectors"] if s["source"] == "kev")
        self.assertEqual(state["status"], "interrupted")
        self.assertEqual(cyber_status(self.settings)["entities"], 1)
        self.assertEqual(self.sync("kev", [kev()])["unchanged"], 1)

    def test_bad_http_limit_is_400_instead_of_an_uncaught_handler_error(self):
        with self.server() as origin:
            request = Request(origin + "/api/cyber/search", data=b'{"limit":null}',
                              headers={"Origin": origin, "Content-Type": "application/json"}, method="POST")
            with self.assertRaises(HTTPError) as caught: urlopen(request)
            self.assertEqual(caught.exception.code, 400)
            caught.exception.close()


class TransportTests(unittest.TestCase):
    def response(self, raw=b'{"ok":true}', headers=None):
        result = io.BytesIO(raw)
        result.status = 200
        result.headers = headers or {}
        return result

    def client(self, side_effect, attempts=3):
        from unittest.mock import Mock
        opener = Mock()
        opener.open.side_effect = side_effect
        sleeps = []
        client = PublicHttpClient(opener=opener, sleep=sleeps.append, monotonic=lambda: 100, attempts=attempts)
        return client, opener, sleeps

    def test_allowlist_rejects_ssrf_credentials_traversal_and_arbitrary_urls(self):
        for url in ("http://api.osv.dev/v1/vulns/CVE-2024-12345", "https://127.0.0.1/a", "https://api.osv.dev:444/v1/vulns/x",
                    "https://secret@api.osv.dev/v1/vulns/x", "https://example.com/a", "https://services.nvd.nist.gov/private", "https://api.osv.dev.evil.test/v1/vulns/a"):
            with self.subTest(url=url), self.assertRaises(ValueError): validate_endpoint(url)

    def test_etag_and_last_modified_304_use_validated_cached_body(self):
        error = HTTPError(KEV_URL, 304, "Not modified", {}, None)
        client, opener, _ = self.client([error])
        cached = {"data": kev(), "etag": '"abc"', "last_modified": "date"}
        result = client.get(KEV_URL, cached)
        self.assertTrue(result.not_modified)
        self.assertEqual(opener.open.call_args[0][0].get_header("If-none-match"), '"abc"')

    def test_retry_after_long_rate_limit_returns_without_hammering(self):
        error = HTTPError(NVD_URL, 429, "Too many", {"Retry-After": "120"}, None)
        client, opener, sleeps = self.client([error])
        with self.assertRaises(FetchError) as caught: client.get(NVD_URL)
        self.assertEqual(caught.exception.retry_after, 120)
        self.assertEqual(opener.open.call_count, 1)
        self.assertEqual(sleeps, [])

    def test_transient_network_and_http_errors_retry_with_backoff(self):
        client, opener, sleeps = self.client([URLError("private exception sentinel"), HTTPError(KEV_URL, 503, "Down", {}, None), self.response()])
        self.assertTrue(client.get(KEV_URL).data["ok"])
        self.assertEqual(opener.open.call_count, 3)
        self.assertIn(2, sleeps)

    def test_size_invalid_json_duplicate_keys_and_nonfinite_rejected(self):
        for raw in (b'not-json', b'{"a":1,"a":2}', b'{"a":NaN}', b'x' * (8 * 1024 * 1024 + 1)):
            client, _, _ = self.client([self.response(raw)])
            with self.assertRaises((FetchError, InvalidFeed)):
                client.get(KEV_URL)


if __name__ == "__main__":
    unittest.main()
