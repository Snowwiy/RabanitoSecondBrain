from __future__ import annotations

import io
import json
import socket
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from rabanito.attack import capture_context, inspect_capture
from rabanito.attack_capture import BASE, MAX_BYTES, capture_release, read_capture, release_url
from rabanito.cli import main
from rabanito.config import Settings
from rabanito.cyber.model import InvalidFeed
from rabanito.cyber.transport import FetchError, NoRedirect
from tests.attack_fixture import COMMIT, DOMAIN, VERSION, Opener, blob, raw_bundle


class AttackCaptureTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parent / ".test-temp"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="attack-ñ-", dir=parent)
        self.root = Path(self.temporary.name)
        self.settings = Settings(self.root, {"data_dir": "data", "database_path": "data/brain.db", "knowledge_dir": "knowledge"})
        self.raw = raw_bundle()

    def tearDown(self):
        self.temporary.cleanup()

    def capture(self, **options):
        return capture_release(self.settings, DOMAIN, VERSION, COMMIT, blob(self.raw), len(self.raw), **options)

    def test_transport_pins_size_blob_and_license_with_public_get_only(self):
        opener = Opener()
        result = self.capture(opener=opener)
        self.assertEqual(len(opener.requests), 2)
        self.assertEqual(opener.requests[0].full_url, release_url(DOMAIN, VERSION, COMMIT))
        self.assertEqual(opener.requests[1].full_url, BASE + COMMIT + "/LICENSE.txt")
        for request in opener.requests:
            self.assertIsNone(request.data)
            self.assertEqual(request.method, "GET")
            self.assertNotIn("Authorization", request.headers)
            self.assertNotIn("Cookie", request.headers)
        self.assertFalse(result["database_written"])
        self.assertFalse(self.settings.database_path.exists())
        with patch.object(socket, "socket", side_effect=AssertionError("offline only")):
            self.assertEqual(read_capture(self.settings, result["manifest"])[0], self.raw)
            report = inspect_capture(self.settings, result["manifest"])
        self.assertEqual(report["requests"], 0)
        self.assertEqual(report["coverage"]["semantic_objects"], 2)

    def test_no_arbitrary_url_or_mutable_ref_is_accepted(self):
        for domain, version, commit in (("../private", VERSION, COMMIT), (DOMAIN, "latest", COMMIT),
                                         (DOMAIN, VERSION, "master"), (DOMAIN, "020.0", COMMIT), (DOMAIN, VERSION, [])):
            with self.subTest(domain=domain, version=version), self.assertRaises(ValueError):
                release_url(domain, version, commit)

    def test_budgets_and_blob_fail_before_network(self):
        for options in ({"max_bytes": True}, {"max_bytes": MAX_BYTES+1}, {"max_seconds": True},
                        {"max_seconds": 301}, {"max_bytes": len(self.raw)-1}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.capture(opener=Opener(), **options)
        with self.assertRaises(ValueError):
            capture_release(self.settings, DOMAIN, VERSION, COMMIT, "bad", len(self.raw), opener=Opener())

    def test_headers_html_gzip_and_false_declared_lengths_rejected(self):
        for headers in ({"Content-Type": "text/html"}, {"Content-Type": "text/plain", "Content-Encoding": "gzip"},
                        {"Content-Type": "application/json", "Content-Length": "1"},
                        {"Content-Type": "text/plain", "Content-Length": "99999999999"}):
            with self.subTest(headers=headers), self.assertRaises(InvalidFeed):
                self.capture(opener=Opener(headers=headers))
        self.assertEqual(list((self.settings.data_dir/"attack-captures").iterdir()), [])

    def test_truncated_oversized_and_wrong_blob_never_get_a_manifest(self):
        for raw in (self.raw[:-1], self.raw+b" ", self.raw.replace(b"Unicode", b"Changed")):
            with self.subTest(size=len(raw)), self.assertRaises(InvalidFeed):
                self.capture(opener=Opener(raw, headers={"Content-Type": "text/plain"}))
        self.assertFalse(list((self.settings.data_dir/"attack-captures").iterdir()))

    def test_deadline_cleanup(self):
        clock = iter([0, 0, 121])
        with self.assertRaisesRegex(InvalidFeed, "deadline"):
            self.capture(opener=Opener(), monotonic=lambda: next(clock))
        self.assertFalse(list((self.settings.data_dir/"attack-captures").iterdir()))

    def test_failed_license_does_not_publish_a_transport_manifest(self):
        for raw in (b"unrelated document", b"MITRE license \0", b"MITRE license \xff"):
            with self.subTest(raw=raw), self.assertRaises(InvalidFeed):
                self.capture(opener=Opener(license_raw=raw))
        self.assertFalse(list((self.settings.data_dir/"attack-captures").iterdir()))

    def test_429_reports_retry_without_retrying_or_leaking_body(self):
        opener = Opener()
        with patch.object(opener, "open", side_effect=HTTPError("https://public.invalid", 429, "private body", {"Retry-After": "17"}, None)) as mocked:
            with self.assertRaises(FetchError) as caught:
                self.capture(opener=opener)
        self.assertEqual((caught.exception.status, caught.exception.retry_after, mocked.call_count), (429, 17, 1))
        self.assertNotIn("private", str(caught.exception))

    def test_network_error_is_stable_and_has_no_completed_artifacts(self):
        opener = Opener()
        with patch.object(opener, "open", side_effect=URLError("secret detail")):
            with self.assertRaisesRegex(FetchError, "^attack_transport_error$"):
                self.capture(opener=opener)
        self.assertFalse(list((self.settings.data_dir/"attack-captures").iterdir()))

    def test_replay_corruption_of_either_file_fails_before_normalization(self):
        for field in ("body", "license"):
            capture = self.capture(opener=Opener())
            path = self.settings.data_dir/"attack-captures"/capture[field]
            raw = path.read_bytes()
            path.write_bytes(b"X" + raw[1:])
            with patch("rabanito.attack.normalize_bundle", side_effect=AssertionError("must verify first")):
                with self.assertRaisesRegex(ValueError, "hash_or_stat"):
                    inspect_capture(self.settings, capture["manifest"])

    def test_manifest_traversal_scope_and_metadata_tampering(self):
        for name in ("../a.metadata.json", "C:/private.json", "a.metadata.json"):
            with self.assertRaises(ValueError):
                read_capture(self.settings, name)
        for field, value in (("body", "../other.json"), ("license", "../other.txt"), ("transport_complete", False),
                             ("schema", True), ("captured_at", "2026-10-17"), ("source_url", "https://example.invalid")):
            capture = self.capture(opener=Opener())
            path = self.settings.data_dir/"attack-captures"/capture["manifest"]
            metadata = json.loads(path.read_text(encoding="utf-8"))
            metadata[field] = value
            path.write_text(json.dumps(metadata), encoding="utf-8")
            with self.subTest(field=field), self.assertRaises(ValueError):
                read_capture(self.settings, capture["manifest"])

    def test_read_only_context_citations_limits_unicode_and_inactive(self):
        capture = self.capture(opener=Opener())
        with patch.object(socket, "socket", side_effect=AssertionError("offline")):
            context = capture_context(self.settings, capture["manifest"], "MEMORIA Unicode", max_chars=17)
            active = capture_context(self.settings, capture["manifest"], "T1001")
            old = capture_context(self.settings, capture["manifest"], "T1001", include_inactive=True)
        self.assertEqual((context["total_matches"], context["used_chars"]), (1, 17))
        fragment = context["fragments"][0]
        self.assertEqual(fragment["citation"], capture["source_url"])
        self.assertEqual(fragment["source_sha256"], capture["sha256"])
        self.assertTrue(fragment["text_truncated"])
        self.assertEqual(active["total_matches"], 0)
        self.assertTrue(old["fragments"][0]["revoked"])
        self.assertFalse(self.settings.database_path.exists())

    def test_context_invalid_arguments_fail_without_reading_files(self):
        for options in ({"kind": "relationship"}, {"limit": True}, {"max_chars": 12001}, {"include_inactive": 1}):
            with self.assertRaises(ValueError):
                capture_context(self.settings, "not-read", "T1000", **options)

    def test_reparse_or_outside_data_folder_fails_before_writes(self):
        outside = Settings(self.root, {"data_dir": str(self.root.parent/"outside-attack")})
        with self.assertRaisesRegex(ValueError, "directory"):
            capture_release(outside, DOMAIN, VERSION, COMMIT, blob(self.raw), len(self.raw), opener=Opener())
        with patch("rabanito.attack_capture.contains_reparse_component", return_value=True):
            with self.assertRaisesRegex(ValueError, "directory"):
                self.capture(opener=Opener())

    def test_collision_does_not_remove_previous_capture(self):
        with patch("rabanito.attack_capture.uuid.uuid4") as ident:
            ident.return_value.hex = "b"*32
            first = self.capture(opener=Opener())
            with self.assertRaisesRegex(ValueError, "collision"):
                self.capture(opener=Opener())
            self.assertEqual(read_capture(self.settings, first["manifest"])[0], self.raw)

    def test_production_opener_blocks_proxies_and_redirects(self):
        with patch("rabanito.attack_capture.build_opener") as build:
            build.return_value = Opener()
            self.capture()
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsInstance(build.call_args.args[1], NoRedirect)

    def test_cli_inspect_and_context_are_real_offline_queries(self):
        capture = self.capture(opener=Opener())
        (self.root/"config").mkdir()
        config = self.root/"config/settings.json"
        config.write_text(json.dumps(self.settings.raw), encoding="utf-8")
        for args in (["inspect", "--capture", capture["manifest"]],
                     ["context", "T1000", "--capture", capture["manifest"], "--max-chars", "19"]):
            output = io.StringIO()
            with patch("sys.argv", ["rabanito", "--config", str(config), "attack", *args]), redirect_stdout(output):
                main()
            result = json.loads(output.getvalue())
            self.assertEqual(result["requests"], 0)
            self.assertFalse(result["database_written"])
