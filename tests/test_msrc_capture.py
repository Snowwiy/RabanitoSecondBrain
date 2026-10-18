from __future__ import annotations

import io
import gzip
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rabanito.config import Settings
from rabanito.cyber.model import InvalidFeed
from rabanito.cyber.msrc_capture import capture_month, normalize_capture
from tests.test_msrc import cvrf


class Response(io.BytesIO):
    status = 200
    headers = {"Content-Type": "application/json"}


class Opener:
    def __init__(self, raw=None, headers=None):
        self.raw, self.headers = raw or json.dumps(cvrf()).encode(), headers
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        result = Response(self.raw)
        if self.headers is not None:
            result.headers = self.headers
        return result


class MsrcCaptureTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parent / ".test-temp"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="capture-msrc-", dir=parent)
        self.root = Path(self.temporary.name)
        self.settings = Settings(self.root, {"data_dir": "data"})

    def tearDown(self):
        self.temporary.cleanup()

    def test_capture_then_offline_normalization_without_network_or_database(self):
        opener = Opener()
        capture = capture_month(self.settings, "2026-Oct", opener=opener)
        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(opener.requests[0].method, "GET")
        self.assertFalse(capture["envelope_validated"])
        with patch("socket.socket", side_effect=AssertionError("offline only")):
            result = normalize_capture(self.settings, capture["manifest"], save_records=True)
        self.assertEqual(result["record_count"], 1)
        self.assertEqual(result["requests"], 0)
        self.assertFalse(result["database_written"])
        self.assertEqual(list(self.root.rglob("*.db")), [])

    def test_failed_transfer_cleans_only_new_partial_and_preserves_existing_capture(self):
        first = capture_month(self.settings, "2026-Oct", opener=Opener())
        with self.assertRaisesRegex(InvalidFeed, "byte_limit"):
            capture_month(self.settings, "2026-Oct", opener=Opener(), max_bytes=10)
        folder = self.settings.data_dir / "msrc-captures"
        self.assertEqual(list(folder.glob("*.partial")), [])
        self.assertTrue((folder / first["body"]).is_file())

    def test_declared_length_and_content_type_are_checked(self):
        for headers in ({"Content-Type": "text/html"}, {"Content-Type": "application/json", "Content-Length": "999999999999999"},
                        {"Content-Type": "application/json", "Content-Length": "1"}, {"Content-Type": "application/json", "Content-Encoding": "gzip"}):
            with self.subTest(headers=headers), self.assertRaises(InvalidFeed):
                capture_month(self.settings, "2026-Oct", opener=Opener(headers=headers))

    def test_corrupt_capture_never_reaches_normalizer(self):
        capture = capture_month(self.settings, "2026-Oct", opener=Opener())
        path = self.settings.data_dir / "msrc-captures" / capture["body"]
        path.write_bytes(path.read_bytes().replace(b"Fixture", b"Changed"))
        with patch("rabanito.cyber.msrc_capture.normalize_stream", side_effect=AssertionError("must reject before normalization")):
            with self.assertRaisesRegex(ValueError, "hash_mismatch"):
                normalize_capture(self.settings, capture["manifest"])

    def test_paths_and_false_budgets_are_rejected(self):
        for name in ("../secrets.json", "C:/private.json", "x.metadata.json"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                normalize_capture(self.settings, name)
        for options in ({"max_bytes": True}, {"max_seconds": 301}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                capture_month(self.settings, "2026-Oct", opener=Opener(), **options)

    def test_timeout_cleans_partial(self):
        ticks = iter([0, 0, 121])
        with self.assertRaisesRegex(InvalidFeed, "deadline"):
            capture_month(self.settings, "2026-Oct", opener=Opener(), monotonic=lambda: next(ticks))
        self.assertEqual(list((self.settings.data_dir / "msrc-captures").iterdir()), [])

    def test_invalid_json_capture_is_quarantined_not_published_or_normalized(self):
        capture = capture_month(self.settings, "2026-Oct", opener=Opener(raw=b'{"incomplete":'))
        self.assertTrue(capture["transport_complete"])
        with self.assertRaises(InvalidFeed):
            normalize_capture(self.settings, capture["manifest"])
        self.assertEqual(list(self.root.rglob("*.db")), [])

    def test_gzip_capture_is_bounded_and_verified_before_offline_use(self):
        raw = json.dumps(cvrf()).encode()
        capture = capture_month(self.settings, "2026-Oct", opener=Opener(raw=gzip.compress(raw), headers={"Content-Type": "application/json", "Content-Encoding": "gzip"}), compressed=True)
        self.assertEqual(capture["bytes"], len(raw))
        self.assertLess(capture["wire_bytes"], capture["bytes"])
        self.assertEqual(normalize_capture(self.settings, capture["manifest"], profile_stats=True)["record_count"], 1)
        self.assertTrue(list((self.settings.data_dir / "msrc-captures").glob("*.profile.json")))

    def test_gzip_bombs_truncation_and_trailing_data_fail_without_capture(self):
        compressed = gzip.compress(b"x" * 100000)
        for raw, cap in ((compressed, 512), (compressed[:-4], 200000), (compressed + b"trailing", 200000)):
            with self.subTest(cap=cap), self.assertRaises(InvalidFeed):
                capture_month(self.settings, "2026-Oct", opener=Opener(raw=raw, headers={"Content-Type": "application/json", "Content-Encoding": "gzip"}), compressed=True, max_bytes=cap)
        self.assertEqual(list((self.settings.data_dir / "msrc-captures").iterdir()), [])

    def test_retry_after_is_recorded_and_prevents_another_request(self):
        from urllib.error import HTTPError
        from rabanito.cyber.transport import FetchError
        class Limited:
            calls = 0
            def open(self, *args, **kwargs):
                self.calls += 1
                raise HTTPError("https://api.msrc.microsoft.com", 429, "fixture", {"Retry-After": "300"}, None)
        limited = Limited()
        with self.assertRaises(FetchError) as error:
            capture_month(self.settings, "2026-Oct", opener=limited)
        self.assertEqual(error.exception.status, 429)
        self.assertEqual(error.exception.retry_after, 300)
        with self.assertRaisesRegex(FetchError, "provider_cooldown"):
            capture_month(self.settings, "2026-Oct", opener=limited)
        self.assertEqual(limited.calls, 1)

    def test_interrupted_chunked_stream_is_cleaned_and_typed(self):
        from http.client import IncompleteRead
        from rabanito.cyber.transport import FetchError
        class Broken(Response):
            def read1(self, size=-1):
                raise IncompleteRead(b"partial", 10)
        class Open:
            def open(self, *args, **kwargs):
                return Broken(b"data")
        with self.assertRaisesRegex(FetchError, "incomplete_transfer"):
            capture_month(self.settings, "2026-Oct", opener=Open())
        self.assertEqual(list((self.settings.data_dir / "msrc-captures").iterdir()), [])

    def test_manifest_cannot_cross_month_or_supply_another_path(self):
        capture = capture_month(self.settings, "2026-Oct", opener=Opener())
        path = self.settings.data_dir / "msrc-captures" / capture["manifest"]
        original = json.loads(path.read_text(encoding="utf-8"))
        for edit in ({"body": "../secret.json"}, {"month": "2026-Sep"}, {"source_url": "https://unapproved.invalid/feed"}):
            path.write_text(json.dumps({**original, **edit}), encoding="utf-8")
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                normalize_capture(self.settings, capture["manifest"])

    def test_capture_directory_must_stay_inside_project(self):
        other = Settings(self.root, {"data_dir": "../outside"})
        with self.assertRaisesRegex(ValueError, "unsafe_msrc_capture_directory"):
            capture_month(other, "2026-Oct", opener=Opener())

    def test_unicode_and_spaced_data_directory(self):
        settings = Settings(self.root, {"data_dir": "data ñ with spaces"})
        capture = capture_month(settings, "2026-Oct", opener=Opener())
        self.assertEqual(normalize_capture(settings, capture["manifest"])["record_count"], 1)

    def test_growing_capture_cannot_make_hash_verification_unbounded(self):
        capture = capture_month(self.settings, "2026-Oct", opener=Opener())
        body = self.settings.data_dir / "msrc-captures" / capture["body"]
        original_open = Path.open
        class Growing:
            def __enter__(self):
                self.handle = original_open(body, "rb")
                return self
            def __exit__(self, *args):
                self.handle.close()
            def fileno(self):
                return self.handle.fileno()
            def read(self, size):
                return b"x" * size  # A source that never reaches EOF.
        def open_path(path, mode="r", *args, **kwargs):
            return Growing() if path == body and mode == "rb" else original_open(path, mode, *args, **kwargs)
        with patch.object(Path, "open", open_path), self.assertRaisesRegex(ValueError, "verification_byte_limit"):
            normalize_capture(self.settings, capture["manifest"])
