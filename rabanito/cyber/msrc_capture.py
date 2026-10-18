"""Quarantined public captures. Validation alone never publishes to SQLite."""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
import zlib
from http.client import HTTPException
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

from ..config import Settings
from ..utils import contains_reparse_component, iso_now, safe_relative, write_json_atomic
from .model import InvalidFeed
from .msrc import document_url, normalize_stream
from .transport import FetchError, NoRedirect, _retry_seconds, _unique_object


MAX_BYTES = 64 * 1024 * 1024
MANIFEST = re.compile(r"20\d{2}-[A-Z][a-z]{2}-[0-9a-f]{32}\.metadata\.json\Z")


def _folder(settings: Settings) -> Path:
    folder = settings.data_dir / "msrc-captures"
    if safe_relative(folder, settings.root) in {None, "", "."} or contains_reparse_component(folder):
        raise ValueError("unsafe_msrc_capture_directory")
    return folder


def capture_month(settings: Settings, month: str, *, opener=None, max_bytes=MAX_BYTES, max_seconds=120,
                  monotonic=time.monotonic, progress=None, compressed=False) -> dict:
    url = document_url(month)
    if (type(max_bytes) is not int or not 1 <= max_bytes <= MAX_BYTES or type(max_seconds) is not int or not 1 <= max_seconds <= 300
            or type(compressed) is not bool):
        raise ValueError("invalid_msrc_capture_budget")
    folder = _folder(settings)
    folder.mkdir(parents=True, exist_ok=True)
    cooldown = folder / "provider-cooldown.json"
    if cooldown.is_file():
        if contains_reparse_component(cooldown) or cooldown.stat().st_size > 2048:
            raise ValueError("unsafe_msrc_cooldown_metadata")
        stored = json.loads(cooldown.read_text(encoding="utf-8"))
        if datetime.now(timezone.utc) < datetime.fromisoformat(stored["retry_at"]):
            raise FetchError("msrc_provider_cooldown")
    stem = month + "-" + uuid.uuid4().hex
    target, partial = folder / (stem + ".json"), folder / (stem + ".partial")
    created, renamed = False, False
    started, total, wire_bytes, digest, notified = monotonic(), 0, 0, hashlib.sha256(), 0
    wire_limit = min(max_bytes, 16*1024*1024) if compressed else max_bytes
    decoder = zlib.decompressobj(16+zlib.MAX_WBITS) if compressed else None
    http = opener or build_opener(ProxyHandler({}), NoRedirect())
    request = Request(url, headers={"Accept": "application/json", "Accept-Encoding": "gzip" if compressed else "identity",
                                   "User-Agent": "RabanitoSecondBrain-public-capture"}, method="GET")
    try:
        with http.open(request, timeout=25) as response:
            opened = monotonic()
            encoding = response.headers.get("Content-Encoding", "identity").lower()
            if (response.status != 200 or encoding not in ({"gzip"} if compressed else {"identity", ""})
                    or response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() not in {"application/json", "text/json"}):
                raise InvalidFeed("invalid_msrc_capture_response")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdigit() or len(length) > 12 or int(length) > wire_limit):
                raise InvalidFeed("msrc_capture_declared_length_limit")
            if progress:
                progress({"phase": "headers", "seconds": round(opened-started, 3)})
            with partial.open("xb") as output:
                created = True
                while True:
                    if monotonic() - started > max_seconds:
                        raise InvalidFeed("msrc_capture_deadline")
                    raw = getattr(response, "read1", response.read)(min(65536, wire_limit-wire_bytes+1))
                    if not isinstance(raw, bytes):
                        raise InvalidFeed("invalid_msrc_capture_stream")
                    if not raw:
                        break
                    wire_bytes += len(raw)
                    if wire_bytes > wire_limit:
                        raise InvalidFeed("msrc_capture_wire_byte_limit")
                    pending = raw
                    while pending:
                        try:
                            decoded = decoder.decompress(pending, min(65536, max_bytes-total+1)) if decoder else pending
                        except zlib.error:
                            raise InvalidFeed("invalid_msrc_gzip") from None
                        pending = decoder.unconsumed_tail if decoder else b""
                        total += len(decoded)
                        if total > max_bytes:
                            raise InvalidFeed("msrc_capture_byte_limit")
                        digest.update(decoded); output.write(decoded)
                        if decoder and decoder.unused_data:
                            raise InvalidFeed("trailing_msrc_gzip_data")
                    if progress and total // (4*1024*1024) > notified:
                        notified = total // (4*1024*1024)
                        progress({"phase": "transfer", "bytes": total, "wire_bytes": wire_bytes, "seconds": round(monotonic()-opened, 3)})
                if decoder and not decoder.eof:
                    raise InvalidFeed("incomplete_msrc_gzip")
                if not total or length is not None and wire_bytes != int(length):
                    raise InvalidFeed("msrc_capture_incomplete_length")
                output.flush(); os.fsync(output.fileno())
            if target.exists():
                raise ValueError("msrc_capture_collision")
            partial.rename(target); renamed = True
        result = {"month": month, "source_url": url, "captured_at": iso_now(), "body": target.name,
                  "sha256": digest.hexdigest(), "bytes": total, "transport_complete": True, "envelope_validated": False,
                  "open_seconds": round(opened-started, 3), "transfer_seconds": round(monotonic()-opened, 3),
                  "requests": 1, "wire_bytes": wire_bytes, "encoding": encoding, "database_written": False}
        manifest = stem + ".metadata.json"
        write_json_atomic(folder / manifest, result)
        return {**result, "manifest": manifest}
    except BaseException as exc:
        # Only these freshly created UUID artifacts belong to this operation.
        if created:
            partial.unlink(missing_ok=True)
        if renamed:
            target.unlink(missing_ok=True)
        if isinstance(exc, HTTPError):
            status = exc.code
            retry = _retry_seconds(exc.headers.get("Retry-After"))
            exc.close()
            if retry:
                write_json_atomic(cooldown, {"retry_at": (datetime.now(timezone.utc)+timedelta(seconds=retry)).isoformat(), "status": status})
            raise FetchError("msrc_http_error", status, retry) from None
        if isinstance(exc, (URLError, TimeoutError)):
            raise FetchError("msrc_network_error") from None
        if isinstance(exc, HTTPException):
            raise FetchError("msrc_incomplete_transfer") from None
        raise


def read_capture(settings: Settings, manifest_name: str, *, profile_stats=False) -> tuple[dict, dict, dict]:
    """Hash and normalize the original body, not a cached normalized artifact."""
    if (not isinstance(manifest_name, str) or not MANIFEST.fullmatch(manifest_name)
            or type(profile_stats) is not bool):
        raise ValueError("invalid_msrc_capture_manifest_name")
    folder = _folder(settings)
    manifest_path = folder / manifest_name
    if contains_reparse_component(manifest_path) or manifest_path.stat().st_size > 8192:
        raise ValueError("unsafe_msrc_capture_manifest")
    metadata = json.loads(manifest_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    body_name = manifest_name.removesuffix(".metadata.json") + ".json"
    if (not isinstance(metadata, dict) or metadata.get("body") != body_name or metadata.get("transport_complete") is not True
            or metadata.get("month") != manifest_name.removesuffix(".metadata.json").rsplit("-", 1)[0]
            or metadata.get("source_url") != document_url(metadata.get("month"))
            or type(metadata.get("bytes")) is not int or not 1 <= metadata["bytes"] <= MAX_BYTES
            or not isinstance(metadata.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", metadata["sha256"])):
        raise ValueError("invalid_msrc_capture_metadata")
    path = folder / body_name
    if contains_reparse_component(path) or path.stat().st_size != metadata["bytes"]:
        raise ValueError("unsafe_or_changed_msrc_capture_body")
    started, digest = time.perf_counter(), hashlib.sha256()
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        checked_bytes = 0
        for raw in iter(lambda: stream.read(65536), b""):
            checked_bytes += len(raw)
            if checked_bytes > metadata["bytes"]:
                raise ValueError("msrc_capture_verification_byte_limit")
            digest.update(raw)
        if checked_bytes != metadata["bytes"] or digest.hexdigest() != metadata["sha256"]:
            raise ValueError("msrc_capture_hash_mismatch")
        hash_seconds = time.perf_counter()-started
        stream.seek(0)
        wall, cpu = time.perf_counter(), time.process_time()
        import cProfile
        profiler = cProfile.Profile() if profile_stats else None
        try:
            if profiler:
                profiler.enable()
            normalized = normalize_stream(stream, metadata["month"])
        finally:
            if profiler:
                profiler.disable()
                stats = [{"function": item.code.co_name if hasattr(item.code, "co_name") else str(item.code),
                          "file": Path(item.code.co_filename).name if hasattr(item.code, "co_filename") else "builtin",
                          "calls": item.callcount, "cumulative_seconds": round(item.totaltime, 6),
                          "exclusive_seconds": round(item.inlinetime, 6)} for item in profiler.getstats()]
                write_json_atomic(folder / (body_name.removesuffix(".json") + ".profile.json"), sorted(stats, key=lambda item: -item["cumulative_seconds"])[:100])
        elapsed, cpu_seconds = time.perf_counter()-wall, time.process_time()-cpu
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
            raise ValueError("msrc_capture_changed_during_normalization")
    timings = {"hash_seconds": round(hash_seconds, 3), "normalization_wall_seconds": round(elapsed, 3),
               "normalization_cpu_seconds": round(cpu_seconds, 3)}
    return normalized, metadata, timings


def normalize_capture(settings: Settings, manifest_name: str, *, save_records=False, profile_stats=False) -> dict:
    if type(save_records) is not bool:
        raise ValueError("invalid_msrc_capture_manifest_name")
    normalized, metadata, timings = read_capture(settings, manifest_name, profile_stats=profile_stats)
    folder, body_name = _folder(settings), metadata["body"]
    from collections import Counter
    records = normalized["records"]
    result = {"manifest": manifest_name, "normalized_at": iso_now(), "month": metadata["month"],
              "capture_sha256": metadata["sha256"], "capture_bytes": metadata["bytes"], **timings,
              "record_count": len(records), "record_kinds": dict(Counter(r["record_kind"] for r in records)),
              "numeric_metrics": sum(m["score"] is not None for r in records for m in r["metrics"]),
              "vendor_fix_records": sum(bool(r["fixes"]) for r in records),
              "exploitation_reports": sum(r["exploitation_reported"] for r in records), "coverage": normalized["coverage"],
              "requests": 0, "database_written": False}
    if save_records:
        name = body_name.removesuffix(".json") + ".normalized.json"
        write_json_atomic(folder / name, normalized)
        result["normalized_artifact"] = name
    write_json_atomic(folder / (body_name.removesuffix(".json") + ".normalization-report.json"), result)
    return result
