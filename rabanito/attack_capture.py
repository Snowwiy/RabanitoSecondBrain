"""Explicit, commit-pinned public data capture; never publishes to SQLite.

Only the official MITRE STIX-data repository is accessed. No SDK, TAXII client,
credentials, proxy, redirects, private queries or automatic polling are used.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from datetime import datetime
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, build_opener

from .config import Settings
from .cyber.model import InvalidFeed
from .cyber.transport import FetchError, NoRedirect, _retry_seconds, _unique_object
from .utils import contains_reparse_component, iso_now, safe_relative, write_json_atomic
from .public_capture import transfer, read_checked


MAX_BYTES = 64 * 1024 * 1024
LICENSE_MAX = 16384
DOMAINS = ("enterprise-attack", "mobile-attack", "ics-attack")
VERSION = re.compile(r"(?:0|[1-9][0-9]?)\.(?:0|[1-9][0-9]?)\Z")
SHA1 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MANIFEST = re.compile(r"(enterprise-attack|mobile-attack|ics-attack)-([0-9]{1,2}\.[0-9]{1,2})-[0-9a-f]{32}\.metadata\.json\Z")
BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"


def release_url(domain: str, version: str, commit: str) -> str:
    if (domain not in DOMAINS or not isinstance(version, str) or not VERSION.fullmatch(version)
            or not isinstance(commit, str) or not SHA1.fullmatch(commit)):
        raise ValueError("invalid_attack_release_identity")
    return f"{BASE}{commit}/{domain}/{domain}-{version}.json"


def _folder(settings: Settings):
    path = settings.data_dir / "attack-captures"
    if safe_relative(path, settings.root) in {None, "", "."} or contains_reparse_component(path):
        raise ValueError("unsafe_attack_capture_directory")
    return path


def _transfer(http, url, path, *, limit, expected_size, started, seconds, monotonic):
    return transfer(http, url, path, limit=limit, expected_size=expected_size, started=started,
                    seconds=seconds, monotonic=monotonic, prefix="attack")


def capture_release(settings: Settings, domain: str, version: str, commit: str, blob_sha1: str, size: int,
                    *, opener=None, max_bytes=MAX_BYTES, max_seconds=120, monotonic=time.monotonic) -> dict:
    """Capture one explicit release and its license, manifest published last.

    Commit/blob/size must first be reviewed from the official repository API.
    No retry is implicit: a failed/429 call has no completed capture to replay.
    """
    url = release_url(domain, version, commit)
    if (not isinstance(blob_sha1, str) or not SHA1.fullmatch(blob_sha1)
            or type(max_bytes) is not int or not 1 <= max_bytes <= MAX_BYTES
            or type(size) is not int or not 1 <= size <= max_bytes
            or type(max_seconds) is not int or not 1 <= max_seconds <= 300):
        raise ValueError("invalid_attack_capture_budget")
    folder = _folder(settings)
    folder.mkdir(parents=True, exist_ok=True)
    stem = f"{domain}-{version}-{uuid.uuid4().hex}"
    body, license_path, manifest = folder / (stem + ".json"), folder / (stem + ".license.txt"), folder / (stem + ".metadata.json")
    # Never remove an existing file, even if a UUID collision is forced.
    if any(p.exists() for p in (body, license_path, manifest)):
        raise ValueError("attack_capture_collision")
    http, started = opener or build_opener(ProxyHandler({}), NoRedirect()), monotonic()
    created = []
    try:
        created.append(body)
        info = _transfer(http, url, body, limit=size, expected_size=size, started=started,
                         seconds=max_seconds, monotonic=monotonic)
        if info["git_blob_sha1"] != blob_sha1:
            raise InvalidFeed("attack_capture_blob_mismatch")
        created.append(license_path)
        license_url = BASE + commit + "/LICENSE.txt"
        license_info = _transfer(http, license_url, license_path, limit=LICENSE_MAX, expected_size=None,
                                 started=started, seconds=max_seconds, monotonic=monotonic)
        try:
            license_text = license_path.read_text(encoding="utf-8")
        except UnicodeError:
            raise InvalidFeed("invalid_attack_license_utf8") from None
        if "MITRE" not in license_text or "license" not in license_text.lower() or "\0" in license_text:
            raise InvalidFeed("invalid_attack_license_notice")
        result = {"schema": 1, "domain": domain, "version": version, "commit": commit, "source_url": url,
                  "body": body.name, **info, "license": license_path.name, "license_url": license_url,
                  "license_bytes": license_info["bytes"], "license_sha256": license_info["sha256"],
                  "captured_at": iso_now(), "transport_complete": True, "requests": 2,
                  "database_written": False}
        write_json_atomic(manifest, result)
        return {"manifest": manifest.name, **result}
    except Exception as exc:
        for path in created:
            if path.is_file():
                path.unlink()
        if isinstance(exc, HTTPError):
            retry = _retry_seconds(exc.headers.get("Retry-After"))
            exc.close()
            raise FetchError("attack_http_error", exc.code, retry) from None
        if isinstance(exc, (URLError, TimeoutError, HTTPException)):
            raise FetchError("attack_transport_error") from None
        raise


def _read_checked(path, size, digest, maximum):
    return read_checked(path, size, digest, maximum, prefix="attack")


def read_capture(settings: Settings, manifest_name: str) -> tuple[bytes, dict]:
    """Verify both byte-pinned files offline, before any normalization."""
    if not isinstance(manifest_name, str) or not (match := MANIFEST.fullmatch(manifest_name)):
        raise ValueError("invalid_attack_capture_manifest")
    folder = _folder(settings)
    path = folder / manifest_name
    if contains_reparse_component(path) or path.stat().st_size > 8192:
        raise ValueError("unsafe_attack_capture_manifest")
    metadata = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    stem = manifest_name.removesuffix(".metadata.json")
    if (not isinstance(metadata, dict) or type(metadata.get("schema")) is not int or metadata["schema"] != 1
            or metadata.get("transport_complete") is not True or metadata.get("domain") != match[1]
            or metadata.get("version") != match[2] or metadata.get("body") != stem + ".json"
            or metadata.get("license") != stem + ".license.txt"
            or metadata.get("source_url") != release_url(match[1], match[2], metadata.get("commit"))
            or metadata.get("license_url") != BASE + metadata["commit"] + "/LICENSE.txt"
            or not isinstance(metadata.get("git_blob_sha1"), str) or not SHA1.fullmatch(metadata["git_blob_sha1"])):
        raise ValueError("invalid_attack_capture_metadata")
    try:
        when = datetime.fromisoformat(metadata["captured_at"])
        if when.tzinfo is None:
            raise ValueError()
    except (ValueError, TypeError, KeyError):
        raise ValueError("invalid_attack_capture_date") from None
    raw = _read_checked(folder / metadata["body"], metadata.get("bytes"), metadata.get("sha256"), MAX_BYTES)
    git_blob = hashlib.sha1(f"blob {len(raw)}\0".encode())
    git_blob.update(raw)
    if git_blob.hexdigest() != metadata["git_blob_sha1"]:
        raise ValueError("attack_capture_blob_mismatch")
    _read_checked(folder / metadata["license"], metadata.get("license_bytes"), metadata.get("license_sha256"), LICENSE_MAX)
    return raw, metadata
