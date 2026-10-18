"""Bounded public bytes shared by fixed MITRE/OWASP capture adapters.

Internal URLs are constructed by adapters, and checked here again. No arbitrary
hosts, payloads, credentials, proxies, redirects or code execution are supported.
"""
from __future__ import annotations

import hashlib
import os
import re
from urllib.request import Request

from .cyber.model import InvalidFeed
from .utils import contains_reparse_component


URL = re.compile(r"https://raw\.githubusercontent\.com/(?:"
    r"mitre-attack/attack-stix-data/[0-9a-f]{40}/(?:LICENSE\.txt|"
    r"(?:enterprise-attack|mobile-attack|ics-attack)/(?:enterprise-attack|mobile-attack|ics-attack)-[0-9]{1,2}\.[0-9]{1,2}\.json)|"
    r"OWASP/ASVS/[0-9a-f]{40}/(?:LICENSE\.md|5\.0/docs_en/OWASP_Application_Security_Verification_Standard_5\.0\.0_en\.json))\Z")


def transfer(http, url, path, *, limit, expected_size, started, seconds, monotonic, prefix):
    if not isinstance(url, str) or not URL.fullmatch(url) or prefix not in {"attack", "asvs"}:
        raise ValueError("unapproved_public_capture_url")
    def fail(reason):
        raise InvalidFeed(("invalid_" if reason in {"capture_response","capture_stream"} else "") + prefix + "_" + reason)
    if monotonic() - started > seconds:
        fail("capture_deadline")
    request = Request(url, headers={"Accept": "application/json, text/plain", "Accept-Encoding": "identity",
                                   "User-Agent": "RabanitoSecondBrain-public-capture"}, method="GET")
    with http.open(request, timeout=min(25, seconds)) as response:
        if (response.status != 200 or response.headers.get("Content-Encoding", "identity").lower() not in {"", "identity"}
                or response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() not in {"text/plain", "application/json"}):
            fail("capture_response")
        length = response.headers.get("Content-Length")
        if length is not None and (not length.isdigit() or len(length)>10 or not 1<=int(length)<=limit
                                   or expected_size is not None and int(length)!=expected_size):
            fail("capture_declared_length")
        sha256, total = hashlib.sha256(), 0
        git_blob = hashlib.sha1(f"blob {expected_size}\0".encode()) if expected_size is not None else None
        with path.open("xb") as output:
            while True:
                if monotonic()-started>seconds:
                    fail("capture_deadline")
                raw = getattr(response, "read1", response.read)(min(65536, limit-total+1))
                if monotonic()-started>seconds:
                    fail("capture_deadline")
                if not isinstance(raw, bytes):
                    fail("capture_stream")
                if not raw:
                    break
                total += len(raw)
                if total>limit:
                    fail("capture_byte_limit")
                output.write(raw)
                sha256.update(raw)
                if git_blob:
                    git_blob.update(raw)
            output.flush()
            os.fsync(output.fileno())
        if not total or expected_size is not None and total!=expected_size or length is not None and total!=int(length):
            fail("capture_incomplete_transfer")
        return {"bytes": total, "sha256": sha256.hexdigest(), "git_blob_sha1": git_blob.hexdigest() if git_blob else None}


def read_checked(path, size, digest, maximum, *, prefix):
    if (type(size) is not int or not 1<=size<=maximum or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest) or contains_reparse_component(path) or path.stat().st_size!=size):
        raise ValueError("unsafe_or_changed_"+prefix+"_capture")
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno()); raw = stream.read(size+1); after = os.fstat(stream.fileno())
    if ((before.st_size,before.st_mtime_ns,before.st_ino)!=(after.st_size,after.st_mtime_ns,after.st_ino)
            or len(raw)!=size or hashlib.sha256(raw).hexdigest()!=digest):
        raise ValueError(prefix+"_capture_hash_or_stat_mismatch")
    return raw
