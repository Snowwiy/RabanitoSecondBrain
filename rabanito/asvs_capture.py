"""One official ASVS5.0.0 JSON and license, pinned to reviewed Git metadata."""
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

from .cyber.model import InvalidFeed
from .cyber.transport import FetchError, NoRedirect, _retry_seconds, _unique_object
from .public_capture import transfer, read_checked
from .utils import contains_reparse_component, iso_now, safe_relative, write_json_atomic


VERSION = "5.0.0"
BASE = "https://raw.githubusercontent.com/OWASP/ASVS/"
PATH = "5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
MAX_BYTES, LICENSE_MAX = 2*1024*1024, 65536
MANIFEST = re.compile(r"asvs-5\.0\.0-[0-9a-f]{32}\.metadata\.json\Z")


def source_url(commit):
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("invalid_asvs_commit")
    return BASE+commit+"/"+PATH


def folder(settings):
    path = settings.data_dir/"asvs-captures"
    if safe_relative(path, settings.root) in {None,"","."} or contains_reparse_component(path):
        raise ValueError("unsafe_asvs_capture_directory")
    return path


def capture(settings, commit, blob_sha1, size, license_blob_sha1, license_size, *, opener=None, max_seconds=120, monotonic=time.monotonic):
    url = source_url(commit)
    if (any(not isinstance(v,str) or not re.fullmatch(r"[0-9a-f]{40}",v) for v in (blob_sha1,license_blob_sha1))
            or type(size) is not int or not 1<=size<=MAX_BYTES or type(license_size) is not int or not 1<=license_size<=LICENSE_MAX
            or type(max_seconds) is not int or not 1<=max_seconds<=300):
        raise ValueError("invalid_asvs_capture_budget")
    parent = folder(settings); parent.mkdir(parents=True,exist_ok=True)
    stem = "asvs-5.0.0-"+uuid.uuid4().hex
    body, notice, manifest = parent/(stem+".json"), parent/(stem+".license.md"), parent/(stem+".metadata.json")
    if any(p.exists() for p in (body,notice,manifest)):
        raise ValueError("asvs_capture_collision")
    http, started, created = opener or build_opener(ProxyHandler({}),NoRedirect()), monotonic(), []
    try:
        created.append(body)
        info = transfer(http,url,body,limit=size,expected_size=size,started=started,seconds=max_seconds,monotonic=monotonic,prefix="asvs")
        if info["git_blob_sha1"]!=blob_sha1:
            raise InvalidFeed("asvs_capture_blob_mismatch")
        created.append(notice)
        license_url = BASE+commit+"/LICENSE.md"
        license_info = transfer(http,license_url,notice,limit=license_size,expected_size=license_size,started=started,seconds=max_seconds,monotonic=monotonic,prefix="asvs")
        if license_info["git_blob_sha1"]!=license_blob_sha1:
            raise InvalidFeed("asvs_license_blob_mismatch")
        text = notice.read_text(encoding="utf-8")
        if "Attribution-ShareAlike 4.0 International" not in text or "\0" in text:
            raise InvalidFeed("invalid_asvs_license")
        result = {"schema":1,"provider":"owasp-asvs","version":VERSION,"commit":commit,"source_url":url,
            "body":body.name,**info,"license":notice.name,"license_url":license_url,"license_bytes":license_info["bytes"],
            "license_sha256":license_info["sha256"],"license_git_blob_sha1":license_blob_sha1,"captured_at":iso_now(),
            "transport_complete":True,"requests":2,"database_written":False}
        write_json_atomic(manifest,result)
        return {"manifest":manifest.name,**result}
    except Exception as exc:
        for path in created:
            if path.is_file():path.unlink()
        if isinstance(exc,HTTPError):
            retry = _retry_seconds(exc.headers.get("Retry-After"));exc.close()
            raise FetchError("asvs_http_error",exc.code,retry) from None
        if isinstance(exc,(URLError,TimeoutError,HTTPException)):
            raise FetchError("asvs_transport_error") from None
        raise


def read_capture(settings, name):
    if not isinstance(name,str) or not MANIFEST.fullmatch(name):
        raise ValueError("invalid_asvs_capture_manifest")
    parent = folder(settings);path = parent/name
    if contains_reparse_component(path) or path.stat().st_size>8192:
        raise ValueError("unsafe_asvs_capture_manifest")
    meta = json.loads(path.read_text(encoding="utf-8"),object_pairs_hook=_unique_object)
    stem = name.removesuffix(".metadata.json")
    if (not isinstance(meta,dict) or type(meta.get("schema")) is not int or meta["schema"]!=1 or meta.get("provider")!="owasp-asvs"
            or meta.get("version")!=VERSION or meta.get("transport_complete") is not True
            or meta.get("source_url")!=source_url(meta.get("commit")) or meta.get("body")!=stem+".json"
            or meta.get("license")!=stem+".license.md" or meta.get("license_url")!=BASE+meta["commit"]+"/LICENSE.md"):
        raise ValueError("invalid_asvs_capture_metadata")
    try:
        if datetime.fromisoformat(meta["captured_at"]).tzinfo is None:raise ValueError()
    except (ValueError,TypeError,KeyError):
        raise ValueError("invalid_asvs_capture_date") from None
    raw = read_checked(parent/meta["body"],meta.get("bytes"),meta.get("sha256"),MAX_BYTES,prefix="asvs")
    license_raw = read_checked(parent/meta["license"],meta.get("license_bytes"),meta.get("license_sha256"),LICENSE_MAX,prefix="asvs")
    for value,key in ((raw,"git_blob_sha1"),(license_raw,"license_git_blob_sha1")):
        digest = hashlib.sha1(f"blob {len(value)}\0".encode());digest.update(value)
        if digest.hexdigest()!=meta.get(key):raise ValueError("asvs_capture_blob_mismatch")
    return raw,meta,license_raw.decode("utf-8")
