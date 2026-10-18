"""Capture one official public uv.lock blob, then rehearse it offline in isolation.

Never runs uv, installs packages, sends local package names, scans user projects,
or replaces the live DB. Outputs aggregate proof, not the dependency inventory.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import uuid
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rabanito.config import Settings, load_settings
from rabanito.cyber.transport import NoRedirect, _unique_object
from rabanito.db import Database, restore_database
from rabanito.dependencies import inspect_manifest
from rabanito.dependency_memory import snapshot_inventory
from rabanito.knowledge_graph import graph_page, sync_graph
from rabanito.utils import contains_reparse_component, iso_now, path_key, safe_relative, write_json_atomic
from rabanito.uv_lock import parse_uv_lock
from scripts.validate_msrc_sync import check_db


DEFAULT_BLOB = "31308b5bda05d7dcab481e3a4b576542a622f321"
MANIFEST = re.compile(r"upstream-[0-9a-f]{32}\.metadata\.json\Z")


def folder(settings):
    path = settings.data_dir / "uv-lock-research"
    if settings.root.resolve() != ROOT or safe_relative(path, ROOT) in {None, "", "."} or contains_reparse_component(path):
        raise ValueError("unsafe_uv_research_root")
    return path


def capture(settings, blob):
    if not isinstance(blob, str) or not re.fullmatch(r"[0-9a-f]{40}", blob):
        raise ValueError("invalid_public_uv_blob")
    url = "https://api.github.com/repos/astral-sh/uv/git/blobs/" + blob
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        with opener.open(Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "Rabanito-public-contract-review"}), timeout=25) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
    except HTTPError as exc:
        status = exc.code; exc.close()
        raise ValueError("public_uv_capture_http_" + str(status)) from None
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("public_uv_response_limit")
    data = json.loads(raw, object_pairs_hook=_unique_object)
    if (not isinstance(data, dict) or data.get("sha") != blob or data.get("encoding") != "base64"
            or type(data.get("size")) is not int or not 0 < data["size"] <= 2 * 1024 * 1024
            or not isinstance(data.get("content"), str)):
        raise ValueError("invalid_public_uv_blob_response")
    body = base64.b64decode(data["content"].replace("\n", "").replace("\r", ""), validate=True)
    if len(body) != data["size"] or hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest() != blob:
        raise ValueError("public_uv_blob_mismatch")
    format_name, components, duplicates, _ = parse_uv_lock(body.decode("utf-8-sig"), 10000)
    target = folder(settings); target.mkdir(parents=True, exist_ok=True)
    stem = "upstream-" + uuid.uuid4().hex
    body_path, manifest = target / (stem + ".uv.lock"), target / (stem + ".metadata.json")
    if body_path.exists() or manifest.exists():
        raise ValueError("uv_capture_collision")
    metadata = {"repository": "astral-sh/uv", "api_url": url, "blob_sha1": blob, "captured_at": iso_now(),
                "body": body_path.name, "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body),
                "format": format_name, "normalized_components": len(components), "duplicates": duplicates,
                "private_content_sent": False, "package_tools_run": False}
    created = False
    try:
        with body_path.open("xb") as stream:
            created = True
            stream.write(body); stream.flush(); os.fsync(stream.fileno())
        write_json_atomic(manifest, metadata)
    except BaseException:
        if created:
            body_path.unlink(missing_ok=True)  # Only this newly created capture, not earlier/user data.
        raise
    return {**metadata, "manifest": manifest.name}


def rehearse(settings, manifest):
    target = folder(settings)
    if not isinstance(manifest, str) or not MANIFEST.fullmatch(manifest):
        raise ValueError("invalid_uv_capture_manifest")
    path = target / manifest
    if contains_reparse_component(path) or path.stat().st_size > 8192:
        raise ValueError("unsafe_uv_manifest")
    metadata = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    expected_name = manifest.removesuffix(".metadata.json") + ".uv.lock"
    if (not isinstance(metadata, dict) or metadata.get("body") != expected_name or type(metadata.get("bytes")) is not int or not 0 < metadata["bytes"] <= 2 * 1024 * 1024
            or not isinstance(metadata.get("blob_sha1"), str) or not re.fullmatch(r"[0-9a-f]{40}", metadata["blob_sha1"])
            or not isinstance(metadata.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", metadata["sha256"])
            or metadata.get("repository") != "astral-sh/uv"
            or metadata.get("api_url") != "https://api.github.com/repos/astral-sh/uv/git/blobs/" + metadata["blob_sha1"]):
        raise ValueError("invalid_uv_capture_metadata")
    body_path = target / expected_name
    if contains_reparse_component(body_path): raise ValueError("unsafe_uv_capture_body")
    with body_path.open("rb") as stream: body = stream.read(2 * 1024 * 1024 + 1)
    if len(body) != metadata["bytes"] or hashlib.sha256(body).hexdigest() != metadata.get("sha256"):
        raise ValueError("uv_capture_hash_mismatch")
    result = {"at": iso_now(), "scope": "isolated_public_upstream_lock_against_copied_real_local_osv",
              "external_requests": 0, "live_database_replaced": False, "capture_sha256": metadata["sha256"]}
    parent = ROOT / "tests/.test-temp"
    if safe_relative(parent, ROOT) in {None, "", "."} or contains_reparse_component(parent):
        raise ValueError("unsafe_uv_rehearsal_temporary_directory")
    parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="uv-public-rehearsal-", dir=parent) as temporary:
        temp = Path(temporary); project = temp / "projects/UpstreamPublicUv"; project.mkdir(parents=True)
        selected = project / "uv.lock"; selected.write_bytes(body)
        copied = temp / "copy.db"
        with Database(settings.database_path, read_only=True) as db: db.backup(copied)
        isolated = Settings(ROOT, {**settings.raw, "database_path": str(copied), "data_dir": str(temp / "data"),
                                   "projects_root": str(temp / "projects")})
        with Database(copied) as db:
            db.execute("INSERT INTO projects(name,root_path,path_key,first_seen,last_seen,status) VALUES (?,?,?,?,?,'active')",
                       (project.name, str(project), path_key(project), iso_now(), iso_now()))
        report = inspect_manifest(isolated, str(project), "uv.lock")
        saved = snapshot_inventory(isolated, str(project), "uv.lock", kind="manifest", save=True)
        reused = inspect_manifest(isolated, str(project), "uv.lock")
        if report["analysis_id"] != reused["analysis_id"] or reused["cache"]["status"] != "reused_saved_analysis":
            raise ValueError("uv_rehearsal_reuse_failed")
        result.update(components=report["component_count"], duplicates_removed=report["duplicates_removed"],
                      summary=report["summary"], findings=len(report["findings"]), format=report["source"]["format"],
                      observed_local_osv=report["coverage"]["examined"], saved_in_temporary_copy=True, reused=True)
        for _ in range(64):
            batch = sync_graph(isolated, max_inputs=2000)
            if batch["errors"]: raise ValueError("uv_rehearsal_graph_error")
            if batch["status"] == "ok": break
        else: raise ValueError("uv_rehearsal_graph_not_converged")
        result["project_dependency_nodes_first_page"] = len(graph_page(isolated, kind="dependency", project=str(project), limit=100)["nodes"])
        backup, restored = temp / "backup.db", temp / "restored.db"
        result["database"] = check_db(copied)
        with Database(copied, read_only=True) as db: db.backup(backup)
        restore_database(backup, restored)
        result["restore"] = check_db(restored)
        recovered = Settings(ROOT, {**isolated.raw, "database_path": str(restored)})
        result["restored_analysis_id_equal"] = inspect_manifest(recovered, str(project), "uv.lock")["analysis_id"] == report["analysis_id"]
        if not result["restored_analysis_id_equal"]: raise ValueError("uv_rehearsal_restore_mismatch")
        if selected.read_bytes() != body: raise ValueError("uv_rehearsal_modified_original")
    result["temporary_copy_cleaned"] = True
    write_json_atomic(settings.data_dir / "uv-lock-rehearsal.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    download = commands.add_parser("capture"); download.add_argument("--blob", default=DEFAULT_BLOB)
    offline = commands.add_parser("rehearse"); offline.add_argument("manifest")
    args = parser.parse_args(); settings = load_settings()
    try:
        print(json.dumps(capture(settings, args.blob) if args.action == "capture" else rehearse(settings, args.manifest), ensure_ascii=True, indent=2))
    except (ValueError, OSError) as exc:
        code = str(exc) if isinstance(exc, ValueError) and re.fullmatch(r"[a-z0-9_]+", str(exc)) else "uv_rehearsal_invalid_data_or_io"
        print(json.dumps({"error": code}))
        raise SystemExit(1) from None
