"""Offline real-document HTTP/restore validation. Never prints document bodies.

Optional frontend checkout inspection is strictly read-only. No browser, merge,
source writes, index refresh, provider requests or existing-server replacement.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rabanito.config import Settings, load_settings
from rabanito.db import Database, restore_database
from rabanito.document_content import DocumentContentError, _authorize, _open_readonly, document_content
from rabanito.server import RabanitoHandler, ThreadingHTTPServer
from rabanito.utils import contains_reparse_component, iso_now, safe_relative, write_json_atomic
from scripts.validate_attack_index import check_attack_db


def originals(settings):
    result = {}
    with Database(settings.database_path, read_only=True) as db:
        projects = db.query("SELECT root_path,status FROM projects")
        rows = db.query("SELECT * FROM documents WHERE status='active' AND source_kind IN ('obsidian','projects') ORDER BY source_kind,absolute_path")
        for kind in ("obsidian", "projects"):
            digest, count = hashlib.sha256(), 0
            for row in rows:
                if row["source_kind"] != kind:
                    continue
                path = _authorize(settings, row, projects)
                if path.stat().st_size > 2_097_152:
                    raise ValueError("original_hash_file_budget")
                with _open_readonly(path) as stream:
                    body = stream.read(2_097_153)
                if len(body) > 2_097_152:
                    raise ValueError("original_hash_changed_size")
                digest.update(str(path).encode("utf-8")); digest.update(hashlib.sha256(body).digest())
                count += 1
            result[kind] = {"files": count, "sha256": digest.hexdigest()}
    return result


def frontend_snapshot(root):
    root = root.absolute()
    if root == ROOT or not root.is_dir() or contains_reparse_component(root):
        raise ValueError("invalid_readonly_frontend_checkout")
    def git(*args):
        return subprocess.check_output(["git", "--no-optional-locks", "-C", str(root), *args])
    paths = sorted(set(v.decode("utf-8") for v in git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0") if v))
    digest = hashlib.sha256()
    for name in paths:
        path = root / name
        if (safe_relative(path, root) in {None, "", "."} or contains_reparse_component(path)
                or not path.is_file() or path.stat().st_size > 3 * 1024 * 1024):
            raise ValueError("unsafe_frontend_inventory")
        digest.update(name.encode("utf-8")); digest.update(hashlib.sha256(path.read_bytes()).digest())
    return {"branch": git("branch", "--show-current").decode().strip(), "head": git("rev-parse", "HEAD").decode().strip(),
            "files": len(paths), "sha256": digest.hexdigest(), "status": git("status", "--porcelain").decode(),
            "contract_sha256": hashlib.sha256((root / "FRONTEND_BACKEND_CONTRACT.md").read_bytes()).hexdigest()}


def reader_compatibility(root, payloads):
    # The frontend's exported pure parser is loaded in memory; no DOM/browser,
    # server, generated UI file, dependency installation or UI initialization.
    source = (root / "web/knowledge.js").read_text(encoding="utf-8")
    if not source.startswith("import {createRequestGate, requestJson, safeReference} from './cyber.js';"):
        raise ValueError("frontend_import_contract_changed")
    code = r"""
import {readFileSync} from 'node:fs';
const input=JSON.parse(readFileSync(0,'utf8'));
const cyber='data:text/javascript;base64,'+Buffer.from(input.cyber).toString('base64');
const source=input.source.replace("'./cyber.js'",JSON.stringify(cyber));
const module=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
for(const p of input.payloads){
 if(!Number.isSafeInteger(p.document_id)||typeof p.content_markdown!=='string'||!Array.isArray(p.references)||p.references.length>512||typeof p.truncated!=='boolean'||!Number.isSafeInteger(p.bytes_returned))throw Error('shape');
 const bytes=new TextEncoder().encode(p.content_markdown).byteLength;
 if(bytes!==p.bytes_returned||bytes>65536)throw Error('budget');
 const tree=module.parseSafeMarkdown(p.content_markdown,p.references);
 if(!Array.isArray(tree)||!tree.length)throw Error('empty parser result');
}
console.log(JSON.stringify({responses:input.payloads.length,shape:true,byte_counts:true,pure_parser:true,browser_qa:false}));
"""
    completed = subprocess.run(["node", "--input-type=module", "-e", code],
        input=json.dumps({"source": source, "cyber": (root / "web/cyber.js").read_text(encoding="utf-8"),
                          "payloads": payloads}, ensure_ascii=True), text=True,
        capture_output=True, cwd=ROOT, timeout=20)
    if completed.returncode:
        raise ValueError("frontend_reader_compatibility_failed")
    return json.loads(completed.stdout)


def validate(frontend_root=None):
    settings = load_settings()
    if (settings.root.resolve() != ROOT or contains_reparse_component(settings.database_path)
            or safe_relative(settings.database_path, ROOT) in {None, "", "."}):
        raise ValueError("unexpected_document_validation_root")
    started = time.perf_counter()
    report = {"at": iso_now(), "external_provider_requests": 0, "sources_written": False,
              "live_database_replaced": False, "browser_used": False}
    report["originals_before"] = originals(settings)
    before_ui = frontend_snapshot(frontend_root) if frontend_root else None
    with Database(settings.database_path, read_only=True) as db:
        rows = db.query("""SELECT document_id,source_kind,size_bytes FROM documents d WHERE status='active'
            ORDER BY CASE WHEN source_kind='obsidian' AND EXISTS(SELECT 1 FROM links l
            WHERE l.source_document_id=d.document_id AND l.status='resolved') THEN 0 ELSE 1 END,
            size_bytes,document_id""")
        report["integrity"] = db.one("PRAGMA integrity_check")[0]
        report["fk_errors"] = len(db.query("PRAGMA foreign_key_check"))
        report["counts"] = {"documents": db.one("SELECT count(*) FROM documents WHERE status='active'")[0],
            "resolved_links": db.one("SELECT count(*) FROM links WHERE status='resolved'")[0],
            "projects": db.one("SELECT count(*) FROM projects WHERE status='active'")[0]}
    payloads, selected = [], []
    for kind in ("obsidian", "projects", "internal"):
        for row in rows:
            if row["source_kind"] != kind or not 80 <= row["size_bytes"] <= 65536:
                continue
            try:
                result = document_content(settings, row["document_id"], 65536)
            except DocumentContentError:
                continue
            if result["content_markdown"]:
                selected.append((kind, row["document_id"])); payloads.append(result); break
        else:
            raise ValueError("no_real_authorized_document_in_source")
    class Handler(RabanitoHandler):
        settings = None
        def log_message(self, *args): pass
    Handler.settings = settings
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
    report["http"] = []
    try:
        for (kind, document_id), expected in zip(selected, payloads):
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
            try:
                connection.request("POST", "/api/doc/content", json.dumps({"document_id": document_id, "max_bytes": 65536}),
                    {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{server.server_port}"})
                response = connection.getresponse(); actual = json.loads(response.read())
                if response.status != 200 or actual != expected or response.getheader("Cache-Control") != "no-store":
                    raise ValueError("real_document_http_contract")
                report["http"].append({"source_kind": kind, "document_id": document_id, "status": response.status,
                    "bytes_returned": actual["bytes_returned"], "references": len(actual["references"]),
                    "truncated": actual["truncated"], "matches_authorized_source_view": True, "no_store": True})
            finally: connection.close()
    finally:
        server.shutdown(); server.server_close(); worker.join(5)
    report["server_closed"] = not worker.is_alive()
    if frontend_root:
        report["frontend_reader"] = reader_compatibility(frontend_root, payloads)
    parent = ROOT / "tests/.test-temp"
    if contains_reparse_component(parent) or safe_relative(parent, ROOT) in {None, "", "."}:
        raise ValueError("unsafe_document_validation_temp")
    parent.mkdir(exist_ok=True)
    backup = settings.data_dir / "backups" / ("checkpoint-doc-content-" + uuid.uuid4().hex + ".db")
    with Database(settings.database_path, read_only=True) as db: db.backup(backup)
    with tempfile.TemporaryDirectory(prefix="doc-content-restore-", dir=parent) as temporary:
        restored = Path(temporary) / "restore.db"
        restore_database(backup, restored)
        recovered = Settings(ROOT, {**settings.raw, "database_path": str(restored)})
        report["restored_database"] = check_attack_db(restored)
        report["restored_contents_equal"] = all(document_content(recovered, doc, 65536) == expected
            for (_, doc), expected in zip(selected, payloads))
        if not report["restored_contents_equal"]: raise ValueError("document_restore_mismatch")
    report["backup"] = backup.name; report["temporary_copy_cleaned"] = True
    report["originals_after"] = originals(settings)
    report["originals_unchanged"] = report["originals_before"] == report["originals_after"]
    baseline_path = settings.data_dir / "checkpoint22-integrity.json"
    if baseline_path.is_file():
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))["originals"]
        report["matches_checkpoint22_originals"] = all(all(value == baseline[kind][key] for key, value in info.items())
            for kind, info in report["originals_after"].items())
    if frontend_root:
        after_ui = frontend_snapshot(frontend_root)
        report["frontend_checkout"] = after_ui
        report["frontend_unchanged"] = before_ui == after_ui
        baseline = json.loads((settings.data_dir / "checkpoint23-ui-baseline.json").read_text(encoding="utf-8"))
        report["matches_frontend_initial_baseline"] = all(after_ui[k] == baseline[k] for k in after_ui)
    if report["integrity"] != "ok" or report["fk_errors"] or not report["originals_unchanged"]:
        raise ValueError("document_integrity_or_sources_changed")
    report["seconds"] = round(time.perf_counter() - started, 3)
    write_json_atomic(settings.data_dir / "checkpoint23-live.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontend-root", type=Path)
    args = parser.parse_args()
    print(json.dumps(validate(args.frontend_root), ensure_ascii=True, indent=2))
