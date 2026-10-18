"""Rehearse a validated public MSRC capture on a disposable copy of the real DB.

Two small official summary GETs; no vault/project content leaves the machine.
Never replaces the live DB. Reports aggregate proof only, without private paths.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rabanito.config import Settings, load_settings
from rabanito.cyber.history import vulnerability_history
from rabanito.cyber.msrc_capture import _folder, read_capture
from rabanito.cyber.msrc_state import schema as msrc_schema
from rabanito.cyber.store import get_vulnerability, search_vulnerabilities, vulnerability_context
from rabanito.cyber.sync import sync_source
from rabanito.db import Database, restore_database
from rabanito.knowledge_graph import graph_page, sync_graph
from rabanito.utils import contains_reparse_component, iso_now, safe_relative, write_json_atomic


def check_db(path):
    with Database(path) as db:
        integrity, fks = db.one("PRAGMA integrity_check")[0], len(db.query("PRAGMA foreign_key_check"))
        if integrity != "ok" or fks:
            raise ValueError("msrc_rehearsal_database_integrity")
        fts = []
        for table in ("documents_fts", "chunks_fts", "cyber_fts", "security_fts"):
            if db.one("SELECT 1 FROM sqlite_master WHERE name=?", (table,)):
                db.execute(f"INSERT INTO {table}({table}) VALUES ('integrity-check')")
                fts.append(table)
        msrc_schema(db)
        return {"integrity": integrity, "fk_errors": fks, "fts": fts}


def rehearse(manifest):
    settings = load_settings()
    if settings.root.resolve() != ROOT or contains_reparse_component(settings.database_path) or safe_relative(settings.database_path, ROOT) is None:
        raise ValueError("unexpected_validation_root")
    normalized, metadata, _ = read_capture(settings, manifest)
    month, expected = metadata["month"], len(normalized["records"])
    if not expected:
        raise ValueError("empty_rehearsal_capture")
    public_id = next(r["aliases"][0] for r in normalized["records"] if r["aliases"])
    del normalized
    result = {"at": iso_now(), "scope": "temporary_copy_of_real_database", "month": month,
              "capture_sha256": metadata["sha256"], "live_database_replaced": False}
    parent = ROOT / "tests/.test-temp"
    parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="msrc-rehearsal-", dir=parent) as temporary:
        folder = Path(temporary)
        copied = folder / "copy.db"
        with Database(settings.database_path, read_only=True) as db:
            db.backup(copied)
        isolated = Settings(ROOT, {**settings.raw, "database_path": str(copied), "data_dir": str(folder / "data")})
        quarantine = isolated.data_dir / "msrc-captures"
        quarantine.mkdir(parents=True)
        for name in (manifest, metadata["body"]):
            shutil.copyfile(_folder(settings) / name, quarantine / name)
        print(json.dumps({"phase": "copy_sync", "month": month}), flush=True)
        started = time.perf_counter()
        first = sync_source(isolated, "msrc", month=month, capture_manifest=manifest)
        result["publication_seconds"] = round(time.perf_counter() - started, 3)
        result["first_sync"] = first
        if first["status"] != "ok":
            raise ValueError("msrc_rehearsal_sync_failed_" + str(first["error_code"]))
        second = sync_source(isolated, "msrc", month=month)
        result["second_sync"] = second
        if second["status"] != "ok" or not second["scope"]["incremental_skip"] or second["unchanged"] != expected:
            raise ValueError("msrc_rehearsal_not_idempotent")
        context = vulnerability_context(isolated, public_id, max_chars=1500)
        result.update(source_results=search_vulnerabilities(isolated, source="msrc", limit=1)["total"],
                      cited_fragments=len(context["fragments"]), context_chars=context["used_chars"],
                      observed_revisions=vulnerability_history(isolated, public_id, source="msrc")["total"])
        if not any(f["source"] == "msrc" and f["locator"] for f in context["fragments"]):
            raise ValueError("msrc_rehearsal_missing_citation")
        batches = []
        started = time.perf_counter()
        for i in range(64):
            batch = sync_graph(isolated, max_inputs=2000)
            summary = {k: batch[k] for k in ("examined", "changed", "unchanged", "errors", "status")}
            batches.append(summary)
            print(json.dumps({"phase": "graph", "batch": i + 1, **summary}), flush=True)
            if batch["errors"]:
                raise ValueError("msrc_rehearsal_graph_errors")
            if batch["status"] == "ok":
                break
        else:
            raise ValueError("msrc_rehearsal_graph_not_converged")
        result.update(graph_seconds=round(time.perf_counter() - started, 3), graph_batches=batches,
                      advisory_nodes=len(graph_page(isolated, kind="security_advisory", limit=100)["nodes"]))
        result["database"] = check_db(copied)
        backup, restored = folder / "backup.db", folder / "restored.db"
        with Database(copied, read_only=True) as db:
            db.backup(backup)
        restore_database(backup, restored)
        result["restored_database"] = check_db(restored)
        recovered = Settings(ROOT, {**isolated.raw, "database_path": str(restored)})
        if get_vulnerability(recovered, public_id) != get_vulnerability(isolated, public_id):
            raise ValueError("msrc_rehearsal_restore_mismatch")
        result["restored_cited_record_equal"] = True
    result.update(temporary_copy_cleaned=True, large_body_downloads=0)
    write_json_atomic(settings.data_dir / "msrc-sync-rehearsal.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", help="Validated quarantine manifest basename")
    args = parser.parse_args()
    try:
        print(json.dumps(rehearse(args.manifest), ensure_ascii=True, indent=2))
    except (ValueError, OSError) as exc:
        print(json.dumps({"error": str(exc) if isinstance(exc, ValueError) else "msrc_rehearsal_io_error"}))
        raise SystemExit(1) from None
