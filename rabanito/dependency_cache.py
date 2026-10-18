"""Read-only reuse of explicitly saved, input-bound inventory analyses.

No new schema, writes, implicit inventory discovery, or external requests.
Checksums detect accidental corruption, not an administrator forging the DB.
"""
from __future__ import annotations

import hashlib
import json

from .db import Database
from .utils import iso_now


MAX_REPORT_BYTES = 4 * 1024 * 1024


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def result_checksum(report: dict) -> str:
    return digest({key: value for key, value in report.items() if key not in {"cache", "result_sha256"}})


def annotate(report: dict, status: str) -> dict:
    report["cache"] = {"status": status, "checked_at": iso_now(),
                       "validation": "current_inventory_bytes_and_local_osv_metadata",
                       "writes": 0, "does_not_prove_installed_state": True}
    return report


def validate_osv_schema(db: Database) -> None:
    from .cyber.store import DDL, DDL_2, DDL_3
    rows = db.query("SELECT version,checksum FROM cyber_migrations ORDER BY version")
    definitions = (DDL, DDL_2, DDL_3)
    if not rows or len(rows) > len(definitions) or any(
            row["version"] != index + 1 or row["checksum"] != hashlib.sha256(definition.encode()).hexdigest()
            for index, (row, definition) in enumerate(zip(rows, definitions))):
        raise ValueError("unsupported_dependency_osv_migration")


def reuse_saved(db: Database, identity: str, selected: dict, kind: str, relative: str, source_hash: str, engine: int) -> dict | None:
    # Lazy import: dependency_memory exposes inspect_inventory, but a lookup
    # must never call its migration/backup/write preparation path.
    from .dependency_memory import _schema
    if not _schema(db):
        return None
    row = db.one("SELECT project_id,inventory_kind,relative_path,source_sha256,length(CAST(report_json AS BLOB)) bytes "
                 "FROM dependency_analyses WHERE analysis_id=?", (identity,))
    if (row is None or row["project_id"] != selected["project_id"] or row["inventory_kind"] != kind
            or row["relative_path"] != relative or row["source_sha256"] != source_hash or row["bytes"] > MAX_REPORT_BYTES):
        return None
    raw = db.one("SELECT report_json FROM dependency_analyses WHERE analysis_id=?", (identity,))[0]
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_saved_analysis_key")
            result[key] = value
        return result
    try:
        report = json.loads(raw, object_pairs_hook=unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_saved_analysis")))
        if (not isinstance(report, dict) or report.get("analysis_id") != identity or report.get("engine_version") != engine
                or report.get("project") != selected["name"] or report.get("source", {}).get("relative_path") != relative
                or report.get("source", {}).get("sha256") != source_hash
                or not isinstance(report.get("components"), list) or not isinstance(report.get("findings"), list)
                or report.get("component_count") != len(report["components"])
                or report.get("result_sha256") != result_checksum(report)):
            return None
    except (ValueError, TypeError, AttributeError, RecursionError):
        return None
    return annotate(report, "reused_saved_analysis")
