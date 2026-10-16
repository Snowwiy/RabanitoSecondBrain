"""Bounded unpublished NVD window checkpoint; never a queryable knowledge source."""
from __future__ import annotations

import hashlib
import json
import uuid
from contextlib import nullcontext

from ..config import Settings
from ..db import Database
from ..indexer import _index_lock
from ..utils import contains_reparse_component, iso_now, safe_relative
from .model import CVE, date
from .transport import Response, validate_endpoint


DDL_2 = """
CREATE TABLE cyber_pending_windows(
 source TEXT PRIMARY KEY CHECK(source='nvd'),scope_json TEXT NOT NULL CHECK(json_valid(scope_json)),
 next_offset INTEGER NOT NULL CHECK(next_offset>=0),expected_total INTEGER NOT NULL CHECK(expected_total>=next_offset),
 page_size INTEGER NOT NULL CHECK(page_size BETWEEN 1 AND 2000),
 records_json TEXT NOT NULL CHECK(json_valid(records_json)),responses_json TEXT NOT NULL CHECK(json_valid(responses_json)),
 byte_count INTEGER NOT NULL CHECK(byte_count>=0),checksum TEXT NOT NULL,updated_at TEXT NOT NULL);
"""
MAX_PENDING_BYTES = 32 * 1024 * 1024
MAX_PENDING_RECORDS = 20000


class IncompleteWindow(ValueError):
    pass


class PendingPages(IncompleteWindow):
    def __init__(self, records: list[dict], offset: int, total: int, page_size: int):
        super().__init__("page_budget_exhausted")
        self.records, self.offset, self.total, self.page_size = records, offset, total, page_size


def _checksum(scope: str, records: str, responses: str, offset: int, total: int, page_size: int) -> str:
    return hashlib.sha256(json.dumps([scope, records, responses, offset, total, page_size], ensure_ascii=True).encode()).hexdigest()


def prepare_pending(scope: dict, error: PendingPages, responses: list[Response]) -> tuple:
    if (scope.get("type") != "modified_window" or error.offset != len(error.records) or
            not 0 < error.offset < error.total or error.offset > MAX_PENDING_RECORDS or len(responses) > 200):
        raise ValueError("invalid_pending_window")
    serialized_scope = json.dumps(scope, sort_keys=True, ensure_ascii=False, allow_nan=False)
    records = json.dumps(error.records, ensure_ascii=False, allow_nan=False)
    pages = json.dumps([{"url": p.url, "etag": p.etag, "last_modified": p.last_modified,
                         "not_modified": p.not_modified, "fetched_at": p.fetched_at or iso_now(), "data": p.data} for p in responses], ensure_ascii=False, allow_nan=False)
    byte_count = len((serialized_scope + records + pages).encode())
    if byte_count > MAX_PENDING_BYTES:
        raise ValueError("pending_window_byte_limit")
    return ("nvd", serialized_scope, error.offset, error.total, error.page_size, records, pages, byte_count,
            _checksum(serialized_scope, records, pages, error.offset, error.total, error.page_size), iso_now())


def save_pending(db: Database, values: tuple) -> None:
    db.execute("INSERT INTO cyber_pending_windows VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET "
               "scope_json=excluded.scope_json,next_offset=excluded.next_offset,expected_total=excluded.expected_total,"
               "page_size=excluded.page_size,records_json=excluded.records_json,responses_json=excluded.responses_json,"
               "byte_count=excluded.byte_count,checksum=excluded.checksum,updated_at=excluded.updated_at", values)


def load_pending(db: Database) -> dict | None:
    row = db.one("SELECT * FROM cyber_pending_windows WHERE source='nvd'")
    if not row:
        return None
    if (row["byte_count"] > MAX_PENDING_BYTES or
            len((row["scope_json"] + row["records_json"] + row["responses_json"]).encode()) > MAX_PENDING_BYTES or
            row["checksum"] != _checksum(row["scope_json"], row["records_json"], row["responses_json"],
                                         row["next_offset"], row["expected_total"], row["page_size"])):
        raise ValueError("invalid_pending_window_checksum_or_size")
    scope, records, pages = (json.loads(row[k]) for k in ("scope_json", "records_json", "responses_json"))
    if (not isinstance(scope, dict) or scope.get("type") != "modified_window" or not isinstance(records, list)
            or len(records) != row["next_offset"] or len(records) > MAX_PENDING_RECORDS
            or not isinstance(pages, list) or len(pages) > 200):
        raise ValueError("invalid_pending_window_shape")
    ids = [r.get("id") for r in records if isinstance(r, dict)]
    if len(ids) != len(records) or any(not isinstance(i, str) or not CVE.fullmatch(i) for i in ids) or len(set(ids)) != len(ids):
        raise ValueError("invalid_pending_window_identifiers")
    ids_set = set(ids)
    responses, observed_at = [], {}
    for page in pages:
        if (not isinstance(page, dict) or validate_endpoint(page.get("url", "")) != "services.nvd.nist.gov"
                or not isinstance(page.get("data"), dict)):
            raise ValueError("invalid_pending_window_response")
        fetched_at = date(page.get("fetched_at") or row["updated_at"])
        responses.append(Response(page["data"], page["url"], page.get("etag"), page.get("last_modified"), page.get("not_modified", False), fetched_at))
        for item in page["data"].get("vulnerabilities", []):
            if (isinstance(item, dict) and isinstance(item.get("cve"), dict) and
                    isinstance(item["cve"].get("id"), str) and item["cve"]["id"] in ids_set):
                observed_at[item["cve"]["id"]] = fetched_at
    if set(observed_at) != set(ids):
        raise ValueError("pending_record_provenance_missing")
    return {"scope": scope, "records": records, "responses": responses, "offset": row["next_offset"],
            "total": row["expected_total"], "page_size": row["page_size"], "byte_count": row["byte_count"], "observed_at": observed_at}


def discard_pending_window(settings: Settings, *, approve: bool = False) -> dict:
    """Preview by default; explicit recovery discards only backed-up unpublished cache."""
    if type(approve) is not bool:
        raise ValueError("approve_must_be_boolean")
    if (safe_relative(settings.database_path, settings.root) in {None, "", "."}
            or contains_reparse_component(settings.database_path)):
        raise ValueError("unsafe_pending_database_path")
    if not settings.database_path.is_file():
        return {"pending": False, "discarded": False}
    with (_index_lock(settings) if approve else nullcontext()), Database(settings.database_path, read_only=not approve) as db:
        if not db.one("SELECT 1 FROM sqlite_master WHERE name='cyber_pending_windows'"):
            return {"pending": False, "discarded": False}
        row = db.one("SELECT next_offset,expected_total,byte_count FROM cyber_pending_windows WHERE source='nvd'")
        if not row:
            return {"pending": False, "discarded": False}
        result = {"pending": True, "discarded": False, "source": "nvd", "unpublished_records": row["next_offset"],
                  "expected_total": row["expected_total"], "bytes": row["byte_count"], "requires_explicit_approval": True}
        if not approve:
            return result
        backup = settings.data_dir / "backups" / ("pre-pending-discard-" + uuid.uuid4().hex + ".db")
        if safe_relative(backup, settings.root) in {None, "", "."} or contains_reparse_component(backup):
            raise ValueError("unsafe_pending_backup_path")
        db.backup(backup)
        now = iso_now()
        scope = {"type": "pending_discard", "unpublished_records": row["next_offset"], "reason": "explicit_operator_request"}
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM cyber_pending_windows WHERE source='nvd'")
            db.execute("UPDATE cyber_sync_state SET status='interrupted',error_code='pending_discarded',scope_json=? WHERE source='nvd'", (json.dumps(scope),))
            db.execute("INSERT INTO cyber_sync_runs(source,started_at,finished_at,status,error_code,scope_json) VALUES ('nvd',?,?,'interrupted','pending_discarded',?)", (now, now, json.dumps(scope)))
            db.commit()
        except BaseException:
            db.connection.rollback()
            raise
        return result | {"discarded": True, "backup": backup.name}
