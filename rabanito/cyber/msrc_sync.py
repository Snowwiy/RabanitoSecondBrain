"""Explicit single-month MSRC sync; complete documents publish atomically."""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from ..db import Database
from ..indexer import _index_lock
from ..utils import iso_now
from .model import InvalidFeed
from .msrc import ADAPTER_VERSION, document_url
from .msrc_capture import MANIFEST, capture_month, read_capture
from .msrc_state import migrate, own_outputs, record_proof
from .store import SCHEMA_VERSION, apply_records, cache_for, ensure_schema, has_schema, schema_version
from .transport import FetchError, PublicHttpClient


def utc(value: str) -> datetime:
    if not isinstance(value, str) or len(value) > 80 or "T" not in value:
        raise InvalidFeed("invalid_msrc_release_date")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise InvalidFeed("invalid_msrc_release_date") from None
    if parsed.year < 2000:
        raise InvalidFeed("invalid_msrc_release_date")
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def summary_version(data, month: str) -> str:
    values = data.get("value") if isinstance(data, dict) else None
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise InvalidFeed("invalid_msrc_month_summary")
    row = values[0]
    if row.get("ID") != month or row.get("CvrfUrl") != document_url(month).split("?", 1)[0]:
        raise InvalidFeed("msrc_summary_identity_mismatch")
    return utc(row.get("CurrentReleaseDate")).isoformat()


def sync_month(settings, month: str, *, capture_manifest: str | None = None, client=None, now=None) -> dict:
    url = document_url(month).replace("/cvrf/" + month, "/updates/" + month)
    if capture_manifest is not None and (not isinstance(capture_manifest, str) or not MANIFEST.fullmatch(capture_manifest)
                                         or not capture_manifest.startswith(month + "-")):
        raise ValueError("invalid_msrc_capture_manifest_name")
    config = settings.raw.get("cyber", {})
    if not isinstance(config, dict):
        raise ValueError("cyber must be an object")
    seconds = config.get("msrc_capture_seconds", 300)
    if type(seconds) is not int or not 1 <= seconds <= 300:
        raise ValueError("msrc_capture_seconds must be 1 to 300")
    own_outputs(settings)
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    started = current.isoformat(timespec="seconds")
    http = client or PublicHttpClient(max_bytes=64 * 1024)
    with _index_lock(settings), Database(settings.database_path) as db:
        backups = []
        if ((has_schema(db) and schema_version(db) < SCHEMA_VERSION) or
                not has_schema(db) and db.one("SELECT count(*) FROM documents")[0]):
            path = settings.data_dir / "backups" / ("pre-cyber-schema3-" + uuid.uuid4().hex + ".db")
            db.backup(path); backups.append(path.name)
        ensure_schema(db)
        backup = migrate(settings, db)
        if backup:
            backups.append(backup)
        db.execute("UPDATE cyber_sync_runs SET status='interrupted',finished_at=? WHERE status='running'", (started,))
        db.execute("UPDATE cyber_sync_state SET status='interrupted',error_code='previous_run_interrupted' WHERE status='running'")
        previous = db.one("SELECT scope_json FROM cyber_sync_state WHERE source='msrc'")
        retry_at = json.loads(previous[0]).get("retry_at") if previous else None
        if retry_at and current < utc(retry_at):
            db.commit()
            return {"source": "msrc", "status": "deferred", "error_code": "provider_cooldown", "requests": 0,
                    "retry_at": retry_at, "added": 0, "modified": 0, "unchanged": 0, "retired": 0}
        db.execute("INSERT INTO cyber_sync_state(source,last_attempt,status) VALUES ('msrc',?,'running') "
                   "ON CONFLICT(source) DO UPDATE SET last_attempt=excluded.last_attempt,status='running',error_code=NULL", (started,))
        run_id = db.execute("INSERT INTO cyber_sync_runs(source,started_at,status) VALUES ('msrc',?,'running')", (started,)).lastrowid
        db.commit()
        requests, response, error_code, status = 0, None, None, "ok"
        counts = {"added": 0, "modified": 0, "unchanged": 0, "retired": 0}
        scope = {"type": "monthly_document", "month": month, "global_coverage": False}
        try:
            requests += 1
            response = http.get(url, cache_for(db, url))
            version = summary_version(response.data, month)
            old = db.one("SELECT * FROM msrc_documents WHERE month=?", (month,))
            if old and utc(version) < utc(old["summary_modified"]):
                raise InvalidFeed("msrc_summary_regressed")
            count, proof = record_proof(db, month)
            same = (old is not None and old["summary_modified"] == version and old["adapter_version"] == ADAPTER_VERSION
                    and old["record_count"] == count and old["records_sha256"] == proof)
            scope.update(summary_modified=version, body_downloaded=False, incremental_skip=bool(same))
            if same:
                # Checking the summary is not a new retrieval of the body/observations.
                counts["unchanged"] = count
                scope.update(captured_at=old["captured_at"], capture_sha256=old["capture_sha256"])
            else:
                if capture_manifest is None:
                    requests += 1
                    captured = capture_month(settings, month, max_seconds=seconds)
                    capture_manifest = captured["manifest"]
                    scope["body_downloaded"] = True
                normalized, metadata, timings = read_capture(settings, capture_manifest)
                if normalized["month"] != month or utc(normalized["document_modified"]).isoformat() != version:
                    raise InvalidFeed("msrc_capture_version_mismatch")
                if utc(metadata.get("captured_at")) > datetime.now(timezone.utc) + timedelta(minutes=5):
                    raise InvalidFeed("msrc_capture_timestamp_in_future")
                if not normalized["records"]:
                    raise InvalidFeed("unexpected_empty_msrc_document")
                if scope["body_downloaded"]:
                    requests += 1
                    response = http.get(url)  # Unconditional: protect against a document changing mid-transfer.
                    if summary_version(response.data, month) != version:
                        raise InvalidFeed("msrc_summary_changed_during_capture")
                scope.update(captured_at=metadata["captured_at"], capture_sha256=metadata["sha256"],
                             capture_bytes=metadata["bytes"], coverage=normalized["coverage"], **timings)
            db.execute("BEGIN IMMEDIATE")
            if same:
                db.execute("UPDATE msrc_documents SET checked_at=? WHERE month=?", (iso_now(), month))
            else:
                prefix = "MSRC-" + month + "-"
                retire = [r[0] for r in db.query("SELECT source_id FROM cyber_records WHERE source='msrc' AND active=1 "
                                                "AND substr(source_id,1,?)=?", (len(prefix), prefix))]
                counts = apply_records(db, "msrc", normalized["records"], [], retire_ids=retire,
                                       retrieved_at=metadata["captured_at"])
                count, proof = record_proof(db, month)
                if count != len(normalized["records"]) or proof is None:
                    raise InvalidFeed("msrc_publication_proof_mismatch")
                db.execute("INSERT INTO msrc_documents VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(month) DO UPDATE SET "
                           "summary_modified=excluded.summary_modified,document_modified=excluded.document_modified,"
                           "adapter_version=excluded.adapter_version,capture_sha256=excluded.capture_sha256,"
                           "capture_manifest=excluded.capture_manifest,captured_at=excluded.captured_at,"
                           "published_at=excluded.published_at,checked_at=excluded.checked_at,"
                           "record_count=excluded.record_count,records_sha256=excluded.records_sha256",
                           (month, version, normalized["document_modified"], ADAPTER_VERSION, metadata["sha256"], capture_manifest,
                            metadata["captured_at"], iso_now(), iso_now(), count, proof))
            # Only the small summary is cached, never the large CVRF body or normalized array.
            db.execute("INSERT INTO cyber_http_cache VALUES (?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET "
                       "etag=excluded.etag,last_modified=excluded.last_modified,body_json=excluded.body_json,retrieved_at=excluded.retrieved_at",
                       (url, response.etag, response.last_modified, json.dumps(response.data), response.fetched_at or iso_now()))
            db.execute("DELETE FROM cyber_http_cache WHERE url NOT IN (SELECT url FROM cyber_http_cache ORDER BY retrieved_at DESC,url LIMIT 100)")
            db.execute("UPDATE cyber_sync_state SET status='ok',last_success=?,error_code=NULL,scope_json=? WHERE source='msrc'",
                       (iso_now(), json.dumps(scope)))
            db.execute("UPDATE cyber_sync_runs SET finished_at=?,status='ok',added=?,modified=?,unchanged=?,retired=?,requests=?,scope_json=? WHERE run_id=?",
                       (iso_now(), counts["added"], counts["modified"], counts["unchanged"], counts["retired"], requests, json.dumps(scope), run_id))
            db.commit()
        except (FetchError, InvalidFeed, ValueError, OSError, sqlite3.Error, KeyboardInterrupt) as exc:
            db.connection.rollback()
            status = "interrupted" if isinstance(exc, KeyboardInterrupt) else "error"
            error_code = exc.code if isinstance(exc, FetchError) else str(exc) if isinstance(exc, InvalidFeed) else type(exc).__name__
            scope["published"] = False
            if isinstance(exc, FetchError):
                scope.update(http_status=exc.status, retry_after_seconds=exc.retry_after)
                if exc.retry_after:
                    scope["retry_at"] = (datetime.now(timezone.utc) + timedelta(seconds=exc.retry_after)).isoformat()
            db.execute("UPDATE cyber_sync_state SET status=?,error_code=?,scope_json=? WHERE source='msrc'", (status, error_code, json.dumps(scope)))
            db.execute("UPDATE cyber_sync_runs SET finished_at=?,status=?,requests=?,error_code=?,scope_json=? WHERE run_id=?",
                       (iso_now(), status, requests, error_code, json.dumps(scope), run_id))
            db.commit()
            counts = {"added": 0, "modified": 0, "unchanged": 0, "retired": 0}
        return {"source": "msrc", "run_id": run_id, "status": status, **counts, "requests": requests,
                "error_code": error_code, "scope": scope, "migration_backups": backups}
