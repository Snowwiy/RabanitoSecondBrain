from __future__ import annotations

import json
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlencode

from ..config import Settings
from ..db import Database
from ..indexer import _index_lock
from ..utils import iso_now
from .model import CVE, NORMALIZERS, InvalidFeed, identifier
from .store import SCHEMA_VERSION, SOURCES, apply_records, cache_for, ensure_schema, has_schema, schema_version
from .pending import IncompleteWindow, PendingPages, load_pending, prepare_pending, save_pending
from .transport import FetchError, PublicHttpClient


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
OSV_URL = "https://api.osv.dev/v1/vulns/"


def _utc(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)


def _bound(config: dict, key: str, default: int, minimum: int, maximum: int) -> int:
    value = config.get(key, default)
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("Invalid Cyber limit: " + key)
    return value


def sync_source(settings: Settings, source: str, ids: list[str] | None = None, *, client=None,
                now: datetime | None = None, month: str | None = None, capture_manifest: str | None = None) -> dict:
    """Fetch only public identifiers and windows. One atomic transaction per complete source scope."""
    if source not in SOURCES:
        raise ValueError("Unknown Cyber source")
    if source == "msrc":
        if ids is not None and ids != []:
            raise ValueError("MSRC requires a month, not vulnerability identifiers")
        from .msrc_sync import sync_month
        return sync_month(settings, month, capture_manifest=capture_manifest, client=client, now=now)
    if month is not None or capture_manifest is not None:
        raise ValueError("Month and capture apply only to MSRC")
    if ids is not None and (not isinstance(ids, list) or len(ids) > 200):
        raise ValueError("At most 200 public vulnerability identifiers are allowed")
    requested = list(dict.fromkeys(identifier(x) for x in (ids or [])))
    if source in {"nvd", "epss"} and any(not CVE.fullmatch(x) for x in requested):
        raise ValueError("This provider requires CVE identifiers")
    if source == "kev" and requested:
        raise ValueError("KEV is a complete catalog, not an identifier lookup")
    config = settings.raw.get("cyber", {})
    if not isinstance(config, dict):
        raise ValueError("cyber must be an object")
    max_pages = _bound(config, "max_pages", 3, 1, 20)
    page_size = _bound(config, "nvd_page_size", 500, 1, 2000)
    initial_days = _bound(config, "nvd_initial_days", 1, 1, 30)
    window_minutes = _bound(config, "nvd_window_minutes", 60, 1, 7200)
    target_limit = _bound(config, "epss_target_limit", 100, 1, 200)
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    started = current.isoformat(timespec="seconds")
    http = client or PublicHttpClient()
    with _index_lock(settings), Database(settings.database_path) as db:
        backup_name = None
        if ((has_schema(db) and schema_version(db) < SCHEMA_VERSION) or
                not has_schema(db) and db.one("SELECT count(*) n FROM documents")["n"]):
            target = settings.data_dir / "backups" / (f"pre-cyber-schema{SCHEMA_VERSION}-" + uuid.uuid4().hex + ".db")
            db.backup(target)
            backup_name = target.name
        ensure_schema(db)
        db.execute("UPDATE cyber_sync_runs SET status='interrupted',finished_at=? WHERE status='running'", (started,))
        db.execute("UPDATE cyber_sync_state SET status='interrupted',error_code='previous_run_interrupted' WHERE status='running'")
        previous = db.one("SELECT * FROM cyber_sync_state WHERE source=?", (source,))
        previous_scope = json.loads(previous["scope_json"]) if previous else {}
        retry_at = previous_scope.get("retry_at")
        if retry_at and current < _utc(retry_at):
            return {"source": source, "status": "deferred", "error_code": "provider_cooldown", "requests": 0,
                    "retry_at": retry_at, "added": 0, "modified": 0, "unchanged": 0, "retired": 0}
        db.execute("INSERT INTO cyber_sync_state(source,last_attempt,status) VALUES (?,?,'running') "
                   "ON CONFLICT(source) DO UPDATE SET last_attempt=excluded.last_attempt,status='running',error_code=NULL", (source, started))
        run_id = db.execute("INSERT INTO cyber_sync_runs(source,started_at,status) VALUES (?,?,'running')", (source, started)).lastrowid
        db.commit()
        records, responses = [], []
        scope: dict = {}
        watermark = previous["watermark"] if previous else None
        next_watermark = watermark
        status, error_code = "ok", None
        requests = 0
        response_bytes = 0
        pending_window = None
        retrieved_times = {}

        def fetch(url: str):
            nonlocal requests, response_bytes
            if requests >= max_pages * 6 + 20:
                raise IncompleteWindow("request_budget_exhausted")
            requests += 1
            response = http.get(url, cache_for(db, url))
            response.fetched_at = response.fetched_at or datetime.now(timezone.utc).isoformat(timespec="microseconds")
            response_bytes += len(json.dumps(response.data, ensure_ascii=False).encode("utf-8"))
            if response_bytes > 32 * 1024 * 1024:
                raise IncompleteWindow("sync_byte_budget_exhausted")
            responses.append(response)
            return response.data

        def paged(url: str, params: dict, provider: str, resume: dict | None = None):
            result = list(resume["records"]) if resume else []
            offset, expected_total = (resume["offset"], resume["total"]) if resume else (0, None)
            seen_ids = {r["id"] for r in result}
            for _ in range(max_pages):
                query = {**params, "startIndex" if provider == "nvd" else "offset": offset}
                for _resize in range(12):
                    try:
                        payload = fetch(url + "?" + urlencode(query))
                        break
                    except FetchError as error:
                        if provider != "nvd" or error.code != "response_too_large" or query["resultsPerPage"] <= 1:
                            raise
                        params["resultsPerPage"] = query["resultsPerPage"] = max(1, query["resultsPerPage"] // 2)
                else:
                    raise InvalidFeed("page_resize_budget")
                if not isinstance(payload, dict):
                    raise InvalidFeed("invalid_page")
                total = payload.get("totalResults" if provider == "nvd" else "total")
                remote_offset = payload.get("startIndex" if provider == "nvd" else "offset")
                # FIRST returns numeric metadata as strings on some versions.
                if provider == "epss":
                    if isinstance(total, str) and total.isdigit(): total = int(total)
                    if isinstance(remote_offset, str) and remote_offset.isdigit(): remote_offset = int(remote_offset)
                if type(total) is not int or total < 0 or type(remote_offset) is not int or remote_offset != offset:
                    raise InvalidFeed("invalid_pagination")
                if expected_total is not None and total != expected_total:
                    raise InvalidFeed("changing_pagination_total")
                expected_total = total
                page = NORMALIZERS[provider](payload, url + "?" + urlencode(query))
                page_ids = [x["id"] for x in page]
                if len(set(page_ids)) != len(page_ids) or seen_ids.intersection(page_ids):
                    raise InvalidFeed("duplicate_page_records")
                seen_ids.update(page_ids)
                result.extend(page)
                if provider == "nvd":
                    retrieved_times.update((r["id"], responses[-1].fetched_at) for r in page)
                offset += len(page)
                if offset > total:
                    raise InvalidFeed("pagination_overflow")
                if offset == total:
                    return result
                if not page:
                    raise InvalidFeed("empty_incomplete_page")
            if provider == "nvd":
                raise PendingPages(result, offset, expected_total, params["resultsPerPage"])
            raise IncompleteWindow("page_budget_exhausted")

        try:
            if source == "nvd" and previous and previous["last_attempt"] and client is None:
                # Cross-process/source calls are serialized; respect the public unauthenticated rate.
                previous_run = db.one("SELECT finished_at FROM cyber_sync_runs WHERE source=? AND finished_at IS NOT NULL "
                                      "ORDER BY run_id DESC LIMIT 1", (source,))
                last = previous_run["finished_at"] if previous_run else previous["last_attempt"]
                elapsed = (current - _utc(last)).total_seconds()
                if elapsed < 6.1:
                    time.sleep(max(0, 6.1 - elapsed))
            if source == "kev":
                url = KEV_URL
                try:
                    payload = fetch(url)
                except FetchError as exc:
                    if exc.status not in {403, 404}:
                        raise
                    url = KEV_MIRROR
                    payload = fetch(url)
                records = NORMALIZERS[source](payload, url)
                if not records:
                    raise InvalidFeed("unexpected_empty_kev_catalog")
                scope = {"type": "complete_catalog", "endpoint": url}
            elif source == "nvd":
                if requested:
                    if len(requested) > max_pages:
                        raise ValueError("CVE lookup exceeds request budget")
                    for value in requested:
                        found = paged(NVD_URL, {"cveId": value, "resultsPerPage": page_size}, source)
                        if any(record["id"] != value for record in found):
                            raise InvalidFeed("unexpected_nvd_identifier")
                        records.extend(found)
                    scope = {"type": "public_identifiers", "count": len(requested)}
                else:
                    pending_window = load_pending(db)
                    if pending_window:
                        scope = {**pending_window["scope"], "resumed": True, "resume_offset": pending_window["offset"]}
                        if _utc(scope["start"]) >= _utc(scope["end"]) or _utc(scope["end"]) > current:
                            raise InvalidFeed("invalid_pending_window_dates")
                        responses.extend(pending_window["responses"])
                        retrieved_times.update(pending_window["observed_at"])
                        response_bytes = sum(len(json.dumps(r.data, ensure_ascii=False).encode()) for r in responses)
                        records = paged(NVD_URL, {"lastModStartDate": _utc(scope["start"]).isoformat(timespec="milliseconds"),
                                                 "lastModEndDate": _utc(scope["end"]).isoformat(timespec="milliseconds"),
                                                 "resultsPerPage": pending_window["page_size"]}, source, pending_window)
                        scope.update(staged=False, records_in_window=len(records), light_windows=0)
                        next_watermark = scope["end"]
                    else:
                        span = window_minutes
                        last_window = db.one("SELECT scope_json FROM cyber_sync_runs WHERE source='nvd' AND status='ok' "
                                             "AND json_extract(scope_json,'$.type')='modified_window' ORDER BY run_id DESC LIMIT 1")
                        adaptive = json.loads(last_window["scope_json"]) if last_window else {}
                        previous_span = adaptive.get("window_minutes")
                        quiet = adaptive.get("light_windows", 0)
                        quiet = quiet if type(quiet) is int and 0 <= quiet <= 3 else 0
                        if adaptive.get("backlog") and type(previous_span) is int and 1 <= previous_span <= 7200:
                            span = min(span, previous_span)
                            if quiet >= 3:
                                span = min(window_minutes, span * 2)
                                quiet = 0
                        for narrowing in range(7):
                            overlap = timedelta(seconds=min(120, span * 6))
                            start = _utc(watermark) - overlap if watermark else current - timedelta(days=initial_days)
                            if start > current:
                                raise InvalidFeed("future_watermark")
                            end = min(current, start + timedelta(days=119), start + timedelta(minutes=span))
                            scope = {"type": "modified_window", "start": start.isoformat(), "end": end.isoformat(),
                                     "backlog": end < current, "window_minutes": span}
                            try:
                                records = paged(NVD_URL, {"lastModStartDate": start.isoformat(timespec="milliseconds"),
                                                         "lastModEndDate": end.isoformat(timespec="milliseconds"), "resultsPerPage": page_size}, source)
                                scope["records_in_window"] = len(records)
                                scope["light_windows"] = min(3, quiet + 1) if narrowing == 0 and len(records) < max(1, page_size // 4) else 0
                                break
                            except IncompleteWindow:
                                if span <= 1 or narrowing == 6:
                                    raise
                                span = max(1, span // 2)
                                responses.clear()
                        next_watermark = end.isoformat()
            elif source == "epss":
                if not requested:
                    requested = [r["vulnerability_id"] for r in db.query("SELECT e.vulnerability_id FROM cyber_entities e "
                        "WHERE e.vulnerability_id LIKE 'CVE-%' ORDER BY e.kev DESC,COALESCE((SELECT json_extract(r.data_json,'$.kev.date_added') "
                        "FROM cyber_aliases a JOIN cyber_records r USING(source,source_id) WHERE a.vulnerability_id=e.vulnerability_id "
                        "AND r.source='kev' AND r.active=1 LIMIT 1),e.modified) DESC,e.vulnerability_id LIMIT ?", (target_limit,))]
                scope = {"type": "public_identifiers", "count": len(requested), "coverage": "selected CVEs only; not the global EPSS dataset"}
                for offset in range(0, len(requested), 50):
                    batch = requested[offset:offset + 50]
                    records.extend(paged(EPSS_URL, {"cve": ",".join(batch), "limit": 100}, source))
                if any(r["id"] not in requested for r in records):
                    raise InvalidFeed("unexpected_epss_identifier")
            else:
                if not requested:
                    configured = config.get("osv_ids", [])
                    if not isinstance(configured, list) or len(configured) > 20:
                        raise ValueError("osv_ids must contain at most 20 public advisory IDs")
                    requested = list(dict.fromkeys(identifier(x) for x in configured))
                scope = {"type": "public_identifiers", "count": len(requested)}
                if len(requested) > 20:
                    raise ValueError("At most 20 OSV lookups per sync")
                for value in requested:
                    url = OSV_URL + quote(value, safe="")
                    page = NORMALIZERS[source](fetch(url), url)
                    if value not in [page[0]["id"], *page[0]["aliases"]]:
                        raise InvalidFeed("unexpected_osv_identifier")
                    records.extend(page)
            if source in {"epss", "osv"} and not requested:
                status = "not_configured"
            scope["cache_not_modified"] = sum(response.not_modified for response in responses)
            db.execute("BEGIN IMMEDIATE")
            counts = apply_records(db, source, records, responses, snapshot=source == "kev", retrieved_at=iso_now(),
                                   retire_ids=requested if source == "epss" else None, retrieved_times=retrieved_times,
                                   protect_newer=pending_window is not None)
            if source == "nvd" and not requested:
                db.execute("DELETE FROM cyber_pending_windows WHERE source='nvd'")
            if counts.get("retained_newer"):
                scope["retained_newer"] = counts["retained_newer"]
            finished = iso_now()
            db.execute("UPDATE cyber_sync_state SET last_success=?,watermark=?,status=?,error_code=NULL,scope_json=? WHERE source=?",
                       (finished if status == "ok" else (previous["last_success"] if previous else None), next_watermark, status, json.dumps(scope), source))
            db.execute("UPDATE cyber_sync_runs SET finished_at=?,status=?,added=?,modified=?,unchanged=?,retired=?,requests=?,scope_json=? WHERE run_id=?",
                       (finished, status, counts["added"], counts["modified"], counts["unchanged"], counts["retired"], requests, json.dumps(scope), run_id))
            db.commit()
        except KeyboardInterrupt:
            db.connection.rollback()
            db.execute("UPDATE cyber_sync_state SET status='interrupted',error_code='interrupted' WHERE source=?", (source,))
            db.execute("UPDATE cyber_sync_runs SET finished_at=?,status='interrupted',requests=?,error_code='interrupted' WHERE run_id=?",
                       (iso_now(), requests, run_id))
            db.commit()
            raise
        except (FetchError, InvalidFeed, IncompleteWindow, ValueError, TypeError, KeyError, RecursionError, sqlite3.Error) as exc:
            db.connection.rollback()
            status = "partial" if isinstance(exc, IncompleteWindow) else "error"
            error_code = exc.code if isinstance(exc, FetchError) else str(exc) if isinstance(exc, (InvalidFeed, IncompleteWindow)) else type(exc).__name__
            if isinstance(exc, PendingPages) and source == "nvd" and not requested and scope.get("window_minutes") == 1:
                try:
                    values = prepare_pending(scope, exc, responses)
                    save_pending(db, values)
                    scope.update(staged=True, resumable=True, next_offset=exc.offset, expected_total=exc.total,
                                 pending_bytes=values[7])
                except (ValueError, sqlite3.Error):
                    db.connection.rollback()
                    error_code = "pending_window_checkpoint_limit_or_error"
                    scope["resumable"] = bool(pending_window)
            elif pending_window and isinstance(exc, InvalidFeed) and str(exc) in {
                    "changing_pagination_total", "duplicate_page_records", "pagination_overflow"}:
                db.execute("DELETE FROM cyber_pending_windows WHERE source='nvd'")
                scope.update(staging_discarded="provider_snapshot_changed", resumable=False)
            scope["retry_after_seconds"] = exc.retry_after if isinstance(exc, FetchError) else None
            if isinstance(exc, FetchError):
                scope["http_status"] = exc.status
            if isinstance(exc, FetchError) and exc.retry_after:
                scope["retry_at"] = (current + timedelta(seconds=exc.retry_after)).isoformat()
            db.execute("UPDATE cyber_sync_state SET status=?,error_code=?,scope_json=? WHERE source=?", (status, error_code, json.dumps(scope), source))
            db.execute("UPDATE cyber_sync_runs SET finished_at=?,status=?,requests=?,error_code=?,scope_json=? WHERE run_id=?",
                       (iso_now(), status, requests, error_code, json.dumps(scope), run_id))
            db.commit()
            counts = {"added": 0, "modified": 0, "unchanged": 0, "retired": 0}
        return {"source": source, "run_id": run_id, "status": status, **counts, "requests": requests,
                "error_code": error_code, "scope": scope, "migration_backup": backup_name}
