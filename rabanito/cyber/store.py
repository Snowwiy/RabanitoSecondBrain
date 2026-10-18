from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from ..config import Settings
from ..db import Database
from ..utils import iso_now
from .model import CVE, identifier
from .pending import DDL_2
from .history import DDL_3, record_change
from .providers import SOURCES


SCHEMA_VERSION = 3
DDL = """
CREATE TABLE cyber_migrations(version INTEGER PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL);
CREATE TABLE cyber_records(
 source TEXT NOT NULL, source_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
 data_json TEXT NOT NULL CHECK(json_valid(data_json)), retrieved_at TEXT NOT NULL,
 active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), PRIMARY KEY(source,source_id));
CREATE TABLE cyber_aliases(
 source TEXT NOT NULL, source_id TEXT NOT NULL, vulnerability_id TEXT NOT NULL,
 PRIMARY KEY(source,source_id,vulnerability_id),
 FOREIGN KEY(source,source_id) REFERENCES cyber_records(source,source_id) ON DELETE CASCADE);
CREATE INDEX cyber_alias_entity ON cyber_aliases(vulnerability_id);
CREATE TABLE cyber_entities(
 vulnerability_id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL,
 data_json TEXT NOT NULL CHECK(json_valid(data_json)), kev INTEGER NOT NULL, cvss REAL,
 epss REAL, published TEXT, modified TEXT, retrieved_at TEXT NOT NULL, status TEXT NOT NULL);
CREATE INDEX cyber_risk ON cyber_entities(kev DESC,epss DESC,cvss DESC);
CREATE INDEX cyber_modified ON cyber_entities(modified DESC);
CREATE VIRTUAL TABLE cyber_fts USING fts5(vulnerability_id UNINDEXED,title,description,terms);
CREATE TABLE cyber_sync_state(source TEXT PRIMARY KEY, last_attempt TEXT, last_success TEXT,
 watermark TEXT, status TEXT NOT NULL DEFAULT 'never', error_code TEXT, scope_json TEXT NOT NULL DEFAULT '{}');
CREATE TABLE cyber_sync_runs(run_id INTEGER PRIMARY KEY,source TEXT NOT NULL,started_at TEXT NOT NULL,
 finished_at TEXT,status TEXT NOT NULL,added INTEGER NOT NULL DEFAULT 0,modified INTEGER NOT NULL DEFAULT 0,
 unchanged INTEGER NOT NULL DEFAULT 0,retired INTEGER NOT NULL DEFAULT 0,requests INTEGER NOT NULL DEFAULT 0,
 error_code TEXT,scope_json TEXT NOT NULL DEFAULT '{}');
CREATE TABLE cyber_http_cache(url TEXT PRIMARY KEY,etag TEXT,last_modified TEXT,
 body_json TEXT NOT NULL CHECK(json_valid(body_json)),retrieved_at TEXT NOT NULL);
"""


def has_schema(db: Database) -> bool:
    return db.one("SELECT 1 FROM sqlite_master WHERE type='table' AND name='cyber_migrations'") is not None


def schema_version(db: Database) -> int:
    return int(db.one("SELECT max(version) FROM cyber_migrations")[0] or 0) if has_schema(db) else 0


def ensure_schema(db: Database) -> None:
    migrations = [(1, DDL), (2, DDL_2), (3, DDL_3)]
    applied = []
    if has_schema(db):
        applied = db.query("SELECT version,checksum FROM cyber_migrations ORDER BY version")
        if not applied or len(applied) > len(migrations) or any(
                row["version"] != version or row["checksum"] != hashlib.sha256(ddl.encode()).hexdigest()
                for row, (version, ddl) in zip(applied, migrations)):
            raise ValueError("Unsupported or modified Cyber schema migration")
    pending = migrations[len(applied):]
    if not pending:
        return
    try:
        db.connection.executescript("BEGIN IMMEDIATE;\n" + "\n".join(ddl for _, ddl in pending))
        for version, ddl in pending:
            db.execute("INSERT INTO cyber_migrations VALUES (?,?,?)", (version, hashlib.sha256(ddl.encode()).hexdigest(), iso_now()))
        db.commit()
    except BaseException:
        db.connection.rollback()
        raise


def cache_for(db: Database, url: str) -> dict | None:
    row = db.one("SELECT etag,last_modified,body_json FROM cyber_http_cache WHERE url=?", (url,))
    if row:
        return {"etag": row["etag"], "last_modified": row["last_modified"], "data": json.loads(row["body_json"])}
    return None


def _merge_entity(db: Database, entity_id: str) -> None:
    rows = db.query("SELECT r.source,r.source_id,r.data_json,r.retrieved_at FROM cyber_records r JOIN cyber_aliases a "
                    "USING(source,source_id) WHERE a.vulnerability_id=? AND r.active=1", (entity_id,))
    db.execute("DELETE FROM cyber_fts WHERE vulnerability_id=?", (entity_id,))
    if not rows:
        db.execute("DELETE FROM cyber_entities WHERE vulnerability_id=?", (entity_id,))
        return
    rank = {"nvd": 0, "msrc": 1, "osv": 2, "kev": 3, "epss": 4}
    observations = [{**json.loads(r["data_json"]), "source": r["source"], "retrieved_at": r["retrieved_at"]} for r in rows]
    observations.sort(key=lambda x: (rank[x["source"]], x["id"]))
    # Retractions are retained and surfaced, never promoted to active vulnerabilities.
    primary = observations[0]
    active = [x for x in observations if x["record_status"] == "published"]
    kev = any(x.get("kev") for x in active)
    kind = "security_advisory" if primary["record_status"] == "advisory" else "vulnerability"
    metrics = [{**m, "provider": x["source"]} for x in active for m in x["metrics"]]
    numeric = [m for m in metrics if m.get("score") is not None]
    # Prefer NVD primary CVSS v4/v3 over secondary/v2; preserve every metric in observations.
    numeric.sort(key=lambda m: (m.get("type") != "Primary", -float(re.sub(r"[^0-9.]", "", m.get("version", "")) or "0")))
    cvss = numeric[0]["score"] if numeric else None
    epss_rows = [x["epss"] for x in active if x["epss"]]
    epss = max(epss_rows, key=lambda x: x["date"]) if epss_rows else None
    known = kev or any(x.get("exploitation_reported") for x in active)
    entity = {
        "id": entity_id, "title": next((x["title"] for x in observations if x["title"] and x["title"] != x["id"]), entity_id),
        "description": next((x["description"] for x in observations if x["description"]), ""),
        "status": primary["record_status"], "record_kind": kind, "kev": kev,
        "exploitation": "known_exploited" if known else "not_established",
        "cvss": numeric[0] if numeric else None, "epss": epss,
        "published": next((x["published"] for x in observations if x["published"]), None),
        "modified": max((x["modified"] for x in observations if x["modified"]), default=None),
        "retrieved_at": max(x["retrieved_at"] for x in observations),
        "sources": sorted({x["source"] for x in observations}), "observations": observations,
        "priority": ("known_exploited" if known else "high_prediction" if epss and epss["score"] >= .1 else "published")
                    if primary["record_status"] == "published" else None,
        "priority_basis": "KEV/exploitation evidence, then EPSS >= 0.1; CVSS breaks ties. Not project risk or applicability.",
    }
    db.execute("INSERT INTO cyber_entities VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(vulnerability_id) DO UPDATE SET "
               "title=excluded.title,description=excluded.description,data_json=excluded.data_json,kev=excluded.kev,"
               "cvss=excluded.cvss,epss=excluded.epss,published=excluded.published,modified=excluded.modified,"
               "retrieved_at=excluded.retrieved_at,status=excluded.status",
               (entity_id, entity["title"], entity["description"], json.dumps(entity, ensure_ascii=False), int(kev), cvss,
                epss["score"] if epss else None, entity["published"], entity["modified"], entity["retrieved_at"], entity["status"]))
    terms = " ".join(json.dumps({"id": x["id"], "aliases": x["aliases"], "affected": x["affected"], "cwes": x["cwes"]}, ensure_ascii=False) for x in observations)
    db.execute("INSERT INTO cyber_fts VALUES (?,?,?,?)", (entity_id, entity["title"], entity["description"], terms))


def apply_records(db: Database, source: str, records: list[dict], responses: list, *, snapshot: bool = False,
                  retrieved_at: str | None = None, retire_ids: list[str] | None = None,
                  retrieved_times: dict[str, str] | None = None, protect_newer: bool = False) -> dict:
    """Caller owns a transaction. Fingerprints exclude retrieval timestamps."""
    now = retrieved_at or iso_now()
    counts = {"added": 0, "modified": 0, "unchanged": 0, "retired": 0}
    touched: set[str] = set()
    seen: dict[str, str] = {}
    for record in records:
        source_id = identifier(record["id"])
        rendered = json.dumps(record, sort_keys=True, ensure_ascii=False, allow_nan=False)
        if len(rendered.encode("utf-8")) > 2 * 1024 * 1024:
            raise ValueError("Normalized record exceeds limit")
        fingerprint = hashlib.sha256(rendered.encode()).hexdigest()
        if source_id in seen:
            if seen[source_id] != fingerprint:
                raise ValueError("Conflicting duplicate provider identifier")
            continue
        seen[source_id] = fingerprint
        old = db.one("SELECT fingerprint,active,data_json,retrieved_at FROM cyber_records WHERE source=? AND source_id=?", (source, source_id))
        if protect_newer and old and old["active"] and old["fingerprint"] != fingerprint:
            def timestamp(value):
                if not value: return None
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
            old_modified = timestamp(json.loads(old["data_json"]).get("modified"))
            new_modified = timestamp(record.get("modified"))
            old_is_newer = (old_modified > new_modified if old_modified and new_modified and old_modified != new_modified else
                            timestamp(old["retrieved_at"]) > timestamp((retrieved_times or {}).get(source_id, now)))
            if old_is_newer:
                counts["unchanged"] += 1
                counts["retained_newer"] = counts.get("retained_newer", 0) + 1
                continue
        entities = sorted({x for x in [source_id, *record["aliases"]] if CVE.fullmatch(x)}) or [source_id]
        touched.update(r["vulnerability_id"] for r in db.query("SELECT vulnerability_id FROM cyber_aliases WHERE source=? AND source_id=?", (source, source_id)))
        touched.update(entities)
        counts["added" if old is None else "unchanged" if old["fingerprint"] == fingerprint and old["active"] else "modified"] += 1
        record_change(db, source, source_id, rendered, fingerprint, True, (retrieved_times or {}).get(source_id, now), old=old)
        db.execute("INSERT INTO cyber_records VALUES (?,?,?,?,?,1) ON CONFLICT(source,source_id) DO UPDATE SET "
                   "fingerprint=excluded.fingerprint,data_json=excluded.data_json,retrieved_at=excluded.retrieved_at,active=1",
                   (source, source_id, fingerprint, rendered, (retrieved_times or {}).get(source_id, now)))
        db.execute("DELETE FROM cyber_aliases WHERE source=? AND source_id=?", (source, source_id))
        db.executemany("INSERT INTO cyber_aliases VALUES (?,?,?)", [(source, source_id, x) for x in entities])
    if snapshot or retire_ids:
        for old in db.query("SELECT source_id,fingerprint,data_json,retrieved_at,active FROM cyber_records WHERE source=? AND active=1", (source,)):
            if old["source_id"] not in seen and (snapshot or old["source_id"] in (retire_ids or [])):
                touched.update(r["vulnerability_id"] for r in db.query("SELECT vulnerability_id FROM cyber_aliases WHERE source=? AND source_id=?", (source, old["source_id"])))
                record_change(db, source, old["source_id"], old["data_json"], old["fingerprint"], False, old["retrieved_at"], old=old)
                db.execute("UPDATE cyber_records SET active=0 WHERE source=? AND source_id=?", (source, old["source_id"]))
                counts["retired"] += 1
    for response in responses:
        db.execute("INSERT INTO cyber_http_cache VALUES (?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET "
                   "etag=excluded.etag,last_modified=excluded.last_modified,body_json=excluded.body_json,retrieved_at=excluded.retrieved_at",
                   (response.url, response.etag, response.last_modified, json.dumps(response.data, ensure_ascii=False), response.fetched_at or now))
    # Bound cache size. Eviction costs bandwidth only; records/watermarks remain canonical.
    db.execute("DELETE FROM cyber_http_cache WHERE url NOT IN (SELECT url FROM cyber_http_cache ORDER BY retrieved_at DESC,url LIMIT 100)")
    for entity_id in sorted(touched):
        _merge_entity(db, entity_id)
    return counts


def search_vulnerabilities(settings: Settings, query: str = "", *, source: str | None = None,
                           kev_only: bool = False, limit: int = 20, offset: int = 0,
                           since: str | None = None, min_epss: float | None = None, sort: str = "risk") -> dict:
    if not isinstance(query, str) or len(query) > 500:
        raise ValueError("Query exceeds 500 characters")
    if source is not None and source not in SOURCES:
        raise ValueError("Unknown source")
    if sort not in {"risk", "modified", "published"}:
        raise ValueError("Unknown Cyber sort")
    limit, offset = min(max(int(limit), 0), 100), min(max(int(offset), 0), 100_000)
    if min_epss is not None and not 0 <= float(min_epss) <= 1:
        raise ValueError("EPSS must be between 0 and 1")
    conditions, params = [], []
    if kev_only:
        conditions.append("e.kev=1")
    if source:
        conditions.append("EXISTS(SELECT 1 FROM cyber_aliases a JOIN cyber_records r USING(source,source_id) "
                          "WHERE a.vulnerability_id=e.vulnerability_id AND r.source=? AND r.active=1)")
        params.append(source)
    if since:
        datetime.fromisoformat(since.replace("Z", "+00:00"))
        conditions.append("e.modified>=?")
        params.append(since)
    if min_epss is not None:
        conditions.append("e.epss>=?")
        params.append(float(min_epss))
    tokens = re.findall(r"[\w.-]+", query, re.UNICODE)[:30]
    join = ""
    if tokens:
        join = " JOIN cyber_fts f ON f.vulnerability_id=e.vulnerability_id"
        conditions.append("cyber_fts MATCH ?")
        params.append(" AND ".join('"' + x.replace('"', '""') + '"' for x in tokens))
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    if not settings.database_path.is_file():
        return {"results": [], "total": 0, "limit": limit, "offset": offset}
    with Database(settings.database_path, read_only=True) as db:
        if not has_schema(db) or limit == 0:
            return {"results": [], "total": 0, "limit": limit, "offset": offset}
        total = db.one("SELECT count(*) n FROM cyber_entities e" + join + where, params)["n"]
        ordering = ("CASE WHEN e.kev=1 OR json_extract(e.data_json,'$.priority')='known_exploited' THEN 1 ELSE 0 END DESC,"
                    "e.epss DESC,e.cvss DESC,") if sort == "risk" else "e." + sort + " DESC,"
        rows = db.query("SELECT e.data_json FROM cyber_entities e" + join + where +
                        " ORDER BY CASE e.status WHEN 'published' THEN 0 ELSE 1 END," + ordering
                        + ("bm25(cyber_fts)," if tokens else "") + "e.modified DESC,e.vulnerability_id LIMIT ? OFFSET ?", [*params, limit, offset])
    results = []
    for row in rows:
        data = json.loads(row["data_json"])
        data.pop("observations", None)
        data["description"] = data["description"][:700]
        results.append(data)
    return {"results": results, "total": total, "limit": limit, "offset": offset,
            "truncated": offset + len(results) < total}


def get_vulnerability(settings: Settings, vulnerability_id: str) -> dict | None:
    requested = identifier(vulnerability_id)
    if not settings.database_path.is_file():
        return None
    with Database(settings.database_path, read_only=True) as db:
        if not has_schema(db):
            return None
        row = db.one("SELECT data_json FROM cyber_entities WHERE vulnerability_id=?", (requested,))
        if row:
            return json.loads(row["data_json"])
        aliases = db.query("SELECT DISTINCT a.vulnerability_id FROM cyber_aliases a JOIN cyber_records r "
                           "USING(source,source_id) WHERE a.source_id=? AND r.active=1 ORDER BY a.vulnerability_id", (requested,))
        return {"id": requested, "related_cves": [r["vulnerability_id"] for r in aliases],
                "relation": "advisory_covers; CVEs are not asserted equivalent"} if aliases else None


def cyber_status(settings: Settings) -> dict:
    cyber = settings.raw.get("cyber", {})
    cadence = cyber.get("cadence", {}) if isinstance(cyber, dict) else {}
    enabled = isinstance(cadence, dict) and cadence.get("enabled") is True
    cadence_status = {"periodic_enabled": enabled, "cadence_mode": "foreground_only", "background_process_managed": False}
    empty = {"schema_version": 0, "entities": 0, "records": 0, "kev": 0, "connectors": [{"source": s, "status": "never", "stale": True, "records": 0} for s in SOURCES], "runs": [], **cadence_status}
    if not settings.database_path.is_file():
        return empty
    with Database(settings.database_path, read_only=True) as db:
        if not has_schema(db):
            return empty
        states = {r["source"]: dict(r) for r in db.query("SELECT * FROM cyber_sync_state")}
        connectors = []
        for source in SOURCES:
            state = states.get(source, {"source": source, "status": "never"})
            state["scope"] = json.loads(state.pop("scope_json", "{}"))
            last = state.get("last_success")
            state["stale"] = bool(state["scope"].get("backlog")) or not last or (datetime.now(timezone.utc) - datetime.fromisoformat(last)).total_seconds() > 86400
            if source == "nvd":
                window = db.one("SELECT scope_json,finished_at FROM cyber_sync_runs WHERE source='nvd' AND status='ok' "
                                "AND json_extract(scope_json,'$.type')='modified_window' ORDER BY run_id DESC LIMIT 1")
                window_scope = json.loads(window["scope_json"]) if window else {}
                incomplete = not window or bool(window_scope.get("backlog"))
                window_old = not window or not window["finished_at"] or (
                    datetime.now(timezone.utc) - datetime.fromisoformat(window["finished_at"])).total_seconds() > 86400
                state["coverage"] = {"kind": "incremental_window_checkpoint" if window else "identifier_lookups_only_or_none",
                                     "covered_until": state.get("watermark"), "backlog": incomplete,
                                     "last_complete_window_at": window["finished_at"] if window else None}
                state["stale"] = bool(incomplete or window_old)
            elif source == "msrc":
                from .msrc_state import months
                state["coverage"] = {"kind": "selected_monthly_documents", "months": months(db),
                                     "global_coverage": False}
            else:
                state["coverage"] = {"kind": "full_catalog_snapshot" if source == "kev" else "selective_public_identifiers"}
            state["records"] = db.one("SELECT count(*) n FROM cyber_records WHERE source=? AND active=1", (source,))["n"]
            connectors.append(state)
        pending = [dict(r) for r in db.query("SELECT source,next_offset,expected_total,page_size,byte_count,updated_at FROM cyber_pending_windows")] if schema_version(db) >= 2 else []
        return {"schema_version": schema_version(db), "entities": db.one("SELECT count(*) n FROM cyber_entities")["n"],
                "records": db.one("SELECT count(*) n FROM cyber_records WHERE active=1")["n"],
                "kev": db.one("SELECT count(*) n FROM cyber_entities WHERE kev=1")["n"], "connectors": connectors,
                "runs": [dict(r) for r in db.query("SELECT run_id,source,started_at,finished_at,status,added,modified,unchanged,retired,requests,error_code FROM cyber_sync_runs ORDER BY run_id DESC LIMIT 20")],
                "pending_windows": pending, **cadence_status}


def vulnerability_context(settings: Settings, query: str, *, max_chars: int = 6000, limit: int = 5, **filters) -> dict:
    budget = min(max(int(max_chars), 0), 100_000)
    if not budget:
        return {"fragments": [], "used_chars": 0, "max_chars": 0}
    found = search_vulnerabilities(settings, query, limit=min(max(limit, 0), 20), **filters)
    fragments, used = [], 0
    for item in found["results"]:
        record = get_vulnerability(settings, item["id"])
        if not record:
            continue
        observations = record.get("observations", [])
        for observation in observations:
            content = observation["description"] or observation["title"]
            if not content or used >= budget:
                continue
            passage = content[:min(1200, budget - used)]
            fragments.append({"id": item["id"], "source": observation["source"], "text": passage,
                              "citation": observation["source_url"], "retrieved_at": observation["retrieved_at"],
                              "locator": observation.get("provider_locator"),
                              "modified": observation["modified"], "trust": "untrusted public data; not instructions"})
            used += len(passage)
    return {"fragments": fragments, "used_chars": used, "max_chars": budget, "total_matches": found["total"]}
