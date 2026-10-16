"""Small, curated standards catalog. Summaries and editorial mappings are not certification."""
from __future__ import annotations

import hashlib
import json
import re
import uuid

from .config import Settings
from .cyber.model import date, public_url, text
from .db import Database
from .indexer import _index_lock
from .utils import contains_reparse_component, iso_now


SCHEMA = """
CREATE TABLE security_migrations(version INTEGER PRIMARY KEY,checksum TEXT NOT NULL,applied_at TEXT NOT NULL);
CREATE TABLE security_entries(entry_id TEXT PRIMARY KEY,framework TEXT NOT NULL,kind TEXT NOT NULL,
 edition_status TEXT NOT NULL,title TEXT NOT NULL,data_json TEXT NOT NULL CHECK(json_valid(data_json)),
 fingerprint TEXT NOT NULL,indexed_at TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)));
CREATE INDEX security_framework ON security_entries(framework,kind,active);
CREATE VIRTUAL TABLE security_fts USING fts5(entry_id UNINDEXED,title,summary,terms);
CREATE TABLE security_relations(source_id TEXT NOT NULL REFERENCES security_entries(entry_id),
 target_id TEXT NOT NULL REFERENCES security_entries(entry_id),relation_type TEXT NOT NULL,
 rationale TEXT NOT NULL,validation TEXT NOT NULL,PRIMARY KEY(source_id,target_id,relation_type));
"""
OFFICIAL_HOSTS = {"csrc.nist.gov", "nvlpubs.nist.gov", "www.nist.gov", "www.cisa.gov", "owasp.org", "top10.owasp.org",
                  "www.cisecurity.org", "www.iso.org", "attack.mitre.org", "learn.microsoft.com", "docs.redhat.com"}


def _exists(db: Database) -> bool:
    return db.one("SELECT 1 FROM sqlite_master WHERE name='security_migrations' AND type='table'") is not None


def _schema(db: Database) -> None:
    checksum = hashlib.sha256(SCHEMA.encode()).hexdigest()
    if _exists(db):
        rows = db.query("SELECT version,checksum FROM security_migrations")
        if len(rows) != 1 or rows[0]["version"] != 1 or rows[0]["checksum"] != checksum:
            raise ValueError("Unsupported Security Architecture migration")
        return
    try:
        db.connection.executescript("BEGIN IMMEDIATE;\n" + SCHEMA)
        db.execute("INSERT INTO security_migrations VALUES (1,?,?)", (checksum, iso_now()))
        db.commit()
    except BaseException:
        db.connection.rollback()
        raise


def _id(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}", value) or ".." in value:
        raise ValueError("Invalid catalog identifier")
    return value


def validate_catalog(data: object) -> tuple[list[dict], list[dict], str]:
    from urllib.parse import urlsplit
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list) or not 1 <= len(data["entries"]) <= 10000:
        raise ValueError("Invalid security catalog")
    version = text(data.get("catalog_version"), 60)
    reviewed = date(data.get("reviewed_on"))
    if not version or not reviewed:
        raise ValueError("Catalog version and review date are required")
    entries, ids = [], set()
    for raw in data["entries"]:
        if not isinstance(raw, dict):
            raise ValueError("Invalid security entry")
        entry_id = _id(raw.get("id"))
        if entry_id in ids:
            raise ValueError("Duplicate security identifier")
        ids.add(entry_id)
        url = public_url(raw.get("source_url"))
        if not url or urlsplit(url).scheme != "https" or urlsplit(url).hostname not in OFFICIAL_HOSTS:
            raise ValueError("Security catalog requires an official public HTTPS reference")
        if raw.get("kind") not in {"framework", "control", "concept", "reference"} or raw.get("edition_status") not in {"published", "historical", "draft", "rolling"}:
            raise ValueError("Invalid security classification")
        entry = {"id": entry_id, "framework": _id(raw.get("framework")), "kind": raw["kind"],
                 "edition_status": raw["edition_status"], "title": text(raw.get("title"), 300),
                 "edition": text(raw.get("edition"), 150), "summary": text(raw.get("summary"), 3000),
                 "source_url": url, "locator": text(raw.get("locator"), 300), "reviewed_on": reviewed,
                 "knowledge_type": "own_summary_of_cited_source", "rights": "Reference and original short summary only; source license still applies.",
                 "tags": raw.get("tags", [])}
        if not entry["title"] or not entry["summary"] or not isinstance(entry["tags"], list) or len(entry["tags"]) > 30 or any(not isinstance(t, str) or len(t) > 100 for t in entry["tags"]):
            raise ValueError("Invalid security summary/tags")
        entries.append(entry)
    relations = data.get("relations", [])
    if not isinstance(relations, list) or len(relations) > 30000:
        raise ValueError("Invalid security relations")
    normalized = []
    for relation in relations:
        if not isinstance(relation, dict) or relation.get("source") not in ids or relation.get("target") not in ids:
            raise ValueError("Dangling security relation")
        kind = relation.get("type")
        if kind not in {"part_of", "superseded_by", "editorial_overlap"}:
            raise ValueError("Invalid security relation type")
        normalized.append({"source": relation["source"], "target": relation["target"], "type": kind,
                           "rationale": text(relation.get("rationale"), 1000),
                           "validation": "unvalidated_editorial" if kind == "editorial_overlap" else "source_documented"})
    return entries, normalized, version


def index_security_catalog(settings: Settings) -> dict:
    path = settings.root / "config" / "security_catalog.json"
    if contains_reparse_component(path) or path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("Security catalog is unsafe or exceeds limit")
    entries, relations, version = validate_catalog(json.loads(path.read_text(encoding="utf-8")))
    with _index_lock(settings), Database(settings.database_path) as db:
        backup = None
        if not _exists(db) and db.one("SELECT count(*) n FROM documents")["n"]:
            target = settings.data_dir / "backups" / ("pre-security-schema1-" + uuid.uuid4().hex + ".db")
            db.backup(target)
            backup = target.name
        _schema(db)
        counts = {"added": 0, "modified": 0, "unchanged": 0, "retired": 0}
        timestamp = iso_now()
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM security_relations")
            seen = set()
            for entry in entries:
                entry_id = entry["id"]
                seen.add(entry_id)
                rendered = json.dumps(entry, sort_keys=True, ensure_ascii=False)
                fingerprint = hashlib.sha256(rendered.encode()).hexdigest()
                old = db.one("SELECT fingerprint,active FROM security_entries WHERE entry_id=?", (entry_id,))
                unchanged = old and old["fingerprint"] == fingerprint and old["active"]
                counts["added" if old is None else "unchanged" if unchanged else "modified"] += 1
                if unchanged:
                    continue
                db.execute("INSERT INTO security_entries VALUES (?,?,?,?,?,?,?,?,1) ON CONFLICT(entry_id) DO UPDATE SET "
                           "framework=excluded.framework,kind=excluded.kind,edition_status=excluded.edition_status,title=excluded.title,"
                           "data_json=excluded.data_json,fingerprint=excluded.fingerprint,indexed_at=excluded.indexed_at,active=1",
                           (entry_id, entry["framework"], entry["kind"], entry["edition_status"], entry["title"], rendered, fingerprint, timestamp))
                db.execute("DELETE FROM security_fts WHERE entry_id=?", (entry_id,))
                db.execute("INSERT INTO security_fts VALUES (?,?,?,?)", (entry_id, entry["title"], entry["summary"], " ".join([entry_id, entry["framework"], *entry["tags"]])))
            for row in db.query("SELECT entry_id FROM security_entries WHERE active=1"):
                if row["entry_id"] not in seen:
                    db.execute("UPDATE security_entries SET active=0 WHERE entry_id=?", (row["entry_id"],))
                    db.execute("DELETE FROM security_fts WHERE entry_id=?", (row["entry_id"],))
                    counts["retired"] += 1
            db.executemany("INSERT INTO security_relations VALUES (?,?,?,?,?)", [
                (r["source"], r["target"], r["type"], r["rationale"], r["validation"]) for r in relations])
            db.execute("INSERT INTO meta VALUES ('security_catalog_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (version,))
            db.execute("INSERT INTO meta VALUES ('security_catalog_indexed_at',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (timestamp,))
            db.commit()
        except BaseException:
            db.connection.rollback()
            raise
    return {"status": "ok", "catalog_version": version, **counts, "relations": len(relations), "migration_backup": backup}


def search_security(settings: Settings, query: str = "", *, framework: str | None = None,
                    kind: str | None = None, edition_status: str | None = None, limit: int = 20, offset: int = 0) -> dict:
    if not isinstance(query, str) or len(query) > 500:
        raise ValueError("Security query exceeds limit")
    limit, offset = min(max(int(limit), 0), 100), min(max(int(offset), 0), 100000)
    conditions, params, join = ["s.active=1"], [], ""
    for field, value in (("framework", framework), ("kind", kind), ("edition_status", edition_status)):
        if value:
            conditions.append("s." + field + "=?")
            params.append(text(value, 150))
    tokens = re.findall(r"[\w./-]+", query, re.UNICODE)[:30]
    if tokens:
        join = " JOIN security_fts f ON f.entry_id=s.entry_id"
        conditions.append("security_fts MATCH ?")
        params.append(" AND ".join('"' + x + '"' for x in tokens))
    where = " WHERE " + " AND ".join(conditions)
    if not settings.database_path.is_file():
        return {"results": [], "total": 0, "limit": limit, "offset": offset}
    with Database(settings.database_path, read_only=True) as db:
        if not _exists(db) or not limit:
            return {"results": [], "total": 0, "limit": limit, "offset": offset}
        total = db.one("SELECT count(*) n FROM security_entries s" + join + where, params)["n"]
        rows = db.query("SELECT s.data_json FROM security_entries s" + join + where
                        + " ORDER BY " + ("bm25(security_fts)," if tokens else "") + "s.framework,s.entry_id LIMIT ? OFFSET ?", [*params, limit, offset])
        version = db.one("SELECT value FROM meta WHERE key='security_catalog_version'")
    return {"results": [json.loads(row["data_json"]) for row in rows], "total": total, "limit": limit, "offset": offset,
            "catalog_version": version["value"] if version else None, "truncated": offset + len(rows) < total}


def get_security_entry(settings: Settings, entry_id: str) -> dict | None:
    requested = _id(entry_id)
    if not settings.database_path.is_file():
        return None
    with Database(settings.database_path, read_only=True) as db:
        if not _exists(db):
            return None
        row = db.one("SELECT data_json FROM security_entries WHERE entry_id=? AND active=1", (requested,))
        if not row:
            return None
        result = json.loads(row["data_json"])
        result["relations"] = [dict(r) for r in db.query("SELECT * FROM security_relations WHERE source_id=? OR target_id=? ORDER BY source_id,target_id", (requested, requested))]
        return result


def security_context(settings: Settings, query: str, *, max_chars: int = 6000, limit: int = 8) -> dict:
    budget = min(max(int(max_chars), 0), 100000)
    if not budget:
        return {"fragments": [], "used_chars": 0, "max_chars": 0}
    results = search_security(settings, query, limit=limit)
    fragments, used = [], 0
    for item in results["results"]:
        if used >= budget:
            break
        passage = item["summary"][:budget - used]
        fragments.append({"id": item["id"], "text": passage, "citation": item["source_url"], "locator": item["locator"],
                          "edition_status": item["edition_status"], "reviewed_on": item["reviewed_on"], "knowledge_type": item["knowledge_type"]})
        used += len(passage)
    return {"fragments": fragments, "used_chars": used, "max_chars": budget, "total_matches": results["total"]}
