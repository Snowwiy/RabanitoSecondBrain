"""Transactional ATT&CK namespace; explicit publication of a verified capture.

Releases are immutable collection memberships. Revisions record only locally
observed changes, not a reconstructed history of the publisher or local attacks.
"""
from __future__ import annotations

import hashlib
import json
import uuid

from .attack import normalize_bundle, _stamp
from .attack_capture import _folder, _read_checked, read_capture, LICENSE_MAX
from .db import Database
from .indexer import _index_lock
from .utils import contains_reparse_component, iso_now, safe_relative


ENGINE_VERSION = 1
DDL = """
CREATE TABLE attack_migrations(version INTEGER PRIMARY KEY,checksum TEXT NOT NULL,applied_at TEXT NOT NULL);
CREATE TABLE attack_releases(release_id TEXT PRIMARY KEY,domain TEXT NOT NULL,version TEXT NOT NULL,
 collection_modified TEXT NOT NULL,source_commit TEXT NOT NULL,body_sha256 TEXT NOT NULL,
 engine INTEGER NOT NULL,data_json TEXT NOT NULL CHECK(json_valid(data_json)),license_text TEXT NOT NULL,
 captured_at TEXT NOT NULL,published_at TEXT NOT NULL);
CREATE INDEX attack_release_domain ON attack_releases(domain,version);
CREATE TABLE attack_heads(domain TEXT PRIMARY KEY,release_id TEXT NOT NULL REFERENCES attack_releases(release_id));
CREATE TABLE attack_revisions(revision_id INTEGER PRIMARY KEY,domain TEXT NOT NULL,stix_id TEXT NOT NULL,
 event TEXT NOT NULL CHECK(event IN ('added','modified','reactivated','retired')),fingerprint TEXT NOT NULL,
 kind TEXT NOT NULL,title TEXT NOT NULL,modified TEXT NOT NULL,revoked INTEGER NOT NULL CHECK(revoked IN (0,1)),
 deprecated INTEGER NOT NULL CHECK(deprecated IN (0,1)),present INTEGER NOT NULL CHECK(present IN (0,1)),
 source_ref TEXT,target_ref TEXT,relationship_type TEXT,data_json TEXT NOT NULL CHECK(json_valid(data_json)),
 release_id TEXT NOT NULL REFERENCES attack_releases(release_id),
 citation_release_id TEXT NOT NULL REFERENCES attack_releases(release_id),locator TEXT NOT NULL,observed_at TEXT NOT NULL);
CREATE INDEX attack_revision_identity ON attack_revisions(domain,stix_id,revision_id DESC);
CREATE INDEX attack_revision_source ON attack_revisions(domain,source_ref,relationship_type);
CREATE INDEX attack_revision_target ON attack_revisions(domain,target_ref,relationship_type);
CREATE TABLE attack_records(domain TEXT NOT NULL,stix_id TEXT NOT NULL,
 revision_id INTEGER NOT NULL REFERENCES attack_revisions(revision_id),
 citation_release_id TEXT NOT NULL REFERENCES attack_releases(release_id),locator TEXT NOT NULL,
 present INTEGER NOT NULL CHECK(present IN (0,1)),PRIMARY KEY(domain,stix_id));
CREATE TABLE attack_members(release_id TEXT NOT NULL REFERENCES attack_releases(release_id),domain TEXT NOT NULL,
 stix_id TEXT NOT NULL,revision_id INTEGER NOT NULL REFERENCES attack_revisions(revision_id),locator TEXT NOT NULL,
 PRIMARY KEY(release_id,stix_id));
CREATE INDEX attack_member_revision ON attack_members(revision_id,release_id);
CREATE VIRTUAL TABLE attack_fts USING fts5(revision_id UNINDEXED,title,description,identifiers,aliases);
"""


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def schema(db: Database, *, create=False) -> bool:
    exists = db.one("SELECT 1 FROM sqlite_master WHERE type='table' AND name='attack_migrations'") is not None
    digest = hashlib.sha256(DDL.encode()).hexdigest()
    if exists:
        rows = db.query("SELECT version,checksum FROM attack_migrations ORDER BY version")
        if len(rows) != 1 or rows[0]["version"] != 1 or rows[0]["checksum"] != digest:
            raise ValueError("unsupported_attack_schema_migration")
        return True
    if not create:
        return False
    try:
        db.connection.executescript("BEGIN IMMEDIATE;\n" + DDL)
        db.execute("INSERT INTO attack_migrations VALUES (1,?,?)", (digest, iso_now()))
        db.commit()
    except BaseException:
        db.connection.rollback()
        raise
    return True


def _own_outputs(settings):
    for path in (settings.database_path, settings.data_dir, settings.data_dir / "backups", settings.data_dir / "index.lock"):
        if safe_relative(path, settings.root) in {None, "", "."} or contains_reparse_component(path):
            raise ValueError("unsafe_attack_index_output")


def _revision(db, domain, item, event, release_id, citation_release, locator, timestamp):
    present = event != "retired"
    payload = {k: v for k, v in item.items() if k != "locator"}
    cursor = db.execute("INSERT INTO attack_revisions(domain,stix_id,event,fingerprint,kind,title,modified,revoked,deprecated,"
        "present,source_ref,target_ref,relationship_type,data_json,release_id,citation_release_id,locator,observed_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (domain, item["id"], event, item["fingerprint"], item["type"], item.get("name", item.get("relationship_type", "")),
         item["modified"], int(item["revoked"]), int(item["deprecated"]), int(present), item.get("source_ref"),
         item.get("target_ref"), item.get("relationship_type"), encode(payload), release_id, citation_release, locator, timestamp))
    revision_id = cursor.lastrowid
    if present:
        db.execute("INSERT INTO attack_fts VALUES (?,?,?,?,?)", (revision_id, item.get("name", item.get("relationship_type", "")),
                   item["description"], " ".join([item["id"], *item.get("attack_ids", [])]), " ".join(item.get("aliases", []))))
    return revision_id


def index_capture(settings, manifest_name: str) -> dict:
    """Publish a complete domain atomically; no network or source writes.

    FTS only changes for new/modified/reactivated revisions. Provenance membership
    is stored for every release, including unchanged objects and moved pointers.
    Repeating the same current release performs no namespace data writes.
    """
    _own_outputs(settings)
    raw, metadata = read_capture(settings, manifest_name)
    normalized = normalize_bundle(raw, metadata["domain"], metadata["version"])
    license_raw = _read_checked(_folder(settings) / metadata["license"], metadata["license_bytes"], metadata["license_sha256"], LICENSE_MAX)
    license_text = license_raw.decode("utf-8")
    domain, timestamp = metadata["domain"], iso_now()
    release_id = hashlib.sha256(encode([domain, metadata["version"], metadata["commit"], metadata["sha256"],
                                       metadata["license_sha256"], ENGINE_VERSION]).encode()).hexdigest()
    release = {k: v for k, v in metadata.items() if k not in {"transport_complete", "requests", "database_written"}}
    release.update(release_id=release_id, collection_id=normalized["collection_id"], bundle_id=normalized["bundle_id"],
                   collection_modified=normalized["collection_modified"], coverage=normalized["coverage"], engine=ENGINE_VERSION)
    items = normalized["objects"] + normalized["relationships"]
    counts = {k: 0 for k in ("added", "modified", "reactivated", "retired", "unchanged")}
    with _index_lock(settings), Database(settings.database_path) as db:
        backup = None
        if not schema(db):
            target = settings.data_dir / "backups" / ("pre-attack-schema1-" + uuid.uuid4().hex + ".db")
            db.backup(target)
            backup = target.name
            schema(db, create=True)
        head = db.one("SELECT r.* FROM attack_heads h JOIN attack_releases r ON r.release_id=h.release_id WHERE h.domain=?", (domain,))
        if head and head["release_id"] == release_id:
            counts["unchanged"] = len(items)
            return {"status": "ok", "domain": domain, "release_id": release_id, **counts, "requests": 0,
                    "content_reused": True, "checked_at": timestamp, "migration_backup": backup}
        if head and (tuple(map(int, metadata["version"].split("."))) < tuple(map(int, head["version"].split(".")))
                     or _stamp(normalized["collection_modified"]) < _stamp(head["collection_modified"])):
            raise ValueError("stale_attack_collection")
        if db.one("SELECT 1 FROM attack_releases WHERE release_id=?", (release_id,)):
            raise ValueError("attack_release_already_superseded")
        previous = {row["stix_id"]: dict(row) for row in db.query(
            "SELECT c.*,r.fingerprint,r.modified,r.data_json FROM attack_records c "
            "JOIN attack_revisions r ON r.revision_id=c.revision_id WHERE c.domain=?", (domain,))}
        for item in items:
            old = previous.get(item["id"])
            if old and _stamp(item["modified"]) < _stamp(old["modified"]):
                raise ValueError("stale_attack_object")
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO attack_releases VALUES (?,?,?,?,?,?,?,?,?,?,?)", (release_id, domain, metadata["version"],
                normalized["collection_modified"], metadata["commit"], metadata["sha256"], ENGINE_VERSION, encode(release),
                license_text, metadata["captured_at"], timestamp))
            members, records, seen = [], [], set()
            for item in items:
                identity = item["id"]
                seen.add(identity)
                old = previous.get(identity)
                event = ("added" if old is None else "reactivated" if not old["present"] else
                         "unchanged" if old["fingerprint"] == item["fingerprint"] else "modified")
                counts[event] += 1
                revision_id = old["revision_id"] if event == "unchanged" else _revision(
                    db, domain, item, event, release_id, release_id, item["locator"], timestamp)
                members.append((release_id, domain, identity, revision_id, item["locator"]))
                records.append((domain, identity, revision_id, release_id, item["locator"], 1))
            for identity, old in previous.items():
                if identity not in seen and old["present"]:
                    counts["retired"] += 1
                    revision_id = _revision(db, domain, json.loads(old["data_json"]), "retired", release_id,
                                            old["citation_release_id"], old["locator"], timestamp)
                    records.append((domain, identity, revision_id, old["citation_release_id"], old["locator"], 0))
            db.executemany("INSERT INTO attack_members VALUES (?,?,?,?,?)", members)
            db.executemany("INSERT INTO attack_records VALUES (?,?,?,?,?,?) ON CONFLICT(domain,stix_id) DO UPDATE SET "
                "revision_id=excluded.revision_id,citation_release_id=excluded.citation_release_id,"
                "locator=excluded.locator,present=excluded.present", records)
            db.execute("INSERT INTO attack_heads VALUES (?,?) ON CONFLICT(domain) DO UPDATE SET release_id=excluded.release_id", (domain, release_id))
            db.commit()
        except BaseException:
            db.connection.rollback()
            raise
    return {"status": "ok", "domain": domain, "release_id": release_id, **counts, "requests": 0,
            "content_reused": False, "checked_at": timestamp, "migration_backup": backup}
