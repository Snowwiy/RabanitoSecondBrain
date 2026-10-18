"""Additive monthly MSRC checkpoints, separate from immutable Cyber migrations."""
from __future__ import annotations

import hashlib
import json
import uuid

from ..db import Database
from ..utils import contains_reparse_component, iso_now, safe_relative


DDL = """
CREATE TABLE msrc_migrations(version INTEGER PRIMARY KEY,checksum TEXT NOT NULL,applied_at TEXT NOT NULL);
CREATE TABLE msrc_documents(month TEXT PRIMARY KEY,summary_modified TEXT NOT NULL,
 document_modified TEXT NOT NULL,adapter_version INTEGER NOT NULL,capture_sha256 TEXT NOT NULL,
 capture_manifest TEXT NOT NULL,captured_at TEXT NOT NULL,published_at TEXT NOT NULL,checked_at TEXT NOT NULL,
 record_count INTEGER NOT NULL CHECK(record_count>0),records_sha256 TEXT NOT NULL);
"""


def schema(db: Database, *, create=False) -> bool:
    exists = db.one("SELECT 1 FROM sqlite_master WHERE type='table' AND name='msrc_migrations'") is not None
    checksum = hashlib.sha256(DDL.encode()).hexdigest()
    if exists:
        rows = db.query("SELECT version,checksum FROM msrc_migrations ORDER BY version")
        if len(rows) != 1 or rows[0]["version"] != 1 or rows[0]["checksum"] != checksum:
            raise ValueError("unsupported_msrc_migration")
        return True
    if not create:
        return False
    try:
        db.connection.executescript("BEGIN IMMEDIATE;\n" + DDL)
        db.execute("INSERT INTO msrc_migrations VALUES (1,?,?)", (checksum, iso_now()))
        db.commit()
    except BaseException:
        db.connection.rollback()
        raise
    return True


def own_outputs(settings):
    for path in (settings.database_path, settings.data_dir, settings.data_dir / "backups", settings.data_dir / "index.lock"):
        if safe_relative(path, settings.root) in {None, "", "."} or contains_reparse_component(path):
            raise ValueError("unsafe_msrc_output")


def migrate(settings, db: Database) -> str | None:
    if schema(db):
        return None
    own_outputs(settings)
    backup = settings.data_dir / "backups" / ("pre-msrc-schema1-" + uuid.uuid4().hex + ".db")
    db.backup(backup)
    schema(db, create=True)
    return backup.name


def record_proof(db: Database, month: str) -> tuple[int, str | None]:
    prefix = "MSRC-" + month + "-"
    rows = db.query("SELECT source_id,fingerprint,data_json FROM cyber_records "
                    "WHERE source='msrc' AND active=1 AND substr(source_id,1,?)=? ORDER BY source_id", (len(prefix), prefix))
    digest = hashlib.sha256()
    for row in rows:
        if hashlib.sha256(row["data_json"].encode()).hexdigest() != row["fingerprint"]:
            return len(rows), None
        digest.update(json.dumps([row["source_id"], row["fingerprint"]], separators=(",", ":")).encode())
    return len(rows), digest.hexdigest()


def months(db: Database) -> list[dict]:
    if not schema(db):
        return []
    return [dict(r) for r in db.query("SELECT month,summary_modified,document_modified,adapter_version,capture_sha256,"
                                    "captured_at,published_at,checked_at,record_count FROM msrc_documents ORDER BY month")]
