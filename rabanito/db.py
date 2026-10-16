from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Iterable


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS documents (
    document_id INTEGER PRIMARY KEY,
    source_kind TEXT NOT NULL,
    source_root TEXT NOT NULL,
    project_name TEXT,
    project_root_path TEXT,
    relative_path TEXT NOT NULL,
    absolute_path TEXT NOT NULL UNIQUE,
    path_key TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    frontmatter_json TEXT NOT NULL DEFAULT '{}',
    tags_json TEXT NOT NULL DEFAULT '[]',
    content_hash TEXT NOT NULL DEFAULT '',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    mtime_ns INTEGER NOT NULL DEFAULT 0,
    mtime_iso TEXT,
    indexed_at TEXT NOT NULL,
    last_seen_scan TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    parse_error TEXT
);

CREATE INDEX IF NOT EXISTS idx_documents_active ON documents(status, source_kind);
CREATE INDEX IF NOT EXISTS idx_documents_category ON documents(category);
CREATE INDEX IF NOT EXISTS idx_documents_project ON documents(project_name);
CREATE INDEX IF NOT EXISTS idx_documents_hash ON documents(content_hash);

CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
    document_id UNINDEXED,
    title,
    tags,
    body
);

CREATE TABLE IF NOT EXISTS document_chunks (
    chunk_id INTEGER PRIMARY KEY,
    document_id INTEGER NOT NULL REFERENCES documents(document_id) ON DELETE CASCADE,
    heading TEXT NOT NULL DEFAULT '',
    line_start INTEGER NOT NULL,
    line_end INTEGER NOT NULL,
    text TEXT NOT NULL,
    text_hash TEXT NOT NULL,
    UNIQUE(document_id, line_start, text_hash)
);

CREATE INDEX IF NOT EXISTS idx_chunks_document ON document_chunks(document_id);

CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
    chunk_id UNINDEXED,
    document_id UNINDEXED,
    heading,
    text
);

CREATE TABLE IF NOT EXISTS tags (
    document_id INTEGER NOT NULL REFERENCES documents(document_id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY(document_id, tag)
);

CREATE TABLE IF NOT EXISTS links (
    link_id INTEGER PRIMARY KEY,
    source_document_id INTEGER NOT NULL REFERENCES documents(document_id) ON DELETE CASCADE,
    target_raw TEXT NOT NULL,
    target_document_id INTEGER REFERENCES documents(document_id) ON DELETE SET NULL,
    relation_type TEXT NOT NULL DEFAULT 'wikilink',
    status TEXT NOT NULL DEFAULT 'unresolved',
    label TEXT,
    line_number INTEGER,
    target_path_guess TEXT,
    resolution_reason TEXT,
    UNIQUE(source_document_id, target_raw, line_number)
);

CREATE INDEX IF NOT EXISTS idx_links_source ON links(source_document_id);
CREATE INDEX IF NOT EXISTS idx_links_target ON links(target_document_id);
CREATE INDEX IF NOT EXISTS idx_links_status ON links(status);

CREATE TABLE IF NOT EXISTS link_suggestions (
    suggestion_id INTEGER PRIMARY KEY,
    source_document_id INTEGER NOT NULL REFERENCES documents(document_id) ON DELETE CASCADE,
    target_document_id INTEGER NOT NULL REFERENCES documents(document_id) ON DELETE CASCADE,
    score REAL NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'suggested',
    created_at TEXT NOT NULL,
    UNIQUE(source_document_id, target_document_id, reason)
);

CREATE INDEX IF NOT EXISTS idx_suggestions_status_source ON link_suggestions(status, source_document_id);
CREATE INDEX IF NOT EXISTS idx_suggestions_status_target ON link_suggestions(status, target_document_id);

CREATE TABLE IF NOT EXISTS scan_runs (
    scan_id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    files_seen INTEGER NOT NULL DEFAULT 0,
    added INTEGER NOT NULL DEFAULT 0,
    modified INTEGER NOT NULL DEFAULT 0,
    unchanged INTEGER NOT NULL DEFAULT 0,
    removed INTEGER NOT NULL DEFAULT 0,
    skipped INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    source_summary_json TEXT NOT NULL DEFAULT '{}',
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS document_changes (
    change_id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scan_runs(scan_id) ON DELETE CASCADE,
    document_id INTEGER NOT NULL REFERENCES documents(document_id) ON DELETE CASCADE,
    change_type TEXT NOT NULL CHECK(change_type IN ('added','modified','restored','skipped','removed')),
    reason TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    UNIQUE(scan_id, document_id, change_type)
);

CREATE INDEX IF NOT EXISTS idx_document_changes_recent ON document_changes(change_id DESC);
CREATE INDEX IF NOT EXISTS idx_document_changes_document ON document_changes(document_id, change_id DESC);

CREATE TABLE IF NOT EXISTS projects (
    project_id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    root_path TEXT NOT NULL UNIQUE,
    path_key TEXT NOT NULL UNIQUE,
    technology_json TEXT NOT NULL DEFAULT '[]',
    structure_json TEXT NOT NULL DEFAULT '[]',
    documentation_json TEXT NOT NULL DEFAULT '[]',
    dependencies_json TEXT NOT NULL DEFAULT '[]',
    dependencies_truncated INTEGER NOT NULL DEFAULT 0,
    dependency_errors_json TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS project_files (
    project_file_id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    relative_path TEXT NOT NULL,
    extension TEXT NOT NULL,
    classification TEXT NOT NULL,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    mtime_ns INTEGER NOT NULL DEFAULT 0,
    last_seen TEXT NOT NULL,
    UNIQUE(project_id, relative_path)
);

CREATE TABLE IF NOT EXISTS approved_interviews (
    interview_id INTEGER PRIMARY KEY,
    topic TEXT NOT NULL,
    path TEXT NOT NULL UNIQUE,
    approved_at TEXT NOT NULL,
    question_count INTEGER NOT NULL
);
"""


class Database:
    def __init__(self, path: Path, *, read_only: bool = False):
        self.path = path
        if read_only:
            self.connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=30)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA foreign_keys=ON")
            self.connection.execute("PRAGMA busy_timeout=30000")
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(path), timeout=30)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA busy_timeout=30000")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.connection.executescript(SCHEMA)
        document_columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(documents)")}
        if "project_root_path" not in document_columns:
            self.connection.execute("ALTER TABLE documents ADD COLUMN project_root_path TEXT")
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_documents_project_root ON documents(project_root_path, status)")
        # Existing project-source rows already use the project directory as their
        # source_root, so this backfill needs no file reads or inferred names.
        self.connection.execute(
            "UPDATE documents SET project_root_path=source_root WHERE source_kind='projects' AND project_root_path IS NULL"
        )
        link_columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(links)")}
        if "resolution_reason" not in link_columns:
            self.connection.execute("ALTER TABLE links ADD COLUMN resolution_reason TEXT")
        project_columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(projects)")}
        if "dependencies_json" not in project_columns:
            self.connection.execute("ALTER TABLE projects ADD COLUMN dependencies_json TEXT NOT NULL DEFAULT '[]'")
        if "dependencies_truncated" not in project_columns:
            self.connection.execute("ALTER TABLE projects ADD COLUMN dependencies_truncated INTEGER NOT NULL DEFAULT 0")
        if "dependency_errors_json" not in project_columns:
            self.connection.execute("ALTER TABLE projects ADD COLUMN dependency_errors_json TEXT NOT NULL DEFAULT '[]'")
        self.connection.commit()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type:
            self.connection.rollback()
        else:
            self.connection.commit()
        self.connection.close()

    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        return self.connection.execute(sql, tuple(params))

    def executemany(self, sql: str, rows: Iterable[Iterable[Any]]) -> sqlite3.Cursor:
        return self.connection.executemany(sql, rows)

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        return list(self.execute(sql, params).fetchall())

    def one(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        return self.execute(sql, params).fetchone()

    def commit(self) -> None:
        self.connection.commit()

    def backup(self, target: Path) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        # Reserve a fresh name first so a timestamp collision or accidental
        # explicit path never truncates an older, potentially valuable backup.
        created = False
        destination: sqlite3.Connection | None = None
        try:
            with target.open("xb"):
                created = True
            destination = sqlite3.connect(str(target))
            self.connection.backup(destination)
            # The source uses WAL for concurrent reads. A portable backup is a
            # single self-contained file, so checkpoint and switch the copy to
            # rollback-journal mode before closing it.
            mode = destination.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            if str(mode).casefold() != "delete":
                raise sqlite3.DatabaseError(f"Could not make backup standalone (journal_mode={mode}).")
            integrity = destination.execute("PRAGMA integrity_check").fetchone()[0]
            foreign_key_errors = destination.execute("PRAGMA foreign_key_check").fetchall()
            if integrity != "ok" or foreign_key_errors:
                raise sqlite3.DatabaseError("Created backup failed SQLite integrity checks.")
        except BaseException:
            if destination is not None:
                destination.close()
            if created:
                # These files belong to the just-reserved backup target only.
                for partial in (target, Path(str(target) + "-wal"), Path(str(target) + "-shm")):
                    try:
                        partial.unlink(missing_ok=True)
                    except OSError:
                        pass
            raise
        else:
            # sqlite3.Connection's context manager commits/rolls back but does not close.
            # Close explicitly so Windows releases the handle after validation.
            assert destination is not None
            destination.close()


def _validate_rabanito_database(connection: sqlite3.Connection) -> None:
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
    tables = {
        row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    required = {"meta", "documents", "documents_fts", "document_chunks", "chunks_fts", "links"}
    if integrity != "ok" or foreign_key_errors or not required.issubset(tables):
        raise sqlite3.DatabaseError("Database failed Rabanito integrity/schema validation.")


def restore_database(source: Path, target: Path) -> None:
    """Validate a Rabanito backup, stage it beside the live DB, then replace atomically."""
    source_path = source.resolve(strict=True)
    target_path = target.resolve(strict=False)
    if source_path == target_path:
        raise ValueError("Restore source and target must be different files.")
    if source_path.suffix.casefold() != ".db" or target_path.suffix.casefold() != ".db":
        raise ValueError("Restore source and target must use the .db extension.")

    sidecars = (Path(str(target_path) + "-wal"), Path(str(target_path) + "-shm"))
    if any(path.exists() for path in sidecars):
        raise sqlite3.OperationalError("Database has active SQLite sidecars; stop dashboard/writers and retry.")

    target_path.parent.mkdir(parents=True, exist_ok=True)
    fd, staged_name = tempfile.mkstemp(prefix=target_path.name + ".", suffix=".restore.tmp", dir=target_path.parent)
    os.close(fd)
    staged_path = Path(staged_name)
    source_connection: sqlite3.Connection | None = None
    staged_connection: sqlite3.Connection | None = None
    try:
        source_uri = source_path.as_uri() + "?mode=ro"
        source_connection = sqlite3.connect(source_uri, uri=True, timeout=30)
        _validate_rabanito_database(source_connection)

        staged_connection = sqlite3.connect(str(staged_path), timeout=30)
        source_connection.backup(staged_connection)
        journal_mode = staged_connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        if str(journal_mode).casefold() != "delete":
            raise sqlite3.DatabaseError("Could not make restored database self-contained.")
        _validate_rabanito_database(staged_connection)
        staged_connection.close()
        staged_connection = None
        source_connection.close()
        source_connection = None

        if any(path.exists() for path in sidecars):
            raise sqlite3.OperationalError("Database became active during restore; staged data was not installed.")
        os.replace(staged_path, target_path)
    except BaseException:
        if staged_connection is not None:
            staged_connection.close()
        if source_connection is not None:
            source_connection.close()
        raise
    finally:
        for partial in (staged_path, Path(str(staged_path) + "-wal"), Path(str(staged_path) + "-shm")):
            try:
                partial.unlink(missing_ok=True)
            except OSError:
                pass
