"""Derived graph namespace. Explicit sync writes; graph reads never migrate."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from pathlib import Path

from ..config import Settings
from ..db import Database
from ..utils import contains_reparse_component, iso_now, path_key, safe_relative
from ..indexer import DEFAULT_EXCLUDED_DIRS, _excluded_directory, _excluded_name
from ..source_policy import document_eligibility


ENGINE_VERSION = 4
DDL = """
CREATE TABLE kg_migrations(version INTEGER PRIMARY KEY,checksum TEXT NOT NULL,applied_at TEXT NOT NULL);
CREATE TABLE kg_state(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE kg_epoch(singleton INTEGER PRIMARY KEY CHECK(singleton=1),value INTEGER NOT NULL);
INSERT INTO kg_epoch VALUES (1,0);
CREATE TABLE kg_watch_coverage(table_name TEXT PRIMARY KEY,checksum TEXT NOT NULL);
CREATE TABLE kg_inputs(input_key TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,family TEXT NOT NULL,
 native_id TEXT NOT NULL,origin TEXT NOT NULL,project_id INTEGER,active INTEGER NOT NULL DEFAULT 1,
 processed_at TEXT NOT NULL,error_code TEXT);
CREATE TABLE kg_nodes(input_key TEXT NOT NULL REFERENCES kg_inputs(input_key) ON DELETE CASCADE,
 node_id TEXT NOT NULL,kind TEXT NOT NULL,title TEXT NOT NULL,origin TEXT NOT NULL,category TEXT NOT NULL,
 updated TEXT,citation TEXT NOT NULL,project_id INTEGER,data_json TEXT NOT NULL CHECK(json_valid(data_json)),rank INTEGER NOT NULL,
 PRIMARY KEY(input_key,node_id));
CREATE INDEX kg_node_identity ON kg_nodes(node_id,rank,input_key);
CREATE INDEX kg_node_kind ON kg_nodes(kind,node_id);
CREATE TABLE kg_edges(input_key TEXT NOT NULL REFERENCES kg_inputs(input_key) ON DELETE CASCADE,
 edge_id TEXT NOT NULL,source TEXT NOT NULL,target TEXT NOT NULL,relation TEXT NOT NULL,validation TEXT NOT NULL,
 citation TEXT NOT NULL,project_id INTEGER,data_json TEXT NOT NULL CHECK(json_valid(data_json)),PRIMARY KEY(input_key,edge_id));
CREATE INDEX kg_edge_source ON kg_edges(source,edge_id);
CREATE INDEX kg_edge_target ON kg_edges(target,edge_id);
CREATE TABLE kg_runs(run_id INTEGER PRIMARY KEY,started_at TEXT NOT NULL,finished_at TEXT NOT NULL,status TEXT NOT NULL,
 examined INTEGER NOT NULL,changed INTEGER NOT NULL,unchanged INTEGER NOT NULL,retired INTEGER NOT NULL,
 errors INTEGER NOT NULL,next_key TEXT,source_version TEXT NOT NULL);
"""


def encode(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def fingerprint(*values: object) -> str:
    return hashlib.sha256(encode(values).encode()).hexdigest()


def schema(db: Database, *, create: bool = False) -> bool:
    exists = db.one("SELECT 1 FROM sqlite_master WHERE name='kg_migrations' AND type='table'") is not None
    checksum = hashlib.sha256(DDL.encode()).hexdigest()
    if exists:
        rows = db.query("SELECT version,checksum FROM kg_migrations ORDER BY version")
        if len(rows) != 1 or rows[0]["version"] != 1 or rows[0]["checksum"] != checksum:
            raise ValueError("unsupported_knowledge_graph_migration")
        return True
    if not create:
        return False
    try:
        db.connection.executescript("BEGIN IMMEDIATE;\n" + DDL)
        db.execute("INSERT INTO kg_migrations VALUES (1,?,?)", (checksum, iso_now()))
        db.commit()
    except BaseException:
        db.connection.rollback()
        raise
    return True


def own_outputs(settings: Settings) -> None:
    for path in (settings.database_path, settings.data_dir, settings.data_dir / "backups"):
        if safe_relative(path, settings.root) in {None, "", "."} or contains_reparse_component(path):
            raise ValueError("unsafe_graph_output")


def migrate(settings: Settings, db: Database) -> str | None:
    if schema(db):
        install_watchers(db)
        return None
    own_outputs(settings)
    backup = settings.data_dir / "backups" / ("pre-knowledge-graph-schema1-" + uuid.uuid4().hex + ".db")
    db.backup(backup)
    schema(db, create=True)
    install_watchers(db)
    return backup.name


WATCH_TABLES = {"documents", "projects", "links", "link_suggestions", "cyber_records", "cyber_aliases", "cyber_entities",
                "cyber_migrations", "security_entries", "security_relations", "security_migrations", "dependency_analyses",
                "dependency_analysis_heads", "dependency_reviews", "dependency_migrations"}
WATCH_TABLES |= {"attack_migrations", "attack_heads", "attack_releases", "attack_members", "attack_revisions", "attack_records"}


def _watch_sql(table, operation):
    # Both identifiers come from compiled allowlists, never from imported text.
    return (f"CREATE TRIGGER kg_watch_{table}_{operation.lower()} AFTER {operation} ON {table} "
            "BEGIN UPDATE kg_epoch SET value=value+1 WHERE singleton=1; END")


def _sql_hash(sql):
    return fingerprint(" ".join(sql.strip().rstrip(";").split()))


def install_watchers(db: Database) -> None:
    """Only explicit sync installs graph-owned, non-mutating-source counters."""
    present = {r[0] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'")}
    try:
        db.execute("BEGIN IMMEDIATE")
        for table in sorted(WATCH_TABLES & present):
            signatures = []
            for operation in ("INSERT", "UPDATE", "DELETE"):
                name, sql = f"kg_watch_{table}_{operation.lower()}", _watch_sql(table, operation)
                old = db.one("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,))
                if old is not None and _sql_hash(old[0]) != _sql_hash(sql):
                    raise ValueError("modified_knowledge_graph_watcher")
                if old is None:
                    db.execute(sql)
                signatures.append(_sql_hash(sql))
            db.execute("INSERT INTO kg_watch_coverage VALUES (?,?) ON CONFLICT(table_name) DO UPDATE SET checksum=excluded.checksum",
                       (table, fingerprint(signatures)))
        db.commit()
    except BaseException:
        db.connection.rollback()
        raise


def epoch_proof(db: Database) -> tuple | None:
    """Missing/changed watchers disable memoization, never source verification."""
    present = {r[0] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'")}
    covered = {r["table_name"]: r["checksum"] for r in db.query("SELECT * FROM kg_watch_coverage")}
    actual = {r["name"]: r["sql"] for r in db.query("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name LIKE 'kg_watch_%'")}
    required = sorted(WATCH_TABLES & present)
    for table in required:
        signatures = []
        for operation in ("INSERT", "UPDATE", "DELETE"):
            expected = _watch_sql(table, operation)
            sql = actual.get(f"kg_watch_{table}_{operation.lower()}")
            if sql is None or _sql_hash(sql) != _sql_hash(expected):
                return None
            signatures.append(_sql_hash(expected))
        if covered.get(table) != fingerprint(signatures):
            return None
    row = db.one("SELECT value FROM kg_epoch WHERE singleton=1")
    return (row[0], tuple(required)) if row is not None else None


def check_source_schemas(db: Database) -> None:
    from ..cyber.store import DDL as CYBER_1
    from ..cyber.pending import DDL_2
    from ..cyber.history import DDL_3
    from ..security import SCHEMA as SECURITY_1
    from ..dependency_memory import SCHEMA as DEPENDENCY_1
    from ..attack_store import DDL as ATTACK_1
    tables = {r[0] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'")}
    for table, definitions in (("cyber_migrations", (CYBER_1, DDL_2, DDL_3)), ("security_migrations", (SECURITY_1,)),
                               ("dependency_migrations", (DEPENDENCY_1,)), ("attack_migrations", (ATTACK_1,))):
        if table in tables:
            rows = db.query(f"SELECT version,checksum FROM {table} ORDER BY version")
            if (not rows or len(rows) > len(definitions) or any(r["version"] != i+1 or
                    r["checksum"] != hashlib.sha256(definition.encode()).hexdigest()
                    for i, (r, definition) in enumerate(zip(rows, definitions)))):
                raise ValueError("unsupported_graph_source_migration")


def state(db: Database, key: str, default: str = "") -> str:
    row = db.one("SELECT value FROM kg_state WHERE key=?", (key,))
    return row[0] if row else default


def set_state(db: Database, key: str, value: str) -> None:
    db.execute("INSERT INTO kg_state VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def configure(db: Database, settings: Settings) -> dict[int, dict]:
    """Permissions are evaluated from current roots/exclusions, never the cache."""
    projects = {}
    for row in db.query("SELECT project_id,name,root_path,status FROM projects"):
        root = Path(row["root_path"])
        if (row["status"] == "active" and not settings.is_project_excluded(root)
                and safe_relative(root, settings.projects_root) not in {None, "", "."}
                and not contains_reparse_component(root) and root.is_dir()):
            projects[row["project_id"]] = dict(row)
    by_root = {path_key(p["root_path"]): pid for pid, p in projects.items()}
    roots = {(kind, path_key(root)) for kind, root, _ in settings.source_roots() if kind != "projects"}
    policies = {}
    eligible = document_eligibility(settings)
    def path_visible(kind, value):
        # Dependency snapshots/reviews may cite approved lockfiles or SBOMs
        # that are deliberately NOT eligible for document-body indexing.
        if not isinstance(value, str) or not value or "\\" in value or ":" in value or value.startswith("/") or any(p in {"", ".", ".."} for p in value.split("/")):
            return 0
        if kind not in policies:
            policy = settings.policy(str(kind))
            policies[kind] = (DEFAULT_EXCLUDED_DIRS | {str(v).casefold() for v in policy.get("exclude_dirs", [])},
                              {str(v).casefold() for v in policy.get("exclude_names", [])},
                              {str(v).casefold() for v in policy.get("exclude_extensions", [])})
        dirs, names, extensions = policies[kind]
        return int(Path(value).suffix.casefold() not in extensions and not any(
            _excluded_directory(p, dirs) or _excluded_name(Path(p), names) for p in value.split("/")))
    def doc_visible(kind, source, root, name):
        if kind == "projects":
            return int(bool(root) and path_key(root) in by_root and path_key(source) == path_key(root))
        if (kind, path_key(str(source))) not in roots:
            return 0
        if root:
            return int(path_key(root) in by_root)
        return int(not (kind == "internal" and name))  # Fail closed on legacy unscoped project memory.
    db.connection.create_function("kg_fp", -1, lambda *values: fingerprint("kg-projection", ENGINE_VERSION, *values), deterministic=True)
    db.connection.create_function("kg_pid", 1, lambda root: by_root.get(path_key(root)) if root else None, deterministic=True)
    db.connection.create_function("kg_pvisible", 1, lambda pid: int(pid in projects), deterministic=True)
    db.connection.create_function("kg_dvisible", 4, doc_visible, deterministic=True)
    db.connection.create_function("kg_path_visible", 2, path_visible, deterministic=True)
    db.connection.create_function("kg_document_path_visible", 2,
                                  lambda kind, value: int(bool(eligible(kind, value)) and bool(path_visible(kind, value))), deterministic=True)
    db.connection.create_function("kg_fold", 1, lambda value: str(value or "").casefold(), deterministic=True)
    return projects


def descriptors(db: Database) -> str:
    """Metadata fingerprints only; normalized bodies are loaded per changed input."""
    tables = {r[0] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'")}
    docs = "SELECT * FROM documents WHERE status='active' AND kg_dvisible(source_kind,source_root,project_root_path,project_name)=1 AND kg_document_path_visible(source_kind,relative_path)=1"
    # Reviewed evidence resolves indexed paths to document IDs. A path-map
    # change can affect that relationship even if the memory text is unchanged.
    document_map = "(SELECT fp FROM M)"
    security_targets = ("(SELECT group_concat(x.entry_id||':'||x.fingerprint) FROM (SELECT entry_id,fingerprint FROM security_entries "
                        "WHERE active=1 AND kind IN ('framework','reference') AND json_extract(data_json,'$.source_url')=l.target_raw ORDER BY entry_id) x)"
                        if "security_entries" in tables else "NULL")
    branches = [
        "SELECT 'project:'||project_id k,'project' family,CAST(project_id AS TEXT) native,'projects' origin,project_id pid,"
        "kg_fp(name,root_path,technology_json,structure_json,dependencies_json,documentation_json,last_seen) fp FROM projects WHERE kg_pvisible(project_id)=1",
        "SELECT 'document:'||document_id,'document',CAST(document_id AS TEXT),source_kind,kg_pid(project_root_path),"
        "kg_fp(title,source_kind,source_root,project_root_path,kg_pid(project_root_path),relative_path,absolute_path,path_key,content_hash,frontmatter_json,category,mtime_iso,indexed_at,"
        "CASE WHEN source_kind='internal' AND json_extract(frontmatter_json,'$.kind')='verified-memory' THEN " + document_map + " END) FROM D",
        "SELECT 'link:'||l.link_id,'link',CAST(l.link_id AS TEXT),d.source_kind,kg_pid(d.project_root_path),"
        "kg_fp(l.source_document_id,l.target_document_id,l.target_raw,l.status,l.line_number,l.relation_type,d.relative_path,d.source_kind,kg_pid(d.project_root_path),"
        "CASE WHEN l.status='external' THEN " + security_targets + " END) "
        "FROM links l JOIN D d ON d.document_id=l.source_document_id WHERE l.status IN ('resolved','external')",
        "SELECT 'suggestion:'||s.suggestion_id,'suggestion',CAST(s.suggestion_id AS TEXT),d.source_kind,kg_pid(d.project_root_path),"
        "kg_fp(s.source_document_id,s.target_document_id,s.score,s.status,s.created_at,d.relative_path,kg_pid(d.project_root_path)) "
        "FROM link_suggestions s JOIN D d ON d.document_id=s.source_document_id WHERE s.status='suggested'",
    ]
    extra_ctes = ""
    if "attack_migrations" in tables:
        # Materialize a shared head fingerprint once, not its JSON per SRO.
        extra_ctes = (", A AS MATERIALIZED (SELECT h.domain,a.release_id,"
            "kg_fp(a.version,a.collection_modified,a.source_commit,a.body_sha256,a.data_json,a.captured_at,a.published_at) head_fp "
            "FROM attack_heads h JOIN attack_releases a ON a.release_id=h.release_id AND a.domain=h.domain)")
        members = (" FROM A JOIN attack_members m ON m.release_id=A.release_id AND m.domain=A.domain "
                   "JOIN attack_revisions r ON r.revision_id=m.revision_id AND r.domain=m.domain AND r.stix_id=m.stix_id AND r.present=1 ")
        branches += [
            "SELECT 'attack-collection:'||A.domain,'attack-collection',A.domain,'attack',NULL,kg_fp(A.head_fp) FROM A",
            "SELECT 'attack-object:'||A.domain||':'||m.stix_id,'attack-object',json_array(A.domain,m.stix_id),'attack',NULL,"
            "kg_fp(r.fingerprint,A.head_fp,m.locator)" + members + "WHERE r.kind<>'relationship'",
            "SELECT 'attack-relation:'||A.domain||':'||m.stix_id,'attack-relation',json_array(A.domain,m.stix_id),'attack',NULL,"
            "kg_fp(r.fingerprint,A.head_fp,m.locator,sr.fingerprint,tr.fingerprint)" + members +
            "JOIN attack_members sm ON sm.release_id=A.release_id AND sm.domain=A.domain AND sm.stix_id=r.source_ref "
            "JOIN attack_revisions sr ON sr.revision_id=sm.revision_id AND sr.domain=sm.domain AND sr.stix_id=sm.stix_id AND sr.present=1 "
            "JOIN attack_members tm ON tm.release_id=A.release_id AND tm.domain=A.domain AND tm.stix_id=r.target_ref "
            "JOIN attack_revisions tr ON tr.revision_id=tm.revision_id AND tr.domain=tm.domain AND tr.stix_id=tm.stix_id AND tr.present=1 "
            "WHERE r.kind='relationship' AND sr.kind<>'relationship' AND tr.kind<>'relationship'",
        ]
    if "cyber_records" in tables:
        branches += [
            "SELECT 'observation:'||r.source||':'||r.source_id,'observation',r.source_id,r.source,NULL,kg_fp(r.fingerprint,r.retrieved_at,"
            "(SELECT group_concat(x.vulnerability_id) FROM (SELECT vulnerability_id FROM cyber_aliases WHERE source=r.source AND source_id=r.source_id ORDER BY vulnerability_id) x)) FROM cyber_records r WHERE r.active=1",
            "SELECT 'vulnerability:'||vulnerability_id,'vulnerability',vulnerability_id,'cyber',NULL,"
            "kg_fp(title,status,kev,cvss,epss,published,modified,retrieved_at,json_extract(e.data_json,'$.record_kind'),json_extract(e.data_json,'$.exploitation'),"
            "(SELECT group_concat(z.f) FROM (SELECT r.source||':'||r.source_id||':'||r.fingerprint||':'||r.retrieved_at f "
            "FROM cyber_aliases a JOIN cyber_records r USING(source,source_id) WHERE a.vulnerability_id=e.vulnerability_id AND r.active=1 "
            "ORDER BY r.source,r.source_id) z)) FROM cyber_entities e "
            "WHERE EXISTS(SELECT 1 FROM cyber_aliases a JOIN cyber_records r USING(source,source_id) WHERE a.vulnerability_id=e.vulnerability_id AND r.active=1)",
        ]
    if "security_entries" in tables:
        branches += [
            "SELECT 'security:'||entry_id,'security',entry_id,'security',NULL,kg_fp(fingerprint,indexed_at) FROM security_entries WHERE active=1",
            "SELECT 'security-relation:'||r.source_id||':'||r.target_id||':'||r.relation_type,'security-relation',"
            "json_array(r.source_id,r.target_id,r.relation_type),'security',NULL,kg_fp(r.rationale,r.validation,s.fingerprint,s.active) "
            "FROM security_relations r JOIN security_entries s ON s.entry_id=r.source_id",
        ]
    if "dependency_migrations" in tables:
        from ..dependency_memory import _schema
        _schema(db)
        branches += [
            "SELECT 'snapshot:'||a.analysis_id,'snapshot',a.analysis_id,'projects',a.project_id,kg_fp(a.report_json,a.relative_path,a.created_at) "
            "FROM dependency_analyses a JOIN dependency_analysis_heads h ON h.analysis_id=a.analysis_id WHERE kg_pvisible(a.project_id)=1 AND kg_path_visible('projects',a.relative_path)=1",
            "SELECT 'review:'||review_id,'review',review_id,'projects',project_id,kg_fp(payload_json,revoked_at) "
            "FROM dependency_reviews WHERE kg_pvisible(project_id)=1 AND kg_path_visible('projects',json_extract(payload_json,'$.inventory.relative_path'))=1",
        ]
    mapping = "SELECT kg_fp(group_concat(x.document_id||':'||x.path_key)) fp FROM (SELECT document_id,path_key FROM D ORDER BY document_id) x"
    return "WITH D AS (" + docs + "), M AS MATERIALIZED (" + mapping + ")" + extra_ctes + ", U(k,family,native,origin,pid,fp) AS MATERIALIZED (" + " UNION ALL ".join(branches) + ") "


def source_version(db: Database, settings: Settings, *, include_file: bool = False) -> str:
    tables = {r[0] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'")}
    version = [("engine", ENGINE_VERSION)]
    if "kg_epoch" in tables:
        version.append(("source_epoch", db.one("SELECT value FROM kg_epoch WHERE singleton=1")[0]))
    for table, column in (("scan_runs", "scan_id"), ("document_changes", "change_id"), ("cyber_sync_runs", "run_id"),
                          ("dependency_review_events", "event_id")):
        if table in tables:
            version.append((table, tuple(db.one(f"SELECT count(*),max({column}) FROM {table}"))))
    if "security_entries" in tables:
        version.append(tuple(db.one("SELECT count(*),max(indexed_at) FROM security_entries")))
    if "dependency_analysis_heads" in tables:
        version.append(tuple(tuple(r) for r in db.query("SELECT project_id,inventory_kind,relative_path,analysis_id FROM dependency_analysis_heads ORDER BY project_id,inventory_kind,relative_path")))
    if "attack_heads" in tables:
        version.append(("attack_heads", tuple(tuple(r) for r in db.query("SELECT domain,release_id FROM attack_heads ORDER BY domain"))))
    # Include manual/local edits that bypass application journals. Empty WAL
    # creation by a reader must not invalidate every cursor on Windows.
    for file in ((settings.database_path, Path(str(settings.database_path) + "-wal")) if include_file else ()):
        if file.is_file():
            stat = file.stat()
            if file == settings.database_path or stat.st_size > 32:
                version.append((file.suffix, stat.st_size, stat.st_mtime_ns))
    version.append((str(settings.vault_root), str(settings.projects_root), str(settings.knowledge_root),
                    settings.raw.get("excluded_projects", []), settings.raw.get("additional_sources", []), settings.raw.get("source_policy", {})))
    if settings.raw.get('excluded_memory_contexts'):
        version.append(('excluded_memory_contexts', settings.raw['excluded_memory_contexts']))
    return fingerprint(version)
