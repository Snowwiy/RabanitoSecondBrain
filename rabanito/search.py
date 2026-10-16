from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from urllib.parse import quote
from typing import Any

from .config import Settings
from .db import Database
from .utils import path_key
from .visibility import project_visibility_sql, register_project_visibility


TOKEN_RE = re.compile(r"[\wÀ-ÿ][\wÀ-ÿ./:-]*", re.UNICODE)
FTS_TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)
DOCUMENT_BM25 = "bm25(documents_fts, 0.0, 32.0, 32.0, 1.0)"
CHUNK_BM25 = "bm25(chunks_fts, 0.0, 0.0, 32.0, 1.0)"
SCAN_SOURCE_SUMMARY_MAX_CHARS = 262_144
SCAN_SOURCE_SUMMARY_MAX_DEPTH = 16


def _json_exceeds_nesting_limit(raw: str, limit: int) -> bool:
    depth = 0
    in_string = False
    escaped = False
    for character in raw:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > limit:
                return True
        elif character in "]}":
            depth -= 1
    return False


def project_scan_summary(scan: dict[str, Any]) -> dict[str, Any]:
    source_summary = scan.get("source_summary")
    source_summary_truncated = scan.get("source_summary_truncated") is True
    if not isinstance(source_summary, dict):
        raw_summary = scan.get("source_summary_json") or "{}"
        if (not isinstance(raw_summary, str) or len(raw_summary) > SCAN_SOURCE_SUMMARY_MAX_CHARS
                or _json_exceeds_nesting_limit(raw_summary, SCAN_SOURCE_SUMMARY_MAX_DEPTH)):
            source_summary = {}
            source_summary_truncated = True
        else:
            try:
                source_summary = json.loads(raw_summary)
            except (TypeError, ValueError, RecursionError):
                source_summary = {}
                source_summary_truncated = True
            if not isinstance(source_summary, dict):
                source_summary = {}
                source_summary_truncated = True
    safe_source_summary: dict[str, dict[str, int]] = {}
    if isinstance(source_summary, dict):
        for kind in sorted((key for key in source_summary if isinstance(key, str))):
            if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", kind):
                continue
            counts = source_summary[kind]
            if not isinstance(counts, dict):
                continue
            if len(safe_source_summary) >= 100:
                source_summary_truncated = True
                break
            safe_counts = {
                key: value for key, value in counts.items()
                if key in {"seen", "added", "modified", "unchanged", "skipped", "errors"}
                and type(value) is int and 0 <= value <= 9_007_199_254_740_991
            }
            if safe_counts:
                safe_source_summary[kind] = safe_counts
    keys = (
        "scan_id", "started_at", "finished_at", "status", "files_seen", "added", "modified",
        "unchanged", "removed", "skipped", "errors", "duration_ms",
    )
    result = {key: scan[key] for key in keys if key in scan}
    result["source_summary"] = safe_source_summary
    result["source_summary_truncated"] = source_summary_truncated
    return result


def fts_query(query: str, require_all: bool = True) -> str:
    tokens = TOKEN_RE.findall(query)
    if not tokens:
        return '""'
    # Prefix matching is useful for CLI typing while quoting prevents FTS operators
    # supplied by a user from changing the query structure.
    connector = " AND " if require_all else " OR "
    return connector.join('"' + token.replace('"', '""') + '"*' for token in tokens[:16])


def _query_term_coverage(query: str, row: Any) -> int:
    def normalize(token: str) -> str:
        decomposed = unicodedata.normalize("NFKD", token.casefold())
        return "".join(char for char in decomposed if not unicodedata.combining(char))

    terms = tuple(dict.fromkeys(TOKEN_RE.findall(query)[:16]))
    if not terms:
        return 0
    content = " ".join(str(row[key] or "") for key in ("text", "heading", "title"))
    indexed_tokens = tuple(normalize(token) for token in FTS_TOKEN_RE.findall(content))
    covered = 0
    for term in terms:
        parts = tuple(normalize(token) for token in FTS_TOKEN_RE.findall(term))
        if not parts:
            continue
        for start in range(len(indexed_tokens) - len(parts) + 1):
            if all(
                indexed_tokens[start + offset] == part
                for offset, part in enumerate(parts[:-1])
            ) and indexed_tokens[start + len(parts) - 1].startswith(parts[-1]):
                covered += 1
                break
    return covered


def _source_url(settings: Settings, row: Any) -> str | None:
    if row["source_kind"] != "obsidian":
        return None
    vault_name = settings.vault_root.name
    return f"obsidian://open?vault={quote(vault_name)}&file={quote(str(row['relative_path']).replace('\\', '/'))}"


def _row_result(settings: Settings, row: Any) -> dict[str, Any]:
    return {
        "document_id": int(row["document_id"]),
        "title": row["title"],
        "source_kind": row["source_kind"],
        "project": row["project_name"],
        "project_root": row["project_root_path"],
        "category": row["category"],
        "relative_path": row["relative_path"],
        "tags": json.loads(row["tags_json"] or "[]"),
        "absolute_path": row["absolute_path"],
        "mtime": row["mtime_iso"],
        "snippet": row["snippet"] if "snippet" in row.keys() else None,
        "source_url": _source_url(settings, row),
    }


def _add_tag_filter(where: list[str], params: list[Any], tag: str | None) -> None:
    normalized = (tag or "").strip().lstrip("#")
    if normalized:
        where.append("EXISTS (SELECT 1 FROM tags t WHERE t.document_id=d.document_id AND t.tag=?)")
        params.append(normalized)


def _add_project_filter(
    settings: Settings, db: Database, where: list[str], params: list[Any], project: str | None,
) -> None:
    if not project:
        return
    if Path(project).is_absolute():
        known_roots = {path_key(root): str(root) for _kind, root, _name in settings.source_roots()}
        for row in db.query("SELECT root_path FROM projects WHERE status='active'"):
            root = str(row["root_path"] or "")
            if root and not settings.is_project_excluded(root):
                known_roots.setdefault(path_key(root), root)
        canonical_root = known_roots.get(path_key(project), project)
        where.append("(d.source_root=? OR d.project_root_path=?)")
        params.extend([canonical_root, canonical_root])
        return

    exact_matches = db.query(
        "SELECT DISTINCT d.project_root_path FROM documents d WHERE d.status='active' AND "
        + project_visibility_sql("d") + " AND d.project_name=?",
        (project,),
    )
    exact_roots = {str(row["project_root_path"] or "").casefold() for row in exact_matches}
    if len(exact_roots) > 1:
        # Nested VCS roots can legitimately share a basename with their parent.
        # Require an absolute root in that case instead of leaking across them.
        where.append("0=1")
        return
    if exact_matches:
        where.append("d.project_name=?")
        params.append(project)
        return
    names = [
        str(row["project_name"])
        for row in db.query(
        "SELECT DISTINCT d.project_name FROM documents d "
        "WHERE d.status='active' AND d.project_name IS NOT NULL AND " + project_visibility_sql("d")
        )
    ]
    if project in names:
        canonical_names = [project]
    else:
        canonical_names = [name for name in names if name.casefold() == project.casefold()]
    if len(canonical_names) > 1:
        # Do not broaden retrieval if legacy metadata has case-colliding names.
        where.append("0=1")
        return
    where.append("d.project_name=?")
    params.append(canonical_names[0] if canonical_names else project)


def search_documents(settings: Settings, query: str, limit: int | None = None, source_kind: str | None = None, category: str | None = None, project: str | None = None, tag: str | None = None) -> list[dict[str, Any]]:
    limit = min(max(int(settings.max_search_results if limit is None else limit), 0), 100)
    if limit == 0:
        return []
    filters = ["d.status='active'", project_visibility_sql("d")]
    filter_params: list[Any] = []
    if source_kind:
        filters.append("d.source_kind=?")
        filter_params.append(source_kind)
    if category:
        filters.append("d.category LIKE ?")
        filter_params.append(category + "%")
    _add_tag_filter(filters, filter_params, tag)
    candidate_limit = min(max(limit * 8, limit), 400)

    def query_rows(
        db: Database, expression: str, cap: int, candidate_ids: list[int] | None = None,
        include_snippet: bool = True,
    ) -> list[Any]:
        where = [*filters, "documents_fts MATCH ?"]
        params = [*filter_params, expression]
        if candidate_ids is not None:
            where.append("d.document_id IN (" + ",".join("?" for _ in candidate_ids) + ")")
            params.extend(candidate_ids)
        params.append(cap)
        selection = "d.*, snippet(documents_fts, 3, '[', ']', ' … ', 28) AS snippet" if include_snippet else "d.document_id"
        ordering = f"{DOCUMENT_BM25}, d.mtime_ns DESC" if include_snippet else "d.document_id"
        sql = f"""SELECT {selection}
                  FROM documents_fts JOIN documents d ON d.document_id=CAST(documents_fts.document_id AS INTEGER)
                  WHERE {' AND '.join(where)} ORDER BY {ordering} LIMIT ?"""
        return db.query(sql, params)

    terms_by_key: dict[str, str] = {}
    for token in TOKEN_RE.findall(query)[:16]:
        terms_by_key.setdefault(token.casefold(), token)
    terms = tuple(terms_by_key.values())
    term_count = len(terms)
    with Database(settings.database_path) as db:
        register_project_visibility(db, settings)
        _add_project_filter(settings, db, filters, filter_params, project)
        rows = query_rows(db, fts_query(query), candidate_limit)
        term_coverage: dict[int, int]
        if rows:
            term_coverage = {int(row["document_id"]): term_count for row in rows}
        else:
            # Keep strict AND matching as the primary mode, but provide a bounded
            # best-coverage fallback when a query contains an absent/over-specific term.
            rows = query_rows(db, fts_query(query, require_all=False), candidate_limit)
            candidate_ids = [int(row["document_id"]) for row in rows]
            term_coverage = {document_id: 0 for document_id in candidate_ids}
            if candidate_ids and terms:
                for term in terms:
                    found = query_rows(db, fts_query(term), candidate_limit, candidate_ids, include_snippet=False)
                    for row in found:
                        term_coverage[int(row["document_id"])] += 1
            best_coverage = max(term_coverage.values(), default=0)
            minimum_partial_coverage = max(2, (term_count + 1) // 2)
            if best_coverage < minimum_partial_coverage:
                rows = []
            else:
                rows = [row for row in rows if term_coverage[int(row["document_id"])] == best_coverage]
        rows = rows[:limit]
    results = []
    for row in rows:
        item = _row_result(settings, row)
        matched_terms = term_coverage.get(int(row["document_id"]), 0)
        item["query_match"] = {
            "matched_terms": matched_terms,
            "total_terms": term_count,
            "complete": matched_terms == term_count,
        }
        results.append(item)
    return results


def recent_documents(settings: Settings, limit: int = 20, source_kind: str | None = None, category: str | None = None, project: str | None = None, tag: str | None = None) -> list[dict[str, Any]]:
    limit = min(max(int(limit), 0), 100)
    if limit == 0:
        return []
    where = ["d.status='active'", project_visibility_sql("d")]
    params: list[Any] = []
    if source_kind:
        where.append("source_kind=?")
        params.append(source_kind)
    if category:
        where.append("category LIKE ?")
        params.append(category + "%")
    _add_tag_filter(where, params, tag)
    with Database(settings.database_path) as db:
        register_project_visibility(db, settings)
        _add_project_filter(settings, db, where, params, project)
        params.append(limit)
        rows = db.query(f"SELECT d.*, NULL AS snippet FROM documents d WHERE {' AND '.join(where)} ORDER BY d.mtime_ns DESC LIMIT ?", params)
    return [_row_result(settings, row) for row in rows]


def retrieve_context(settings: Settings, query: str, limit: int | None = None, max_chars: int | None = None, source_kind: str | None = None, category: str | None = None, project: str | None = None, tag: str | None = None) -> dict[str, Any]:
    limit = min(max(int(8 if limit is None else limit), 0), 50)
    requested_max_chars = settings.max_context_chars if max_chars is None else max_chars
    max_chars = min(max(int(requested_max_chars), 0), 100_000)
    if limit == 0 or max_chars == 0:
        return {"query": query, "fragments": [], "characters": 0, "limit": limit, "max_chars": max_chars}
    where = ["d.status='active'", project_visibility_sql("d"), "chunks_fts MATCH ?"]
    params: list[Any] = [fts_query(query, require_all=True)]
    if source_kind:
        where.append("d.source_kind=?")
        params.append(source_kind)
    if category:
        where.append("d.category LIKE ?")
        params.append(category + "%")
    _add_tag_filter(where, params, tag)
    with Database(settings.database_path) as db:
        register_project_visibility(db, settings)
        _add_project_filter(settings, db, where, params, project)
        # Retrieve a bounded candidate pool so query-term coverage can be
        # compared before the user-visible result limit is applied.
        params.append(min(max(limit * 8, limit), 400))
        sql = f"""SELECT c.*, d.title, d.source_kind, d.project_name, d.project_root_path, d.category, d.relative_path, d.absolute_path, d.mtime_iso
                  FROM chunks_fts JOIN document_chunks c ON c.chunk_id=CAST(chunks_fts.chunk_id AS INTEGER)
                  JOIN documents d ON d.document_id=c.document_id
                  WHERE {' AND '.join(where)} ORDER BY {CHUNK_BM25} LIMIT ?"""
        rows = db.query(sql, params)
        term_count = len(set(token.casefold() for token in TOKEN_RE.findall(query)[:16]))
        coverages = [_query_term_coverage(query, row) for row in rows]
        if not rows or max(coverages, default=0) < term_count:
            # Prefer fragments that cover the complete query. OR matching is a
            # useful fallback for exploratory/partial queries, but otherwise
            # tends to fill a bounded context with weak one-token matches. The
            # fields used by FTS include headings; compare coverage against the
            # actual cited text (plus its heading/title) before ranking results.
            params[0] = fts_query(query, require_all=False)
            rows = db.query(sql, params)
            coverages = [_query_term_coverage(query, row) for row in rows]
        if coverages:
            best_coverage = max(coverages)
            rows = [row for row, coverage in zip(rows, coverages) if coverage == best_coverage][:limit]
    fragments: list[dict[str, Any]] = []
    used = 0
    for row in rows:
        text = str(row["text"])
        remaining = max_chars - used
        if remaining <= 0:
            break
        clipped = text[:remaining]
        item = {
            "document_id": int(row["document_id"]), "title": row["title"], "heading": row["heading"],
            "text": clipped, "line_start": row["line_start"], "line_end": row["line_end"],
            "source_kind": row["source_kind"], "project": row["project_name"], "category": row["category"],
            "project_root": row["project_root_path"],
            "relative_path": row["relative_path"], "absolute_path": row["absolute_path"], "mtime": row["mtime_iso"],
            "citation": f"{row['absolute_path']}:{row['line_start']}-{row['line_end']}",
            "source_url": _source_url(settings, row),
        }
        fragments.append(item)
        used += len(clipped)
    return {"query": query, "fragments": fragments, "characters": used, "limit": limit, "max_chars": max_chars}


def get_document(settings: Settings, document_id: int) -> dict[str, Any] | None:
    with Database(settings.database_path) as db:
        register_project_visibility(db, settings)
        row = db.one(
            "SELECT d.* FROM documents d WHERE d.document_id=? AND d.status='active' AND " + project_visibility_sql("d"),
            (document_id,),
        )
        if not row:
            return None
        links = db.query(
            """SELECT l.*, t.title AS target_title, t.absolute_path AS target_path, t.relative_path AS target_relative_path FROM links l LEFT JOIN documents t ON t.document_id=l.target_document_id
               WHERE l.source_document_id=? AND (t.document_id IS NULL OR (t.status='active' AND """ + project_visibility_sql("t") + ")) ORDER BY l.line_number",
            (document_id,),
        )
        incoming = db.query(
            """SELECT l.*, s.title AS source_title, s.absolute_path AS source_path, s.relative_path AS source_relative_path FROM links l JOIN documents s ON s.document_id=l.source_document_id
               WHERE l.target_document_id=? AND l.status='resolved' AND s.status='active' AND """ + project_visibility_sql("s") + " ORDER BY s.title",
            (document_id,),
        )
    result = dict(row)
    result["frontmatter"] = json.loads(result.pop("frontmatter_json") or "{}")
    result["tags"] = json.loads(result.pop("tags_json") or "[]")
    result["links"] = [dict(item) for item in links]
    result["incoming_links"] = [dict(item) for item in incoming]
    result["source_url"] = _source_url(settings, row)
    return result


def related_documents(settings: Settings, document_id: int, limit: int = 20) -> list[dict[str, Any]]:
    limit = min(max(int(limit), 0), 100)
    if limit == 0:
        return []
    with Database(settings.database_path) as db:
        register_project_visibility(db, settings)
        source = db.one(
            "SELECT document_id FROM documents d WHERE d.document_id=? AND d.status='active' AND " + project_visibility_sql("d"),
            (document_id,),
        )
        if source is None:
            return []
        visible_target = project_visibility_sql("d")
        rows = db.query(
            f"""WITH related AS (
               SELECT DISTINCT d.*, l.status AS relation_status, 'explicit' AS relation_kind, 0.0 AS relation_score FROM links l JOIN documents d ON d.document_id=l.target_document_id
               WHERE l.source_document_id=? AND l.status='resolved' AND d.status='active' AND {visible_target}
               UNION
               SELECT DISTINCT d.*, l.status AS relation_status, 'explicit' AS relation_kind, 0.0 AS relation_score FROM links l JOIN documents d ON d.document_id=l.source_document_id
               WHERE l.target_document_id=? AND l.status='resolved' AND d.status='active' AND {visible_target}
               UNION ALL
               SELECT DISTINCT d.*, 'suggested' AS relation_status, 'suggested' AS relation_kind, s.score AS relation_score
               FROM link_suggestions s JOIN documents d ON d.document_id=
                 CASE WHEN s.source_document_id=? THEN s.target_document_id ELSE s.source_document_id END
               WHERE (s.source_document_id=? OR s.target_document_id=?)
                 AND s.status='suggested' AND d.status='active' AND {visible_target}
               )
               SELECT * FROM related
               ORDER BY CASE relation_kind WHEN 'explicit' THEN 0 ELSE 1 END,
                        relation_score DESC, mtime_ns DESC, title COLLATE NOCASE, document_id
               LIMIT ?""",
            (document_id, document_id, document_id, document_id, document_id, limit),
        )
    results = []
    for row in rows:
        item = dict(row)
        item.pop("relation_score", None)
        item["source_url"] = _source_url(settings, row)
        results.append(item)
    return results


def stats(settings: Settings, latest_scan_source_summary_limit: int | None = None) -> dict[str, Any]:
    with Database(settings.database_path) as db:
        register_project_visibility(db, settings)
        visible_document = project_visibility_sql("d")
        visible_source = project_visibility_sql("source")
        visible_target = project_visibility_sql("target")
        parser_version_row = db.one("SELECT value FROM meta WHERE key='parser_version'")
        try:
            parser_version = int(parser_version_row["value"]) if parser_version_row else None
        except (TypeError, ValueError):
            parser_version = None
        active = db.one(
            f"SELECT COUNT(*) AS count FROM documents d WHERE d.status='active' AND {visible_document}"
        )["count"]
        deleted = db.one(
            f"SELECT COUNT(*) AS count FROM documents d WHERE d.status='deleted' AND {visible_document}"
        )["count"]
        relations = db.one(
            f"""SELECT COUNT(*) AS count FROM links l
               JOIN documents source ON source.document_id=l.source_document_id AND source.status='active' AND {visible_source}
               JOIN documents target ON target.document_id=l.target_document_id AND target.status='active' AND {visible_target}
               WHERE l.status='resolved'"""
        )["count"]
        suggested_relations = db.one(
            f"""SELECT COUNT(*) AS count FROM link_suggestions s
               JOIN documents source ON source.document_id=s.source_document_id
               JOIN documents target ON target.document_id=s.target_document_id
               WHERE s.status='suggested' AND source.status='active' AND target.status='active'
                 AND {visible_source} AND {visible_target}"""
        )["count"]
        active_links = {
            str(row["status"]): int(row["count"])
            for row in db.query(
                f"""SELECT l.status, COUNT(*) AS count FROM links l
                   JOIN documents source ON source.document_id=l.source_document_id AND source.status='active' AND {visible_source}
                   GROUP BY l.status"""
            )
        }
        broken = active_links.get("broken", 0)
        ambiguous = active_links.get("ambiguous", 0)
        external = active_links.get("external", 0)
        attachments = active_links.get("attachment", 0)
        directories = active_links.get("directory", 0)
        incomplete = active_links.get("ignored", 0)
        projects = db.one(
            "SELECT COUNT(*) AS count FROM projects "
            "WHERE status='active' AND rabanito_project_visible('projects',name,root_path)=1"
        )["count"]
        tags = db.one(
            f"SELECT COUNT(DISTINCT t.tag) AS count FROM tags t JOIN documents d ON d.document_id=t.document_id "
            f"WHERE {visible_document}"
        )["count"]
        requested_summary_chars = (
            SCAN_SOURCE_SUMMARY_MAX_CHARS + 1
            if latest_scan_source_summary_limit is None else latest_scan_source_summary_limit
        )
        summary_chars = min(
            max(int(requested_summary_chars), 1), SCAN_SOURCE_SUMMARY_MAX_CHARS + 1,
        )
        latest_scan = db.one(
            """SELECT scan_id,started_at,finished_at,status,files_seen,added,modified,unchanged,
                      removed,skipped,errors,substr(source_summary_json,1,?) AS source_summary_json
               FROM scan_runs ORDER BY scan_id DESC LIMIT 1""",
            (summary_chars,),
        )
    return {
        "parser_version": parser_version,
        "documents_active": active, "documents_deleted_tombstones": deleted, "relations_resolved": relations,
        "relations_suggested": suggested_relations,
        "links_broken": broken, "links_ambiguous": ambiguous, "projects": projects, "unique_tags": tags,
        "links_external": external, "links_attachments": attachments, "links_directories": directories,
        "links_intentionally_incomplete": incomplete,
        "latest_scan": project_scan_summary(dict(latest_scan)) if latest_scan else None,
    }
