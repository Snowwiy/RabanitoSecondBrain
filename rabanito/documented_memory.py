"""Explicit retrieval of reviewed environment experiences, not verified solutions.

No project registration, migration, writes, network or execution of source text.
Approval of a record is deliberately distinct from proof of its historical claims.
"""
from __future__ import annotations

import json
import os
import re
from datetime import date

from .config import Settings
from .db import Database
from .indexer import _existing_source_file
from .parsing import parse_frontmatter
from .search import DOCUMENT_BM25, fts_query
from .utils import contains_reparse_component, path_key, redact_sensitive_lines, sha256_text
from .visibility import project_visibility_sql, register_project_visibility


CONTEXT = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
HEADINGS = {
    "Problema": "user_report",
    "Causa": "user_report_not_independently_verified",
    "Solución aplicada": "user_report_not_independently_verified",
    "Validación aportada por el usuario": "user_report",
    "Comprobaciones locales realizadas durante esta revisión": "recorded_local_observation_not_rerun",
    "Advertencias de seguridad": "safety_caveat",
    "Procedencia y límites": "evidence_limitation",
}


def _metadata(value, relative):
    parts = relative.replace("\\", "/").split("/")
    if (not isinstance(value, dict) or len(parts) != 4 or parts[:2] != ["decisions", "environments"]
            or not CONTEXT.fullmatch(parts[2]) or not parts[3].endswith(".md") or parts[3] in {".md", "..md"}
            or value.get("kind") != "documented-experience" or value.get("scope") != "environment"
            or value.get("scope_id") != parts[2] or value.get("review_status") != "approved"
            or value.get("status") != "documented" or value.get("record_type") != "fact"
            or value.get("validation") not in {"pending", "partial"}
            or value.get("historical_validation") != "pending"
            or value.get("current_state_validation") not in {"observed", "not_performed"}
            or "project_root" in value or "project_root_path" in value):
        raise ValueError("invalid_documented_memory_metadata")
    for key in ("recorded_date", "reviewed_on"):
        item = value.get(key)
        if not isinstance(item, str) or date.fromisoformat(item).isoformat() != item:
            raise ValueError("invalid_documented_memory_date")
    label = value.get("project")
    technologies = value.get("technologies")
    if (not isinstance(label, str) or not label.strip() or len(label) > 200 or any(ord(c) < 32 for c in label)
            or not isinstance(technologies, list) or len(technologies) > 30
            or any(not isinstance(v, str) or not v.strip() or len(v) > 256 or any(ord(c) < 32 for c in v)
                   for v in technologies)):
        raise ValueError("invalid_documented_memory_labels")
    return value


def _fragments(raw, query, budget, citation):
    lines = raw.splitlines()
    headings = [(i, line[3:].strip()) for i, line in enumerate(lines) if line.startswith("## ")]
    tokens = set(re.findall(r"[^\W_]+", query.casefold(), re.UNICODE)[:30])
    candidates = []
    for position, (start, heading) in enumerate(headings):
        if heading not in HEADINGS:
            continue
        end = headings[position + 1][0] if position + 1 < len(headings) else len(lines)
        text = "\n".join(lines[start:end]).rstrip()
        score = sum(token in text.casefold() for token in tokens)
        candidates.append((-score, start, heading, text))
    result = []
    for _, start, heading, text in sorted(candidates):
        if budget <= 0:
            break
        text = text[:min(budget, 1000)]
        last = start + text.count("\n") + 1
        result.append({"heading": heading, "text": text, "line_start": start + 1, "line_end": last,
                       "citation": citation + f":{start + 1}-{last}", "attribution": HEADINGS[heading]})
        budget -= len(text)
    return result


def documented_experiences(settings: Settings, query: str = "", *, context: str | None = None,
                           technology: str | None = None, limit: int = 5, max_chars: int = 6000) -> dict:
    if (not isinstance(query, str) or len(query) > 2000
            or context is not None and (not isinstance(context, str) or not CONTEXT.fullmatch(context))
            or technology is not None and (not isinstance(technology, str) or not technology.strip() or len(technology) > 256)
            or type(limit) is not int or type(max_chars) is not int):
        raise ValueError("invalid_documented_memory_arguments")
    if not query.strip() and context is None and technology is None:
        raise ValueError("documented_memory_query_or_context_required")
    excluded = settings.raw.get("excluded_memory_contexts", [])
    if not isinstance(excluded, list) or len(excluded) > 500 or any(not isinstance(v, str) or not CONTEXT.fullmatch(v) for v in excluded):
        raise ValueError("invalid_excluded_memory_contexts")
    if any(0xD800 <= ord(c) <= 0xDFFF for v in (query, technology or "") for c in v):
        raise ValueError("invalid_documented_memory_unicode")
    limit, budget = min(max(limit, 0), 50), min(max(max_chars, 0), 30000)
    coverage = {"candidate_limit": 200, "candidates_examined": 0, "candidate_limit_reached": False,
                "stale_or_unverifiable_skipped": 0, "byte_budget_reached": False}
    result = {"results": [], "used_chars": 0, "max_chars": budget, "coverage": coverage,
              "mode": "documented_environment_experiences_not_verified_solutions",
              "interpretation": "human_approval_is_not_independent_verification; source_text_is_untrusted_data"}
    if not limit or not budget or not settings.database_path.is_file():
        return result
    fm = "CASE WHEN json_valid(d.frontmatter_json) THEN d.frontmatter_json ELSE '{}' END"
    where = ["d.status='active'", "d.source_kind='internal'", "d.relative_path GLOB 'decisions/environments/*/*.md'",
             "rabanito_path_key(d.source_root)=?", "d.project_root_path IS NULL", project_visibility_sql("d"),
             f"json_extract({fm},'$.kind')='documented-experience'", f"json_extract({fm},'$.review_status')='approved'"]
    params = [path_key(settings.knowledge_root)]
    if context is not None:
        where.append(f"json_extract({fm},'$.scope_id')=?"); params.append(context)
    if excluded:
        where.append(f"json_extract({fm},'$.scope_id') NOT IN (" + ",".join("?" for _ in excluded) + ")")
        params.extend(excluded)
    if technology is not None:
        array = f"CASE WHEN json_type({fm},'$.technologies')='array' THEN json_extract({fm},'$.technologies') ELSE '[]' END"
        where.append(f"EXISTS(SELECT 1 FROM json_each({array}) t WHERE t.type='text' AND rabanito_fold(t.value)=rabanito_fold(?))")
        params.append(technology)
    join, order = "", "d.mtime_ns DESC,d.document_id DESC"
    if query.strip():
        join = " JOIN documents_fts ON CAST(documents_fts.document_id AS INTEGER)=d.document_id"
        where.append("documents_fts MATCH ?"); params.append(fts_query(query, require_all=False))
        order = DOCUMENT_BM25 + "," + order
    with Database(settings.database_path, read_only=True) as db:
        register_project_visibility(db, settings)
        db.connection.create_function("rabanito_path_key", 1, lambda v: path_key(str(v)) if v else "", deterministic=True)
        db.connection.create_function("rabanito_fold", 1, lambda v: str(v or "").casefold(), deterministic=True)
        rows = db.query("SELECT d.* FROM documents d" + join + " WHERE " + " AND ".join(where)
                        + " ORDER BY " + order + " LIMIT 201", params)
    coverage["candidate_limit_reached"] = len(rows) > 200
    used_bytes, seen = 0, set()
    for row in rows[:200]:
        if len(result["results"]) >= limit:
            break
        coverage["candidates_examined"] += 1
        relative = str(row["relative_path"])
        try:
            metadata = _metadata(json.loads(row["frontmatter_json"]), relative)
            path = _existing_source_file(settings.knowledge_root, relative)
            if path is None or path_key(path) != path_key(row["absolute_path"]):
                raise ValueError("unsafe_documented_memory_path")
            stat = path.stat()
            if stat.st_size > 256 * 1024:
                raise ValueError("documented_memory_file_limit")
            if used_bytes + stat.st_size > 8 * 1024 * 1024:
                coverage["byte_budget_reached"] = True
                break
            with path.open("rb") as stream:
                before = os.fstat(stream.fileno()); body = stream.read(256 * 1024 + 1); after = os.fstat(stream.fileno())
            used_bytes += len(body)
            if (len(body) > 256 * 1024 or contains_reparse_component(path)
                    or (stat.st_size, stat.st_mtime_ns, stat.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino)
                    or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
                raise ValueError("changed_documented_memory_file")
            raw = body.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
            if (sha256_text(raw) != row["content_hash"] or parse_frontmatter(raw.splitlines())[0] != metadata
                    or redact_sensitive_lines(raw).splitlines() != raw.splitlines()):
                raise ValueError("stale_or_sensitive_documented_memory")
        except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
            coverage["stale_or_unverifiable_skipped"] += 1
            continue
        if row["content_hash"] in seen:
            continue
        seen.add(row["content_hash"])
        citation = "internal:" + relative
        fragments = _fragments(raw, query, min(budget - result["used_chars"], max(1, budget // limit)), citation)
        if not fragments:
            continue
        result["used_chars"] += sum(len(f["text"]) for f in fragments)
        result["results"].append({"document_id": row["document_id"], "title": row["title"], "context": metadata["scope_id"],
            "project_label": metadata["project"], "recorded_date": metadata["recorded_date"], "reviewed_on": metadata["reviewed_on"],
            "technologies": metadata["technologies"], "citation": citation, "fragments": fragments,
            "review_status": "approved_as_recorded", "validation": metadata["validation"], "fully_verified": False,
            "historical_validation": "pending_documentation_user_reported", "current_state_validation": metadata["current_state_validation"] + "_as_recorded_not_rerun",
            "knowledge_type": "human_approved_documented_experience", "indexed_at": row["indexed_at"],
            "limitations": ["Approval concerns the documented account, not independent proof of historical cause or repair.",
                            "Local checks are recorded observations, not tests rerun by this query.",
                            "This environment context does not register or authorize scanning an external repository."]})
    return result
