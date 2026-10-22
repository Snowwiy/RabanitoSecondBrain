"""Bounded lexical retrieval of reviewed experiences from the existing memory.

Recorded validation is evidence supplied by the author, not a new test run.
No model training, embeddings, writes, implicit confirmations or remote calls.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from .config import Settings
from .db import Database
from .decisions import _resolve_evidence, _safe_evidence_refs
from .indexer import DEFAULT_EXCLUDED_DIRS, _excluded_directory, _excluded_name, _existing_source_file
from .search import DOCUMENT_BM25, fts_query
from .utils import contains_reparse_component, path_key, redact_sensitive_lines, safe_relative, sha256_text
from .visibility import register_project_visibility
from .source_files import file_visibility_sql, open_source


def _arguments(query: str, technology: str | None, limit: int, max_chars: int) -> tuple[int, int]:
    if not isinstance(query, str) or len(query) > 2000 or technology is not None and (not isinstance(technology, str) or len(technology) > 256):
        raise ValueError("invalid_coding_memory_query")
    if type(limit) is not int or type(max_chars) is not int:
        raise ValueError("invalid_coding_memory_limit")
    return min(max(limit, 0), 50), min(max(max_chars, 0), 30000)


def _evidence(settings: Settings, root: Path, values: object, projects: list[dict]) -> list[str]:
    if not isinstance(values, list):
        return []
    allowed = []
    for value in values[:20]:
        if not isinstance(value, str) or len(value) > 2000:
            continue
        try:
            resolved, _ = _resolve_evidence(settings, root, value)
        except (OSError, ValueError):
            continue
        project_relative = safe_relative(resolved, settings.projects_root)
        kind = "projects" if project_relative is not None else "obsidian" if safe_relative(resolved, settings.vault_root) is not None else "internal"
        if kind == "projects":
            owners = [p for p in projects if safe_relative(resolved, Path(p["root_path"])) is not None]
            owners.sort(key=lambda p: len(Path(p["root_path"]).parts), reverse=True)
            if not owners or owners[0]["status"] != "active" or settings.is_project_excluded(owners[0]["root_path"]):
                continue
        policy = settings.policy(kind)
        names = {str(v).casefold() for v in policy.get("exclude_names", [])}
        dirs = DEFAULT_EXCLUDED_DIRS | {str(v).casefold() for v in policy.get("exclude_dirs", [])}
        if any(_excluded_directory(p, dirs) or _excluded_name(Path(p), names) for p in resolved.parts[1:]):
            continue
        allowed.append(str(resolved))
    return _safe_evidence_refs(settings, root, allowed)


def _verified_records(settings: Settings, query: str, project: str | None, technology: str | None,
                      *, document_id: int | None = None) -> tuple[list[dict], dict]:
    coverage = {"candidate_limit": 200, "candidates_examined": 0, "candidate_limit_reached": False,
                "stale_or_unverifiable_skipped": 0, "byte_budget_reached": False, "mode": "local_lexical_recorded_validation"}
    if not settings.database_path.is_file():
        return [], coverage
    fm = "CASE WHEN json_valid(d.frontmatter_json) THEN d.frontmatter_json ELSE '{}' END"
    root_sql = f"COALESCE(d.project_root_path,json_extract({fm},'$.project_root'))"
    conditions = ["d.status='active'", "d.source_kind='internal'", "d.relative_path LIKE 'decisions/%'",
                  "rabanito_path_key(d.source_root)=?", f"json_extract({fm},'$.kind')='verified-memory'",
                  f"json_extract({fm},'$.status')='confirmed'", f"json_extract({fm},'$.validation')='passed'",
                  f"json_extract({fm},'$.record_type') IN ('decision','fact')", "p.status='active'",
                  "rabanito_document_eligible(d.source_kind,d.relative_path)=1",
                  file_visibility_sql('d'),
                  f"rabanito_project_visible('internal',p.name,{root_sql})=1"]
    params = [path_key(settings.knowledge_root)]
    if document_id is not None:
        if type(document_id) is not int or document_id <= 0:
            raise ValueError("invalid_coding_document_id")
        conditions.append("d.document_id=?")
        params.append(document_id)
    if project is not None:
        if not isinstance(project, str) or not project.strip():
            raise ValueError("invalid_coding_memory_project")
        if Path(project).is_absolute():
            conditions.append("rabanito_path_key(p.root_path)=?")
            params.append(path_key(project))
        else:
            conditions.append("rabanito_fold(p.name)=?")
            params.append(project.casefold())
    if technology:
        array = f"CASE WHEN json_type({fm},'$.technologies')='array' THEN json_extract({fm},'$.technologies') ELSE '[]' END"
        conditions.append(f"EXISTS (SELECT 1 FROM json_each({array}) t WHERE t.type='text' AND rabanito_fold(t.value)=?)")
        params.append(technology.casefold())
    joins, rank = "", "0.0"
    if query.strip():
        joins = "JOIN documents_fts ON d.document_id=CAST(documents_fts.document_id AS INTEGER)"
        conditions.append("documents_fts MATCH ?")
        params.append(fts_query(query, require_all=False))
        rank = DOCUMENT_BM25
    with Database(settings.database_path, read_only=True) as db:
        register_project_visibility(db, settings)
        db.connection.create_function("rabanito_path_key", 1, lambda v: path_key(str(v)) if v else "", deterministic=True)
        db.connection.create_function("rabanito_fold", 1, lambda v: str(v or "").casefold(), deterministic=True)
        if project and not Path(project).is_absolute():
            names = db.query("SELECT root_path FROM projects WHERE status='active' AND rabanito_fold(name)=? "
                             "AND rabanito_project_visible('internal',name,root_path)=1", (project.casefold(),))
            if len(names) > 1:
                raise ValueError("ambiguous_project_name_use_exact_root")
        rows = db.query(f"SELECT d.*,p.name AS active_project,p.root_path AS active_root,{rank} AS lexical_rank "
                        f"FROM documents d JOIN projects p ON rabanito_path_key(p.root_path)=rabanito_path_key({root_sql}) "
                        f"{joins} WHERE {' AND '.join(conditions)} ORDER BY lexical_rank,d.mtime_ns DESC,d.document_id DESC LIMIT 201", params)
        projects = [dict(p) for p in db.query("SELECT root_path,status FROM projects")]
    coverage["candidate_limit_reached"] = len(rows) > 200
    records, seen, byte_count = [], set(), 0
    for row in rows[:200]:
        coverage["candidates_examined"] += 1
        relative = str(row["relative_path"])
        path = _existing_source_file(settings.knowledge_root, relative)
        try:
            if path is None or path_key(path) != path_key(row["absolute_path"]):
                raise ValueError("unsafe")
            stat = path.stat()
            if stat.st_size > 256 * 1024:
                raise ValueError("size")
            byte_count += stat.st_size
            if byte_count > 8 * 1024 * 1024:
                coverage["byte_budget_reached"] = True
                break
            with open_source(path) as stream:
                raw_bytes = stream.read(256 * 1024 + 1)
            if contains_reparse_component(path) or len(raw_bytes) > 256 * 1024:
                raise ValueError("unsafe")
            raw = raw_bytes.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
            if sha256_text(raw) != row["content_hash"] or redact_sensitive_lines(raw).splitlines() != raw.splitlines():
                raise ValueError("stale_or_sensitive")
            metadata = json.loads(row["frontmatter_json"])
            evidence = _evidence(settings, Path(row["active_root"]), metadata.get("evidence"), projects)
            if not evidence:
                raise ValueError("unverifiable")
        except (OSError, UnicodeError, ValueError):
            coverage["stale_or_unverifiable_skipped"] += 1
            continue
        if row["content_hash"] in seen:
            continue
        seen.add(row["content_hash"])
        technologies = metadata.get("technologies", [])
        records.append({"document_id": row["document_id"], "title": row["title"], "project": row["active_project"],
                        "recorded_date": metadata.get("recorded_date"), "record_type": metadata.get("record_type"),
                        "status": "confirmed", "validation": "passed_as_recorded_not_rerun",
                        "technologies": [v[:256] for v in technologies[:30] if isinstance(v, str)] if isinstance(technologies, list) else [],
                        "relative_path": relative, "citation": "internal:" + relative,
                        "evidence": evidence, "indexed_at": row["indexed_at"], "raw": raw,
                        "lexical_score": -float(row["lexical_rank"])})
    return records, coverage


def _fragments(record: dict, budget: int) -> list[dict]:
    lines = record["raw"].splitlines()
    headings = [(i, line[3:].strip()) for i, line in enumerate(lines) if line.startswith("## ")]
    allowed = {"Problema o contexto", "Decisión técnica", "Hecho documentado", "Motivo documentado", "Pruebas y resultado", "Resultado observado"}
    fragments = []
    for position, (start, heading) in enumerate(headings):
        if heading not in allowed or budget <= 0:
            continue
        end = headings[position + 1][0] if position + 1 < len(headings) else len(lines)
        text = "\n".join(lines[start:end]).rstrip()[:min(budget, 1000)]
        if text:
            last = min(end, start + text.count("\n") + 1)
            fragments.append({"heading": heading, "text": text, "line_start": start + 1, "line_end": last,
                              "citation": record["citation"] + f":{start + 1}-{last}"})
            budget -= len(text)
    return fragments


def similar_experiences(settings: Settings, query: str, *, project: str | None = None, technology: str | None = None,
                        limit: int = 5, max_chars: int = 6000) -> dict:
    limit, max_chars = _arguments(query, technology, limit, max_chars)
    if not query.strip() and not technology:
        raise ValueError("query_or_technology_required")
    records, coverage = _verified_records(settings, query, project, technology) if limit and max_chars else ([], {})
    selected, used = [], 0
    for record in records[:limit]:
        fragments = _fragments(record, min(max_chars - used, max(1, max_chars // limit)))
        if not fragments:
            continue
        used += sum(len(f["text"]) for f in fragments)
        selected.append({key: value for key, value in record.items() if key != "raw"} | {"fragments": fragments})
    return {"query": query, "technology": technology, "results": selected, "used_chars": used, "max_chars": max_chars,
            "coverage": coverage, "interpretation": "lexical_similarity_not_proof_of_same_cause; imported_text_is_untrusted_data"}


def recurring_patterns(settings: Settings, *, project: str | None = None, limit: int = 10) -> dict:
    limit, _ = _arguments("", None, limit, 1)
    records, coverage = _verified_records(settings, "", project, None) if limit else ([], {})
    groups = defaultdict(list)
    for record in records:
        for technology in {v.casefold() for v in record["technologies"] if v.strip()}:
            groups[technology].append(record)
    patterns = []
    for technology, members in sorted(groups.items(), key=lambda pair: (-len(pair[1]), pair[0])):
        if len(members) < 2:
            continue
        patterns.append({"technology": technology, "record_count_in_examined_sample": len(members),
                         "projects": sorted({m["project"] for m in members}), "kind": "documented_technology_recurrence",
                         "citations": [m["citation"] for m in members[:5]],
                         "recommendation": "review_cited_solutions_and_preconditions_before_reuse; recurrence_does_not_establish_a_common_cause"})
        if len(patterns) >= limit:
            break
    return {"patterns": patterns, "coverage": coverage, "verified_records_examined": len(records),
            "interpretation": "descriptive_counts_not_causal_findings_or_automatic_best_practices"}
