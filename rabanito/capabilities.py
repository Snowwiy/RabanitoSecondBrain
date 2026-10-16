from __future__ import annotations

import json
import posixpath
import re
import unicodedata
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

from .config import Settings
from .db import Database
from .indexer import _existing_source_directory, _existing_source_file, _index_lock, _project_is_excluded
from .visibility import project_visibility_sql, register_project_visibility
from .search import stats
from .utils import (
    contains_reparse_component, iso_now, path_key, redact_sensitive_lines, slugify,
    sha256_text, unclosed_private_key_lines,
)


def _write_report_pair(settings: Settings, stem: str, json_value: Any, markdown_text: str) -> tuple[Path, Path]:
    directory = settings.knowledge_root / "quality-reports"
    if contains_reparse_component(directory):
        raise ValueError("La carpeta de informes no puede atravesar un enlace simbólico o reparse-point.")
    try:
        directory.resolve(strict=False).relative_to(settings.knowledge_root.resolve(strict=False))
    except (OSError, ValueError) as exc:
        raise ValueError("La carpeta de informes debe permanecer dentro de knowledge_root.") from exc
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    for suffix in range(1000):
        suffix_text = "" if suffix == 0 else f"-{suffix + 1:02d}"
        basename = f"{stamp}-{stem}{suffix_text}"
        json_path = directory / f"{basename}.json"
        markdown_path = directory / f"{basename}.md"
        created: list[Path] = []
        try:
            with json_path.open("x", encoding="utf-8", newline="\n") as json_handle:
                created.append(json_path)
                with markdown_path.open("x", encoding="utf-8", newline="\n") as markdown_handle:
                    created.append(markdown_path)
                    json.dump(json_value, json_handle, ensure_ascii=False, indent=2)
                    json_handle.write("\n")
                    markdown_handle.write(markdown_text)
            return json_path, markdown_path
        except FileExistsError:
            for created_path in reversed(created):
                created_path.unlink(missing_ok=True)
        except Exception:
            for created_path in reversed(created):
                created_path.unlink(missing_ok=True)
            raise
    raise FileExistsError("No se encontró un nombre libre para guardar el par de informes sin sobrescribir archivos.")


def _potential_contradictions(
    db: Database, settings: Settings, max_bytes: int = 2_097_152, limit: int = 50,
    max_documents: int = 2000, max_total_bytes: int = 67_108_864, max_claims: int = 100_000,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    # Deliberately conservative heuristic. These are review candidates, never facts.
    claim_re = re.compile(
        r"^\s*(?:[-*]\s+)?(?:\*\*)?"
        r"([A-Za-zÀ-ÿ][\wÀ-ÿ /_.-]{2,80}?)"
        r"(?:\*\*)?\s+"
        r"(no\s+se\s+encuentra|no\s+funcionan?|no\s+están?|no\s+es|no\s+son|is not|are not|is|are|"
        r"están?|es|son|se encuentra|funcionan?|=|:)\s+(.+?)\s*$",
        re.I,
    )
    sensitive_claim_re = re.compile(
        r"(?i)\b(?:api[_ -]?key|access[_ -]?token|auth[_ -]?token|token|password|passwd|secret|credential|private[_ -]?key|bearer|authorization)\b"
    )
    generic_subjects = {
        "this", "that", "it", "data", "output", "input", "client", "parser", "payload", "response",
        "controls", "apis", "status", "value", "result", "system", "source", "the", "a", "an",
        "esto", "esta", "este", "eso", "esa", "ese", "ellos", "ellas", "algo", "nada",
    }
    # Retain one example per document/polarity/base claim. Repeated lines must
    # neither multiply comparison cost nor flood the review list.
    claims: dict[tuple[str, str], dict[bool, dict[int, dict[str, Any]]]] = defaultdict(
        lambda: {False: {}, True: {}}
    )
    max_documents = min(max(1, int(max_documents)), 10_000)
    max_bytes = min(max(1, int(max_bytes)), 16_777_216)
    max_total_bytes = min(max(1, int(max_total_bytes)), 268_435_456)
    max_claims = min(max(1, int(max_claims)), 500_000)
    register_project_visibility(db, settings)
    visible_document = project_visibility_sql("d")
    active_documents = int(db.one(
        f"SELECT COUNT(*) AS c FROM documents d WHERE d.status='active' AND {visible_document}"
    )["c"])
    rows = db.query(
        "SELECT d.document_id,d.title,d.source_kind,d.source_root,d.relative_path "
        "FROM documents d WHERE d.status='active' AND " + visible_document +
        " ORDER BY d.document_id LIMIT ?", (max_documents + 1,),
    )
    documents_skipped_by_document_budget = max(0, active_documents - max_documents)
    documents_skipped_by_byte_budget = 0
    documents_unavailable_or_unsafe = 0
    documents_read = 0
    bytes_read = 0
    findings_truncated = False
    claims_indexed = 0
    claim_budget_exhausted = False
    for row in rows[:max_documents]:
        path = _authorized_audit_file(
            settings, str(row["source_kind"] or ""), str(row["source_root"] or ""),
            str(row["relative_path"] or ""),
        )
        if path is None:
            documents_unavailable_or_unsafe += 1
            continue
        try:
            file_size = path.stat().st_size
            if file_size > max_bytes:
                documents_skipped_by_byte_budget += 1
                continue
            remaining_bytes = max_total_bytes - bytes_read
            if file_size > remaining_bytes:
                documents_skipped_by_byte_budget += 1
                continue
            # Read at most the remaining global budget plus one byte to detect
            # concurrent growth without loading an unbounded source into memory.
            read_limit = min(max_bytes, remaining_bytes)
            with path.open("rb") as source:
                raw = source.read(read_limit + 1)
            bytes_read += len(raw)
            if len(raw) > read_limit:
                documents_skipped_by_byte_budget += 1
                continue
            source_text = raw.decode("utf-8-sig", errors="replace")
        except (OSError, UnicodeError):
            documents_unavailable_or_unsafe += 1
            continue
        documents_read += 1
        lines = redact_sensitive_lines(source_text).splitlines()
        for number, line in enumerate(lines, 1):
            match = claim_re.match(line)
            if not match:
                continue
            if match.group(2).strip() == "=":
                # Equality lines are commonly code examples, not prose claims.
                continue
            subject = re.sub(r"\s+", " ", match.group(1).strip()).casefold()
            subject = re.sub(r"^(?:(?:the|a|an|el|la|los|las|un|una|unos|unas)\s+)+", "", subject)
            if subject in generic_subjects or len(subject) < 5:
                continue
            operator = match.group(2).casefold()
            value = match.group(3).strip()
            if sensitive_claim_re.search(subject) or sensitive_claim_re.search(value):
                continue
            normalized_value = re.sub(r"\s+", " ", value.casefold()).strip(" .;:")
            negative_values = ("not ", "no ", "false", "falso", "falsa", "deprecated", "obsoleto", "obsoleta")
            negative = bool(re.search(r"\b(?:not|no)\b", operator)) or normalized_value.startswith(negative_values)
            for prefix in ("not ", "no "):
                if normalized_value.startswith(prefix):
                    normalized_value = normalized_value[len(prefix):].strip()
            document_id = int(row["document_id"])
            bucket = claims[(subject, normalized_value)][negative]
            if document_id in bucket:
                continue
            if claims_indexed >= max_claims:
                claim_budget_exhausted = True
                break
            bucket[document_id] = {
                "document_id": document_id, "title": row["title"], "path": str(path),
                "line": number, "operator": operator, "value": value,
            }
            claims_indexed += 1
        if claim_budget_exhausted:
            break
    candidates: list[dict[str, Any]] = []
    for (subject, _normalized_value), polarity_claims in claims.items():
        seen_document_pairs: set[tuple[int, int]] = set()
        for positive in polarity_claims[False].values():
            for negative in polarity_claims[True].values():
                positive_id = int(positive["document_id"])
                negative_id = int(negative["document_id"])
                if positive_id == negative_id:
                    continue
                document_pair = tuple(sorted((positive_id, negative_id)))
                if document_pair in seen_document_pairs:
                    continue
                seen_document_pairs.add(document_pair)
                candidates.append({
                    "subject": subject, "left": positive, "right": negative,
                    "reason": "heurística: afirmaciones diferentes sobre el mismo sujeto",
                })
                if len(candidates) >= limit:
                    findings_truncated = True
                    break
            if findings_truncated:
                break
        if findings_truncated:
            break
    summary = {
        "active_documents": active_documents,
        "documents_read": documents_read,
        "documents_skipped_by_document_budget": documents_skipped_by_document_budget,
        "documents_skipped_by_byte_budget": documents_skipped_by_byte_budget,
        "documents_unavailable_or_unsafe": documents_unavailable_or_unsafe,
        "bytes_read": bytes_read,
        "claims_indexed": claims_indexed,
        "claim_limit": max_claims,
        "claim_budget_exhausted": claim_budget_exhausted,
        "findings_returned": len(candidates),
        "findings_limit": max(0, limit),
        "findings_truncated": findings_truncated,
        "coverage_complete": not any((
            documents_skipped_by_document_budget,
            documents_skipped_by_byte_budget,
            documents_unavailable_or_unsafe,
            claim_budget_exhausted,
            findings_truncated,
        )),
    }
    return candidates, summary


def _authorized_audit_root(settings: Settings, source_kind: str, source_root: str) -> Path | None:
    try:
        root = Path(source_root)
        if source_kind == "projects":
            base = settings.projects_root
            if contains_reparse_component(base) or contains_reparse_component(root):
                return None
            relative = root.resolve(strict=True).relative_to(base.resolve(strict=True))
            # Discovery models projects as immediate children, never arbitrary nested roots.
            if len(relative.parts) != 1 or _project_is_excluded(settings, root):
                return None
            return root if root.is_dir() else None
        configured = any(
            kind == source_kind and path_key(configured_root) == path_key(root)
            for kind, configured_root, _name in settings.source_roots()
        )
        if not configured:
            return None
        if contains_reparse_component(root) or not root.is_dir():
            return None
        return root
    except (OSError, ValueError):
        return None


def _authorized_audit_file(settings: Settings, source_kind: str, source_root: str, relative_path: str) -> Path | None:
    root = _authorized_audit_root(settings, source_kind, source_root)
    if root is None:
        return None
    try:
        return _existing_source_file(root, relative_path)
    except (OSError, ValueError):
        return None


def _review_index_drift(
    db: Database, settings: Settings, finding_limit: int = 200,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Compare active index metadata/hashes to authorized files without changing either side."""
    def bounded_setting(name: str, default: int, ceiling: int) -> int:
        try:
            return min(max(1, int(settings.raw.get(name, default))), ceiling)
        except (TypeError, ValueError):
            return default

    max_documents = bounded_setting("audit_index_check_max_documents", 2000, 10000)
    max_total_bytes = bounded_setting("audit_index_check_max_bytes", 67_108_864, 268_435_456)
    register_project_visibility(db, settings)
    visible_document = project_visibility_sql("d")
    active_documents = int(db.one(
        f"SELECT COUNT(*) AS c FROM documents d WHERE d.status='active' AND {visible_document}"
    )["c"])
    rows = db.query(
        "SELECT d.document_id,d.title,d.source_kind,d.source_root,d.relative_path,d.size_bytes,d.mtime_ns,d.content_hash "
        "FROM documents d WHERE d.status='active' AND " + visible_document +
        " ORDER BY d.document_id LIMIT ?", (max_documents,),
    )
    by_status: dict[str, int] = defaultdict(int)
    findings: list[dict[str, Any]] = []
    bytes_hashed = 0
    checked = 0
    drift_statuses = {
        "metadata_changed", "content_changed_same_metadata", "path_unavailable_or_unsafe",
        "read_error", "source_exceeds_index_limit", "changed_during_audit",
    }

    def record(row: Any, status: str) -> None:
        by_status[status] += 1
        if status in drift_statuses and len(findings) < finding_limit:
            title = " ".join(redact_sensitive_lines(str(row["title"] or "")).splitlines()).strip()[:200]
            findings.append({
                "document_id": int(row["document_id"]),
                "title": title,
                "source_kind": str(row["source_kind"] or ""),
                "relative_path": str(row["relative_path"] or ""),
                "status": status,
                "review_only": True,
            })

    for row in rows:
        source_kind = str(row["source_kind"] or "")
        path = _authorized_audit_file(settings, source_kind, str(row["source_root"] or ""), str(row["relative_path"] or ""))
        if path is None:
            checked += 1
            record(row, "path_unavailable_or_unsafe")
            continue
        try:
            before = path.stat()
        except OSError:
            checked += 1
            record(row, "read_error")
            continue
        policy = settings.policy(source_kind)
        try:
            file_limit = max(1, int(policy.get("max_file_bytes", settings.raw.get("max_document_bytes", 2_097_152))))
        except (TypeError, ValueError):
            file_limit = 2_097_152
        if before.st_size > file_limit:
            checked += 1
            record(row, "source_exceeds_index_limit")
            continue
        if before.st_size != int(row["size_bytes"] or 0) or before.st_mtime_ns != int(row["mtime_ns"] or 0):
            checked += 1
            record(row, "metadata_changed")
            continue
        if before.st_size > max_total_bytes - bytes_hashed:
            by_status["skipped_byte_budget"] += 1
            continue
        audit_read_limit = min(file_limit, max_total_bytes - bytes_hashed)
        try:
            if contains_reparse_component(path):
                checked += 1
                record(row, "path_unavailable_or_unsafe")
                continue
            with path.open("rb") as handle:
                raw = handle.read(audit_read_limit + 1)
            after = path.stat()
        except OSError:
            checked += 1
            record(row, "read_error")
            continue
        checked += 1
        if len(raw) > audit_read_limit:
            record(row, "changed_during_audit")
            continue
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            record(row, "changed_during_audit")
            continue
        bytes_hashed += len(raw)
        # Path.read_text(), used by the indexer, normalizes CRLF/CR to LF.
        current_text = raw.decode("utf-8-sig", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
        current_hash = sha256_text(current_text)
        if current_hash != str(row["content_hash"] or ""):
            record(row, "content_changed_same_metadata")
        else:
            by_status["unchanged"] += 1

    if active_documents > len(rows):
        by_status["skipped_document_budget"] += active_documents - len(rows)
    drift_count = sum(by_status.get(status, 0) for status in drift_statuses)
    skipped = by_status.get("skipped_byte_budget", 0) + by_status.get("skipped_document_budget", 0)
    summary = {
        "active_documents": active_documents,
        "checked_documents": checked,
        "bytes_hashed": bytes_hashed,
        "documents_out_of_sync": drift_count,
        "documents_skipped_by_budget": skipped,
        "coverage_complete": skipped == 0,
        "by_status": dict(sorted(by_status.items())),
        "findings_truncated": drift_count > len(findings),
        "review_only": True,
    }
    return summary, findings


def _sensitive_redaction_review(
    db: Database, settings: Settings, max_bytes: int = 2_097_152, limit: int = 100,
) -> tuple[list[dict[str, Any]], int]:
    """List metadata-only warnings for a private-key BEGIN marker without END."""
    findings: list[dict[str, Any]] = []
    total = 0
    register_project_visibility(db, settings)
    rows = db.query(
        "SELECT d.document_id,d.title,d.source_kind,d.source_root,d.relative_path "
        "FROM documents d WHERE d.status='active' AND " + project_visibility_sql("d") +
        " ORDER BY d.document_id"
    )
    for row in rows:
        path = _authorized_audit_file(
            settings, str(row["source_kind"]), str(row["source_root"]), str(row["relative_path"]),
        )
        if path is None:
            continue
        try:
            if path.stat().st_size > max(1, max_bytes):
                continue
            source_text = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        marker_lines = unclosed_private_key_lines(source_text)
        if not marker_lines:
            continue
        total += 1
        if len(findings) < max(0, limit):
            line_count = len(source_text.splitlines())
            findings.append({
                "document_id": int(row["document_id"]), "title": str(row["title"]),
                "source_kind": str(row["source_kind"]), "relative_path": str(row["relative_path"]),
                "marker_lines": marker_lines,
                "suppressed_line_count": sum(max(0, line_count - marker + 1) for marker in marker_lines),
                "review_reason": "marcador de clave privada sin cierre; contenido posterior censurado hasta EOF",
            })
    return findings, total


def _live_target_path_review(
    settings: Settings,
    source_kind: str,
    source_root: str,
    source_relative_path: str,
    target_raw: str,
    active_paths: set[str],
) -> dict[str, Any]:
    root = _authorized_audit_root(settings, source_kind, source_root)
    if root is None:
        return {"classification": "not_checked_untrusted_source_root", "candidates": []}
    target = unquote(str(target_raw or "").split("|", 1)[0].strip()).split("#", 1)[0].strip()
    target = target.replace("\\", "/")
    if not target or urlsplit(target).scheme or target.startswith("//"):
        return {"classification": "not_applicable_external_or_empty", "candidates": []}

    suffix = PurePosixPath(target.lstrip("/")).suffix.casefold()
    without_ext = target[:-len(suffix)] if suffix in {".md", ".markdown"} else target
    parent = posixpath.dirname(source_relative_path.replace("\\", "/"))
    root_absolute = target.startswith("/")
    root_candidate = posixpath.normpath(without_ext.lstrip("/"))
    relative_candidate = posixpath.normpath(posixpath.join(parent, without_ext))
    escaped = (
        (root_candidate == ".." or root_candidate.startswith("../")) if root_absolute
        else (relative_candidate == ".." or relative_candidate.startswith("../"))
    )
    if escaped:
        return {"classification": "path_escapes_source_root_now", "candidates": []}

    bases = [root_candidate]
    if not root_absolute and relative_candidate != root_candidate:
        bases.append(relative_candidate)
    file_candidates: list[tuple[str, Path]] = []
    for base in bases:
        if target.endswith("/"):
            continue
        if suffix in {".md", ".markdown"}:
            relative_candidates = [base + suffix]
        elif suffix:
            relative_candidates = [base]
        else:
            relative_candidates = [base, base + ".md", base + ".markdown"]
        for relative in relative_candidates:
            path = _existing_source_file(root, relative)
            if path is not None and all(path_key(path) != path_key(existing) for _, existing in file_candidates):
                file_candidates.append((relative.replace("\\", "/"), path))

    if file_candidates:
        if len(file_candidates) > 1:
            classification = "multiple_live_path_candidates"
        elif path_key(file_candidates[0][1]) in active_paths:
            classification = "indexed_target_still_broken"
        elif file_candidates[0][1].suffix.casefold() in {".md", ".markdown"}:
            classification = "live_markdown_not_indexed"
        else:
            classification = "live_non_markdown_not_indexed"
        return {
            "classification": classification,
            "candidates": [relative for relative, _path in file_candidates[:5]],
        }

    directories = [base for base in bases if _existing_source_directory(root, base)]
    if directories:
        return {"classification": "live_directory_not_indexed", "candidates": directories[:5]}
    return {"classification": "not_present_on_disk", "candidates": []}


def _review_missing_links(
    db: Database, settings: Settings,
) -> tuple[list[dict[str, Any]], dict[str, int], dict[str, int]]:
    def key(value: str) -> str:
        return unicodedata.normalize("NFC", value).strip().casefold()

    title_index: dict[str, dict[int, dict[str, Any]]] = defaultdict(dict)
    register_project_visibility(db, settings)
    visible_source = project_visibility_sql("d")
    active_documents = db.query(
        "SELECT d.document_id,d.title,d.source_kind,d.source_root,d.relative_path,d.absolute_path,d.frontmatter_json "
        "FROM documents d WHERE d.status='active' AND " + visible_source
    )
    active_paths = {path_key(str(row["absolute_path"])) for row in active_documents}
    for row in active_documents:
        document = dict(row)
        names = {str(row["title"]), PurePosixPath(str(row["relative_path"]).replace("\\", "/")).stem}
        try:
            metadata = json.loads(row["frontmatter_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            metadata = {}
        aliases = metadata.get("aliases", []) if isinstance(metadata, dict) else []
        if isinstance(aliases, str):
            names.add(aliases)
        elif isinstance(aliases, list):
            names.update(str(alias) for alias in aliases if isinstance(alias, (str, int, float)))
        for name in names:
            if name.strip():
                title_index[key(name)][int(row["document_id"])] = document

    links = db.query(
        "SELECT l.source_document_id,d.title AS source_title,d.absolute_path AS source_path,"
        "d.source_kind,d.source_root,d.relative_path AS source_relative_path,l.target_raw,l.line_number "
        "FROM links l JOIN documents d ON d.document_id=l.source_document_id "
        "WHERE d.status='active' AND " + visible_source + " AND l.status='broken' AND l.resolution_reason='missing_path' "
        "ORDER BY d.title,l.line_number"
    )
    findings: list[dict[str, Any]] = []
    counts: dict[str, int] = defaultdict(int)
    live_path_counts: dict[str, int] = defaultdict(int)
    for link in links:
        raw_target = str(link["target_raw"] or "").split("|", 1)[0].split("#", 1)[0].strip()
        basename = PurePosixPath(raw_target.replace("\\", "/")).name
        title = basename[:-3] if basename.casefold().endswith(".md") else basename
        candidates = [
            item for document_id, item in title_index.get(key(title), {}).items()
            if document_id != int(link["source_document_id"])
        ] if title else []
        source_root_key = path_key(str(link["source_root"] or ""))
        same_root = [item for item in candidates if path_key(str(item["source_root"] or "")) == source_root_key]
        if not candidates:
            classification = "no_exact_title_candidate"
        elif len(same_root) > 1:
            classification = "multiple_same_root_candidates"
        elif len(same_root) == 1:
            classification = "same_root_alternate_path"
        else:
            classification = "other_root_exact_title_match"
        counts[classification] += 1
        live_path = _live_target_path_review(
            settings, str(link["source_kind"]), str(link["source_root"]),
            str(link["source_relative_path"]), str(link["target_raw"]), active_paths,
        )
        live_path_counts[str(live_path["classification"])] += 1
        findings.append({
            "source_title": link["source_title"], "source_path": link["source_path"],
            "source_document_id": int(link["source_document_id"]),
            "source_relative_path": str(link["source_relative_path"]),
            "line_number": int(link["line_number"]), "target_raw": link["target_raw"],
            "review_classification": classification, "candidate_count": len(candidates),
            "live_path_classification": live_path["classification"],
            "live_path_candidates": live_path["candidates"],
            "candidates": [
                {"title": item["title"], "source_kind": item["source_kind"],
                 "relative_path": item["relative_path"], "absolute_path": item["absolute_path"]}
                for item in sorted(candidates, key=lambda candidate: (str(candidate["title"]).casefold(), str(candidate["absolute_path"]).casefold()))
            ],
            "review_only": True,
        })
    return findings, dict(sorted(counts.items())), dict(sorted(live_path_counts.items()))


def _collect_audit_raw(settings: Settings) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    stale_before = now - timedelta(days=settings.stale_days)
    with Database(settings.database_path) as db:
        register_project_visibility(db, settings)
        visible_document = project_visibility_sql("d")
        visible_source = project_visibility_sql("source")
        visible_target = project_visibility_sql("target")
        active_link_counts = {
            str(row["status"]): int(row["count"])
            for row in db.query(
                f"""SELECT l.status, COUNT(*) AS count FROM links l
                   JOIN documents source ON source.document_id=l.source_document_id AND source.status='active' AND {visible_source}
                   GROUP BY l.status"""
            )
        }
        active_resolved = db.one(
            f"""SELECT COUNT(*) AS c FROM links l
               JOIN documents source ON source.document_id=l.source_document_id AND source.status='active' AND {visible_source}
               JOIN documents target ON target.document_id=l.target_document_id AND target.status='active' AND {visible_target}
               WHERE l.status='resolved'"""
        )["c"]
        inactive_search_payload_documents = db.one(
            f"""SELECT COUNT(DISTINCT payload.document_id) AS c FROM (
                   SELECT d.document_id FROM documents_fts f
                   JOIN documents d ON d.document_id=CAST(f.document_id AS INTEGER)
                   WHERE d.status IN ('deleted','skipped') AND {visible_document}
                   UNION ALL
                   SELECT d.document_id FROM document_chunks c
                   JOIN documents d ON d.document_id=c.document_id
                   WHERE d.status IN ('deleted','skipped') AND {visible_document}
                   UNION ALL
                   SELECT d.document_id FROM chunks_fts f
                   JOIN documents d ON d.document_id=CAST(f.document_id AS INTEGER)
                   WHERE d.status IN ('deleted','skipped') AND {visible_document}
               ) AS payload"""
        )["c"]
        counts = {
            "documents_active": db.one(f"SELECT COUNT(*) AS c FROM documents d WHERE d.status='active' AND {visible_document}")["c"],
            "documents_deleted": db.one(f"SELECT COUNT(*) AS c FROM documents d WHERE d.status='deleted' AND {visible_document}")["c"],
            "documents_with_inactive_search_payload": inactive_search_payload_documents,
            "documents_with_parse_errors": db.one(f"SELECT COUNT(*) AS c FROM documents d WHERE d.status='active' AND d.parse_error IS NOT NULL AND {visible_document}")["c"],
            "links_resolved": active_resolved,
            "links_broken": active_link_counts.get("broken", 0),
            "links_ambiguous": active_link_counts.get("ambiguous", 0),
            "links_external": active_link_counts.get("external", 0),
            "links_attachments": active_link_counts.get("attachment", 0),
            "links_directories": active_link_counts.get("directory", 0),
            "links_intentionally_incomplete": active_link_counts.get("ignored", 0),
            "links_invalid_paths": db.one(
                f"""SELECT COUNT(*) AS c FROM links l JOIN documents source ON source.document_id=l.source_document_id
                   WHERE source.status='active' AND {visible_source} AND l.status='broken'
                   AND l.resolution_reason IN ('invalid_absolute_path','path_escapes_source_root')"""
            )["c"],
            "duplicate_hash_groups": db.one(f"SELECT COUNT(*) AS c FROM (SELECT d.content_hash FROM documents d WHERE d.status='active' AND d.content_hash<>'' AND {visible_document} GROUP BY d.content_hash HAVING COUNT(*)>1)")["c"],
            "duplicate_title_groups": db.one(f"SELECT COUNT(*) AS c FROM (SELECT lower(d.title) FROM documents d WHERE d.status='active' AND {visible_document} GROUP BY lower(d.title) HAVING COUNT(*)>1)")["c"],
            "projects": db.one("SELECT COUNT(*) AS c FROM projects WHERE status='active' AND rabanito_project_visible('projects',name,root_path)=1")["c"],
        }
        project_manifest_warnings: list[dict[str, Any]] = []
        for project_row in db.query(
            "SELECT name, dependency_errors_json FROM projects "
            "WHERE status='active' AND rabanito_project_visible('projects',name,root_path)=1 ORDER BY name, root_path"
        ):
            try:
                issues = json.loads(project_row["dependency_errors_json"] or "[]")
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(issues, list):
                continue
            project_name = " ".join(redact_sensitive_lines(str(project_row["name"] or "")).splitlines()).strip()[:120]
            for issue in issues:
                if not isinstance(issue, dict):
                    continue
                source = str(issue.get("source", "")).replace("\\", "/")
                error_type = str(issue.get("error_type", ""))
                source_path = PurePosixPath(source)
                if (not source or len(source) > 240 or source_path.is_absolute() or ".." in source_path.parts
                        or ":" in source or re.search(r"[\x00-\x1f\x7f]", source)
                        or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", error_type)):
                    continue
                project_manifest_warnings.append({
                    "project": project_name, "source": source, "error_type": error_type,
                    "review_only": True,
                })
        project_manifest_warnings.sort(key=lambda item: (item["project"].casefold(), item["source"].casefold(), item["error_type"]))
        counts["project_dependency_manifest_errors"] = len(project_manifest_warnings)
        index_drift_summary, index_drift_findings = _review_index_drift(db, settings)
        counts["documents_index_drift"] = int(index_drift_summary["documents_out_of_sync"])
        counts["documents_index_check_skipped"] = int(index_drift_summary["documents_skipped_by_budget"])
        stale = db.query(
            "SELECT d.document_id,d.title,d.source_kind,d.relative_path,d.mtime_iso FROM documents d "
            "WHERE d.status='active' AND d.mtime_iso < ? AND " + visible_document + " ORDER BY d.mtime_iso LIMIT 200",
            (stale_before.isoformat(timespec="seconds"),),
        )
        duplicate_hashes = db.query(f"SELECT d.content_hash, COUNT(*) AS count, group_concat(d.title, ' | ') AS titles FROM documents d WHERE d.status='active' AND d.content_hash<>'' AND {visible_document} GROUP BY d.content_hash HAVING COUNT(*)>1 ORDER BY count DESC LIMIT 100")
        duplicate_titles = db.query(f"SELECT lower(d.title) AS title_key, COUNT(*) AS count, group_concat(d.absolute_path, ' | ') AS paths FROM documents d WHERE d.status='active' AND {visible_document} GROUP BY lower(d.title) HAVING COUNT(*)>1 ORDER BY count DESC LIMIT 100")
        latest_scan = db.one(
            """SELECT scan_id,started_at,finished_at,status,files_seen,added,modified,unchanged,
                      removed,skipped,errors
               FROM scan_runs ORDER BY scan_id DESC LIMIT 1"""
        )
        link_classifications = db.query(
            "SELECT l.status, COALESCE(l.resolution_reason,'unclassified') AS reason, COUNT(*) AS count "
            "FROM links l JOIN documents source ON source.document_id=l.source_document_id "
            "LEFT JOIN documents target ON target.document_id=l.target_document_id "
            "WHERE source.status='active' AND " + visible_source + " AND (l.status<>'resolved' OR (target.status='active' AND " + visible_target + ")) "
            "GROUP BY l.status, COALESCE(l.resolution_reason,'unclassified') ORDER BY l.status, reason"
        )
        link_findings = db.query(
            "SELECT d.document_id AS source_document_id, d.title AS source_title, d.absolute_path AS source_path, "
            "d.source_kind, d.relative_path AS source_relative_path, l.target_raw, l.relation_type, "
            "l.status, l.resolution_reason, l.line_number, l.target_path_guess "
            "FROM links l JOIN documents d ON d.document_id=l.source_document_id "
            "WHERE d.status='active' AND " + visible_document + " AND l.status IN ('broken','ambiguous','external','attachment','directory','ignored') "
            "ORDER BY l.status, d.title, l.line_number LIMIT 500"
        )
        missing_link_review, missing_link_review_counts, missing_link_path_state_counts = _review_missing_links(db, settings)
        def bounded_contradiction_setting(name: str, default: int, ceiling: int) -> int:
            try:
                return min(max(1, int(settings.raw.get(name, default))), ceiling)
            except (TypeError, ValueError):
                return default

        contradictions, contradiction_scan_summary = _potential_contradictions(
            db, settings=settings,
            max_bytes=int(settings.raw.get("max_document_bytes", 2_097_152)),
            max_documents=bounded_contradiction_setting("audit_contradiction_max_documents", 2000, 10000),
            max_total_bytes=bounded_contradiction_setting("audit_contradiction_max_bytes", 67_108_864, 268_435_456),
            max_claims=bounded_contradiction_setting("audit_contradiction_max_claims", 100_000, 500_000),
        )
        counts["contradiction_candidates"] = len(contradictions)
        counts["contradiction_documents_skipped"] = (
            int(contradiction_scan_summary["documents_skipped_by_document_budget"])
            + int(contradiction_scan_summary["documents_skipped_by_byte_budget"])
            + int(contradiction_scan_summary["documents_unavailable_or_unsafe"])
        )
        sensitive_redaction_review, sensitive_redaction_count = _sensitive_redaction_review(
            db, settings, max_bytes=int(settings.raw.get("max_document_bytes", 2_097_152)),
        )
        counts["documents_with_unclosed_sensitive_blocks"] = sensitive_redaction_count
        quality_score = 100
        quality_score -= min(30, int(counts["links_broken"]) * 2)
        quality_score -= min(15, int(counts["links_ambiguous"]) * 2)
        quality_score -= min(20, int(counts["documents_with_parse_errors"]) * 5)
        quality_score -= min(15, int(counts["duplicate_hash_groups"]) * 3)
        quality_score -= min(20, int(counts["documents_index_drift"]) * 2)
        quality_score -= min(10, len(contradictions))
    return {
        "generated_at": iso_now(), "stale_before": stale_before.isoformat(timespec="seconds"),
        "quality_score": max(0, quality_score), "counts": counts,
        "link_classifications": [dict(row) for row in link_classifications],
        "link_findings": [dict(row) for row in link_findings],
        "missing_link_review": missing_link_review,
        "missing_link_review_counts": missing_link_review_counts,
        "missing_link_path_state_counts": missing_link_path_state_counts,
        "sensitive_redaction_review": sensitive_redaction_review,
        "contradiction_scan_summary": contradiction_scan_summary,
        "project_manifest_warnings": project_manifest_warnings[:200],
        "project_manifest_warnings_truncated": len(project_manifest_warnings) > 200,
        "index_drift_summary": index_drift_summary,
        "index_drift_findings": index_drift_findings,
        "stale_documents": [dict(row) for row in stale], "duplicate_hashes": [dict(row) for row in duplicate_hashes],
        "duplicate_titles": [dict(row) for row in duplicate_titles], "potential_contradictions": contradictions,
        "latest_scan": dict(latest_scan) if latest_scan else None,
    }


def _safe_audit_display(value: Any) -> str:
    return " ".join(redact_sensitive_lines(str(value or "")).splitlines()).strip()


def _safe_audit_relative_path(value: Any) -> str:
    normalized = _safe_audit_display(value).replace("\\", "/")
    parsed = urlsplit(normalized)
    if parsed.scheme.lower() == "file":
        basename = PurePosixPath(unquote(parsed.path).replace("\\", "/")).name
        return f"[URI de archivo omitida]{' · ' + basename if basename else ''}"
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
        basename = PurePosixPath(normalized).name
        return f"[ruta absoluta omitida]{' · ' + basename if basename else ''}"
    if any(part == ".." for part in normalized.split("/")):
        return "[ruta fuera de raíz omitida]"
    return normalized


def _safe_audit_target(value: Any) -> str:
    normalized = _safe_audit_display(value).replace("\\", "/")
    parsed = urlsplit(normalized)
    if parsed.scheme.lower() == "file":
        basename = PurePosixPath(unquote(parsed.path).replace("\\", "/")).name
        return f"[URI de archivo omitida]{' · ' + basename if basename else ''}"
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
        basename = PurePosixPath(normalized).name
        return f"[ruta absoluta omitida]{' · ' + basename if basename else ''}"
    return normalized


def dashboard_audit_view(report: dict[str, Any]) -> dict[str, Any]:
    """Project a full audit into a minimal, redacted dashboard response."""
    safe_display = _safe_audit_display
    safe_relative_path = _safe_audit_relative_path
    safe_target = _safe_audit_target

    raw_drift_summary = report.get("index_drift_summary")
    drift_summary = raw_drift_summary if isinstance(raw_drift_summary, dict) else {}
    raw_contradiction_summary = report.get("contradiction_scan_summary")
    contradiction_summary = raw_contradiction_summary if isinstance(raw_contradiction_summary, dict) else {}
    raw_drift_findings = report.get("index_drift_findings")
    drift_findings = raw_drift_findings if isinstance(raw_drift_findings, list) else []

    count_keys = (
        "documents_active", "documents_deleted", "documents_with_parse_errors", "links_resolved",
        "documents_with_inactive_search_payload",
        "links_broken", "links_ambiguous", "links_external", "links_attachments", "links_directories",
        "links_intentionally_incomplete", "links_invalid_paths", "projects",
        "documents_with_unclosed_sensitive_blocks", "project_dependency_manifest_errors",
        "documents_index_drift", "documents_index_check_skipped",
        "contradiction_candidates", "contradiction_documents_skipped",
    )
    missing_review = []
    for item in report["missing_link_review"]:
        missing_review.append({
            "source_document_id": int(item["source_document_id"]),
            "source_title": safe_display(item["source_title"]),
            "source_relative_path": safe_relative_path(item["source_relative_path"]),
            "line_number": int(item["line_number"]),
            "target_raw": safe_target(item["target_raw"]),
            "review_classification": safe_display(item["review_classification"]),
            "candidate_count": int(item["candidate_count"]),
            "live_path_classification": safe_display(item["live_path_classification"]),
            "live_path_candidates": [safe_relative_path(value) for value in item["live_path_candidates"]],
            "candidates": [{
                "title": safe_display(candidate["title"]),
                "source_kind": safe_display(candidate["source_kind"]),
                "relative_path": safe_relative_path(candidate["relative_path"]),
            } for candidate in item["candidates"]],
            "review_only": True,
        })
    other_broken = []
    for item in report["link_findings"]:
        if item["status"] not in {"broken", "ambiguous"} or item["resolution_reason"] == "missing_path":
            continue
        other_broken.append({
            "source_document_id": int(item["source_document_id"]),
            "source_title": safe_display(item["source_title"]),
            "source_relative_path": safe_relative_path(item["source_relative_path"]),
            "line_number": int(item["line_number"]),
            "target_raw": safe_target(item["target_raw"]),
            "status": safe_display(item["status"]),
            "resolution_reason": safe_display(item["resolution_reason"]),
            "target_path_guess": safe_target(item["target_path_guess"]),
        })
    return {
        "generated_at": report["generated_at"],
        "quality_score": int(report["quality_score"]),
        "counts": {key: int(report["counts"].get(key, 0)) for key in count_keys},
        "link_classifications": [{
            "status": safe_display(item["status"]), "reason": safe_display(item["reason"]),
            "count": int(item["count"]),
        } for item in report["link_classifications"]],
        "missing_link_review_counts": report["missing_link_review_counts"],
        "missing_link_path_state_counts": report["missing_link_path_state_counts"],
        "contradiction_scan_summary": {
            key: int(contradiction_summary.get(key, 0))
            for key in (
                "active_documents", "documents_read", "documents_skipped_by_document_budget",
                "documents_skipped_by_byte_budget", "documents_unavailable_or_unsafe",
                "bytes_read", "claims_indexed", "claim_limit", "findings_returned", "findings_limit",
            )
        } | {
            "claim_budget_exhausted": bool(contradiction_summary.get("claim_budget_exhausted", False)),
            "findings_truncated": bool(contradiction_summary.get("findings_truncated", False)),
            "coverage_complete": bool(contradiction_summary.get("coverage_complete", False)),
            "review_only": True,
        },
        "missing_link_review": missing_review,
        "project_manifest_warnings": [{
            "project": safe_display(item["project"]),
            "source": safe_relative_path(item["source"]),
            "error_type": safe_display(item["error_type"]),
            "review_only": True,
        } for item in report.get("project_manifest_warnings", [])[:200]],
        "project_manifest_warnings_truncated": bool(report.get("project_manifest_warnings_truncated", False)),
        "index_drift_summary": {
            "active_documents": int(drift_summary.get("active_documents", 0)),
            "checked_documents": int(drift_summary.get("checked_documents", 0)),
            "bytes_hashed": int(drift_summary.get("bytes_hashed", 0)),
            "documents_out_of_sync": int(drift_summary.get("documents_out_of_sync", 0)),
            "documents_skipped_by_budget": int(drift_summary.get("documents_skipped_by_budget", 0)),
            "coverage_complete": bool(drift_summary.get("coverage_complete", False)),
            "findings_truncated": bool(drift_summary.get("findings_truncated", False)) or len(drift_findings) > 100,
            "by_status": {
                safe_display(key): int(value)
                for key, value in drift_summary.get("by_status", {}).items()
            },
            "review_only": True,
        },
        "index_drift_findings": [{
            "document_id": int(item["document_id"]),
            "title": safe_display(item["title"]),
            "source_kind": safe_display(item["source_kind"]),
            "relative_path": safe_relative_path(item["relative_path"]),
            "status": safe_display(item["status"]),
            "review_only": True,
        } for item in drift_findings[:100]],
        "other_broken_findings": other_broken,
        "review_only": True,
    }


def dashboard_audit(settings: Settings) -> dict[str, Any]:
    return dashboard_audit_view(collect_audit(settings))


def audit_report_view(report: dict[str, Any]) -> dict[str, Any]:
    """Return a detailed local audit projection without absolute paths or source claims."""
    safe = dashboard_audit_view(report)
    safe["stale_before"] = _safe_audit_display(report.get("stale_before"))
    safe["counts"] = {str(key): int(value) for key, value in report.get("counts", {}).items()}
    safe["link_findings"] = [{
        "source_document_id": int(item["source_document_id"]),
        "source_title": _safe_audit_display(item["source_title"]),
        "source_kind": _safe_audit_display(item["source_kind"]),
        "source_path": _safe_audit_relative_path(item["source_relative_path"]),
        "source_relative_path": _safe_audit_relative_path(item["source_relative_path"]),
        "target_raw": _safe_audit_target(item["target_raw"]),
        "relation_type": _safe_audit_display(item["relation_type"]),
        "status": _safe_audit_display(item["status"]),
        "resolution_reason": _safe_audit_display(item["resolution_reason"]),
        "line_number": int(item["line_number"] or 0),
        "target_path_guess": _safe_audit_target(item["target_path_guess"]),
        "review_only": True,
    } for item in report.get("link_findings", [])]
    safe["stale_documents"] = [{
        "document_id": int(item["document_id"]),
        "title": _safe_audit_display(item["title"]),
        "source_kind": _safe_audit_display(item["source_kind"]),
        "relative_path": _safe_audit_relative_path(item["relative_path"]),
        "mtime_iso": _safe_audit_display(item["mtime_iso"]),
        "review_only": True,
    } for item in report.get("stale_documents", [])]
    safe["duplicate_hashes"] = [{"count": int(item["count"]), "review_only": True}
                                 for item in report.get("duplicate_hashes", [])]
    safe["duplicate_titles"] = [{"count": int(item["count"]), "review_only": True}
                                 for item in report.get("duplicate_titles", [])]
    safe["potential_contradictions"] = [{
        "left": {
            "document_id": int(item["left"]["document_id"]),
            "line": int(item["left"]["line"]),
        },
        "right": {
            "document_id": int(item["right"]["document_id"]),
            "line": int(item["right"]["line"]),
        },
        "reason": "Heuristic candidate; inspect cited source text manually.",
        "review_only": True,
    } for item in report.get("potential_contradictions", [])]
    safe["sensitive_redaction_review"] = [{
        "document_id": int(item["document_id"]),
        "title": _safe_audit_display(item["title"]),
        "source_kind": _safe_audit_display(item["source_kind"]),
        "relative_path": _safe_audit_relative_path(item["relative_path"]),
        "marker_lines": [int(line) for line in item["marker_lines"]],
        "suppressed_line_count": int(item["suppressed_line_count"]),
        "review_reason": _safe_audit_display(item["review_reason"]),
        "review_only": True,
    } for item in report.get("sensitive_redaction_review", [])]
    latest = report.get("latest_scan")
    scan_keys = (
        "scan_id", "started_at", "finished_at", "status", "files_seen", "added", "modified",
        "unchanged", "removed", "skipped", "errors",
    )
    safe["latest_scan"] = ({key: latest[key] for key in scan_keys if key in latest} if isinstance(latest, dict) else None)
    safe["review_only"] = True
    return safe


def collect_audit(settings: Settings) -> dict[str, Any]:
    """Collect a metadata-only audit suitable for programmatic callers."""
    return audit_report_view(_collect_audit_raw(settings))


def write_audit(settings: Settings) -> dict[str, Any]:
    report = collect_audit(settings)
    counts = report["counts"]
    lines = [
        f"# Rabanito audit — {report['generated_at']}", "", f"**Quality score (heuristic): {report['quality_score']}/100**", "",
        "## Counts", "", *(f"- {key}: {value}" for key, value in counts.items()), "",
        "## Actionable findings", "",
        f"- Broken links: {counts['links_broken']}", f"- Ambiguous links: {counts['links_ambiguous']}",
        f"- Existing directory references (not document nodes): {counts['links_directories']}",
        f"- Documents outside the current index snapshot: {counts['documents_index_drift']}",
        f"- Source checks skipped by configured audit budget: {counts['documents_index_check_skipped']}",
        f"- Stale documents: {len(report['stale_documents'])}", f"- Duplicate content groups: {counts['duplicate_hash_groups']}",
        f"- Potential contradiction candidates (heuristic): {len(report['potential_contradictions'])}", "",
        f"- Contradiction review: {report['contradiction_scan_summary']['documents_read']}/{report['contradiction_scan_summary']['active_documents']} documents read; {report['contradiction_scan_summary']['bytes_read']} bytes; {report['contradiction_scan_summary']['claims_indexed']}/{report['contradiction_scan_summary']['claim_limit']} unique claims; claim budget exhausted: {report['contradiction_scan_summary']['claim_budget_exhausted']}; coverage complete: {report['contradiction_scan_summary']['coverage_complete']}; findings truncated: {report['contradiction_scan_summary']['findings_truncated']}",
        f"- Documents with an unclosed private-key marker (content redacted to EOF): {counts['documents_with_unclosed_sensitive_blocks']}", "",
        "## Notes", "", "- Imported text is treated as data, never as system instructions.", "- Contradiction candidates require human review and are not assertions.", "",
    ]
    if report["link_classifications"]:
        lines.extend(["## Link classification", "", *(
            f"- {item['status']} / {item['reason']}: {item['count']}" for item in report["link_classifications"]
        ), ""])
    if report["link_findings"]:
        lines.extend(["## Link review sample (up to 100)", "", *(
            f"- {item['status']} ({item['resolution_reason'] or 'sin motivo'}): `{item['source_kind']}:{item['source_path']}:{item['line_number']}` → `{item['target_raw']}`"
            for item in report["link_findings"][:100]
        ), ""])
    if report.get("project_manifest_warnings"):
        lines.extend([
            "## Project dependency manifests to review (metadata only)", "",
            "Contents are not retained in these findings. Re-open each local manifest manually; no source file was changed.", "",
            *(
                f"- `{item['project']}` · `{item['source']}` — {item['error_type']}"
                for item in report["project_manifest_warnings"][:200]
            ),
            "",
        ])
        if report.get("project_manifest_warnings_truncated"):
            lines.append("Additional manifest findings were omitted from this Markdown sample; see the local JSON report.")
            lines.append("")
    if report["missing_link_review"]:
        lines.extend([
            "## Broken-link candidates (manual review only)", "",
            "Exact title/basename matches and live filesystem checks are clues only. This audit is read-only; no source, index status, or relation was changed.", "",
            *(f"- {kind}: {count}" for kind, count in report["missing_link_review_counts"].items()), "",
            "### Current destination-path state", "",
            *(f"- {kind}: {count}" for kind, count in report["missing_link_path_state_counts"].items()), "",
            "### Findings (up to 200)", "",
        ])
        for item in report["missing_link_review"][:200]:
            live_candidates = ", ".join(f"`{path}`" for path in item["live_path_candidates"])
            live_detail = f"; live candidates: {live_candidates}" if live_candidates else ""
            lines.append(
                f"- `{item['source_relative_path']}:{item['line_number']}` → `{item['target_raw']}` "
                f"(title review: {item['review_classification']}; path state: {item['live_path_classification']}{live_detail})"
            )
            if item["candidates"]:
                lines.append(
                    "  Title candidates: "
                    + "; ".join(f"`{candidate['source_kind']}:{candidate['relative_path']}`" for candidate in item["candidates"])
                )
        omitted = len(report["missing_link_review"]) - 200
        if omitted > 0:
            lines.append(f"- … {omitted} additional findings are available in the JSON report.")
        lines.append("")
    drift_summary = report["index_drift_summary"]
    lines.extend([
        "## Read-only source/index consistency",
        "",
        f"Checked {drift_summary['checked_documents']} of {drift_summary['active_documents']} active documents; "
        f"hashed {drift_summary['bytes_hashed']} bytes. Findings are clues only and do not update the index.",
        f"Coverage complete: {'yes' if drift_summary['coverage_complete'] else 'no'}; "
        f"skipped by configured budget: {drift_summary['documents_skipped_by_budget']}.",
        "",
    ])
    if report["index_drift_findings"]:
        lines.extend(["### Findings (up to 200)", ""])
        lines.extend(
            f"- `{item['source_kind']}:{item['relative_path']}` · {item['status']} · {item['title']}"
            for item in report["index_drift_findings"]
        )
        if drift_summary["findings_truncated"]:
            lines.append("Additional consistency findings were omitted; see the local JSON report.")
        lines.append("")
    if report["stale_documents"]:
        lines.extend([
            "## Stale documents (first 20)", "",
            *(f"- `{item['source_kind']}:{item['relative_path']}` — {item['mtime_iso']}" for item in report["stale_documents"][:20]), "",
        ])
    if report["sensitive_redaction_review"]:
        lines.extend([
            "## Sensitive-block review (metadata only)", "",
            "Source content is not copied here. An unclosed marker causes the parser to censor through end-of-file.", "",
        ])
        for item in report["sensitive_redaction_review"]:
            safe_relative_path = re.sub(r"[\r\n\t\x00-\x1f\x7f]", " ", str(item["relative_path"])).replace("`", "'")
            for marker in item["marker_lines"]:
                lines.append(
                    f"- `{safe_relative_path}:{marker}` ({item['source_kind']}) — "
                    f"{item['suppressed_line_count']} lines censored; review the source manually."
                )
        lines.append("")
    json_path, markdown_path = _write_report_pair(settings, "audit", report, "\n".join(lines))
    report["json_path"] = json_path.relative_to(settings.knowledge_root).as_posix()
    report["markdown_path"] = markdown_path.relative_to(settings.knowledge_root).as_posix()
    return report


def build_link_suggestions(settings: Settings, limit_per_document: int = 5) -> dict[str, Any]:
    with _index_lock(settings):
        return _build_link_suggestions_locked(settings, limit_per_document)


def _build_link_suggestions_locked(settings: Settings, limit_per_document: int) -> dict[str, Any]:
    created = 0
    considered = 0
    limit_per_document = max(0, int(limit_per_document))
    with Database(settings.database_path) as db:
        register_project_visibility(db, settings)
        rows = db.query(
            "SELECT d.document_id,d.title,d.category,d.tags_json FROM documents d "
            "WHERE d.status='active' AND " + project_visibility_sql("d")
        )
        profiles: dict[int, set[str]] = {}
        inverted: dict[str, set[int]] = defaultdict(set)
        for row in rows:
            try:
                tags = json.loads(row["tags_json"] or "[]")
            except json.JSONDecodeError:
                tags = []
            tokens = set(re.findall(r"[\wÀ-ÿ]{3,}", f"{row['title']} {row['category']} {' '.join(map(str, tags))}".casefold()))
            profiles[int(row["document_id"])] = tokens
            for token in tokens:
                inverted[token].add(int(row["document_id"]))
        explicit_pairs = {
            tuple(sorted((int(row["source_document_id"]), int(row["target_document_id"]))))
            for row in db.query(
                "SELECT source_document_id,target_document_id FROM links "
                "WHERE status='resolved' AND target_document_id IS NOT NULL"
            )
        }
        db.execute("DELETE FROM link_suggestions WHERE status='suggested'")
        candidates: list[tuple[float, int, int, str]] = []
        for source_id in sorted(profiles):
            source_tokens = profiles[source_id]
            possible: set[int] = set()
            for token in source_tokens:
                possible.update(inverted[token])
            possible.discard(source_id)
            for target_id in possible:
                if target_id <= source_id:
                    continue
                pair = (source_id, target_id)
                if pair in explicit_pairs:
                    continue
                target_tokens = profiles[target_id]
                shared = source_tokens & target_tokens
                if len(shared) < 2:
                    continue
                union = source_tokens | target_tokens
                score = len(shared) / max(len(union), 1)
                considered += 1
                candidates.append((score, source_id, target_id, f"shared terms: {', '.join(sorted(shared)[:8])}"))
        degree: dict[int, int] = defaultdict(int)
        for score, source_id, target_id, reason in sorted(candidates, key=lambda item: (-item[0], item[1], item[2])):
            if degree[source_id] >= limit_per_document or degree[target_id] >= limit_per_document:
                continue
            cursor = db.execute(
                "INSERT OR IGNORE INTO link_suggestions(source_document_id,target_document_id,score,reason,created_at) VALUES(?,?,?,?,?)",
                (source_id, target_id, round(score, 4), reason, iso_now()),
            )
            if cursor.rowcount > 0:
                created += 1
                degree[source_id] += 1
                degree[target_id] += 1
        db.commit()
    return {"created": created, "considered": considered, "status": "suggestions only; no facts asserted"}


def level_up(settings: Settings) -> dict[str, Any]:
    report = collect_audit(settings)
    recommendations: list[dict[str, Any]] = []
    counts = report["counts"]
    if counts["links_broken"]:
        recommendations.append({"priority": "high", "action": "Revisar enlaces rotos", "why": f"Hay {counts['links_broken']} destinos no resueltos.", "command": "python -m rabanito audit"})
    if counts["links_ambiguous"]:
        recommendations.append({"priority": "medium", "action": "Desambiguar títulos repetidos", "why": f"Hay {counts['links_ambiguous']} enlaces con más de un candidato.", "command": "python -m rabanito search <término>"})
    if counts["duplicate_hash_groups"]:
        recommendations.append({"priority": "medium", "action": "Revisar duplicados por contenido", "why": f"Hay {counts['duplicate_hash_groups']} grupos con el mismo hash.", "command": "python -m rabanito audit"})
    if counts.get("project_dependency_manifest_errors", 0):
        recommendations.append({
            "priority": "medium", "action": "Revisar manifiestos de dependencias",
            "why": f"Hay {counts['project_dependency_manifest_errors']} manifiestos inaccesibles, demasiado grandes o malformados; no se guardó su contenido.",
            "command": "python -m rabanito audit",
        })
    if counts.get("documents_index_drift", 0):
        recommendations.append({
            "priority": "high", "action": "Sincronizar cambios locales del índice",
            "why": f"Hay {counts['documents_index_drift']} documentos cuya fuente ya no coincide con la última versión indexada o no pudo verificarse.",
            "command": "python -m rabanito index",
        })
    if counts.get("documents_with_inactive_search_payload", 0):
        recommendations.append({
            "priority": "low", "action": "Revisar caché de texto de documentos inactivos",
            "why": f"{counts['documents_with_inactive_search_payload']} documentos retirados u omitidos aún conservan texto/fragmentos en SQLite. `prune-search-cache` permite previsualizar; la aplicación requiere confirmación y crea un backup verificado.",
            "command": "python -m rabanito prune-search-cache",
        })
    if counts.get("documents_index_check_skipped", 0):
        recommendations.append({
            "priority": "medium", "action": "Completar auditoría de consistencia",
            "why": f"{counts['documents_index_check_skipped']} documentos quedaron fuera de los límites configurados; ampliar audit_index_check_max_bytes o audit_index_check_max_documents solo si es necesario.",
            "command": "python -m rabanito audit",
        })
    if not report["contradiction_scan_summary"]["coverage_complete"]:
        summary = report["contradiction_scan_summary"]
        skipped = (
            summary["documents_skipped_by_document_budget"]
            + summary["documents_skipped_by_byte_budget"]
            + summary["documents_unavailable_or_unsafe"]
        )
        why_parts = []
        if summary["findings_truncated"]:
            why_parts.append(f"La lista heurística alcanzó su límite de {summary['findings_limit']} candidatos")
        if summary.get("claim_budget_exhausted"):
            why_parts.append(f"el análisis alcanzó el límite de {summary['claim_limit']} afirmaciones únicas")
        if skipped:
            why_parts.append(f"la revisión omitió {skipped} fuentes por límites o porque no pudieron autorizarse")
        why = "; además, ".join(why_parts) + "." if why_parts else "La cobertura del análisis no pudo confirmarse."
        recommendations.append({
            "priority": "medium", "action": "Completar revisión de contradicciones",
            "why": f"{why} Amplía audit_contradiction_max_documents, audit_contradiction_max_bytes o audit_contradiction_max_claims solo si es necesario.",
            "command": "python -m rabanito audit",
        })
    if len(report["stale_documents"]) > 20:
        recommendations.append({"priority": "low", "action": "Actualizar conocimiento antiguo", "why": f"Hay {len(report['stale_documents'])} documentos más antiguos que el umbral configurado.", "command": "Editar config/settings.json: stale_days"})
    if not recommendations:
        recommendations.append({"priority": "low", "action": "Agregar fuentes aprobadas o ejecutar una entrevista", "why": "No se encontraron problemas estructurales prioritarios.", "command": "python -m rabanito onboard --help"})
    generated_at = iso_now()
    full_output = {
        "generated_at": generated_at,
        "based_on": report,
        "recommendations": recommendations,
    }
    lines = [f"# Rabanito level-up — {generated_at}", "", *(f"- **{item['priority']}** {item['action']}: {item['why']} (`{item['command']}`)" for item in recommendations), ""]
    json_path, markdown_path = _write_report_pair(settings, "level-up", full_output, "\n".join(lines))
    return {
        "generated_at": generated_at,
        "based_on": {
            "quality_score": report["quality_score"],
            "counts": report["counts"],
            "missing_link_review_counts": report["missing_link_review_counts"],
            "scan_id": report["latest_scan"]["scan_id"] if report["latest_scan"] else None,
        },
        "recommendations": recommendations,
        "json_path": json_path.relative_to(settings.knowledge_root).as_posix(),
        "markdown_path": markdown_path.relative_to(settings.knowledge_root).as_posix(),
    }
