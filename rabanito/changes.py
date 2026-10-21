from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path, PurePosixPath
from typing import Any

from .config import SETTINGS_WRITE_LOCK, Settings
from .db import Database
from .utils import path_key, safe_relative
from .visibility import project_visibility_sql, register_project_visibility


def resolve_active_project_root(settings: Settings, identifier: str) -> str:
    """Resolve one active project by exact root path or unambiguous name."""
    value = identifier.strip()
    if not value:
        raise ValueError("project cannot be empty")
    with Database(settings.database_path, query_only=True, empty_if_missing=True) as db:
        rows = db.query("SELECT name,root_path FROM projects WHERE status='active' ORDER BY name,root_path")
    active = [
        row for row in rows
        if safe_relative(Path(str(row["root_path"])), settings.projects_root) is not None
        and not settings.is_project_excluded(Path(str(row["root_path"])))
    ]
    if Path(value).is_absolute():
        matches = [row for row in active if path_key(row["root_path"]) == path_key(value)]
    else:
        matches = [row for row in active if str(row["name"]).casefold() == value.casefold()]
    if not matches:
        raise ValueError("active project not found")
    if len(matches) > 1:
        raise ValueError("ambiguous project name; use its exact root path")
    return str(matches[0]["root_path"])


def recent_document_changes(
    settings: Settings,
    limit: int = 20,
    project_root_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Return bounded, metadata-only events from currently authorized sources."""
    limit = min(max(int(limit), 0), 100)
    if limit == 0:
        return []

    with SETTINGS_WRITE_LOCK:
        settings = Settings(settings.root, deepcopy(settings.raw))
    with Database(settings.database_path, query_only=True, empty_if_missing=True) as db:
        register_project_visibility(db, settings)
        db.connection.create_function("rabanito_path_key", 1, lambda value: path_key(str(value or "")))
        active_project_keys: set[str] = set()
        for project in db.query("SELECT root_path FROM projects WHERE status='active'"):
            root = Path(str(project["root_path"] or ""))
            if (safe_relative(root, settings.projects_root) is not None
                    and not settings.is_project_excluded(root)):
                active_project_keys.add(path_key(root))
        db.connection.create_function(
            "rabanito_active_project", 1,
            lambda value: int(path_key(str(value or "")) in active_project_keys),
        )

        project_filter_key = None
        if project_root_path is not None:
            project_filter_key = path_key(project_root_path)
            if project_filter_key not in active_project_keys:
                raise ValueError("project is not active or is outside the authorized project root")

        source_conditions: list[str] = []
        source_params: list[Any] = []
        for kind, root, _name in settings.source_roots():
            if kind == "projects" and path_key(root) == path_key(settings.projects_root):
                continue
            source_conditions.append("(d.source_kind=? AND rabanito_path_key(d.source_root)=?)")
            source_params.extend([kind, path_key(root)])
        source_conditions.append("(d.source_kind='projects' AND rabanito_active_project(d.project_root_path)=1)")
        association_condition = "(d.project_root_path IS NULL OR rabanito_active_project(d.project_root_path)=1)"
        project_filter_sql = " AND rabanito_path_key(d.project_root_path)=?" if project_filter_key is not None else ""
        params = [*source_params]
        if project_filter_key is not None:
            params.append(project_filter_key)
        params.append(limit)

        rows = db.query(
            """SELECT c.change_id,c.scan_id,c.document_id,c.change_type,c.reason,c.occurred_at,
                      d.title,d.source_kind,d.project_name,d.relative_path,d.status
               FROM document_changes c JOIN documents d ON d.document_id=c.document_id
               WHERE (""" + " OR ".join(source_conditions) + ") AND " + association_condition +
            " AND " + project_visibility_sql('d') + project_filter_sql +
            " ORDER BY c.change_id DESC LIMIT ?",
            params,
        )
        changes = []
        for row in rows:
            relative = str(row["relative_path"] or "").replace("\\", "/")
            safe_path = PurePosixPath(relative)
            if (not relative or safe_path.is_absolute() or ".." in safe_path.parts
                    or ":" in relative or re.search(r"[\x00-\x1f\x7f]", relative)):
                continue
            changes.append({
                "change_id": int(row["change_id"]), "scan_id": int(row["scan_id"]),
                "document_id": int(row["document_id"]), "change_type": str(row["change_type"]),
                "reason": str(row["reason"]), "occurred_at": str(row["occurred_at"]),
                "title": str(row["title"] or "")[:240], "source_kind": str(row["source_kind"]),
                "project": str(row["project_name"])[:160] if row["project_name"] is not None else None,
                "relative_path": relative[:500], "document_status": str(row["status"]),
            })
    return changes
