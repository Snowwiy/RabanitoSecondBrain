from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from .config import SETTINGS_WRITE_LOCK, Settings
from .db import Database
from .source_policy import document_eligibility
from .utils import path_key, safe_relative


def register_project_visibility(db: Database, settings: Settings) -> None:
    """Bind source authority and project association separately, before ranking."""
    with SETTINGS_WRITE_LOCK:
        settings = Settings(settings.root, deepcopy(settings.raw))
    excluded_names: set[str] = set()
    excluded_legacy_names: set[str] = set()
    excluded_paths: set[str] = set()
    disabled_source_roots: dict[str, set[str]] = {}
    active_source_roots = {
        (kind, path_key(root)) for kind, root, _name in settings.source_roots()
        if kind != 'projects' and root.is_absolute()
    }
    for item in settings.additional_sources():
        source_kind = str(item.get("kind", "")).casefold()
        if source_kind and item.get("path") and not item.get("enabled", True):
            disabled_source_roots.setdefault(source_kind, set()).add(path_key(Path(str(item["path"]))))
    for item in settings.raw.get("excluded_projects", []):
        value = str(item).strip()
        if not value:
            continue
        candidate = Path(value)
        if candidate.is_absolute():
            excluded_paths.add(path_key(candidate))
            if candidate.name:
                # A project-associated legacy row may have lost its root. Its
                # basename is the only safe fallback identity in that case.
                excluded_legacy_names.add(candidate.name.casefold())
        elif "/" not in value and "\\" not in value:
            excluded_names.add(value.casefold())
    root_visibility: dict[str, bool] = {}

    def visible(source_kind: object, project_name: object, project_root_path: object) -> int:
        kind = str(source_kind or "")
        if kind not in {"projects", "internal"}:
            return 1
        root_value = str(project_root_path or "")
        if root_value:
            root = Path(root_value)
            key = path_key(root)
            if key not in root_visibility:
                relative_root = safe_relative(root, settings.projects_root)
                root_visibility[key] = (
                    relative_root not in (None, ".", "")
                    and key not in excluded_paths and root.name.casefold() not in excluded_names
                )
            return int(root_visibility[key])
        # Project-source rows without a root cannot be proven to belong to the
        # configured projects directory, so do not expose them from a stale or
        # damaged index. Project-linked internal memory can use its name only
        # when no root was retained; absolute exclusions also contribute their
        # basename above so this fallback fails closed for those records.
        if kind == "projects":
            return 0
        if kind == "internal" and project_name:
            name = str(project_name or "").strip().casefold()
            return int(name not in excluded_names and name not in excluded_legacy_names)
        return 1

    def document_visible(kind, name, project_root, source_root):
        source = str(source_root or '')
        if not source or not Path(source).is_absolute():
            return 0
        key = path_key(source)
        if key in disabled_source_roots.get(str(kind or ''), set()):
            return 0
        if kind == 'projects':
            if not project_root or key != path_key(str(project_root)):
                return 0
        elif (str(kind or ''), key) not in active_source_roots:
            return 0
        return visible(kind, name, project_root)

    db.connection.create_function("rabanito_project_visible", 3, visible)
    db.connection.create_function("rabanito_project_visible", 4, document_visible)
    db.connection.create_function('rabanito_document_eligible', 2, document_eligibility(settings), deterministic=True)


def project_visibility_sql(alias: str = "d") -> str:
    """SQL predicate for an internally named document-table alias."""
    return (
        f"(rabanito_project_visible({alias}.source_kind,{alias}.project_name,"
        f"{alias}.project_root_path,{alias}.source_root)=1 "
        f"AND rabanito_document_eligible({alias}.source_kind,{alias}.relative_path)=1)"
    )
