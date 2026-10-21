from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .utils import path_key, safe_relative, write_json_atomic


SETTINGS_WRITE_LOCK = threading.RLock()


@dataclass(frozen=True)
class Settings:
    root: Path
    raw: dict[str, Any]

    @property
    def vault_root(self) -> Path:
        return self._path(self.raw["vault_root"])

    @property
    def projects_root(self) -> Path:
        return self._path(self.raw["projects_root"])

    @property
    def knowledge_root(self) -> Path:
        return self._path(self.raw["knowledge_dir"])

    @property
    def data_dir(self) -> Path:
        return self._path(self.raw["data_dir"])

    @property
    def database_path(self) -> Path:
        return self._path(self.raw["database_path"])

    @property
    def max_search_results(self) -> int:
        return int(self.raw.get("max_search_results", 20))

    @property
    def max_context_chars(self) -> int:
        return int(self.raw.get("max_context_chars", 12000))

    @property
    def stale_days(self) -> int:
        return int(self.raw.get("stale_days", 180))

    def _path(self, value: str) -> Path:
        candidate = Path(value)
        return candidate if candidate.is_absolute() else (self.root / candidate)

    def policy(self, kind: str) -> dict[str, Any]:
        return dict(self.raw.get("source_policy", {}).get(kind, {}))

    def additional_sources(self) -> list[dict[str, Any]]:
        return list(self.raw.get("additional_sources", []))

    def is_project_excluded(self, root: Path | str) -> bool:
        candidate = Path(root)
        candidate_key = path_key(candidate)
        candidate_name = candidate.name.casefold()
        for item in self.raw.get("excluded_projects", []):
            value = str(item).strip()
            if value and (value.casefold() == candidate_name or path_key(value) == candidate_key):
                return True
        return False

    def is_project_name_excluded(self, name: str | None) -> bool:
        normalized = str(name or "").strip().casefold()
        if not normalized:
            return False
        for item in self.raw.get("excluded_projects", []):
            value = str(item).strip()
            if (value and not Path(value).is_absolute() and "/" not in value and "\\" not in value
                    and value.casefold() == normalized):
                return True
        return False

    def is_configured_root(self, path: Path) -> bool:
        roots = [self.vault_root, self.projects_root, self.knowledge_root]
        roots.extend(
            Path(item["path"]) for item in self.additional_sources()
            if item.get("path") and item.get("enabled", True)
        )
        return any(safe_relative(path, root) is not None for root in roots)

    def source_roots(self, include_disabled: bool = False) -> list[tuple[str, Path, str | None]]:
        roots: list[tuple[str, Path, str | None]] = [
            ("obsidian", self.vault_root, None),
            ("projects", self.projects_root, None),
            ("internal", self.knowledge_root, None),
        ]
        for item in self.additional_sources():
            if item.get("path") and (include_disabled or item.get("enabled", True)):
                roots.append((str(item.get("kind", "local")), Path(item["path"]), item.get("name")))
        return roots


def default_config_path(root: Path | None = None) -> Path:
    project_root = root or Path(__file__).resolve().parent.parent
    return project_root / "config" / "settings.json"


def load_settings(path: Path | None = None) -> Settings:
    config_path = path or default_config_path()
    config_path = config_path.resolve()
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or (raw.get('project_root') is not None and not isinstance(raw['project_root'], str)):
        raise ValueError('invalid_settings_object')
    project_root = Path(raw.get("project_root") or config_path.parent.parent)
    if not project_root.is_absolute():
        project_root = (config_path.parent.parent / project_root).resolve()
    raw["project_root"] = str(project_root)
    settings = Settings(project_root, raw)
    # Startup precedes every CLI writer. Validate BOTH roots before creating
    # either, then pin parents against Windows directory redirection. No DB/lock
    # is opened here; command-specific guards remain authoritative for those.
    from .index_storage import prepare_settings_storage
    prepare_settings_storage(settings)
    return settings


def save_settings(settings: Settings, config_path: Path | None = None) -> None:
    target = config_path or default_config_path(settings.root)
    with SETTINGS_WRITE_LOCK:
        write_json_atomic(target, settings.raw)


def add_source(settings: Settings, path: Path, kind: str, name: str | None = None) -> Settings:
    resolved = path.resolve(strict=True)
    with SETTINGS_WRITE_LOCK:
        existing = next((
            item for item in settings.additional_sources()
            if path_key(item.get("path", "")) == path_key(resolved)
        ), None)
        if existing is None:
            settings.raw.setdefault("additional_sources", []).append(
                {"name": name or resolved.name, "kind": kind, "path": str(resolved)}
            )
            save_settings(settings)
        elif not existing.get("enabled", True):
            existing["enabled"] = True
            save_settings(settings)
    return settings


def set_additional_source_enabled(settings: Settings, path: Path, enabled: bool) -> dict[str, Any]:
    if not isinstance(enabled, bool):
        raise ValueError("A boolean enabled state is required")
    requested_key = path_key(path)
    with SETTINGS_WRITE_LOCK:
        source = next((
            item for item in settings.additional_sources()
            if item.get("path") and path_key(item["path"]) == requested_key
        ), None)
        if source is None:
            raise ValueError("The path is not a registered additional source")
        if bool(source.get("enabled", True)) != enabled:
            source["enabled"] = enabled
            save_settings(settings)
        return dict(source)
