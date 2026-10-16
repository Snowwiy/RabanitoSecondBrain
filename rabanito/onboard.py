from __future__ import annotations

import re
from itertools import islice
from pathlib import Path
from typing import Any

from .config import Settings, add_source
from .utils import contains_reparse_component, safe_relative


SOURCE_KIND_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
RESERVED_SOURCE_KINDS = {"obsidian", "projects", "internal"}
PREVIEW_ENTRY_LIMIT = 20


def _validated_kind(kind: str) -> str:
    value = str(kind or "").strip().casefold()
    if not SOURCE_KIND_RE.fullmatch(value) or value in RESERVED_SOURCE_KINDS:
        raise ValueError("The source kind must be a short non-reserved slug")
    return value


def _validated_name(name: str | None) -> str | None:
    if name is None:
        return None
    value = str(name).strip()
    if not value or len(value) > 120 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("The source name must contain 1–120 printable characters")
    return value


def preview_source(settings: Settings, path: Path, kind: str) -> dict[str, Any]:
    kind = _validated_kind(kind)
    if contains_reparse_component(path):
        raise ValueError("The source path is unsafe or unverifiable (symlink/reparse point)")
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("The source must be a directory")
    existing = settings.is_configured_root(resolved)
    sample: list[str] = []
    for child in islice(resolved.iterdir(), PREVIEW_ENTRY_LIMIT):
        try:
            if contains_reparse_component(child):
                continue
        except OSError:
            continue
        sample.append(child.name)
    sample.sort(key=lambda item: (item.casefold(), item))
    return {"path": str(resolved), "kind": kind, "already_configured": existing, "sample_entries": sample, "approval_required": not existing}


def approve_source(settings: Settings, path: Path, kind: str, name: str | None = None) -> dict[str, Any]:
    kind = _validated_kind(kind)
    name = _validated_name(name)
    preview = preview_source(settings, path, kind)
    if not preview["already_configured"]:
        add_source(settings, Path(preview["path"]), kind, name)
    preview["approved"] = True
    return preview
