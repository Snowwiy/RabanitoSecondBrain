"""Bounded, offline uv.lock inventory reader, not a resolver or installer.

Only explicitly declared public PyPI coordinates are matched automatically.
Other sources stay unresolved; URLs, paths, wheels and marker text never leave
this reader. Pointers address the parsed TOML tree, not imaginary JSON lines.
"""
from __future__ import annotations

import re

from .inventory_toml import PUBLIC_PYPI, TOKEN, digest as _digest, load_inventory


MAX_REVISION = 5


def _markers(data, key):
    values = data.get(key, [])
    if (not isinstance(values, list) or len(values) > 256 or any(not isinstance(v, str) or not v or len(v) > 4096 for v in values)
            or sum(len(v) for v in values) > 65536):
        raise ValueError("invalid_or_oversized_uv_markers")
    return sorted(set(values))


def _source(value):
    if not isinstance(value, dict) or not value or any(not isinstance(v, str) or len(v) > 4096 for v in value.values()):
        return "unknown", False
    if set(value) == {"registry"}:
        public = value["registry"] in PUBLIC_PYPI
        return "pypi_registry_declared" if public else "registry_unverified", public
    for kind in ("git", "url", "path", "directory", "editable", "virtual"):
        if set(value) == {kind} or kind == "url" and set(value) == {"url", "subdirectory"}:
            return kind, False
    return "unknown", False


def parse_uv_lock(raw: str, cap: int) -> tuple[str, list[dict], int, int]:
    # Lazy shared identity rules: dependencies dispatches here after its import.
    from .dependencies import VERSION, package_key
    payload = load_inventory(raw, cap, "uv")
    version, revision = payload.get("version"), payload.get("revision", 0)
    if type(version) is not int or version != 1 or type(revision) is not int or not 0 <= revision <= MAX_REVISION:
        raise ValueError("unsupported_uv_lock_version_or_revision")
    python = payload.get("requires-python")
    if not isinstance(python, str) or not python or len(python) > 2000:
        raise ValueError("invalid_uv_python_requirement")
    global_scope = _digest([python, *[_markers(payload, k) for k in ("resolution-markers", "supported-markers", "required-markers")]])
    packages = payload.get("package", [])
    if not isinstance(packages, list) or len(packages) > cap:
        raise ValueError("invalid_or_oversized_uv_packages")
    result, seen, duplicates = [], {}, 0
    for i, item in enumerate(packages):
        if not isinstance(item, dict):
            raise ValueError("invalid_uv_package")
        original_name, original_version = item.get("name"), item.get("version")
        name = original_name if isinstance(original_name, str) and package_key("PyPI", original_name) and not TOKEN.search(original_name) else ""
        value = original_version if (isinstance(original_version, str) and VERSION.fullmatch(original_version)
                                     and re.match(r"v?[0-9]", original_version, re.I) and ":" not in original_version
                                     and not TOKEN.search(original_version)) else ""
        source_kind, public = _source(item.get("source"))
        issue = "invalid_uv_package_name" if not name else "uv_source_identity_unverified" if not public else "missing_or_unresolved_version" if not value else None
        conditions = _digest([global_scope, _markers(item, "resolution-markers")])
        source = source_kind if public else _digest(item.get("source"))
        scope = _digest([source, conditions, None if name else _digest(original_name), None if value else _digest(original_version)])
        pointer = "/package/" + str(i)
        identity = (package_key("PyPI", name), value, scope) if issue is None else (pointer,)
        if identity in seen:
            duplicates += 1
            prior = seen[identity]
            if len(prior["additional_locations"]) < 5:
                prior["additional_locations"].append(pointer)
            continue
        component = {"ecosystem": "PyPI" if public else "", "name": name, "version": value, "pointer": pointer,
                     "locator_kind": "parsed_toml_tree", "identity_issue": issue, "source_kind": source_kind,
                     "inventory_scope_sha256": scope, "conditions_sha256": conditions, "additional_locations": [],
                     "environment_selection": "universal_lock_entry_not_evaluated"}
        result.append(component); seen[identity] = component
    return "uv.lock v1 revision " + str(revision) + " (inventory subset)", result, duplicates, 0
