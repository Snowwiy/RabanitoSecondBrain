"""PyPA pylock 1.0 declared inventory. No artifact reads, downloads or install.

This is a bounded inventory subset, not a complete lock schema validator or
marker evaluator. Origins and conditions survive only as opaque digests.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from .inventory_toml import PUBLIC_PYPI, TOKEN, digest, load_inventory


ROOT_KEYS = {"lock-version", "created-by", "environments", "requires-python", "extras", "dependency-groups", "default-groups", "packages", "tool"}
PACKAGE_KEYS = {"name", "version", "marker", "requires-python", "dependencies", "index", "vcs", "directory", "archive", "sdist", "wheels", "attestation-identities", "tool"}
SOURCE_KEYS = ("vcs", "directory", "archive", "sdist", "wheels")


def is_pylock_name(name: str) -> bool:
    if not isinstance(name, str): return False
    name = name.casefold()
    return name == "pylock.toml" or bool(len(name) <= 212 and re.fullmatch(r"pylock\.[^.\\/:\x00-\x1f\x7f]+\.toml", name)
                                       and name[7:-5].strip())


def _text(item, key, *, required=False, maximum=4096):
    if key not in item and not required: return None
    value = item.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError("invalid_pylock_metadata")
    return value


def _strings(item, key):
    value = item.get(key, [])
    if (not isinstance(value, list) or len(value) > 256 or any(not isinstance(v, str) or not v or len(v) > 4096 for v in value)
            or sum(len(v) for v in value) > 65536):
        raise ValueError("invalid_or_oversized_pylock_conditions")
    return sorted(set(value))


def _public_artifact(value):
    if not isinstance(value, str) or len(value) > 4096 or re.search(r"[\x00-\x20\x7f\\]", value): return False
    try:
        url = urlsplit(value)
        return (url.scheme == "https" and url.hostname == "files.pythonhosted.org" and url.port in {None, 443}
                and not url.username and not url.password and not url.query and not url.fragment and url.path.startswith("/packages/"))
    except ValueError:
        return False


def _origin(item):
    present = {k for k in SOURCE_KEYS if k in item}
    for key in present - {"wheels"}:
        if not isinstance(item[key], dict) or not item[key]: raise ValueError("invalid_pylock_source")
    wheels = item.get("wheels", [])
    if not isinstance(wheels, list) or len(wheels) > 2000 or any(not isinstance(v, dict) for v in wheels):
        raise ValueError("invalid_or_oversized_pylock_wheels")
    if sum(k in present for k in ("vcs", "directory", "archive")) > 1 or present & {"vcs", "directory", "archive"} and present & {"sdist", "wheels"}:
        return "conflicting_sources", False, 0, "not_verified"
    for key in ("vcs", "directory", "archive"):
        if key in present: return key, False, 1 if key == "archive" else 0, "not_verified"
    artifacts = ([item["sdist"]] if "sdist" in present else []) + wheels
    if not artifacts: return "missing_source", False, 0, "not_verified"
    for artifact in artifacts:
        hashes = artifact.get("hashes")
        if (set(artifact) - {"name", "url", "path", "size", "upload-time", "hashes"}
                or not isinstance(hashes, dict) or not hashes or len(hashes) > 32
                or any(not isinstance(k, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", k)
                       or not isinstance(v, str) or not re.fullmatch(r"[a-fA-F0-9]{1,1024}", v) for k, v in hashes.items())
                or "size" in artifact and (type(artifact["size"]) is not int or artifact["size"] < 0)
                or not ("url" in artifact or "path" in artifact)):
            return "invalid_artifact_metadata", False, len(artifacts), "not_verified"
        for algorithm, length in (("sha256", 64), ("sha384", 96), ("sha512", 128)):
            if algorithm in hashes and len(hashes[algorithm]) != length:
                return "invalid_artifact_metadata", False, len(artifacts), "not_verified"
    if any("path" in a for a in artifacts): return "artifact_path_unverified", False, len(artifacts), "declared_hashes_not_verified"
    if "index" in item and item["index"] not in PUBLIC_PYPI:
        return "index_unverified", False, len(artifacts), "declared_hashes_not_verified"
    if not all(_public_artifact(a.get("url")) for a in artifacts):
        return "artifact_origin_unverified", False, len(artifacts), "declared_hashes_not_verified"
    return ("pypi_index_declared" if "index" in item else "pypi_artifacts_declared"), True, len(artifacts), "declared_hashes_not_verified"


def parse_pylock(raw: str, cap: int) -> tuple[str, list[dict], int, int]:
    from .dependencies import VERSION, package_key
    payload = load_inventory(raw, cap, "pylock")
    if payload.get("lock-version") != "1.0": raise ValueError("unsupported_pylock_version")
    if set(payload) - ROOT_KEYS: raise ValueError("unsupported_pylock_keys")
    _text(payload, "created-by", required=True, maximum=200)
    python = _text(payload, "requires-python")
    global_conditions = digest([python, *[_strings(payload, k) for k in ("environments", "extras", "dependency-groups", "default-groups")]])
    packages = payload.get("packages")
    if not isinstance(packages, list) or len(packages) > cap: raise ValueError("invalid_or_oversized_pylock_packages")
    result, seen, duplicates = [], {}, 0
    for i, item in enumerate(packages):
        if not isinstance(item, dict): raise ValueError("invalid_pylock_package")
        if set(item) - PACKAGE_KEYS: raise ValueError("unsupported_pylock_package_keys")
        marker, requires = _text(item, "marker"), _text(item, "requires-python")
        if "index" in item: _text(item, "index")
        if "dependencies" in item and (not isinstance(item["dependencies"], list) or any(not isinstance(d, dict) for d in item["dependencies"])):
            raise ValueError("invalid_pylock_dependencies")
        original_name, original_version = item.get("name"), item.get("version")
        name = original_name if isinstance(original_name, str) and package_key("PyPI", original_name) and not TOKEN.search(original_name) else ""
        version = original_version if (isinstance(original_version, str) and VERSION.fullmatch(original_version)
                                      and re.match(r"v?[0-9]", original_version, re.I) and ":" not in original_version and not TOKEN.search(original_version)) else ""
        source, public, count, integrity = _origin(item)
        conditions = digest([global_conditions, marker, requires])
        provenance = digest({k: item[k] for k in (*SOURCE_KEYS, "index") if k in item})
        scope = digest([provenance, conditions, None if name else digest(original_name), None if version else digest(original_version)])
        issue = "invalid_pylock_package_name" if not name else "pylock_source_identity_unverified" if not public else "missing_or_unresolved_version" if not version else None
        pointer = "/packages/" + str(i)
        identity = (package_key("PyPI", name), version, scope) if issue is None else (pointer,)
        if identity in seen:
            duplicates += 1
            prior = seen[identity]
            if len(prior["additional_locations"]) < 5: prior["additional_locations"].append(pointer)
            continue
        component = {"ecosystem": "PyPI" if public else "", "name": name, "version": version, "pointer": pointer,
                     "locator_kind": "parsed_toml_tree", "identity_issue": issue, "source_kind": source,
                     "inventory_scope_sha256": scope, "conditions_sha256": conditions, "artifact_scope_sha256": provenance,
                     "artifact_count": count, "artifact_integrity": integrity, "additional_locations": [],
                     "environment_selection": "pylock_entry_conditions_not_evaluated"}
        result.append(component); seen[identity] = component
    return "PyPA pylock.toml 1.0 (inventory subset)", result, duplicates, 0
