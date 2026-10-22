"""Read-only SBOM inspection against the explicitly bounded local OSV snapshot.

No package installation, subprocess, remote lookup or assertion of deployment.
This is a structural reader, not a complete CycloneDX/SPDX schema validator.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from urllib.parse import unquote

from .config import Settings
from .cyber.store import has_schema
from .db import Database
from .dependency_cache import annotate, digest as cache_digest, result_checksum, reuse_saved, validate_osv_schema
from .indexer import DEFAULT_EXCLUDED_DIRS, _excluded_directory, _excluded_name, _existing_source_file
from .pep440 import parse_version, public_version_key
from .pylock import is_pylock_name
from .utils import contains_reparse_component, iso_now, path_key, safe_relative


ENGINE_VERSION = 6
ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "cargo": "crates.io", "nuget": "NuGet"}
SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\Z")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+!:_~-]{0,199}\Z")


def _field(value: object, maximum: int = 500) -> str:
    if not isinstance(value, str) or len(value) > maximum or re.search(r"[\x00-\x20\x7f]", value):
        return ""
    return value


def package_key(ecosystem: str, name: str) -> tuple[str, str] | None:
    """Deliberately small package identity subset; never match by product words."""
    if not _field(name):
        return None
    if ecosystem == "PyPI" and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", name):
        return ecosystem, re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "npm" and re.fullmatch(r"(?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]*", name):
        return ecosystem, name
    if ecosystem == "Maven" and re.fullmatch(r"[A-Za-z0-9._-]+:[A-Za-z0-9._-]+", name):
        return ecosystem, name
    if ecosystem == "crates.io" and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", name):
        return ecosystem, name  # conservative; do not assume underscore/hyphen equivalence
    if ecosystem == "NuGet" and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
        return ecosystem, name.lower()
    return None


def parse_purl(value: object) -> tuple[str, str, str]:
    """Known types only. Qualified/distribution-specific PURLs need manual review."""
    raw = _field(value, 1500)
    if (not raw.startswith("pkg:") or "?" in raw or "#" in raw or "\\" in raw
            or re.search(r"%(?![0-9a-fA-F]{2})", raw)):
        raise ValueError("unsupported_or_invalid_purl")
    kind, slash, body = raw[4:].partition("/")
    if not slash or kind not in ECOSYSTEMS:
        raise ValueError("unsupported_or_invalid_purl")
    position = body.rfind("@")
    encoded_name, encoded_version = (body[:position], body[position + 1:]) if position > 0 else (body, "")
    try:
        parts = [unquote(part, errors="strict") for part in encoded_name.split("/")]
        version = unquote(encoded_version, errors="strict")
    except UnicodeError as exc:
        raise ValueError("unsupported_or_invalid_purl") from exc
    if any(not p or p in {".", ".."} or "/" in p or "\\" in p for p in parts):
        raise ValueError("unsupported_or_invalid_purl")
    if kind == "npm":
        if len(parts) not in {1, 2} or len(parts) == 2 and not parts[0].startswith("@"):
            raise ValueError("unsupported_or_invalid_purl")
        name = "/".join(parts)
    elif kind == "maven":
        if len(parts) != 2:
            raise ValueError("unsupported_or_invalid_purl")
        name = ":".join(parts)
    else:
        if len(parts) != 1:
            raise ValueError("unsupported_or_invalid_purl")
        name = parts[0]
    ecosystem = ECOSYSTEMS[kind]
    if package_key(ecosystem, name) is None or version and not VERSION.fullmatch(version):
        raise ValueError("unsupported_or_invalid_purl")
    return ecosystem, name, version


def semver_key(value: object) -> tuple | None:
    if not isinstance(value, str) or len(value) > 200:
        return None
    match = SEMVER.fullmatch(value)
    if not match:
        return None
    pre = match[4]
    identifiers = []
    if pre:
        for item in pre.split("."):
            if item.isdigit():
                if len(item) > 1 and item.startswith("0"):
                    return None
                identifiers.append((0, int(item)))
            else:
                identifiers.append((1, item))
    return (*map(int, match.group(1, 2, 3)), 0 if pre else 1, tuple(identifiers))


def python_release_key(value: object) -> tuple | None:
    """PEP440 public ordering; downstream/local build applicability needs review."""
    return public_version_key(value)


def _ordered_range(version: str, interval: object, *, python_release: bool = False) -> bool | None:
    expected_type = "ECOSYSTEM" if python_release else "SEMVER"
    if not isinstance(interval, dict) or interval.get("type") != expected_type:
        return None
    comparator = python_release_key if python_release else semver_key
    current = comparator(version)
    events = interval.get("events")
    if current is None or not isinstance(events, list) or not events or len(events) > 500:
        return None
    # Validate the complete stream before returning a positive result.
    intervals = []
    opened = False
    start = None
    previous_end = None
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return None
        key, value = next(iter(event.items()))
        if key not in {"introduced", "fixed", "last_affected", "limit"}:
            return None
        bound = None if key == "introduced" and value == "0" else comparator(value)
        if bound is None and not (key == "introduced" and value == "0"):
            return None
        if key == "introduced":
            if opened or previous_end is not None and (bound is None or bound < previous_end):
                return None
            start, opened = bound, True
        else:
            if not opened or start is not None and bound < start:
                return None
            intervals.append((start, bound, key == "last_affected"))
            previous_end, opened = bound, False
    if opened:
        intervals.append((start, None, False))
    for lower, upper, inclusive in intervals:
        after_start = lower is None or current >= lower
        before_end = upper is None or (current <= upper if inclusive else current < upper)
        if after_start and before_end:
            return True
    return False


def version_evidence(version: str, affected: dict) -> tuple[str, list[str]]:
    versions = affected.get("versions", [])
    if isinstance(versions, list) and version in versions:
        return "potentially_affected", ["explicit_affected_version"]
    parsed = parse_version(version) if affected.get("ecosystem") == "PyPI" else None
    if parsed is not None and parsed.has_local:
        return "needs_review", ["local_build_applicability_not_verified"]
    if parsed is not None and isinstance(versions, list):
        # Same cardinality as the OSV normalizer. Never truncate silently and
        # conclude outside a range when a later explicit equivalent may exist.
        if len(versions) > 20000:
            return "needs_review", ["oversized_affected_versions"]
        for literal in versions:
            equivalent = parse_version(literal)
            if equivalent is not None and not equivalent.has_local and equivalent.key == parsed.key:
                evidence = "pep440_numeric_release_equivalence" if parsed.numeric_final and equivalent.numeric_final else "pep440_public_version_equivalence"
                return "potentially_affected", [evidence]
    ranges = affected.get("ranges", [])
    if not isinstance(ranges, list) or not ranges or len(ranges) > 100:
        return "needs_review", ["no_supported_complete_range"]
    results = [_ordered_range(version, interval, python_release=affected.get("ecosystem") == "PyPI" and
                              isinstance(interval, dict) and interval.get("type") == "ECOSYSTEM") for interval in ranges]
    if True in results:
        return "potentially_affected", ["osv_supported_version_interval"]
    if None in results:
        return "needs_review", ["unsupported_or_invalid_version_range"]
    return "outside_observed_ranges", ["outside_supported_local_intervals_not_a_safety_guarantee"]


def _no_duplicates(items: list[tuple]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _components(payload: object, cap: int) -> tuple[str, list[dict], int]:
    if not isinstance(payload, dict):
        raise ValueError("invalid_sbom_envelope")
    if payload.get("bomFormat") == "CycloneDX" and isinstance(payload.get("specVersion"), str) and payload["specVersion"] in {"1.4", "1.5", "1.6"}:
        format_name = "CycloneDX " + payload["specVersion"]
        items = payload.get("components", [])
        field = "components"
    elif isinstance(payload.get("spdxVersion"), str) and payload["spdxVersion"] in {"SPDX-2.2", "SPDX-2.3"}:
        format_name, items, field = payload["spdxVersion"], payload.get("packages", []), "packages"
    else:
        raise ValueError("unsupported_sbom_format")
    if not isinstance(items, list):
        raise ValueError("invalid_sbom_components")
    if len(items) > cap:
        raise ValueError("sbom_component_limit")
    pending = [(item, f"/{field}/{i}") for i, item in enumerate(items)]
    found, seen, duplicates = [], set(), 0
    examined = 0
    while pending:
        item, pointer = pending.pop()
        examined += 1
        if examined > cap:
            raise ValueError("sbom_component_limit")
        if not isinstance(item, dict):
            raise ValueError("invalid_sbom_component")
        children = item.get("components", []) if field == "components" else []
        if not isinstance(children, list) or len(children) + len(pending) + examined > cap:
            raise ValueError("sbom_component_limit")
        pending.extend((child, f"{pointer}/components/{i}") for i, child in enumerate(children))
        purl = item.get("purl")
        version = _field(item.get("version") if field == "components" else item.get("versionInfo"), 200)
        reason = ""
        if field == "packages":
            references = item.get("externalRefs", [])
            if not isinstance(references, list) or len(references) > 100:
                raise ValueError("invalid_sbom_external_refs")
            purls = {ref.get("referenceLocator") for ref in references if isinstance(ref, dict)
                     and ref.get("referenceType") == "purl" and isinstance(ref.get("referenceLocator"), str)}
            purl = next(iter(purls)) if len(purls) == 1 else None
            if len(purls) > 1:
                reason = "conflicting_package_urls"
        try:
            ecosystem, name, purl_version = parse_purl(purl)
            if version and purl_version and version != purl_version:
                reason = "conflicting_package_versions"
            version = version or purl_version
            if not version or not VERSION.fullmatch(version):
                reason = reason or "missing_or_unresolved_version"
            # CycloneDX names are independently asserted identities; reject disagreement.
            declared = _field(item.get("name"))
            group = _field(item.get("group"))
            if field == "components" and declared:
                candidate = ((group + ":" + declared) if ecosystem == "Maven" and group else
                             (group + "/" + declared) if ecosystem == "npm" and group else declared)
                if package_key(ecosystem, candidate) != package_key(ecosystem, name):
                    reason = "conflicting_package_names"
        except ValueError:
            ecosystem, name = "", ""
            reason = reason or "missing_unsupported_or_invalid_purl"
        component = {"ecosystem": ecosystem, "name": name, "version": version,
                     "pointer": pointer, "identity_issue": reason or None}
        identity = (ecosystem, name, version, reason) if ecosystem and not reason else (pointer,)
        if identity in seen:
            duplicates += 1
            continue
        seen.add(identity)
        found.append(component)
    return format_name, sorted(found, key=lambda c: c["pointer"]), duplicates


def _authorized_file(settings: Settings, project: str, relative: str, kind: str) -> tuple[dict, Path, str]:
    if not isinstance(project, str) or not project.strip() or not isinstance(relative, str):
        raise ValueError("invalid_sbom_request")
    value = relative.replace("\\", "/")
    parts = PurePosixPath(value).parts
    if (not value or not parts or PurePosixPath(value).is_absolute() or any(p in {"..", "."} for p in value.split("/"))
            or ":" in value or re.search(r"[\x00-\x1f\x7f]", value)):
        raise ValueError("inventory_requires_safe_relative_path")
    filename = parts[-1].casefold()
    if (kind == "sbom" and not value.lower().endswith(".json") or kind == "manifest" and
            not (filename in {"package-lock.json", "uv.lock"} or is_pylock_name(filename) or re.fullmatch(r"requirements(?:[-_.][a-z0-9_-]+)?\.txt", filename))):
        raise ValueError("unsupported_inventory_filename")
    if not settings.database_path.is_file():
        raise ValueError("project_inventory_unavailable")
    with Database(settings.database_path, read_only=True) as db:
        inventory = [dict(r) for r in db.query("SELECT project_id,name,root_path,status FROM projects")]
    matches = [r for r in inventory if r["status"] == "active" and
               ((Path(project).is_absolute() and path_key(r["root_path"]) == path_key(project)) or
                (not Path(project).is_absolute() and r["name"].casefold() == project.strip().casefold())) and
               safe_relative(Path(r["root_path"]), settings.projects_root) is not None and
               not settings.is_project_excluded(r["root_path"])]
    if len(matches) != 1:
        raise ValueError("active_authorized_project_not_found_or_ambiguous")
    selected = matches[0]
    root = Path(selected["root_path"])
    policy = settings.policy("projects")
    excluded_dirs = DEFAULT_EXCLUDED_DIRS | {str(x).casefold() for x in policy.get("exclude_dirs", [])}
    excluded_dirs |= {"private", "confidential", "confidencial", "privado", "privados"}
    excluded_names = {str(x).casefold() for x in policy.get("exclude_names", [])}
    if (Path(value).suffix.casefold() in {str(x).casefold() for x in policy.get("exclude_extensions", [])}
            or any(_excluded_directory(p, excluded_dirs) or _excluded_name(Path(p), excluded_names) for p in parts)):
        raise ValueError("sbom_path_excluded")
    target = root / Path(*parts)
    if any(r["project_id"] != selected["project_id"] and safe_relative(target, Path(r["root_path"])) is not None
           and safe_relative(Path(r["root_path"]), root) not in {None, "", "."} for r in inventory):
        raise ValueError("sbom_belongs_to_another_project")
    validated = _existing_source_file(root, value)
    if validated is None or contains_reparse_component(target):
        raise ValueError("sbom_file_unavailable_or_unsafe")
    return selected, validated, value


def inspect_inventory(settings: Settings, project: str, relative_path: str, *, kind: str = "sbom") -> dict:
    """Inspect one explicitly selected inventory file; nothing is written or sent."""
    if not isinstance(kind, str) or kind not in {"sbom", "manifest"}:
        raise ValueError("unsupported_inventory_kind")
    config = settings.raw.get("dependency_analysis", {})
    if not isinstance(config, dict):
        raise ValueError("invalid_dependency_configuration")
    def bounded(name: str, default: int, maximum: int) -> int:
        value = config.get(name, default)
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError("invalid_dependency_limit")
        return value
    max_bytes = bounded("max_sbom_bytes", 2 * 1024 * 1024, 16 * 1024 * 1024)
    max_components = bounded("max_components", 2000, 10000)
    max_advisories = bounded("max_local_advisories", 5000, 10000)
    max_findings = bounded("max_findings", 1000, 5000)
    selected, path, relative = _authorized_file(settings, project, relative_path, kind)
    before = path.stat()
    if before.st_size > max_bytes:
        raise ValueError("sbom_size_limit")
    from .source_files import open_source
    with open_source(path) as stream:
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) or contains_reparse_component(path):
            raise ValueError("sbom_changed_during_read")
        content = stream.read(max_bytes + 1)
    after = path.stat()
    if len(content) > max_bytes or (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError("sbom_changed_during_read")
    digest = hashlib.sha256(content).hexdigest()
    # Bind lookup to a read snapshot of the same bounded OSV prefix used by
    # evaluation. Metadata first avoids JSON parsing/version matching on hits.
    with Database(settings.database_path, read_only=True) as db:
        db.execute("BEGIN")
        metadata, byte_count, total = [], 0, 0
        if has_schema(db):
            validate_osv_schema(db)
            total = db.one("SELECT count(*) FROM cyber_records WHERE source='osv' AND active=1")[0]
            for item in db.execute("SELECT source_id,fingerprint,retrieved_at,length(CAST(data_json AS BLOB)) bytes "
                                   "FROM cyber_records WHERE source='osv' AND active=1 ORDER BY source_id LIMIT ?", (max_advisories,)):
                byte_count += item["bytes"]
                if byte_count > 32 * 1024 * 1024:
                    break
                metadata.append((item["source_id"], item["fingerprint"], item["retrieved_at"], item["bytes"]))
        signature = cache_digest([ENGINE_VERSION, kind, selected["project_id"], path_key(selected["root_path"]),
                                  selected["name"], relative, digest, total, metadata, config, settings.policy("projects")])
        cached = reuse_saved(db, signature, selected, kind, relative, digest, ENGINE_VERSION)
        if cached is not None:
            return cached
        # Keep raw rows inside this snapshot; a concurrent OSV publication
        # cannot produce metadata from one revision and bodies from another.
        rows = db.query("SELECT data_json FROM cyber_records WHERE source='osv' AND active=1 ORDER BY source_id LIMIT ?", (len(metadata),)) if metadata else []
    try:
        decoded = content.decode("utf-8-sig")
        ignored = 0
        if kind == "manifest" and path.suffix.casefold() == ".txt":
            format_name, components, duplicates, ignored = _requirements(decoded, max_components)
        elif kind == "manifest" and path.name.casefold() == "uv.lock":
            from .uv_lock import parse_uv_lock
            format_name, components, duplicates, ignored = parse_uv_lock(decoded, max_components)
        elif kind == "manifest" and is_pylock_name(path.name):
            from .pylock import parse_pylock
            format_name, components, duplicates, ignored = parse_pylock(decoded, max_components)
        else:
            payload = json.loads(decoded, object_pairs_hook=_no_duplicates,
                                 parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_json")))
            if kind == "manifest":
                format_name, components, duplicates, ignored = _npm_lock(payload, max_components)
            else:
                format_name, components, duplicates = _components(payload, max_components)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("malformed_sbom_json") from exc
    requested = {package_key(c["ecosystem"], c["name"]) for c in components if not c["identity_issue"]}
    observations = defaultdict(list)
    examined = len(metadata)
    latest = max((item[2] for item in metadata), default=None)
    for row in rows:
        record = json.loads(row["data_json"])
        if record.get("record_status") != "published":
            continue
        for index, affected in enumerate(record.get("affected", [])[:500]):
            key = package_key(affected.get("ecosystem", ""), affected.get("package", ""))
            if key and key in requested:
                observations[key].append((record, index, affected))
    findings, truncated = [], False
    for component in components:
        key = package_key(component["ecosystem"], component["name"])
        matches = observations.get(key, []) if not component["identity_issue"] else []
        component["assessment"] = "needs_review" if component["identity_issue"] else "no_local_advisory"
        statuses = []
        incomplete_component = False
        for record, index, affected in matches:
            if len(findings) >= max_findings:
                truncated, incomplete_component = True, True
                break
            status, evidence = version_evidence(component["version"], affected)
            statuses.append(status)
            fixes = sorted({e["fixed"] for interval in affected.get("ranges", []) if isinstance(interval, dict)
                            for e in interval.get("events", []) if isinstance(e, dict) and _field(e.get("fixed"), 200)})[:30]
            findings.append({"component_pointer": component["pointer"], "advisory": record["id"], "assessment": status,
                             "evidence": evidence, "affected_pointer": f"/affected/{index}",
                             "citation": record["source_url"], "provider_modified": record.get("modified"),
                             "documented_fixed_versions": fixes, "recommendation": "review_applicability_and_test_upgrade_not_automatically_applied"})
        if statuses:
            component["assessment"] = next(s for s in ("potentially_affected", "needs_review", "outside_observed_ranges") if s in statuses)
        if incomplete_component and component["assessment"] != "potentially_affected":
            component["assessment"] = "needs_review"
        if matches and not statuses:
            component["assessment"] = "needs_review"
    report = {"engine_version": ENGINE_VERSION, "analysis_id": signature, "analyzed_at": iso_now(),
            "project": selected["name"], "source": {"relative_path": relative, "sha256": digest, "format": format_name},
            "coverage": {"mode": "local_osv_only", "total_local_observations": total, "examined": examined,
                         "local_snapshot_complete": examined == total, "latest_retrieved_at": latest,
                         "findings_truncated": truncated, "remote_requests": 0,
                         "ignored_inventory_entries": ignored,
                         "scope": "declared_inventory_not_installed_state; no_match_does_not_mean_safe; not_full_schema_validation"},
            "component_count": len(components), "duplicates_removed": duplicates,
            "summary": dict(Counter(c["assessment"] for c in components)), "components": components, "findings": findings}
    if kind == "manifest" and path.name.casefold() == "uv.lock":
        report["coverage"]["selection"] = "all_lock_entries; markers_extras_groups_and_installed_environment_not_evaluated"
        report["coverage"]["identity"] = "declared_public_pypi_only; custom_registry_git_url_path_and_workspace_unverified"
    if kind == "manifest" and is_pylock_name(path.name):
        report["coverage"]["selection"] = "all_pylock_entries; markers_groups_extras_python_and_wheel_compatibility_not_evaluated"
        report["coverage"]["identity"] = "declared_public_pypi_artifacts_only; indexes_paths_vcs_and_archives_not_assumed_equivalent"
        report["coverage"]["artifacts"] = "metadata_only; no_download_no_hash_verification_no_attestation_verification"
    report["result_sha256"] = result_checksum(report)
    return annotate(report, "computed")


def inspect_sbom(settings: Settings, project: str, relative_path: str) -> dict:
    return inspect_inventory(settings, project, relative_path, kind="sbom")


def inspect_manifest(settings: Settings, project: str, relative_path: str) -> dict:
    return inspect_inventory(settings, project, relative_path, kind="manifest")


def _requirements(raw: str, cap: int) -> tuple[str, list[dict], int, int]:
    result, seen, ignored, duplicates = [], set(), 0, 0
    for number, literal in enumerate(raw.splitlines(), 1):
        if number > max(cap * 10, 1000):
            raise ValueError("manifest_line_limit")
        line = literal.strip()
        if not line or line.startswith("#"):
            continue
        # Never follow includes, URLs, editable installs, environment substitutions or indexes.
        if line.startswith("-") or "${" in line or "://" in line or " @ " in line or line.endswith("\\"):
            ignored += 1
            continue
        line = re.split(r"\s+#", line, maxsplit=1)[0]
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,.-]+\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.+!_*-]{0,199})(.*)", line)
        if not match or package_key("PyPI", match[1]) is None:
            ignored += 1
            continue
        name, version, tail = match.groups()
        issue = None
        if tail.strip() and not re.fullmatch(r"(?:\s+--hash=sha256:[a-fA-F0-9]{64})+", tail):
            issue = "conditional_or_unsupported_requirement_syntax"
        if "*" in version or not VERSION.fullmatch(version):
            issue = "unresolved_or_unsupported_version"
        identity = (package_key("PyPI", name), version, issue)
        if identity in seen:
            duplicates += 1
            continue
        seen.add(identity)
        result.append({"ecosystem": "PyPI", "name": name, "version": version, "pointer": f"line:{number}",
                       "line_number": number, "identity_issue": issue})
        if len(result) > cap:
            raise ValueError("sbom_component_limit")
    return "pip requirements exact-declarations (subset)", result, duplicates, ignored


def _npm_lock(payload: object, cap: int) -> tuple[str, list[dict], int, int]:
    if not isinstance(payload, dict) or type(payload.get("lockfileVersion")) is not int or payload["lockfileVersion"] not in {2, 3}:
        raise ValueError("unsupported_npm_lockfile_version")
    packages = payload.get("packages")
    if not isinstance(packages, dict) or len(packages) > cap + 1:
        raise ValueError("invalid_or_oversized_npm_packages")
    result, seen, ignored, duplicates = [], {}, 0, 0
    for location, item in packages.items():
        if not location:
            continue  # root metadata is not a dependency
        if not isinstance(item, dict):
            raise ValueError("invalid_npm_component")
        if (location.startswith("/") or ":" in location or "\\" in location or
                any(p in {".", ".."} for p in location.split("/")) or re.search(r"[\x00-\x1f\x7f]", location)):
            ignored += 1
            continue
        parts = location.split("node_modules/")
        name = parts[-1]
        if len(parts) < 2 or package_key("npm", name) is None:
            ignored += 1
            continue
        value = item.get("version")
        version = value if isinstance(value, str) and VERSION.fullmatch(value) else ""
        issue = None if version else "missing_or_unresolved_version"
        if item.get("link"):
            issue = "local_link_not_resolved"
        if item.get("name") and item["name"] != name:
            issue = "alias_or_conflicting_package_name"
        identity = (name, version, issue)
        pointer = "/packages/" + location.replace("~", "~0").replace("/", "~1")
        scope = "development" if item.get("dev") is True else "non_development"
        if identity in seen:
            duplicates += 1
            existing = seen[identity]
            existing["declared_scopes"] = sorted(set(existing["declared_scopes"]) | {scope})
            existing["all_occurrences_optional"] = existing["all_occurrences_optional"] and item.get("optional") is True
            if len(existing["additional_locations"]) < 5:
                existing["additional_locations"].append(pointer)
            continue
        normalized = {"ecosystem": "npm", "name": name, "version": version, "pointer": pointer,
                      "identity_issue": issue, "declared_scopes": [scope], "additional_locations": [],
                      "all_occurrences_optional": item.get("optional") is True}
        seen[identity] = normalized
        result.append(normalized)
    return "npm package-lock v" + str(payload["lockfileVersion"]), result, duplicates, ignored
