from __future__ import annotations

import json
import os
import posixpath
import re
import sqlite3
import stat
import threading
import time
import unicodedata
import tomllib
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import unquote, urlsplit

from .config import Settings, set_additional_source_enabled
from .db import Database
from .parsing import ParsedDocument, parse_frontmatter, parse_markdown
from .utils import contains_reparse_component, iso_now, path_key, redact_sensitive_lines, safe_relative, sha256_text, slugify, write_json_atomic, write_text_atomic


SENSITIVE_NAME_RE = re.compile(
    r"(?i)^(?:\.env(?:\..*)?|.*\.env(?:\..*)?|(?:.*[-_.])?(?:credentials?|secrets?|tokens?)(?:[-_.].*)?|"
    r"service-account(?:\..*)?|id_rsa(?:\..*)?|id_ed25519(?:\..*)?|.*\.(?:pem|pfx|p12|p7b|p7c|key|keystore|kdbx|jks))$"
)
PRIVATE_KEY_NAME_RE = re.compile(r"(?i)^(?:id_rsa|id_ed25519)(?:\..*)?$")
SENSITIVE_HEADING_RE = re.compile(r"(?i)(?:password|passwd|token|api[_ -]?key|secret|credential|private[_ -]?key|bearer)")
PRIVATE_KEY_EXTENSIONS = {".pem", ".pfx", ".p12", ".p7b", ".p7c", ".key", ".keystore", ".kdbx", ".jks"}
DESCRIPTIVE_DOCUMENT_EXTENSIONS = {".md", ".markdown", ".rst"}
PARSER_VERSION = 9
PROJECT_PROFILE_VERSION = 21
_PROJECT_VALIDATION_HEADING_RE = re.compile(
    r"\b(?:tests?|testing|pruebas|validación|validation|verifications?|verificar|verificación|qa|test suite|suite de pruebas)\b",
    re.I,
)
_PROJECT_TEST_RUNNER_RE = re.compile(
    r"^\s*(?:(?:\$|>)\s*)?(?:"
    r"(?:python(?:\d+(?:\.\d+)*)?|py(?:\s+-\d+(?:\.\d+)*)?)\s+-m\s+(?:unittest|pytest)\b|"
    r"pytest(?:\d+(?:\.\d+)*)?\b|"
    r"(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?test\b|"
    r"(?:cargo|go|dotnet)\s+test\b|mvnw?\s+test\b|gradlew?\s+test\b)",
    re.I,
)
_PROJECT_DOCUMENT_PRIORITY = {
    "readme.md": 0, "architecture.md": 1,
    "architecture_decisions.md": 2, "decisions.md": 2, "decision_log.md": 2,
    "development_progress.md": 3, "development_status.md": 4,
    "changelog.md": 5, "test_results.md": 6, "testing.md": 7, "tests.md": 8,
    "task_backlog.md": 9, "todo.md": 10, "roadmap.md": 11,
}
DEFAULT_EXCLUDED_DIRS = {".git", ".hg", ".svn", "__pycache__"}
DEFAULT_EXCLUDED_DIRECTORY_SUFFIXES = (".egg-info", ".dist-info")
DOC_EXTENSIONS = {".md", ".markdown", ".rst", ".txt"}
DEPENDENCY_MANIFEST_NAMES = {"pyproject.toml", "package.json", "cargo.toml", "go.mod", "composer.json"}
TECH_BY_EXT = {
    ".py": "Python", ".pyw": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".rs": "Rust", ".go": "Go",
    ".java": "Java", ".kt": "Kotlin", ".cs": ".NET", ".php": "PHP",
    ".rb": "Ruby", ".ps1": "PowerShell", ".sql": "SQL", ".html": "HTML",
    ".css": "CSS", ".scss": "SCSS", ".vue": "Vue", ".svelte": "Svelte",
}
TECH_BY_NAME = {
    "pyproject.toml": "Python", "requirements.txt": "Python", "package.json": "Node.js",
    "package-lock.json": "Node.js", "pnpm-lock.yaml": "Node.js", "yarn.lock": "Node.js",
    "cargo.toml": "Rust", "cargo.lock": "Rust", "go.mod": "Go", "go.sum": "Go",
    "dockerfile": "Docker", "docker-compose.yml": "Docker", "docker-compose.yaml": "Docker",
    "terraform.tf": "Terraform", "terraform.tfvars": "Terraform",
}
_PROCESS_INDEX_LOCK = threading.Lock()


def _project_document_priority(relative: str) -> int | None:
    """Return a bounded selection priority for conventional project knowledge docs."""
    normalized = relative.replace("\\", "/").casefold()
    parts = normalized.split("/")
    name = parts[-1]
    if len(parts) == 1 and name in _PROJECT_DOCUMENT_PRIORITY:
        return _PROJECT_DOCUMENT_PRIORITY[name]
    if len(parts) == 2 and parts[0] in {"docs", "qa"} and name in _PROJECT_DOCUMENT_PRIORITY:
        return 10 + _PROJECT_DOCUMENT_PRIORITY[name]

    adr_directories = {"adr", "adrs", "decisions"}
    stem = Path(name).stem
    adr_named = bool(re.fullmatch(r"adr[-_ ]?\d{1,4}(?:[-_ ].*)?", stem))
    if len(parts) == 1 and adr_named:
        return 12
    if len(parts) == 2 and (
        parts[0] in adr_directories or (parts[0] in {"docs", "qa"} and adr_named)
    ):
        return 12
    if len(parts) == 3 and parts[0] in {"docs", "qa"} and parts[1] in adr_directories:
        return 12
    return None


_ARCHIVED_PROJECT_DOC_DIRS = frozenset({
    "archive", "archives", "archived", "old", "legacy", "deprecated", "obsolete",
    "history", "historical", "anterior", "backup", "backups", "attic",
})
_ARCHIVED_PROJECT_DOC_STEM = re.compile(
    r"(?:^|[._ -])(?:archived|archive|old|legacy|deprecated|obsolete|backup|bak)(?:$|[._ -])",
    re.I,
)


def _is_archived_project_document(relative: str) -> bool:
    """Keep archival docs searchable, but do not present them as current project evidence."""
    parts = [part.casefold() for part in relative.replace("\\", "/").split("/") if part]
    if any(part in _ARCHIVED_PROJECT_DOC_DIRS for part in parts[:-1]):
        return True
    return bool(parts and _ARCHIVED_PROJECT_DOC_STEM.search(Path(parts[-1]).stem))


@dataclass(frozen=True)
class SourceFile:
    kind: str
    root: Path
    path: Path
    relative_path: str
    project_name: str | None = None
    project_root_path: str | None = None


def _is_reparse_entry(entry: os.DirEntry[str]) -> bool:
    """Skip symlinks and Windows junction/mount-point reparse entries."""
    if entry.is_symlink():
        return True
    metadata = entry.stat(follow_symlinks=False)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)


def _is_reparse_path(path: Path) -> bool:
    return contains_reparse_component(path)


def _existing_source_directory(root: Path, relative_path: str) -> bool:
    """Check for an in-root directory without traversing a symlink/junction."""
    if _is_reparse_path(root):
        return False
    parts = relative_path.replace("\\", "/").split("/")
    if not parts or any(part in {"..", "."} for part in parts):
        return False
    current = root
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    try:
        for part in filter(None, parts):
            current = current / part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or (getattr(metadata, "st_file_attributes", 0) & reparse_flag):
                return False
            if not current.is_dir():
                return False
        return True
    except OSError:
        return False


def _existing_source_file(root: Path, relative_path: str) -> Path | None:
    """Return an existing in-root regular file without following reparse points."""
    if _is_reparse_path(root):
        return None
    parts = [part for part in relative_path.replace("\\", "/").split("/") if part]
    if not parts or any(part in {"..", "."} for part in parts):
        return None
    current = root
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    try:
        for index, part in enumerate(parts):
            current = current / part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or (getattr(metadata, "st_file_attributes", 0) & reparse_flag):
                return None
            final = index == len(parts) - 1
            if final:
                return current if stat.S_ISREG(metadata.st_mode) else None
            if not stat.S_ISDIR(metadata.st_mode):
                return None
    except OSError:
        return None
    return None


def _excluded_name(path: Path, exclude_names: set[str]) -> bool:
    name = path.name.casefold()
    if name in exclude_names:
        return True
    suffix = path.suffix.casefold()
    if suffix in PRIVATE_KEY_EXTENSIONS or PRIVATE_KEY_NAME_RE.match(path.name):
        return True
    return bool(SENSITIVE_NAME_RE.match(path.name) and suffix not in DESCRIPTIVE_DOCUMENT_EXTENSIONS)


def _excluded_directory(name: str, excluded_dirs: set[str]) -> bool:
    folded = name.casefold()
    return folded in excluded_dirs or folded.endswith(DEFAULT_EXCLUDED_DIRECTORY_SUFFIXES)


@contextmanager
def _index_lock(settings: Settings):
    """Serialize index and derived-link writes across CLI/dashboard processes."""
    timeout = float(settings.raw.get("index_lock_timeout_seconds", 30))
    if not _PROCESS_INDEX_LOCK.acquire(timeout=max(0.0, timeout)):
        raise TimeoutError("Another Rabanito index operation is still running.")
    lock_path = settings.data_dir / "index.lock"
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = lock_path.open("a+b")
        try:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            deadline = time.monotonic() + timeout
            while True:
                try:
                    handle.seek(0)
                    if os.name == "nt":
                        import msvcrt
                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"Index lock is busy: {lock_path}")
                    time.sleep(0.1)
            try:
                yield
            finally:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
    finally:
        _PROCESS_INDEX_LOCK.release()


def _iter_tree(
    root: Path, excluded_dirs: set[str], on_error=None,
    excluded_roots: set[str] | None = None,
) -> Iterator[Path]:
    if not root.exists() or not root.is_dir():
        return
    excluded_root_keys = excluded_roots or set()
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            entries = list(os.scandir(current))
        except OSError as exc:
            if on_error:
                on_error(exc)
            continue
        for entry in entries:
            try:
                entry_path = Path(entry.path)
                if _is_reparse_entry(entry):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if (path_key(entry_path) not in excluded_root_keys
                            and not _excluded_directory(entry.name, excluded_dirs)
                            and not _excluded_name(entry_path, set())):
                        pending.append(entry_path)
                elif entry.is_file(follow_symlinks=False):
                    yield entry_path
            except OSError as exc:
                if on_error:
                    on_error(exc)
                continue


def _has_vcs_marker(root: Path, on_error=None) -> bool:
    """Recognize common repository roots without reading marker contents."""
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    for name in (".git", ".hg", ".svn"):
        try:
            metadata = (root / name).lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            if on_error:
                on_error(exc)
            continue
        if getattr(metadata, "st_file_attributes", 0) & reparse_flag:
            continue
        if stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode):
            return True
    return False


def _nested_vcs_roots(root: Path, excluded_dirs: set[str], on_error=None) -> list[Path]:
    """Find nested repository roots without following symlinks/reparse points."""
    pending = [root]
    found: list[Path] = []
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as entries:
                children = list(entries)
        except OSError as exc:
            if on_error:
                on_error(exc)
            continue
        for entry in children:
            try:
                if (_is_reparse_entry(entry) or not entry.is_dir(follow_symlinks=False)
                        or _excluded_directory(entry.name, excluded_dirs)):
                    continue
                child = Path(entry.path)
                if _has_vcs_marker(child, on_error=on_error):
                    found.append(child)
                pending.append(child)
            except OSError as exc:
                if on_error:
                    on_error(exc)
    return found


def _policy(settings: Settings, kind: str) -> dict[str, Any]:
    return settings.policy(kind) or settings.policy("internal")


def _is_document_candidate(path: Path, policy: dict[str, Any]) -> bool:
    if _excluded_name(path, {str(name).casefold() for name in policy.get("exclude_names", [])}):
        return False
    extension = path.suffix.casefold()
    allowed = {str(item).casefold() for item in policy.get("extensions", [])}
    metadata_names = {str(item).casefold() for item in policy.get("metadata_names", [])}
    return extension in allowed or path.name.casefold() in metadata_names


def _relative(root: Path, path: Path) -> str:
    return safe_relative(path, root) or path.name


def _top_category(relative_path: str, fallback: str) -> str:
    parts = relative_path.replace("\\", "/").split("/", 1)
    return (parts[0] if len(parts) > 1 else fallback) or fallback


def _normalized_path_parts(relative_path: str) -> tuple[str, ...]:
    normalized = posixpath.normpath(relative_path.replace("\\", "/"))
    return tuple(
        unicodedata.normalize("NFC", part).casefold()
        for part in normalized.split("/") if part not in {"", ".", ".."}
    )


def _is_dependency_manifest(path: Path) -> bool:
    name = path.name.casefold()
    return (
        name in DEPENDENCY_MANIFEST_NAMES
        or bool(re.fullmatch(r"requirements(?:[-_.][a-z0-9_-]+)?\.txt", name))
        or path.suffix.casefold() == ".csproj"
    )


def _project_files(
    project_root: Path, policy: dict[str, Any], on_error=None,
    oversized_dependency_manifests: list[str] | None = None,
    excluded_project_roots: set[str] | None = None,
) -> list[Path]:
    excluded = {str(item).casefold() for item in policy.get("exclude_dirs", [])} | DEFAULT_EXCLUDED_DIRS
    excluded_names = {str(item).casefold() for item in policy.get("exclude_names", [])} | DEFAULT_EXCLUDED_DIRS
    excluded_extensions = {str(item).casefold() for item in policy.get("exclude_extensions", [])}
    max_metadata_bytes = max(1, int(policy.get("max_metadata_file_bytes", 2_097_152)))
    result: list[Path] = []
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    for path in _iter_tree(
        project_root, excluded, on_error=on_error, excluded_roots=excluded_project_roots,
    ):
        if _excluded_name(path, excluded_names) or path.suffix.casefold() in excluded_extensions:
            continue
        try:
            metadata = path.lstat()
        except OSError as exc:
            if on_error:
                on_error(exc)
            continue
        if (not stat.S_ISREG(metadata.st_mode)
                or getattr(metadata, "st_file_attributes", 0) & reparse_flag):
            continue
        if metadata.st_size > max_metadata_bytes:
            if oversized_dependency_manifests is not None and _is_dependency_manifest(path):
                relative = safe_relative(path, project_root)
                if relative is not None:
                    oversized_dependency_manifests.append(relative.replace("\\", "/"))
            continue
        result.append(path)
    return result


def _project_is_excluded(settings: Settings, root: Path) -> bool:
    return settings.is_project_excluded(root)


def _excluded_project_memory(settings: Settings, path: Path, project_statuses: dict[str, str] | None = None) -> bool:
    relative = safe_relative(path, settings.knowledge_root)
    parts = relative.split("/") if relative else []
    area = parts[0].casefold() if parts else ""
    if len(parts) < 3 or area not in {"projects", "decisions"}:
        return False
    if area == "projects" and path.name.casefold() != "project_memory.md":
        return False
    if area == "decisions" and path.suffix.casefold() != ".md":
        return False
    try:
        frontmatter, _ = parse_frontmatter(path.read_text(encoding="utf-8", errors="replace").splitlines()[:40])
    except OSError:
        return False
    project_name = str(frontmatter.get("project", "")).casefold()
    excluded_names = {
        str(value).strip().casefold()
        for value in settings.raw.get("excluded_projects", [])
        if str(value).strip() and not Path(str(value).strip()).is_absolute()
        and "/" not in str(value) and "\\" not in str(value)
    }
    if area == "projects":
        status_key = path_key(path)
    else:
        status_key = f"decision:{parts[1].casefold()}"
    status = (project_statuses or {}).get(status_key)
    return project_name in excluded_names or status in {"excluded", "missing"}


def _project_technology(files: list[Path]) -> list[str]:
    technologies: set[str] = set()
    for path in files:
        lower_name = path.name.casefold()
        if lower_name in TECH_BY_NAME:
            technologies.add(TECH_BY_NAME[lower_name])
        if path.suffix.casefold() in TECH_BY_EXT:
            technologies.add(TECH_BY_EXT[path.suffix.casefold()])
    return sorted(technologies)


DEPENDENCY_NAME_RE = re.compile(r"^(@?[A-Za-z0-9][A-Za-z0-9._/-]*)")


def _dependency_name(value: Any) -> str | None:
    candidate = str(value or "").strip()
    if not candidate or "://" in candidate or candidate.startswith((".", "/", "-")):
        return None
    match = DEPENDENCY_NAME_RE.match(candidate)
    if not match:
        return None
    name = match.group(1).rstrip("/.")
    if not name or name in {".", ".."} or len(name) > 160:
        return None
    return name


def _dependency_names_from_toml(relative: str, data: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    if Path(relative).name.casefold() == "pyproject.toml":
        build_system = data.get("build-system", {})
        if isinstance(build_system, dict) and isinstance(build_system.get("requires"), list):
            for value in build_system["requires"]:
                name = _dependency_name(value)
                if name and name.casefold() != "python":
                    names.add(name)
        project = data.get("project", {})
        if isinstance(project, dict):
            for value in project.get("dependencies", []) if isinstance(project.get("dependencies", []), list) else []:
                name = _dependency_name(value)
                if name and name.casefold() != "python":
                    names.add(name)
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for values in optional.values():
                    if isinstance(values, list):
                        for value in values:
                            name = _dependency_name(value)
                            if name and name.casefold() != "python":
                                names.add(name)
        poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool", {}), dict) else {}
        if isinstance(poetry, dict):
            dependency_tables = [poetry.get("dependencies", {})]
            groups = poetry.get("group", {})
            if isinstance(groups, dict):
                dependency_tables.extend(
                    group.get("dependencies", {}) for group in groups.values() if isinstance(group, dict)
                )
            for table in dependency_tables:
                if isinstance(table, dict):
                    names.update(
                        str(key) for key in table
                        if str(key).casefold() != "python" and _dependency_name(key)
                    )
        return names

    dependency_tables = {"dependencies", "dev-dependencies", "build-dependencies"}

    def walk(value: Any) -> None:
        if not isinstance(value, dict):
            return
        for key, item in value.items():
            if str(key).casefold() in dependency_tables and isinstance(item, dict):
                for name in item:
                    normalized = _dependency_name(name)
                    if normalized:
                        names.add(normalized)
            else:
                walk(item)

    walk(data)
    return names


def _project_dependencies(
    project_root: Path, files: list[Path], policy: dict[str, Any],
    oversized_manifests: list[str] | None = None,
) -> tuple[list[dict[str, Any]], bool, list[dict[str, str]]]:
    """Read dependency names only from bounded, declarative manifests; never execute tools."""
    max_bytes = max(1, int(policy.get("max_metadata_file_bytes", 2_097_152)))
    max_manifests = min(max(int(policy.get("max_project_dependency_manifests", 20)), 1), 100)
    max_dependencies = min(max(int(policy.get("max_project_dependencies", 500)), 1), 5000)
    candidates = [(path, False) for path in files if _is_dependency_manifest(path)]
    for relative in oversized_manifests or []:
        candidates.append((project_root / relative.replace("/", os.sep), True))
    candidates.sort(key=lambda item: (
        0 if item[0].parent == project_root else 1,
        item[0].name.casefold(),
        safe_relative(item[0], project_root) or item[0].name,
    ))
    truncated = len(candidates) > max_manifests
    candidates = candidates[:max_manifests]
    collected: dict[str, dict[str, Any]] = {}
    dependency_errors: list[dict[str, str]] = []

    def add(name: Any, relative: str) -> None:
        normalized = _dependency_name(name)
        if not normalized:
            return
        key = normalized.casefold()
        entry = collected.setdefault(key, {"name": normalized, "sources": set()})
        entry["sources"].add(relative.replace("\\", "/"))

    for candidate, known_oversized in candidates:
        relative = safe_relative(candidate, project_root)
        if relative is None:
            continue
        relative = relative.replace("\\", "/")
        if known_oversized:
            dependency_errors.append({"source": relative, "error_type": "FileTooLarge"})
            continue
        safe_path = _existing_source_file(project_root, relative)
        if safe_path is None:
            continue
        try:
            with safe_path.open("rb") as stream:
                raw_content = stream.read(max_bytes + 1)
            if len(raw_content) > max_bytes:
                dependency_errors.append({"source": relative, "error_type": "FileTooLarge"})
                continue
            content = raw_content.decode("utf-8-sig")
        except UnicodeDecodeError:
            dependency_errors.append({"source": relative, "error_type": "UnicodeDecodeError"})
            continue
        except OSError as exc:
            dependency_errors.append({"source": relative, "error_type": type(exc).__name__})
            continue
        lower_name = safe_path.name.casefold()
        try:
            if lower_name in {"pyproject.toml", "cargo.toml"}:
                parsed = tomllib.loads(content)
                for name in _dependency_names_from_toml(relative, parsed):
                    add(name, relative)
            elif lower_name in {"package.json", "composer.json"}:
                parsed_json = json.loads(content)
                sections = (
                    ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
                    if lower_name == "package.json" else ("require", "require-dev")
                )
                for section in sections:
                    table = parsed_json.get(section, {}) if isinstance(parsed_json, dict) else {}
                    if isinstance(table, dict):
                        for name in table:
                            if lower_name == "composer.json" and str(name).casefold() == "php":
                                continue
                            add(name, relative)
            elif lower_name == "go.mod":
                in_require_block = False
                for raw_line in content.splitlines():
                    line = raw_line.split("//", 1)[0].strip()
                    if not line:
                        continue
                    if line == "require (":
                        in_require_block = True
                        continue
                    if in_require_block and line == ")":
                        in_require_block = False
                        continue
                    if in_require_block:
                        add(line.split()[0], relative)
                    elif line.startswith("require "):
                        parts = line.split()
                        if len(parts) >= 3:
                            add(parts[1], relative)
            elif lower_name.endswith(".csproj"):
                if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", content, re.IGNORECASE):
                    raise ValueError("DTD declarations are not accepted in local project manifests")
                xml_root = ET.fromstring(content)
                for element in xml_root.iter():
                    if element.tag.rsplit("}", 1)[-1] == "PackageReference":
                        add(element.attrib.get("Include") or element.attrib.get("Update"), relative)
            else:
                for raw_line in content.splitlines():
                    line = raw_line.strip()
                    if not line or line.startswith(("#", "-", "--")):
                        continue
                    line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
                    name = _dependency_name(line)
                    if name:
                        add(name, relative)
        except (tomllib.TOMLDecodeError, json.JSONDecodeError, ET.ParseError, TypeError, ValueError,
                RecursionError, OverflowError) as exc:
            dependency_errors.append({"source": relative, "error_type": type(exc).__name__})
            continue

    ordered = sorted(collected.values(), key=lambda item: (str(item["name"]).casefold(), str(item["name"])))
    if len(ordered) > max_dependencies:
        truncated = True
        ordered = ordered[:max_dependencies]
    result = [
        {"name": item["name"], "sources": sorted(item["sources"], key=str.casefold)}
        for item in ordered
    ]
    dependency_errors.sort(key=lambda item: (item["source"].casefold(), item["source"], item["error_type"]))
    return result, truncated, dependency_errors


def _project_readme_overview(project_root: Path, docs: list[str]) -> dict[str, Any] | None:
    """Extract one small literal README paragraph with a physical line citation."""
    relative = next((item for item in docs if "/" not in item and Path(item).name.casefold() == "readme.md"), None)
    if not relative:
        return None
    path = _existing_source_file(project_root, relative)
    if path is None:
        return None
    try:
        if path.stat().st_size > 2_097_152:
            return None
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    _frontmatter, body_offset = parse_frontmatter(lines)
    start_at = body_offset
    paragraph: list[str] = []
    line_start = line_end = 0
    fenced = False
    for index in range(start_at, len(lines)):
        raw = lines[index]
        stripped = raw.strip()
        if stripped.startswith(("```", "~~~")):
            if paragraph:
                break
            fenced = not fenced
            continue
        if fenced:
            continue
        if not stripped:
            if paragraph:
                break
            continue
        is_block = stripped.startswith(("#", ">", "|", "- ", "* ", "+ ", "![", "<", "---", "***", "___")) or bool(re.match(r"^\d+[.)]\s", stripped))
        if is_block:
            if paragraph:
                break
            continue
        if not paragraph:
            line_start = index + 1
        paragraph.append(stripped)
        line_end = index + 1
        if sum(len(item) for item in paragraph) >= 600:
            break
    if not paragraph:
        return None
    literal = " ".join(paragraph)
    if literal.rstrip().endswith(":") or "`" in literal or re.search(r"!?\[[^\]]+\](?:\([^)]*\)|\[[^\]]*\])|(?:\*\*|__|~~)", literal):
        return None
    if re.search(
        r"(?i)\b(?:password|passwd|token|api[_ -]?key|secret|credential|private key|bearer)\b|"
        r"-----BEGIN|://[^/\s:@]+:[^/\s@]+@|\b[A-Za-z0-9_+/=-]{32,}\b",
        literal,
    ):
        return None
    literal = re.sub(r"\s+", " ", literal).strip()
    if len(literal) < 12:
        return None
    if len(literal) > 420:
        literal = literal[:417].rstrip() + "…"
    return {"text": literal, "relative_path": relative, "line_start": line_start, "line_end": line_end}


def _project_document_outline(
    project_root: Path, docs: list[str], max_bytes: int = 2_097_152,
) -> list[dict[str, Any]]:
    """Create a small citation-only map of headings in recognized project docs.

    The outline identifies where a source discusses a topic; it does not assert
    implementation status or summarize imported prose.
    """
    def rank(relative: str) -> tuple[int, str]:
        normalized = relative.replace("\\", "/").casefold()
        priority = _project_document_priority(relative)
        return (priority if priority is not None else 100), normalized

    candidates = [
        relative for relative in docs
        if Path(relative).suffix.casefold() in {".md", ".markdown"}
        and rank(relative)[0] < 100
    ]
    outline: list[dict[str, Any]] = []
    for relative in sorted(candidates, key=rank):
        path = _existing_source_file(project_root, relative)
        if path is None:
            continue
        try:
            if path.stat().st_size > max(1, max_bytes):
                continue
            lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        except OSError:
            continue
        _frontmatter, body_offset = parse_frontmatter(lines)
        headings: list[dict[str, Any]] = []
        fence_char: str | None = None
        for index in range(body_offset, len(lines)):
            raw = lines[index]
            stripped = raw.lstrip()
            fence = re.match(r"^(`{3,}|~{3,})", stripped)
            if fence:
                marker = fence.group(1)[0]
                if fence_char is None:
                    fence_char = marker
                elif marker == fence_char:
                    fence_char = None
                continue
            if fence_char is not None:
                continue
            match = re.match(r"^\s{0,3}(#{2,6})\s+(.+?)\s*#*\s*$", raw)
            if not match:
                continue
            title = re.sub(r"\s+", " ", match.group(2)).strip()
            title = re.sub(r"[`*_~]", "", title)
            if (
                not 2 <= len(title) <= 120
                or SENSITIVE_HEADING_RE.search(title)
                or re.search(r"-----BEGIN|\b[A-Za-z0-9_+/=-]{32,}\b", title)
            ):
                continue
            headings.append({"title": title, "line": index + 1})
            if len(headings) >= 8:
                break
        if headings:
            outline.append({"relative_path": relative.replace("\\", "/"), "headings": headings})
            if len(outline) >= 6:
                break
    return outline


def _normalize_project_excerpt_markdown(value: str) -> str | None:
    """Remove common inline Markdown presentation and link targets; fail closed on unsupported markup."""
    if re.search(r"<!--|<\s*/?\s*[A-Za-z][^>]*>", value):
        return None
    value = re.sub(r"!\[[^\]\n]*\]\([^()\n]*\)", " ", value)
    value = re.sub(r"(?<!!)\[([^\]\n]+)\]\([^()\n]*\)", r"\1", value)
    # Nested-parenthesis destinations are not parsed, so do not risk retaining part of one.
    if re.search(r"(?<!!)\[[^\]\n]+\]\(", value):
        return None
    value = re.sub(r"(?<!!)\[([^\]\n]+)\]\[[^\]\n]*\]", r"\1", value)
    value = re.sub(r"!\[[^\]\n]*\]\[[^\]\n]*\]", " ", value)
    value = re.sub(r"(?<!`)`+([^`\n]+?)`+(?!`)", r"\1", value)
    value = re.sub(r"(?<!\\)(\*\*|__|~~)(.+?)\1", r"\2", value)
    value = re.sub(r"(?<![\w\\])([*_])(\S(?:.*?\S)?)\1(?!\w)", r"\2", value)
    value = re.sub(r"\\([\\`*_{}\[\]()#+\-.!>])", r"\1", value)
    # Keep visible labels, never copy ordinary external URL targets.
    value = re.sub(r"https?://\S+", " ", value, flags=re.I)
    value = re.sub(r"\s+", " ", value).strip()
    if "`" in value or re.search(r"!?\[[^\]]+\](?:\([^)]*\)|\[[^]]*\])|(?:\*\*|__|~~)", value):
        return None
    return value


def _project_document_evidence(
    project_root: Path, docs: list[str], max_bytes: int = 2_097_152, max_items: int = 8,
    max_total_bytes: int = 8_388_608,
) -> list[dict[str, Any]]:
    """Extract short, cited passages under recognizable headings, normalizing common Markdown."""
    categories = [
        # Any explicit pending marker wins over status/decision/test words in
        # mixed headings (for example, "Implementation and validation pending").
        ("pending", re.compile(r"\b(?:pending|todo|backlog|roadmap|pendientes?|future work|next steps|próximos pasos)\b", re.I)),
        ("decisions", re.compile(r"\b(?:decisions?|technical decisions?|architecture decisions?|decision log|adr|decisiones?|decisiones técnicas?|decisiones arquitectónicas?|registro de decisiones|trade.?offs|alternatives considered)\b", re.I)),
        ("architecture", re.compile(r"\b(?:architecture|arquitectura|design|diseño|components?|componentes|data flow|flujo de datos|structure|estructura|data model|modelo de datos)\b", re.I)),
        ("features", re.compile(r"\b(?:features?|funcionalidades?|capabilities|capacidades|what it does|widgets?|controls?|controles|apis?|endpoints?|data sources|fuentes de datos|monitoring|monitoreo|reporting|reportes)\b", re.I)),
        ("status", re.compile(r"\b(?:status|estado|current state|estado actual|implementation|implementación|changelog|changes|cambios)\b", re.I)),
        ("tests", _PROJECT_VALIDATION_HEADING_RE),
        ("issues", re.compile(r"\b(?:known issues?|open issues?|problems?|bugs?|blockers?|limitations?|troubleshooting|problemas?|incidencias|bloqueos?|limitaciones|errores conocidos)\b", re.I)),
        ("solutions", re.compile(r"\b(?:solutions?|fixes?|workarounds?|mitigations?|resolutions?|soluciones|correcciones|arreglos|mitigaciones|resoluciones)\b", re.I)),
    ]
    def rank(relative: str) -> tuple[int, str]:
        normalized = relative.replace("\\", "/").casefold()
        priority = _project_document_priority(relative)
        return (priority if priority is not None else 50), normalized

    candidates = sorted(
        (item for item in docs if Path(item).suffix.casefold() in {".md", ".markdown"}
         and rank(item)[0] < 100 and not _is_archived_project_document(item)),
        key=rank,
    )
    selected: dict[str, list[dict[str, Any]]] = {}
    category_limits = {"features": 3}
    item_limit = min(max(1, max_items), 8)
    sensitive_excerpt = re.compile(
        r"(?i)\b(?:password|passwd|token|api[_ -]?key|secret|credential|private key|bearer|authorization)\b|"
        r"-----BEGIN|://[^/\s:@]+:[^/\s@]+@|\b[A-Za-z0-9_+/=-]{32,}\b|\b[A-Z]:[\\/]"
    )
    scanned_bytes = 0
    for relative in candidates[:60]:
        path = _existing_source_file(project_root, relative)
        if path is None:
            continue
        try:
            file_size = path.stat().st_size
            if file_size > max(1, max_bytes) or scanned_bytes + file_size > max(1, max_total_bytes):
                continue
            lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        except OSError:
            continue
        scanned_bytes += file_size
        _frontmatter, body_offset = parse_frontmatter(lines)
        fence_char: str | None = None
        for index in range(body_offset, len(lines)):
            raw = lines[index]
            stripped = raw.strip()
            fence = re.match(r"^(`{3,}|~{3,})", stripped)
            if fence:
                marker = fence.group(1)[0]
                fence_char = None if fence_char == marker else (marker if fence_char is None else fence_char)
                continue
            if fence_char is not None:
                continue
            heading = re.match(r"^\s{0,3}(#{2,6})\s+(.+?)\s*#*\s*$", raw)
            if not heading:
                continue
            title = re.sub(r"[\s`*_~]+", " ", heading.group(2)).strip()
            if SENSITIVE_HEADING_RE.search(title):
                continue
            category = next((name for name, pattern in categories if pattern.search(title)), None)
            if category is None or len(selected.get(category, [])) >= category_limits.get(category, 1):
                continue

            cursor = index + 1
            while cursor < len(lines):
                first = lines[cursor].strip()
                if not first:
                    cursor += 1
                    continue
                if re.match(r"^#{1,6}\s+", first):
                    break
                fence = re.match(r"^(`{3,}|~{3,})", first)
                if fence:
                    marker = fence.group(1)[0]
                    cursor += 1
                    while cursor < len(lines):
                        closing = re.match(r"^(`{3,}|~{3,})", lines[cursor].strip())
                        cursor += 1
                        if closing and closing.group(1)[0] == marker:
                            break
                    continue
                if first.startswith((">", "|", "<", "---", "***", "___")):
                    cursor += 1
                    continue

                line_start = cursor + 1
                list_item = bool(re.match(r"^(?:[-*+]\s+|\d+[.)]\s)", first))
                bullet_re = r"^(?:[-*+]\s+|\d+[.)]\s)"
                excerpt_lines = [re.sub(bullet_re, "", first) if list_item else first]
                line_end = cursor + 1
                cursor += 1
                if not list_item:
                    while cursor < len(lines):
                        current = lines[cursor].strip()
                        if (not current or re.match(r"^#{1,6}\s+", current)
                                or current.startswith(("```", "~~~", ">", "|", "<", "---", "***", "___"))
                                or re.match(bullet_re, current)):
                            break
                        excerpt_lines.append(current)
                        line_end = cursor + 1
                        cursor += 1
                        if sum(map(len, excerpt_lines)) >= 500:
                            break
                else:
                    while cursor < len(lines) and lines[cursor].startswith(("  ", "\t")):
                        continuation = lines[cursor].strip()
                        if not continuation:
                            break
                        if re.match(bullet_re, continuation):
                            continuation = re.sub(bullet_re, "", continuation)
                            child_checkbox = re.match(r"^\[([ xX])\]\s+", continuation)
                            if child_checkbox and (
                                child_checkbox.group(1).casefold() == "x" or category != "pending"
                            ):
                                cursor += 1
                                continue
                        excerpt_lines.append(continuation)
                        line_end = cursor + 1
                        cursor += 1
                        if sum(map(len, excerpt_lines)) >= 500:
                            break
                    # A feature heading often contains several sibling bullets. Preserve a
                    # bounded, cited run of that list instead of silently retaining only its
                    # first item (common in project READMEs describing widgets and controls).
                    if category == "features":
                        while cursor < len(lines):
                            sibling = cursor
                            while sibling < len(lines) and not lines[sibling].strip():
                                sibling += 1
                            if sibling >= len(lines) or not re.match(bullet_re, lines[sibling].strip()):
                                break
                            cursor = sibling
                            sibling_text = re.sub(bullet_re, "", lines[cursor].strip())
                            if re.match(r"^\[([ xX])\]\s+", sibling_text):
                                # Checked and unchecked checklist entries are not evidence of
                                # implemented features; skip their indented children as well.
                                cursor += 1
                                while cursor < len(lines) and lines[cursor].startswith(("  ", "\t")):
                                    cursor += 1
                                continue
                            excerpt_lines.append(sibling_text)
                            line_end = cursor + 1
                            cursor += 1
                            while cursor < len(lines) and lines[cursor].startswith(("  ", "\t")):
                                continuation = lines[cursor].strip()
                                if not continuation:
                                    break
                                if re.match(bullet_re, continuation):
                                    continuation = re.sub(bullet_re, "", continuation)
                                    if re.match(r"^\[([ xX])\]\s+", continuation):
                                        cursor += 1
                                        continue
                                excerpt_lines.append(continuation)
                                line_end = cursor + 1
                                cursor += 1
                                if sum(map(len, excerpt_lines)) >= 500:
                                    break
                            if sum(map(len, excerpt_lines)) >= 500:
                                break

                literal = re.sub(r"\s+", " ", " ".join(excerpt_lines)).strip()
                checkbox = re.match(r"^\[([ xX])\]\s+", literal)
                if checkbox and (checkbox.group(1).casefold() == "x" or category != "pending"):
                    continue
                if literal.endswith(":"):
                    continue
                if len(literal) < 28 or redact_sensitive_lines(literal) != literal or sensitive_excerpt.search(literal):
                    continue
                normalized = _normalize_project_excerpt_markdown(literal)
                if normalized is None or len(normalized) < 28:
                    continue
                literal = normalized
                if "`" in literal or re.search(r"!?\[[^\]]+\](?:\([^)]*\)|\[[^\]]*\])|(?:\*\*|__|~~)", literal):
                    continue
                if len(literal) > 500:
                    literal = literal[:497].rstrip() + "…"
                safe_relative = re.sub(r"[\r\n\t\x00-\x1f\x7f]", " ", relative.replace("\\", "/")).replace("`", "'")
                selected.setdefault(category, []).append({
                    "category": category, "heading": title.replace("`", "'"), "relative_path": safe_relative,
                    "line_start": line_start, "line_end": line_end, "text": literal,
                })
                break
            if sum(len(items) for items in selected.values()) >= item_limit:
                break
    return [
        item for name, _pattern in categories for item in selected.get(name, [])
    ]


def _project_document_validation_procedures(
    project_root: Path, docs: list[str], max_bytes: int = 2_097_152,
    max_items: int = 8, max_total_bytes: int = 8_388_608,
) -> list[dict[str, Any]]:
    """Cite documented test-runner invocations without retaining or executing commands."""
    def rank(relative: str) -> tuple[int, str]:
        normalized = relative.replace("\\", "/").casefold()
        priority = _project_document_priority(relative)
        return (priority if priority is not None else 100), normalized

    candidates = sorted(
        (item for item in docs if Path(item).suffix.casefold() in {".md", ".markdown"}
         and rank(item)[0] < 100 and not _is_archived_project_document(item)),
        key=rank,
    )
    procedures: list[dict[str, Any]] = []
    scanned_bytes = 0
    for relative in candidates[:60]:
        path = _existing_source_file(project_root, relative)
        if path is None:
            continue
        try:
            file_size = path.stat().st_size
            if file_size > max(1, max_bytes) or scanned_bytes + file_size > max(1, max_total_bytes):
                continue
            lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        except OSError:
            continue
        scanned_bytes += file_size
        _frontmatter, body_offset = parse_frontmatter(lines)
        in_validation_section = False
        section_title = ""
        index = body_offset
        while index < len(lines):
            raw = lines[index]
            heading = re.match(r"^\s{0,3}(#{2,6})\s+(.+?)\s*#*\s*$", raw)
            if heading:
                section_title = re.sub(r"[\s`*_~]+", " ", heading.group(2)).strip()
                in_validation_section = (
                    not SENSITIVE_HEADING_RE.search(section_title)
                    and bool(_PROJECT_VALIDATION_HEADING_RE.search(section_title))
                )
                index += 1
                continue
            if not in_validation_section:
                index += 1
                continue
            fence = re.match(r"^(`{3,}|~{3,})", raw.strip())
            if not fence:
                index += 1
                continue
            marker = fence.group(1)[0]
            cursor = index + 1
            command_line: int | None = None
            while cursor < len(lines):
                closing = re.match(r"^(`{3,}|~{3,})", lines[cursor].strip())
                if closing and closing.group(1)[0] == marker:
                    break
                if command_line is None and _PROJECT_TEST_RUNNER_RE.match(lines[cursor]):
                    command_line = cursor + 1
                cursor += 1
            if command_line is not None:
                safe_relative = re.sub(
                    r"[\r\n\t\x00-\x1f\x7f]", " ", relative.replace("\\", "/"),
                ).replace("`", "'")
                safe_heading = re.sub(r"[\r\n\t\x00-\x1f\x7f]", " ", section_title).replace("`", "'")
                procedures.append({
                    "relative_path": safe_relative, "heading": safe_heading,
                    "line_start": command_line, "line_end": command_line,
                })
                break
            index = min(len(lines), cursor + 1)
        if len(procedures) >= min(max(1, max_items), 8):
            break
    return procedures


def discover_projects(
    settings: Settings,
    db: Database,
    now: str | None = None,
    scan_state: dict[str, set[str]] | None = None,
) -> list[dict[str, Any]]:
    now = now or iso_now()
    root = settings.projects_root
    policy = settings.policy("projects")
    excluded = {str(item).casefold() for item in policy.get("exclude_dirs", [])} | DEFAULT_EXCLUDED_DIRS
    discovered: list[dict[str, Any]] = []
    if not root.exists() or _is_reparse_path(root):
        return discovered
    scan_complete = True
    try:
        with os.scandir(root) as entries:
            project_entries = list(entries)
    except OSError:
        if scan_state is not None:
            scan_state["failed_kinds"].add("projects")
        return discovered
    project_dirs: list[Path] = []
    for entry in project_entries:
        try:
            if not _is_reparse_entry(entry) and entry.is_dir(follow_symlinks=False) and not _excluded_directory(entry.name, excluded):
                project_dirs.append(Path(entry.path))
        except OSError:
            scan_complete = False
            if scan_state is not None:
                scan_state["failed_kinds"].add("projects")
    top_level_dirs = list(project_dirs)
    nested_scan_errors: list[OSError] = []
    for top_level_root in top_level_dirs:
        if _project_is_excluded(settings, top_level_root):
            continue
        project_dirs.extend(_nested_vcs_roots(
            top_level_root, excluded, on_error=nested_scan_errors.append,
        ))
    if nested_scan_errors:
        scan_complete = False
        if scan_state is not None:
            scan_state["failed_kinds"].add("projects")
    unique_project_dirs = {path_key(path): path for path in project_dirs}
    project_dirs = sorted(unique_project_dirs.values(), key=lambda item: (len(item.parts), path_key(item)))
    if scan_state is not None:
        scan_state["project_roots"] = {str(path) for path in project_dirs}
    for project_root in project_dirs:
        if _project_is_excluded(settings, project_root):
            db.execute("UPDATE projects SET status='excluded', last_seen=? WHERE path_key=?", (now, path_key(project_root)))
            continue
        project_scan_errors: list[OSError] = []
        oversized_manifests: list[str] = []
        nested_roots = {
            path_key(candidate) for candidate in project_dirs
            if path_key(candidate) != path_key(project_root)
            and safe_relative(candidate, project_root) is not None
        }
        files = _project_files(
            project_root, policy, on_error=project_scan_errors.append,
            oversized_dependency_manifests=oversized_manifests,
            excluded_project_roots=nested_roots,
        )
        if project_scan_errors:
            scan_complete = False
            if scan_state is not None:
                scan_state["failed_kinds"].add("projects")
            continue
        technologies = _project_technology(files)
        structure = sorted({path.relative_to(project_root).parts[0] for path in files if path != project_root})
        docs = sorted(
            str(path.relative_to(project_root)).replace(os.sep, "/")
            for path in files
            if _is_document_candidate(path, policy)
        )
        dependencies, dependencies_truncated, dependency_errors = _project_dependencies(
            project_root, files, policy, oversized_manifests,
        )
        row = db.one(
            "SELECT project_id, first_seen, technology_json, structure_json, documentation_json, dependencies_json, dependencies_truncated, dependency_errors_json "
            "FROM projects WHERE path_key=?", (path_key(project_root),),
        )
        first_seen = row["first_seen"] if row else now
        technology_json = json.dumps(technologies, ensure_ascii=False)
        structure_json = json.dumps(structure, ensure_ascii=False)
        documentation_json = json.dumps(docs, ensure_ascii=False)
        dependencies_json = json.dumps(dependencies, ensure_ascii=False, sort_keys=True)
        dependency_errors_json = json.dumps(dependency_errors, ensure_ascii=False, sort_keys=True)
        metadata_changed = not row or any(
            old != new
            for old, new in (
                (row["technology_json"], technology_json),
                (row["structure_json"], structure_json),
                (row["documentation_json"], documentation_json),
                (row["dependencies_json"], dependencies_json),
                (row["dependency_errors_json"], dependency_errors_json),
            )
        ) or bool(row and int(row["dependencies_truncated"]) != int(dependencies_truncated))
        if row:
            project_id = int(row["project_id"])
            if metadata_changed:
                db.execute(
                    """UPDATE projects SET name=?, technology_json=?, structure_json=?, documentation_json=?,
                       dependencies_json=?, dependencies_truncated=?, dependency_errors_json=?, last_seen=?, status='active' WHERE project_id=?""",
                    (project_root.name, technology_json, structure_json, documentation_json, dependencies_json,
                     int(dependencies_truncated), dependency_errors_json, now, project_id),
                )
            else:
                db.execute("UPDATE projects SET name=?, last_seen=?, status='active' WHERE project_id=?", (project_root.name, now, project_id))
        else:
            cursor = db.execute(
                """INSERT INTO projects(name, root_path, path_key, technology_json, structure_json, documentation_json,
                   dependencies_json, dependencies_truncated, dependency_errors_json, first_seen, last_seen)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (project_root.name, str(project_root), path_key(project_root), technology_json, structure_json,
                 documentation_json, dependencies_json, int(dependencies_truncated), dependency_errors_json, first_seen, now),
            )
            project_id = int(cursor.lastrowid)
        project_file_scan_failed = False
        for path in files:
            try:
                stat = path.stat()
            except OSError:
                project_file_scan_failed = True
                if scan_state is not None:
                    scan_state["failed_kinds"].add("projects")
                continue
            classification = "documentation" if _is_document_candidate(path, policy) else "structure-metadata"
            relative = str(path.relative_to(project_root)).replace(os.sep, "/")
            db.execute(
                """INSERT INTO project_files(project_id, relative_path, extension, classification, size_bytes, mtime_ns, last_seen)
                   VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(project_id, relative_path) DO UPDATE SET extension=excluded.extension, classification=excluded.classification,
                   size_bytes=excluded.size_bytes, mtime_ns=excluded.mtime_ns, last_seen=excluded.last_seen""",
                (project_id, relative, path.suffix.casefold(), classification, stat.st_size, stat.st_mtime_ns, now),
            )
        if not project_file_scan_failed:
            db.execute("DELETE FROM project_files WHERE project_id=? AND last_seen<>?", (project_id, now))
        else:
            scan_complete = False
            if scan_state is not None:
                scan_state["failed_kinds"].add("projects")
        memory_path = _project_memory_path(settings, project_root)
        overview = _project_readme_overview(project_root, docs)
        outline = _project_document_outline(
            project_root, docs, int(policy.get("max_metadata_file_bytes", 2_097_152)),
        )
        evidence = _project_document_evidence(
            project_root, docs, int(policy.get("max_metadata_file_bytes", 2_097_152)),
        )
        validation_procedures = _project_document_validation_procedures(
            project_root, docs, int(policy.get("max_metadata_file_bytes", 2_097_152)),
        )
        _write_project_memory(
            memory_path, project_root, technologies, structure, docs, now, overview, outline,
            dependencies, dependencies_truncated, dependency_errors, evidence=evidence,
            validation_procedures=validation_procedures,
        )
        discovered.append({
            "project_id": project_id, "name": project_root.name, "root": str(project_root),
            "technologies": technologies, "structure": structure, "documentation": docs,
            "dependencies": dependencies, "dependencies_truncated": dependencies_truncated,
            "dependency_errors": dependency_errors,
            "first_seen": first_seen, "last_seen": now,
        })
    if scan_complete:
        present = {path_key(project_root) for project_root in project_dirs}
        for row in db.query("SELECT project_id, path_key FROM projects WHERE status='active'"):
            if row["path_key"] not in present:
                db.execute("UPDATE projects SET status='missing' WHERE project_id=?", (row["project_id"],))
    db.commit()
    return discovered


def _project_memory_path(settings: Settings, project_root: Path) -> Path:
    projects_dir = settings.knowledge_root / "projects"
    slug = slugify(project_root.name)
    root_key = path_key(project_root)

    def belongs_to_project(path: Path) -> bool:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        routes = []
        for line in content.splitlines():
            if line.startswith("- Ruta: `") and line.endswith("`"):
                routes.append(path_key(Path(line[len("- Ruta: `"):-1])))
        return bool(routes) and all(route == root_key for route in routes)

    ordinary = projects_dir / slug / "PROJECT_MEMORY.md"
    if not ordinary.exists() or belongs_to_project(ordinary):
        return ordinary

    path_digest = sha256_text(root_key)
    for length in (8, 12, 16, 24, 32, 64):
        candidate = projects_dir / f"{slug}-{path_digest[:length]}" / "PROJECT_MEMORY.md"
        if not candidate.exists() or belongs_to_project(candidate):
            return candidate
    suffix = 2
    while True:
        candidate = projects_dir / f"{slug}-{path_digest}-{suffix}" / "PROJECT_MEMORY.md"
        if not candidate.exists() or belongs_to_project(candidate):
            return candidate
        suffix += 1


def _legacy_project_profile_prefix(text: str, project_name: str, observed_at: str | None = None) -> str | None:
    """Return only a legacy profile's frontmatter when its body is wholly generated.

    Unknown headings or free-form paragraphs make the profile user-authored for
    migration purposes, so they are preserved rather than replaced.
    """
    lines = text.splitlines()
    metadata, body_start = parse_frontmatter(lines)
    if (not body_start or metadata.get("kind") != "project-memory"
            or metadata.get("source_type") != "derived-metadata"
            or str(metadata.get("project", "")).casefold() != project_name.casefold()):
        return None

    body = [line.rstrip() for line in lines[body_start:]]
    while body and not body[0].strip():
        body.pop(0)
    body = body[:next((index for index, line in enumerate(body) if line.strip() == "<!-- RABANITO:GENERATED:START -->"), len(body))]
    while body and not body[-1].strip():
        body.pop()
    nonempty_body = [line for line in body if line.strip()]
    expected_headings = [
        "## Fuente", "## Tecnologías detectadas", "## Estructura observada",
        "## Documentación indexable", "## Pendiente de revisión humana",
    ]
    if len(nonempty_body) < 2 or nonempty_body[0] != f"# {project_name} — memoria observada":
        return None
    if nonempty_body[1] != "> Esta memoria se genera a partir de nombres, estructura y documentación seleccionada. No copia código fuente ni afirma decisiones que no estén documentadas.":
        return None
    headings = [line for line in body if line.startswith("## ")]
    if headings != expected_headings:
        return None
    heading_index = {heading: body.index(heading) for heading in expected_headings}
    sections = {
        heading: body[start + 1: (body.index(expected_headings[index + 1]) if index + 1 < len(expected_headings) else len(body))]
        for index, heading in enumerate(expected_headings)
        for start in [heading_index[heading]]
    }
    if not all(not line.strip() or line.startswith("- ") for line in sections["## Fuente"]):
        return None
    source_items = [line for line in sections["## Fuente"] if line.strip()]
    if len(source_items) != 2 or not source_items[0].startswith("- Ruta: `") or not source_items[1].startswith("- Observado: `"):
        return None
    technology_items = [line[2:] for line in sections["## Tecnologías detectadas"] if line.strip()]
    known_technologies = set(TECH_BY_EXT.values()) | set(TECH_BY_NAME.values()) | {"No concluyente"}
    if not technology_items or any(item not in known_technologies for item in technology_items):
        return None
    for heading in ("## Estructura observada", "## Documentación indexable"):
        items = [line for line in sections[heading] if line.strip()]
        path_items = [line for line in items if line not in {
            "- No se encontró documentación seleccionada", "- Sin elementos documentados",
        }]
        if any(not re.fullmatch(r"- `[^`]+`", line) for line in path_items):
            return None
    pending = [line for line in sections["## Pendiente de revisión humana"] if line.strip()]
    if pending != [
        "- Confirmar estado funcional y decisiones técnicas.",
        "- Añadir problemas, soluciones y tareas pendientes cuando estén documentados.",
    ]:
        return None
    separator = next((index for index in range(1, len(lines)) if lines[index].strip() == "---"), None)
    if separator is None:
        return None
    frontmatter = lines[:separator + 1]
    if not any(line.startswith("generated_version:") for line in frontmatter[1:separator]):
            frontmatter.insert(separator, f"generated_version: {PROJECT_PROFILE_VERSION}")
    if observed_at is not None:
        frontmatter = [f"observed_at: {observed_at}" if line.startswith("observed_at:") else line for line in frontmatter]
    return "\n".join(frontmatter) + "\n\n"


def _version_project_profile_prefix(
    prefix: str, observed_at: str, version: int = PROJECT_PROFILE_VERSION,
) -> str:
    lines = prefix.splitlines()
    _metadata, body_start = parse_frontmatter(lines)
    if not body_start:
        return prefix
    frontmatter = lines[:body_start]
    closing = body_start - 1
    found_version = False
    found_observed = False
    for index in range(1, closing):
        if frontmatter[index].startswith("generated_version:"):
            frontmatter[index] = f"generated_version: {version}"
            found_version = True
        elif frontmatter[index].startswith("observed_at:"):
            frontmatter[index] = f"observed_at: {observed_at}"
            found_observed = True
    if not found_version:
        frontmatter.insert(closing, f"generated_version: {version}")
        closing += 1
    if not found_observed:
        frontmatter.insert(closing, f"observed_at: {observed_at}")
    return "\n".join(frontmatter + lines[body_start:]).rstrip("\n") + "\n"


def _write_project_memory(
    path: Path, project_root: Path, technologies: list[str], structure: list[str], docs: list[str],
    observed_at: str, overview: dict[str, Any] | None = None,
    outline: list[dict[str, Any]] | None = None,
    dependencies: list[dict[str, Any]] | None = None, dependencies_truncated: bool = False,
    dependency_errors: list[dict[str, str]] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    validation_procedures: list[dict[str, Any]] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    limited_docs = docs[:200]
    start_marker = "<!-- RABANITO:GENERATED:START -->"
    end_marker = "<!-- RABANITO:GENERATED:END -->"
    body_lines = [
        start_marker, f"# {project_root.name} — memoria observada", "",
        "> Esta memoria se genera a partir de nombres, estructura y documentación seleccionada. No copia código fuente ni afirma decisiones que no estén documentadas.", "",
        "## Fuente", "", f"- Ruta: `{project_root}`", f"- Observado: `{observed_at}`", "",
        "## Tecnologías detectadas", "",
    ]
    if technologies:
        body_lines.extend(f"- {item}" for item in technologies)
    else:
        body_lines.append("- No concluyente")
    body_lines.extend(["", "## Estructura observada", ""])
    if structure:
        body_lines.extend(f"- `{item}`" for item in structure[:100])
    else:
        body_lines.append("- Sin elementos documentados")
    body_lines.extend(["", "## Documentación indexable", ""])
    if limited_docs:
        body_lines.extend(
            f"- `{item}`" + (
                " — ruta histórica; se conserva indexada, pero no se usa como evidencia vigente."
                if _is_archived_project_document(item) else ""
            )
            for item in limited_docs
        )
    else:
        body_lines.append("- No se encontró documentación seleccionada")
    if len(docs) > len(limited_docs):
        body_lines.append(f"- … y {len(docs) - len(limited_docs)} archivos más")
    body_lines.extend([
        "", "## Dependencias declaradas", "",
        "> Nombres extraídos de manifiestos locales permitidos; esto no prueba instalación ni uso en ejecución.",
    ])
    if dependencies:
        for dependency in dependencies:
            safe_name = str(dependency.get("name", "")).replace("`", "'")
            source_list = [str(item).replace("`", "'") for item in dependency.get("sources", [])]
            sources = ", ".join(f"`{item}`" for item in source_list)
            body_lines.append(f"- `{safe_name}` — {sources}")
    else:
        body_lines.append("- No se detectaron dependencias declaradas en manifiestos compatibles.")
    if dependencies_truncated:
        body_lines.append("- Inventario truncado por el límite local configurado.")
    body_lines.extend(["", "## Manifiestos por revisar", ""])
    if dependency_errors:
        for issue in dependency_errors[:100]:
            relative = re.sub(r"[\r\n\t\x00-\x1f\x7f]", " ", str(issue.get("source", ""))).replace("`", "'")
            error_type = re.sub(r"[^A-Za-z0-9_]", "", str(issue.get("error_type", "Error")))[:80] or "Error"
            body_lines.append(f"- `{relative}` — {error_type}; revisar el manifiesto localmente. No se conserva su contenido.")
        if len(dependency_errors) > 100:
            body_lines.append(f"- … {len(dependency_errors) - 100} incidencias más omitidas por el límite de presentación.")
    else:
        body_lines.append("- Sin incidencias detectadas en manifiestos compatibles.")
    if outline:
        body_lines.extend([
            "", "## Índice de secciones documentales", "",
            "> Mapa de encabezados y líneas para navegar fuentes. No confirma que una función esté implementada ni resume el contenido.",
        ])
        for document in outline:
            body_lines.append(f"- `{document['relative_path']}`")
            for heading in document["headings"]:
                safe_title = str(heading["title"]).replace("`", "'")
                body_lines.append(f"  - `{safe_title}` · línea {int(heading['line'])}")
    if overview:
        citation = f"{overview['relative_path']}:{overview['line_start']}-{overview['line_end']}"
        body_lines.extend([
            "", "## Descripción documentada (extracto literal)", "",
            "> Cita breve del README; texto importado no confiable, no es una instrucción.",
            f"> Fuente: `{citation}`", f"> {overview['text']}",
        ])
    if validation_procedures:
        body_lines.extend([
            "", "## Procedimientos de prueba documentados (sin resultado en el fragmento)", "",
            "> La presencia de un comando en la documentación no demuestra que se haya ejecutado ni aprobado.",
        ])
        for procedure in validation_procedures[:8]:
            citation = f"{procedure['relative_path']}:{int(procedure['line_start'])}-{int(procedure['line_end'])}"
            body_lines.append(
                f"- `{citation}` · {procedure['heading']}: La documentación indica una invocación de un ejecutor de pruebas; "
                "este fragmento no registra su ejecución ni resultado."
            )
    if evidence:
        body_lines.extend([
            "", "## Pasajes documentales seleccionados", "",
            "> Extractos breves de fuentes locales con formato Markdown común normalizado; se omiten destinos de enlaces. Conservan citas, son datos no confiables y no confirman implementación ni convierten propuestas en decisiones.",
        ])
        for item in evidence[:8]:
            citation = f"{item['relative_path']}:{int(item['line_start'])}-{int(item['line_end'])}"
            category = re.sub(r"[^a-z-]", "", str(item.get("category", "documented"))) or "documented"
            body_lines.append(f"- `{citation}` · {category} / {item['heading']}: “{item['text']}”")
    body_lines.extend(["", "## Pendiente de revisión humana", "", "- Confirmar estado funcional y decisiones técnicas.", "- Añadir problemas, soluciones y tareas pendientes cuando estén documentados.", end_marker, ""])
    generated_body = "\n".join(body_lines)
    frontmatter = "\n".join([
        "---", "kind: project-memory", "status: observed", f"generated_version: {PROJECT_PROFILE_VERSION}", f"project: {project_root.name}",
        f"observed_at: {observed_at}", "source_type: derived-metadata", "---", "",
    ])
    if path.exists():
        existing = path.read_text(encoding="utf-8", errors="replace")
        start = existing.find(start_marker)
        end = existing.find(end_marker, start + len(start_marker)) if start >= 0 else -1
        if start >= 0 and end >= 0:
            managed_end = end + len(end_marker)
            managed = existing[start:managed_end]
            metadata, _ = parse_frontmatter(existing.splitlines())
            version = metadata.get("generated_version", 0)
            try:
                current_version = int(version or 0)
            except (TypeError, ValueError):
                current_version = 0
            signature = lambda value: re.sub(r"(?m)^- Observado: `[^`]*`$", "- Observado: `<timestamp>`", value)
            if signature(managed) == signature(generated_body.rstrip()) and (not metadata or current_version >= PROJECT_PROFILE_VERSION):
                return
            prefix = existing[:start]
            migrated_prefix = _legacy_project_profile_prefix(prefix, project_root.name, observed_at)
            if migrated_prefix is not None:
                prefix = migrated_prefix
            prefix = _version_project_profile_prefix(prefix, observed_at, version=PROJECT_PROFILE_VERSION)
            updated = prefix + generated_body.rstrip() + existing[managed_end:]
        elif (migrated_prefix := _legacy_project_profile_prefix(existing, project_root.name, observed_at)) is not None:
            updated = migrated_prefix + generated_body
        else:
            # Preserve legacy/user-authored content verbatim on first managed refresh.
            updated = existing.rstrip() + "\n\n" + generated_body.replace(
                f"# {project_root.name} — memoria observada", f"## Metadatos observados — {project_root.name}", 1
            )
    else:
        updated = frontmatter + generated_body
    write_text_atomic(path, updated)


def iter_source_files(
    settings: Settings,
    project_info: list[dict[str, Any]],
    scan_state: dict[str, set[str]] | None = None,
    project_statuses: dict[str, str] | None = None,
) -> Iterator[SourceFile]:
    scan_state = scan_state if scan_state is not None else {"scanned_kinds": set(), "failed_kinds": set()}
    project_profile_bindings: dict[str, tuple[str, str]] = {}
    decision_prefix_bindings: list[tuple[str, str, str]] = []
    for project in project_info:
        project_root = Path(project["root"])
        project_name = str(project["name"])
        project_root_path = str(project_root)
        profile = _project_memory_path(settings, project_root)
        project_profile_bindings[path_key(profile)] = (project_name, project_root_path)
        decision_folder = f"{slugify(project_name)}-{sha256_text(path_key(project_root))[:8]}"
        decision_prefix_bindings.append((f"decisions/{decision_folder}".casefold(), project_name, project_root_path))
    for kind, root, name in settings.source_roots():
        try:
            if _is_reparse_path(root) or not root.is_dir():
                scan_state["failed_kinds"].add(kind)
                continue
            with os.scandir(root) as root_entries:
                next(root_entries, None)
            scan_state["scanned_kinds"].add(kind)
        except OSError:
            scan_state["failed_kinds"].add(kind)
            continue
        if kind == "projects":
            known_roots = {
                Path(candidate) for candidate in scan_state.get("project_roots", set())
            } or {Path(project["root"]) for project in project_info}
            for project in project_info:
                project_root = Path(project["root"])
                policy = settings.policy("projects")
                nested_roots = {
                    path_key(candidate) for candidate in known_roots
                    if path_key(candidate) != path_key(project_root)
                    and safe_relative(candidate, project_root) is not None
                }
                for path in _project_files(
                    project_root, policy,
                    on_error=lambda _exc, k=kind: scan_state["failed_kinds"].add(k),
                    excluded_project_roots=nested_roots,
                ):
                    if _is_document_candidate(path, policy):
                        yield SourceFile(
                            "projects", project_root, path, _relative(project_root, path),
                            project["name"], str(project_root),
                        )
            continue
        policy = _policy(settings, kind)
        excluded = {str(item).casefold() for item in policy.get("exclude_dirs", [])} | DEFAULT_EXCLUDED_DIRS
        for path in _iter_tree(root, excluded, on_error=lambda _exc, k=kind: scan_state["failed_kinds"].add(k)):
            if kind == "internal" and _excluded_project_memory(settings, path, project_statuses):
                continue
            if _is_document_candidate(path, policy):
                relative = _relative(root, path)
                associated_name = name
                associated_root = None
                if kind == "internal":
                    association = project_profile_bindings.get(path_key(path))
                    if association is None:
                        normalized_relative = relative.replace("\\", "/").casefold()
                        association = next(
                            ((project_name, project_root_path) for prefix, project_name, project_root_path in decision_prefix_bindings
                             if normalized_relative.startswith(prefix + "/")),
                            None,
                        )
                    if association is not None:
                        associated_name, associated_root = association
                yield SourceFile(kind, root, path, relative, associated_name, associated_root)


def _category(source: SourceFile, parsed: ParsedDocument) -> str:
    explicit = parsed.frontmatter.get("category")
    if explicit:
        return str(explicit)
    if source.kind == "projects":
        return f"projects/{source.project_name or source.root.name}"
    return _top_category(source.relative_path, source.kind)


def _upsert_document(db: Database, source: SourceFile, parsed: ParsedDocument, now: str, stat: os.stat_result) -> int:
    existing = db.one("SELECT document_id FROM documents WHERE path_key=?", (path_key(source.path),))
    fields = (
        source.kind, str(source.root), source.project_name, source.project_root_path,
        source.relative_path, str(source.path), path_key(source.path),
        parsed.title, _category(source, parsed), json.dumps(parsed.frontmatter, ensure_ascii=False, sort_keys=True),
        json.dumps(parsed.tags, ensure_ascii=False), parsed.content_hash, stat.st_size, stat.st_mtime_ns,
        __import__("datetime").datetime.fromtimestamp(stat.st_mtime, __import__("datetime").timezone.utc).isoformat(timespec="seconds"), now, now, "active", parsed.parse_error,
    )
    if existing:
        document_id = int(existing["document_id"])
        db.execute(
            """UPDATE documents SET source_kind=?, source_root=?, project_name=?, project_root_path=?, relative_path=?, absolute_path=?, path_key=?, title=?, category=?,
               frontmatter_json=?, tags_json=?, content_hash=?, size_bytes=?, mtime_ns=?, mtime_iso=?, indexed_at=?, last_seen_scan=?, status=?, parse_error=?
               WHERE document_id=?""",
            fields + (document_id,),
        )
        db.execute("DELETE FROM documents_fts WHERE document_id=?", (str(document_id),))
        old_chunks = db.query("SELECT chunk_id FROM document_chunks WHERE document_id=?", (document_id,))
        for row in old_chunks:
            db.execute("DELETE FROM chunks_fts WHERE chunk_id=?", (str(row["chunk_id"]),))
        db.execute("DELETE FROM document_chunks WHERE document_id=?", (document_id,))
        db.execute("DELETE FROM tags WHERE document_id=?", (document_id,))
        db.execute("DELETE FROM links WHERE source_document_id=?", (document_id,))
    else:
        cursor = db.execute(
            """INSERT INTO documents(source_kind, source_root, project_name, project_root_path, relative_path, absolute_path, path_key, title, category,
               frontmatter_json, tags_json, content_hash, size_bytes, mtime_ns, mtime_iso, indexed_at, last_seen_scan, status, parse_error)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            fields,
        )
        document_id = int(cursor.lastrowid)
    db.execute(
        "INSERT INTO documents_fts(document_id, title, tags, body) VALUES(?,?,?,?)",
        (str(document_id), parsed.title, " ".join(parsed.tags), parsed.text),
    )
    for tag in parsed.tags:
        db.execute("INSERT OR IGNORE INTO tags(document_id, tag) VALUES(?,?)", (document_id, tag))
    for chunk in parsed.chunks:
        cursor = db.execute(
            """INSERT INTO document_chunks(document_id, heading, line_start, line_end, text, text_hash) VALUES(?,?,?,?,?,?)""",
            (document_id, chunk["heading"], chunk["line_start"], chunk["line_end"], chunk["text"], sha256_text(chunk["text"])),
        )
        chunk_id = int(cursor.lastrowid)
        db.execute("INSERT INTO chunks_fts(chunk_id, document_id, heading, text) VALUES(?,?,?,?)", (str(chunk_id), str(document_id), chunk["heading"], chunk["text"]))
    for link in parsed.links:
        db.execute(
            "INSERT OR IGNORE INTO links(source_document_id, target_raw, label, line_number, relation_type) VALUES(?,?,?,?,?)",
            (document_id, link["target_raw"], link.get("label"), link.get("line_number"), link.get("relation_type", "wikilink")),
        )
    return document_id


def _inactive_search_payload_summary(connection: sqlite3.Connection, inactive_ids: list[int]) -> dict[str, int]:
    summary = {
        "inactive_documents": len(inactive_ids),
        "documents_with_payload": 0,
        "documents_fts_rows": 0,
        "document_chunks_rows": 0,
        "chunks_fts_rows": 0,
    }
    documents_with_payload: set[int] = set()
    for offset in range(0, len(inactive_ids), 400):
        batch = inactive_ids[offset:offset + 400]
        placeholders = ",".join("?" for _ in batch)
        text_ids = [str(document_id) for document_id in batch]
        doc_fts = connection.execute(
            f"SELECT DISTINCT document_id FROM documents_fts WHERE document_id IN ({placeholders})", text_ids,
        ).fetchall()
        chunks = connection.execute(
            f"SELECT DISTINCT document_id FROM document_chunks WHERE document_id IN ({placeholders})", batch,
        ).fetchall()
        chunk_fts = connection.execute(
            f"SELECT DISTINCT document_id FROM chunks_fts WHERE document_id IN ({placeholders})", text_ids,
        ).fetchall()
        summary["documents_fts_rows"] += int(connection.execute(
            f"SELECT COUNT(*) AS c FROM documents_fts WHERE document_id IN ({placeholders})", text_ids,
        ).fetchone()["c"])
        summary["document_chunks_rows"] += int(connection.execute(
            f"SELECT COUNT(*) AS c FROM document_chunks WHERE document_id IN ({placeholders})", batch,
        ).fetchone()["c"])
        summary["chunks_fts_rows"] += int(connection.execute(
            f"SELECT COUNT(*) AS c FROM chunks_fts WHERE document_id IN ({placeholders})", text_ids,
        ).fetchone()["c"])
        documents_with_payload.update(int(row["document_id"]) for row in doc_fts)
        documents_with_payload.update(int(row["document_id"]) for row in chunks)
        documents_with_payload.update(int(row["document_id"]) for row in chunk_fts)
    summary["documents_with_payload"] = len(documents_with_payload)
    return summary


def _purge_inactive_search_payload(connection: sqlite3.Connection, inactive_ids: list[int]) -> None:
    """Delete only derived FTS/chunk rows for explicitly selected inactive records."""
    for offset in range(0, len(inactive_ids), 400):
        batch = inactive_ids[offset:offset + 400]
        placeholders = ",".join("?" for _ in batch)
        text_ids = [str(document_id) for document_id in batch]
        connection.execute(f"DELETE FROM documents_fts WHERE document_id IN ({placeholders})", text_ids)
        connection.execute(f"DELETE FROM chunks_fts WHERE document_id IN ({placeholders})", text_ids)
        connection.execute(f"DELETE FROM document_chunks WHERE document_id IN ({placeholders})", batch)


def _record_document_change(
    db: Database, scan_id: int, document_id: int, change_type: str, reason: str, occurred_at: str,
) -> None:
    """Persist a metadata-only change event in the same transaction as its scan."""
    db.execute(
        """INSERT OR IGNORE INTO document_changes(scan_id,document_id,change_type,reason,occurred_at)
           VALUES(?,?,?,?,?)""",
        (scan_id, document_id, change_type, reason, occurred_at),
    )


def _resolve_links(db: Database) -> None:
    documents = db.query("SELECT * FROM documents WHERE status='active'")
    by_rel: dict[tuple[str, str], list[Any]] = {}
    by_path_suffix: dict[tuple[str, tuple[str, ...]], list[Any]] = {}
    by_stem: dict[tuple[str, str], list[Any]] = {}
    by_title: dict[tuple[str, str], list[Any]] = {}
    by_alias: dict[tuple[str, str], list[Any]] = {}
    for doc in documents:
        root_key = path_key(str(doc["source_root"]))
        rel = str(doc["relative_path"]).replace("\\", "/")
        rel_no_ext = str(Path(rel).with_suffix("")).replace("\\", "/")
        by_rel.setdefault((root_key, rel_no_ext.casefold()), []).append(doc)
        path_parts = _normalized_path_parts(rel_no_ext)
        for start in range(max(0, len(path_parts) - 1)):
            by_path_suffix.setdefault((root_key, path_parts[start:]), []).append(doc)
        by_stem.setdefault((root_key, Path(rel).stem.casefold()), []).append(doc)
        by_title.setdefault((root_key, str(doc["title"]).casefold()), []).append(doc)
        try:
            frontmatter = json.loads(doc["frontmatter_json"])
        except json.JSONDecodeError:
            frontmatter = {}
        aliases = frontmatter.get("aliases", [])
        if not isinstance(aliases, list):
            aliases = [aliases]
        for alias in aliases:
            by_alias.setdefault((root_key, str(alias).casefold()), []).append(doc)
    for link in db.query("SELECT * FROM links"):
        source = db.one("SELECT * FROM documents WHERE document_id=?", (link["source_document_id"],))
        if not source or source["status"] != "active":
            continue
        root_key = path_key(str(source["source_root"]))
        original = unquote(str(link["target_raw"]).strip()).replace("\\", "/")
        target = original.split("#", 1)[0].strip()
        scheme = urlsplit(target).scheme
        placeholder = target.casefold().strip(" /")
        if not target:
            status, reason, target_id, guess = "ignored", "empty_or_heading_only", None, target
        elif scheme or target.startswith("//"):
            status, reason, target_id, guess = "external", "external_reference", None, target
        elif placeholder in {"...", "page", "links", "cree un enlace", "wiki/category/page-name", "wiki/category/related-page"} or "..." in placeholder:
            status, reason, target_id, guess = "ignored", "intentional_placeholder", None, target
        elif re.match(r"^[a-z]:", target, re.IGNORECASE):
            status, reason, target_id, guess = "broken", "invalid_absolute_path", None, target
        else:
            status, target_id, guess = "unresolved", None, target
            root_target = target.lstrip("/")
            suffix = Path(root_target).suffix.casefold()
            if suffix and suffix not in {".md", ".markdown"}:
                status, reason, target_id, guess = "attachment", "non_markdown_reference_not_indexed", None, root_target
            else:
                without_ext = root_target[:-len(suffix)] if suffix in {".md", ".markdown"} else root_target
                parent = posixpath.dirname(str(source["relative_path"]).replace("\\", "/"))
                root_absolute = target.startswith("/")
                root_candidate = posixpath.normpath(without_ext.lstrip("/"))
                relative_candidate = posixpath.normpath(posixpath.join(parent, without_ext))
                escaped = ((root_candidate == ".." or root_candidate.startswith("../")) if root_absolute
                           else (relative_candidate == ".." or relative_candidate.startswith("../")))
                if escaped:
                    status, reason, target_id, guess = "broken", "path_escapes_source_root", None, target
                else:
                    exact = by_rel.get((root_key, root_candidate.casefold()), [])
                    if not exact and not root_absolute and relative_candidate != root_candidate:
                        exact = by_rel.get((root_key, relative_candidate.casefold()), [])
                    if exact:
                        candidates = exact
                        reason = "relative_path_match" if relative_candidate != root_candidate else "root_path_match"
                    elif "/" in without_ext or without_ext in {".", ".."}:
                        file_candidates = [] if without_ext.endswith("/") else [root_candidate]
                        if not without_ext.endswith("/") and not root_absolute and relative_candidate != root_candidate:
                            file_candidates.append(relative_candidate)
                        existing_file = next((candidate for candidate in file_candidates
                                              if _existing_source_file(Path(source["source_root"]), candidate)), None)
                        directory_candidates = [root_candidate]
                        if not root_absolute and relative_candidate != root_candidate:
                            directory_candidates.append(relative_candidate)
                        existing_directory = next((candidate for candidate in directory_candidates
                                                   if _existing_source_directory(Path(source["source_root"]), candidate)), None)
                        candidates = []
                        if existing_file is not None:
                            status, reason, target_id, guess = "attachment", "existing_non_markdown_file_not_indexed", None, existing_file
                        elif existing_directory is not None:
                            status, reason, target_id, guess = "directory", "existing_directory_not_document", None, existing_directory
                        else:
                            suffix_key = _normalized_path_parts(without_ext)
                            suffix_matches = (
                                by_path_suffix.get((root_key, suffix_key), [])
                                if not target.endswith("/") and ".." not in without_ext.split("/") and len(suffix_key) >= 2
                                else []
                            )
                            candidates = suffix_matches
                            reason = "suffix_path_match" if candidates else "missing_path"
                    else:
                        candidates = (by_stem.get((root_key, without_ext.casefold()), [])
                                      or by_title.get((root_key, without_ext.casefold()), [])
                                      or by_alias.get((root_key, without_ext.casefold()), []))
                        reason = "title_or_alias_match"
                    unique = {int(item["document_id"]): item for item in candidates}
                    candidates = list(unique.values())
                    if status in {"directory", "attachment"}:
                        pass
                    elif len(candidates) == 1:
                        status, target_id, guess = "resolved", int(candidates[0]["document_id"]), candidates[0]["relative_path"]
                    elif len(candidates) > 1:
                        ambiguity_reason = "multiple_suffix_path_matches" if reason == "suffix_path_match" else "multiple_candidates"
                        status, reason, target_id = "ambiguous", ambiguity_reason, None
                        guess = "; ".join(str(item["relative_path"]) for item in candidates[:5])
                    elif len(candidates) == 0:
                        reason = "missing_path" if "/" in without_ext else "missing_document"
                        status, target_id, guess = "broken", None, target
        db.execute(
            "UPDATE links SET target_document_id=?, status=?, target_path_guess=?, resolution_reason=? WHERE link_id=?",
            (target_id, status, guess, reason, link["link_id"]),
        )


def _index_all_locked(settings: Settings, force: bool = False) -> dict[str, Any]:
    # Scan markers need sub-second uniqueness so rapid successive CLI calls can
    # still detect a deletion reliably.
    started = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    started_clock = time.perf_counter()
    stats: dict[str, Any] = {
        "started_at": started, "status": "running", "files_seen": 0, "added": 0, "modified": 0,
        "unchanged": 0, "removed": 0, "skipped": 0, "errors": 0, "source_summary": {},
    }
    with Database(settings.database_path) as db:
        parser_version = db.one("SELECT value FROM meta WHERE key='parser_version'")
        reparse_for_parser_update = not parser_version or str(parser_version["value"]) != str(PARSER_VERSION)
        effective_force = force or reparse_for_parser_update
        scan_state = {"scanned_kinds": set(), "failed_kinds": set()}
        project_info = discover_projects(settings, db, started, scan_state)
        project_statuses: dict[str, str] = {}
        for row in db.query("SELECT name, root_path, status FROM projects"):
            project_root = Path(row["root_path"])
            status = str(row["status"])
            project_statuses[path_key(_project_memory_path(settings, project_root))] = status
            decision_folder = f"{slugify(str(row['name']))}-{sha256_text(path_key(project_root))[:8]}"
            project_statuses[f"decision:{decision_folder.casefold()}"] = status
        scan_id = int(db.execute("INSERT INTO scan_runs(started_at, status) VALUES(?,?)", (started, "running")).lastrowid)
        for source in iter_source_files(settings, project_info, scan_state, project_statuses):
            stats["files_seen"] += 1
            source_summary = stats["source_summary"].setdefault(source.kind, {"seen": 0, "added": 0, "modified": 0, "unchanged": 0, "skipped": 0, "errors": 0})
            source_summary["seen"] += 1
            try:
                stat = source.path.stat()
                key = path_key(source.path)
                existing = db.one(
                    "SELECT document_id, size_bytes, mtime_ns, content_hash, status, project_name, project_root_path "
                    "FROM documents WHERE path_key=?", (key,),
                )
                max_bytes = max(1, int(settings.policy(source.kind).get("max_file_bytes", settings.raw.get("max_document_bytes", 2_097_152))))
                if stat.st_size > max_bytes:
                    stats["skipped"] += 1
                    source_summary["skipped"] += 1
                    if existing:
                        db.execute("UPDATE documents SET status='skipped', last_seen_scan=? WHERE document_id=?", (started, existing["document_id"]))
                        if existing["status"] != "skipped":
                            _record_document_change(
                                db, scan_id, int(existing["document_id"]), "skipped", "file_size_limit", started,
                            )
                    continue
                unchanged_metadata = (
                    existing and not effective_force and int(existing["size_bytes"]) == stat.st_size
                    and int(existing["mtime_ns"]) == stat.st_mtime_ns and existing["status"] == "active"
                    and existing["project_name"] == source.project_name
                    and existing["project_root_path"] == source.project_root_path
                )
                raw_text = None
                if unchanged_metadata:
                    raw_text = source.path.read_text(encoding="utf-8-sig", errors="replace")
                    if sha256_text(raw_text) == existing["content_hash"]:
                        db.execute("UPDATE documents SET last_seen_scan=? WHERE document_id=?", (started, existing["document_id"]))
                        stats["unchanged"] += 1
                        source_summary["unchanged"] += 1
                        continue
                parsed = parse_markdown(source.path, raw_text=raw_text)
                if parsed.parse_error:
                    stats["errors"] += 1
                    source_summary["errors"] += 1
                    if existing:
                        db.execute("UPDATE documents SET last_seen_scan=? WHERE document_id=?", (started, existing["document_id"]))
                    continue
                document_id = _upsert_document(db, source, parsed, started, stat)
                if existing is None:
                    _record_document_change(db, scan_id, document_id, "added", "new_document", started)
                elif existing["status"] != "active":
                    _record_document_change(db, scan_id, document_id, "restored", "source_reappeared", started)
                elif str(existing["content_hash"] or "") != parsed.content_hash:
                    _record_document_change(db, scan_id, document_id, "modified", "content_changed", started)
                changed = bool(existing)
                stats["modified" if changed else "added"] += 1
                source_summary["modified" if changed else "added"] += 1
            except (OSError, ValueError, UnicodeError) as exc:
                scan_state["failed_kinds"].add(source.kind)
                stats["errors"] += 1
                source_summary["errors"] += 1
                continue
        for kind in sorted(scan_state["failed_kinds"]):
            source_summary = stats["source_summary"].setdefault(
                kind,
                {"seen": 0, "added": 0, "modified": 0, "unchanged": 0, "skipped": 0, "errors": 0},
            )
            # Enumeration failures have no per-file exception to count, so retain
            # one source-level error indicator in the existing bounded summary.
            if source_summary["errors"] == 0:
                source_summary["errors"] = 1
                stats["errors"] += 1
        disabled_roots = {
            (str(item.get("kind", "local")), path_key(item["path"]))
            for item in settings.additional_sources()
            if item.get("path") and not item.get("enabled", True)
        }
        if disabled_roots:
            candidates = db.query("SELECT document_id, source_kind, source_root FROM documents WHERE status IN ('active','skipped')")
            retired_ids = [
                int(row["document_id"])
                for row in candidates
                if (str(row["source_kind"]), path_key(row["source_root"])) in disabled_roots
            ]
            for offset in range(0, len(retired_ids), 500):
                batch = retired_ids[offset:offset + 500]
                placeholders = ",".join("?" for _ in batch)
                retired = db.query(
                    f"SELECT document_id FROM documents WHERE status IN ('active','skipped') AND document_id IN ({placeholders})",
                    batch,
                )
                cursor = db.execute(
                    f"UPDATE documents SET status='deleted' WHERE status IN ('active','skipped') AND document_id IN ({placeholders})",
                    batch,
                )
                for row in retired:
                    _record_document_change(db, scan_id, int(row["document_id"]), "removed", "source_excluded", started)
                stats["removed"] += cursor.rowcount
        scanned_kinds = scan_state["scanned_kinds"] - scan_state["failed_kinds"]
        expected_kinds = {kind for kind, _root, _name in settings.source_roots()}
        if (
            not scan_state["failed_kinds"] and not stats["errors"]
            and expected_kinds.issubset(scanned_kinds)
        ):
            db.execute(
                "INSERT INTO meta(key,value) VALUES('parser_version',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(PARSER_VERSION),),
            )
        if scanned_kinds:
            placeholders = ",".join("?" for _ in scanned_kinds)
            params = [started, *sorted(scanned_kinds)]
            removed_rows = db.query(
                f"SELECT document_id FROM documents WHERE status IN ('active','skipped') AND last_seen_scan<>? AND source_kind IN ({placeholders})",
                params,
            )
            cursor = db.execute(
                f"UPDATE documents SET status='deleted' WHERE status IN ('active','skipped') AND last_seen_scan<>? AND source_kind IN ({placeholders})",
                params,
            )
            for row in removed_rows:
                _record_document_change(
                    db, scan_id, int(row["document_id"]), "removed", "not_seen_in_complete_scan", started,
                )
            stats["removed"] += cursor.rowcount
        _resolve_links(db)
        finished = iso_now()
        stats["finished_at"] = finished
        stats["duration_ms"] = round((time.perf_counter() - started_clock) * 1000, 2)
        has_failures = bool(stats["errors"] or scan_state["failed_kinds"])
        stats["status"] = (
            "error" if has_failures and not scan_state["scanned_kinds"]
            else "partial" if has_failures
            else "ok"
        )
        db.execute(
            """UPDATE scan_runs SET finished_at=?, status=?, files_seen=?, added=?, modified=?, unchanged=?, removed=?, skipped=?, errors=?, source_summary_json=? WHERE scan_id=?""",
            (finished, stats["status"], stats["files_seen"], stats["added"], stats["modified"], stats["unchanged"], stats["removed"], stats["skipped"], stats["errors"], json.dumps(stats["source_summary"], ensure_ascii=False), scan_id),
        )
        db.commit()
    history_dir = settings.knowledge_root / "history" / "index-runs"
    history_name = datetime.now().strftime("%Y%m%d-%H%M%S-%f") + ".json"
    write_json_atomic(history_dir / history_name, stats)
    return stats


def index_all(settings: Settings, force: bool = False) -> dict[str, Any]:
    with _index_lock(settings):
        return _index_all_locked(settings, force=force)


def prune_inactive_search_payload(settings: Settings, *, apply: bool = False) -> dict[str, Any]:
    """Preview or explicitly prune inactive search text after making a verified backup."""
    if not apply:
        empty = {
            "inactive_documents": 0, "documents_with_payload": 0, "documents_fts_rows": 0,
            "document_chunks_rows": 0, "chunks_fts_rows": 0,
        }
        if not settings.database_path.is_file():
            return {"status": "preview", **empty, "backup": None}
        uri = settings.database_path.resolve(strict=True).as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN")
            inactive_ids = [
                int(row["document_id"])
                for row in connection.execute("SELECT document_id FROM documents WHERE status IN ('deleted','skipped')")
            ]
            summary = _inactive_search_payload_summary(connection, inactive_ids)
            connection.rollback()
            return {"status": "preview", **summary, "backup": None}
        finally:
            connection.close()

    with _index_lock(settings):
        with Database(settings.database_path) as db:
            inactive_ids = [
                int(row["document_id"])
                for row in db.query("SELECT document_id FROM documents WHERE status IN ('deleted','skipped')")
            ]
            summary = _inactive_search_payload_summary(db.connection, inactive_ids)
            if summary["documents_with_payload"] == 0:
                return {"status": "nothing_to_prune", **summary, "backup": None}

            backup_dir = settings.data_dir / "backups"
            backup_stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
            backup_path = backup_dir / f"pre-inactive-search-purge-{backup_stamp}.db"
            db.backup(backup_path)
            _purge_inactive_search_payload(db.connection, inactive_ids)
            integrity = str(db.one("PRAGMA integrity_check")[0])
            foreign_key_errors = db.query("PRAGMA foreign_key_check")
            if integrity != "ok" or foreign_key_errors:
                raise sqlite3.DatabaseError("El índice falló la validación después de purgar; se revirtió la transacción.")
            db.commit()
            return {
                "status": "applied",
                **summary,
                "backup": safe_relative(backup_path, settings.root) or backup_path.name,
                "integrity_check": integrity,
                "foreign_key_errors": 0,
            }


def set_additional_source_enabled_and_sync(settings: Settings, path: Path, enabled: bool) -> dict[str, Any]:
    """Toggle a registered source and reconcile its derived index under one writer lock."""
    with _index_lock(settings):
        requested_key = path_key(path)
        registered = next((
            item for item in settings.additional_sources()
            if item.get("path") and path_key(item["path"]) == requested_key
        ), None)
        if registered is None:
            raise ValueError("The path is not a registered additional source")
        if enabled:
            if contains_reparse_component(path):
                raise ValueError("The source path is unsafe or unverifiable (symlink/reparse point)")
            resolved = path.resolve(strict=True)
            if not resolved.is_dir():
                raise ValueError("The source must be a directory")
            if path_key(resolved) != path_key(registered["path"]):
                raise ValueError("The registered source path no longer matches its canonical location")
        source = set_additional_source_enabled(settings, path, enabled)
        scan = _index_all_locked(settings)
    return {"source": source, "enabled": enabled, "index": scan}
