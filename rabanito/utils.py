from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

PRIVATE_KEY_BEGIN_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE)
PRIVATE_KEY_END_RE = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![A-Z0-9_])((?:[A-Z0-9]+[_-])*(?:api[_ -]?keys?|access[_ -]?(?:keys?|tokens?)|"
    r"auth[_ -]?(?:keys?|tokens?)|refresh[_ -]?tokens?|id[_ -]?tokens?|tokens?|passwords?|passwds?|"
    r"secrets?|client[_ -]?secrets?|credentials?|private[_ -]?keys?|ssh[_ -]?keys?|signing[_ -]?keys?|"
    r"encryption[_ -]?keys?|bearer|authorization)(?:[_-][A-Z0-9]+)*\s*[:=]\s*)(.*)$"
)
CREDENTIAL_URL_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat(timespec="seconds")


def path_key(path: Path | str) -> str:
    """Stable Windows-friendly identity for a path without following content."""
    return os.path.normcase(os.path.normpath(str(Path(path))))


def contains_reparse_component(path: Path | str) -> bool:
    """Fail closed when a path component is a reparse point or cannot be inspected."""
    raw_path = Path(path)
    if os.pardir in raw_path.parts:
        return True
    absolute = Path(os.path.abspath(raw_path))
    current = Path(absolute.anchor)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    try:
        for part in absolute.parts[1:]:
            current = current / part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & reparse_flag:
                return True
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return False


def safe_relative(path: Path, root: Path) -> str | None:
    try:
        path_resolved = path.resolve(strict=False)
        root_resolved = root.resolve(strict=False)
        relative = os.path.relpath(path_resolved, root_resolved)
    except (OSError, ValueError):
        return None
    if relative == os.pardir or relative.startswith(os.pardir + os.sep):
        return None
    return relative.replace(os.sep, "/")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)


def write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def write_text_atomic(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(value)
            if not value.endswith("\n"):
                handle.write("\n")
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def unclosed_private_key_lines(text: str) -> list[int]:
    """Return line numbers of private-key BEGIN markers with no later END marker."""
    open_line: int | None = None
    for number, line in enumerate(text.splitlines(), 1):
        if open_line is None:
            if PRIVATE_KEY_BEGIN_RE.search(line) and not PRIVATE_KEY_END_RE.search(line):
                open_line = number
        elif PRIVATE_KEY_END_RE.search(line):
            open_line = None
    return [open_line] if open_line is not None else []


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^\w\-\s]", "", value, flags=re.UNICODE)
    value = re.sub(r"[\s_]+", "-", value)
    return value.strip("-") or "item"


def split_lines_with_numbers(text: str) -> Iterable[tuple[int, str]]:
    for number, line in enumerate(text.splitlines(), 1):
        yield number, line


def redact_sensitive_lines(text: str) -> str:
    """Redact common secret assignments and private-key blocks from derived text."""
    output: list[str] = []
    in_private_key = False
    yaml_block_indent: int | None = None
    for line in text.splitlines():
        if in_private_key:
            output.append("[REDACTED PRIVATE KEY LINE]")
            if PRIVATE_KEY_END_RE.search(line):
                in_private_key = False
            continue

        if yaml_block_indent is not None:
            indentation = len(line) - len(line.lstrip())
            if not line.strip() or indentation > yaml_block_indent:
                output.append("[REDACTED SENSITIVE VALUE LINE]")
                continue
            yaml_block_indent = None

        if PRIVATE_KEY_BEGIN_RE.search(line):
            output.append("[REDACTED PRIVATE KEY LINE]")
            if not PRIVATE_KEY_END_RE.search(line):
                in_private_key = True
            continue

        line = CREDENTIAL_URL_RE.sub(r"\1[REDACTED]@", line)
        assignment = SENSITIVE_ASSIGNMENT_RE.search(line)
        if assignment:
            output.append(line[:assignment.start(1)] + assignment.group(1) + "[REDACTED]")
            value = assignment.group(2).strip()
            if not value or re.fullmatch(r"[|>][+-]?(?:\s+#.*)?|#.*", value):
                yaml_block_indent = len(line) - len(line.lstrip())
            continue

        output.append(line)
    return "\n".join(output)
