"""Bounded, read-only document views. Source text is data, not executable code."""
from __future__ import annotations

import codecs
import os
import re
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import unquote

from .config import SETTINGS_WRITE_LOCK, Settings
from .db import Database
from .indexer import DEFAULT_EXCLUDED_DIRS, _excluded_directory, _is_document_candidate, _policy
from .utils import contains_reparse_component, path_key, redact_sensitive_lines, sha256_text
from .visibility import project_visibility_sql, register_project_visibility

MAX_BYTES, MAX_REFERENCES, MAX_ID = 65_536, 512, 9_007_199_254_740_991
AUTH_COLUMNS = ",".join("d." + name for name in (
    "document_id", "source_kind", "source_root", "project_root_path", "relative_path",
    "absolute_path", "path_key", "status", "content_hash", "size_bytes", "mtime_ns",
))


class DocumentContentError(ValueError):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status, self.code = status, code


def validate_request(document_id, max_bytes):
    if type(document_id) is not int or not 1 <= document_id <= MAX_ID:
        raise DocumentContentError(400, "invalid_document_id")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_BYTES:
        raise DocumentContentError(400, "invalid_max_bytes")


def _parts(value):
    if not isinstance(value, str) or len(value) > 1000:
        raise DocumentContentError(404, "document_not_available")
    parts = value.replace("\\", "/").split("/")
    if any(not p or p in {".", ".."} or p[-1:] in {" ", "."}
           or re.search(r'[<>:"|?*\x00-\x1f\x7f\ud800-\udfff]', p)
           or re.fullmatch(r"(?i)(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", p) for p in parts):
        raise DocumentContentError(404, "document_not_available")
    return parts


def _inside(path, root):
    try:
        return os.path.commonpath([path_key(path), path_key(root)]) == path_key(root)
    except ValueError:
        return False


def _authorize(settings, row, projects):
    """Do not trust stored paths, the FTS body, or an old visibility decision."""
    unavailable = DocumentContentError(404, "document_not_available")
    if row["status"] != "active":
        raise unavailable
    kind, root = row["source_kind"], Path(row["source_root"])
    if (not root.is_absolute() or ".." in root.parts or str(root).startswith(("\\\\", "//"))
            or contains_reparse_component(root)):
        raise unavailable
    parts = _parts(row["relative_path"])
    path = root.joinpath(*parts)
    if (path_key(path) != path_key(row["absolute_path"]) or path_key(path) != row["path_key"]
            or contains_reparse_component(path)):
        raise unavailable
    policy = _policy(settings, kind)
    excluded_dirs = DEFAULT_EXCLUDED_DIRS | {str(v).casefold() for v in policy.get("exclude_dirs", [])}
    if (any(_excluded_directory(p, excluded_dirs) for p in parts[:-1])
            or not _is_document_candidate(path, policy)
            or path.suffix.casefold() in {str(v).casefold() for v in policy.get("exclude_extensions", [])}):
        raise unavailable
    if kind == "projects":
        if path_key(row["project_root_path"] or "") != path_key(root):
            raise unavailable
        # A parent project cannot read documentation owned by a nested project.
        if any(_inside(path, p["root_path"]) and path_key(p["root_path"]) != path_key(root)
               and _inside(p["root_path"], root) for p in projects):
            raise unavailable
    elif not any(k == kind and path_key(r) == path_key(root) for k, r, _ in settings.source_roots()):
        raise unavailable
    project_root = row["project_root_path"]
    if project_root:
        project = next((p for p in projects if path_key(p["root_path"]) == path_key(project_root)), None)
        proot = Path(project_root)
        if (not project or project["status"] != "active" or not _inside(proot, settings.projects_root)
                or path_key(proot) == path_key(settings.projects_root)
                or settings.is_project_excluded(proot) or contains_reparse_component(proot)):
            raise unavailable
        if any(_inside(proot, p["root_path"]) and (p["status"] != "active"
               or settings.is_project_excluded(p["root_path"])) for p in projects):
            raise unavailable
    if kind == "internal" and parts[:2] == ["decisions", "environments"]:
        if len(parts) > 2 and parts[2] in settings.raw.get("excluded_memory_contexts", []):
            raise unavailable
    return path


@contextmanager
def _open_readonly(path: Path):
    """Pin a regular file before reading. See Microsoft API sources in the contract.

    Windows: OPEN_EXISTING/GENERIC_READ, no write/delete sharing, no final reparse
    following, and actual handle path verification. POSIX: dir_fd + O_NOFOLLOW.
    """
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        create = api.CreateFileW
        create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                           wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        create.restype = wintypes.HANDLE
        close = api.CloseHandle
        close.argtypes, close.restype = [wintypes.HANDLE], wintypes.BOOL
        final = api.GetFinalPathNameByHandleW
        final.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        final.restype = wintypes.DWORD
        file_type = api.GetFileType
        file_type.argtypes, file_type.restype = [wintypes.HANDLE], wintypes.DWORD
        handle = create(str(path), 0x80000000, 1, None, 3, 0x00200000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise OSError("source_open_failed")
        try:
            buffer = ctypes.create_unicode_buffer(32768)
            length = final(handle, buffer, len(buffer), 0)
            actual = buffer.value
            if actual.startswith("\\\\?\\UNC\\"):
                actual = "\\\\" + actual[8:]
            elif actual.startswith("\\\\?\\"):
                actual = actual[4:]
            if not 0 < length < len(buffer) or file_type(handle) != 1 or path_key(actual) != path_key(path):
                raise DocumentContentError(404, "document_not_available")
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            handle = None  # The fd now owns the handle.
        finally:
            if handle is not None:
                close(handle)
    else:
        parent_fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in path.parts[1:-1]:
                child_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                os.close(parent_fd)
                parent_fd = child_fd
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
    with os.fdopen(fd, "rb", buffering=0) as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise DocumentContentError(404, "document_not_available")
        yield stream


# Defense in depth, not a universal DLP or a replacement for source exclusions.
_ABSOLUTE = re.compile(r"(?i)(?:file://[^\s<>\"`]+|(?<!\w)[a-z]:[\\/][^\r\n<>\"`]*|\\\\[^\r\n<>\"`]+|(?<![:/\w])/(?:Users|home|tmp|var|mnt|opt|etc|root)/[^\r\n<>\"`]*)")
_TOKEN = re.compile(r"(?i)\b(?:gh[pousr]_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|sk-[a-z0-9_-]{20,}|AKIA[A-Z0-9]{16}|eyJ[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+)\b")
_BEARER = re.compile(r"(?i)\b(?:bearer|basic)\s+[a-z0-9+/_.=-]{8,}")


def _redact(text, settings):
    text = _BEARER.sub("[REDACTED AUTH]", _TOKEN.sub("[REDACTED TOKEN]", redact_sensitive_lines(text)))
    roots = [settings.root, settings.projects_root, settings.vault_root, settings.knowledge_root,
             settings.data_dir, *(r for _, r, _ in settings.source_roots())]
    for root in sorted({str(r) for r in roots}, key=len, reverse=True):
        for variant in {root, root.replace("\\", "/"), root.replace("\\", "\\\\")}:
            if variant:
                text = re.sub(re.escape(variant) + r"[^\r\n<>\"`]*", "[REDACTED PATH]", text, flags=re.I)
    return _ABSOLUTE.sub("[REDACTED PATH]", text)


def _identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _read(settings, row, path, max_bytes):
    before = path.stat()
    if (before.st_size, before.st_mtime_ns) != (row["size_bytes"], row["mtime_ns"]):
        raise DocumentContentError(409, "document_changed_reindex_required")
    if before.st_size > int(settings.raw.get("max_document_bytes", 2_097_152)):
        raise DocumentContentError(413, "document_size_limit")
    with _open_readonly(path) as stream:
        opened = os.fstat(stream.fileno())
        if _identity(before) != _identity(opened) or contains_reparse_component(path):
            raise DocumentContentError(409, "document_changed_reindex_required")
        body = stream.read(max_bytes)
        after = os.fstat(stream.fileno())
        if (_identity(opened) != _identity(after) or after.st_nlink != 1 or _identity(after) != _identity(path.stat())
                or contains_reparse_component(path)):
            raise DocumentContentError(409, "document_changed_reindex_required")
    truncated = after.st_size > len(body)
    if not truncated and len(body) != after.st_size:
        raise DocumentContentError(409, "document_changed_reindex_required")
    try:
        raw = codecs.getincrementaldecoder("utf-8-sig")("strict").decode(body, final=not truncated)
        raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeError:
        raise DocumentContentError(400, "invalid_document_encoding") from None
    if "\x00" in raw:
        raise DocumentContentError(400, "invalid_document_encoding")
    if not truncated and sha256_text(raw) != row["content_hash"]:
        raise DocumentContentError(409, "document_changed_reindex_required")
    if truncated:
        raw = raw[:raw.rfind("\n") + 1]  # Never expose a partially read secret line.
    text = _redact(raw, settings)
    encoded = text.encode("utf-8")
    if len(encoded) > max_bytes:
        text, truncated = encoded[:max_bytes].decode("utf-8", errors="ignore"), True
    return text, truncated


def document_content(settings: Settings, document_id, max_bytes) -> dict:
    validate_request(document_id, max_bytes)
    if not settings.database_path.is_file() or contains_reparse_component(settings.database_path):
        raise DocumentContentError(503, "document_index_unavailable")
    try:
        with SETTINGS_WRITE_LOCK, Database(settings.database_path, read_only=True) as db:
            register_project_visibility(db, settings)
            db.execute("BEGIN")  # Consistent RO snapshot; no migrations or indexing.
            projects = db.query("SELECT root_path,status FROM projects LIMIT 5001")
            if len(projects) > 5000:
                raise DocumentContentError(503, "document_authorization_limit")
            row = db.one("SELECT " + AUTH_COLUMNS + " FROM documents d WHERE document_id=? AND d.status='active' AND "
                         + project_visibility_sql("d"), (document_id,))
            if not row:
                raise DocumentContentError(404, "document_not_available")
            path = _authorize(settings, row, projects)
            text, truncated = _read(settings, row, path, max_bytes)
            _authorize(settings, row, projects)
            references, seen = [], set()
            links = db.query("SELECT " + AUTH_COLUMNS + """, substr(d.title,1,1001) AS title,
                substr(l.target_raw,1,1001) AS target_raw
                FROM links l JOIN documents d ON d.document_id=l.target_document_id
                WHERE l.source_document_id=? AND l.status='resolved' AND d.status='active'
                AND l.relation_type IN ('wikilink','markdown','embed')
                AND """ + project_visibility_sql("d") + " ORDER BY l.link_id LIMIT 513", (document_id,))
            for link in links[:MAX_REFERENCES]:
                try:
                    _authorize(settings, link, projects)
                    if not 1 <= link["document_id"] <= MAX_ID:
                        continue
                    values = [link["title"], link["target_raw"], link["relative_path"].replace("\\", "/")]
                    if any(not isinstance(v, str) or not v or len(v) > 1000
                           or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in v)
                           or _redact(v, settings) != v for v in values):
                        continue
                    raw = unquote(values[1]).replace("\\", "/")
                    if raw.startswith(("/", "~")) or re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", raw):
                        continue
                    identity = (link["document_id"], values[1])
                    if identity in seen:
                        continue
                    seen.add(identity)
                    references.append(dict(zip(("title", "target_raw", "relative_path"), values))
                                      | {"target_document_id": link["document_id"], "status": "resolved"})
                except (DocumentContentError, OSError, ValueError):
                    continue
            return {"document_id": document_id, "content_markdown": text, "bytes_returned": len(text.encode("utf-8")),
                    "truncated": truncated, "references": references}
    except DocumentContentError:
        raise
    except sqlite3.Error:
        raise DocumentContentError(503, "document_index_unavailable") from None
    except OSError:
        raise DocumentContentError(409, "document_source_unavailable") from None
    except (TypeError, ValueError, KeyError, OverflowError):
        raise DocumentContentError(404, "document_not_available") from None
