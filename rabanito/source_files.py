"""Shared read-only identity checks for index ingestion and cached retrieval."""
from __future__ import annotations

import errno
import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path

from .utils import contains_reparse_component, path_key, sha256_text


class UnsafeSourceError(OSError):
    """A source cannot be proven to be a single-link regular file."""


def identity(info):
    # Windows named stat and handle stat can disagree on ChangeTime just after
    # an atomic publication. Use the shared file ID, size and write timestamp.
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _regular(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not info.st_ino
            or getattr(info, "st_file_attributes", 0) & 0x400):
        raise UnsafeSourceError("source_not_available")


def _directories(path):
    if not path.is_absolute() or ".." in path.parts or str(path).startswith(("\\\\", "//")):
        raise UnsafeSourceError("source_not_available")
    result = []
    for directory in reversed(path.parents):
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or not info.st_ino
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise UnsafeSourceError("source_not_available")
        result.append((info.st_dev, info.st_ino))
    return result


@contextmanager
def _native_open(path: Path):
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
                raise UnsafeSourceError("source_not_available")
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
            raise UnsafeSourceError("source_not_available")
        yield stream


@contextmanager
def open_source(path):
    """Pin the file; reject hardlinks/reparse paths and identity changes."""
    path = Path(path)
    directories = _directories(path)
    before = path.lstat()
    _regular(before)
    with _native_open(path) as stream:
        opened = os.fstat(stream.fileno())
        _regular(opened)
        if identity(before) != identity(opened) or directories != _directories(path):
            raise UnsafeSourceError("source_changed_during_read")
        yield stream
        after, named = os.fstat(stream.fileno()), path.lstat()
        _regular(after)
        _regular(named)
        if (identity(opened) != identity(after) or identity(after) != identity(named)
                or directories != _directories(path)):
            raise UnsafeSourceError("source_changed_during_read")


def read_source(path, max_bytes=2_097_152):
    with open_source(path) as stream:
        info = os.fstat(stream.fileno())
        if info.st_size > max_bytes:
            raise OSError(errno.EFBIG, "source_size_limit")
        body = stream.read(max_bytes + 1)
        if len(body) > max_bytes or len(body) != info.st_size:
            raise UnsafeSourceError("source_changed_during_read")
    text = body.decode("utf-8-sig", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    return text, info


def read_text(path, max_bytes=2_097_152):
    return read_source(path, max_bytes)[0]


def identity_binding(info, content_hash):
    return json.dumps([str(info.st_dev), str(info.st_ino), info.st_size,
                       info.st_mtime_ns, info.st_ctime_ns, content_hash], separators=(',', ':'))


def remember_identity(db, document_id, info, content_hash):
    db.execute('INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
               ('document_file_identity:' + str(document_id), identity_binding(info, content_hash)))


def file_visible(root, relative, absolute, key, content_hash=None, size=None, mtime=None, binding=None):
    """No persistent approval cache. Permission and identity are checked live."""
    try:
        from .document_content import _parts
        root = Path(root)
        if not root.is_absolute() or contains_reparse_component(root):
            return 0
        path = root.joinpath(*_parts(relative))
        if path_key(path) != path_key(absolute) or path_key(path) != key:
            return 0
        with open_source(path) as stream:
            if content_hash is not None:
                if not isinstance(content_hash, str) or len(content_hash) != 64:
                    return 0
                info = os.fstat(stream.fileno())
                if binding is not None:
                    if not isinstance(binding, str) or len(binding) > 2048:
                        return 0
                    try:
                        recorded = json.loads(binding)
                    except (ValueError, RecursionError):
                        return 0
                    if not isinstance(recorded, list) or len(recorded) != 6:
                        return 0
                else:
                    recorded = None
                # Windows Python versions expose ctime/creation time differently.
                # Do not use that metadata as a content-cache shortcut on Windows.
                if os.name == 'nt' or recorded != json.loads(identity_binding(info, content_hash)):
                    # Legacy cache or changed identity: bounded, pinned content
                    # verification, not a path-only authorization shortcut.
                    if info.st_size > 16_777_216:
                        return 0
                    body = stream.read(info.st_size + 1)
                    if len(body) != info.st_size:
                        return 0
                    text = body.decode('utf-8-sig', errors='replace').replace('\r\n','\n').replace('\r','\n')
                    if sha256_text(text) != content_hash:
                        return 0
        return 1
    except (OSError, ValueError, TypeError, OverflowError):
        return 0


def derived_visibility_sql(alias="d"):
    # Generated project profiles quote source documentation. A regular generated
    # output is not authority to launder a now-forbidden upstream document.
    inputs = ("NOT EXISTS (SELECT 1 FROM documents _file_inputs WHERE _file_inputs.source_kind='projects' "
              "AND _file_inputs.status IN ('active','skipped') "
              f"AND rabanito_same_root(_file_inputs.project_root_path,{alias}.project_root_path)=1 "
              "AND (rabanito_document_eligible(_file_inputs.source_kind,_file_inputs.relative_path)=0 "
              f"OR NOT ({direct_visibility_sql('_file_inputs')})))")
    return (f"({alias}.source_kind<>'internal' OR {alias}.project_root_path IS NULL "
            f"OR lower({alias}.relative_path) NOT LIKE 'projects/%/project_memory.md' OR {inputs})")


def file_visibility_sql(alias="d"):
    direct = direct_visibility_sql(alias)
    return f"({direct} AND {derived_visibility_sql(alias)})"


def direct_visibility_sql(alias='d'):
    return (f"rabanito_file_visible({alias}.source_root,{alias}.relative_path,{alias}.absolute_path,"
            f"{alias}.path_key,{alias}.content_hash,{alias}.size_bytes,{alias}.mtime_ns,"
            f"(SELECT substr(value,1,2049) FROM meta WHERE key='document_file_identity:'||{alias}.document_id))=1")
