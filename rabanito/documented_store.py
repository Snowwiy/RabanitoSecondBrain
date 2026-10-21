"""Explicitly approved local records. No HTTP writer, external writes or execution.

The approval digest is a caller's assertion of prior human review, not an
authentication factor or independent proof of any recorded historical claim.
The first writer implementation deliberately requires native Windows semantics.
"""
from __future__ import annotations

import copy
import hmac
import json
import os
import re
import sqlite3
import stat
import tempfile
from contextlib import ExitStack, contextmanager
from pathlib import Path

from .config import SETTINGS_WRITE_LOCK, Settings, default_config_path
from .db import Database
from .document_content import _open_readonly, _parts
from .documented_draft import MAX_INPUT_BYTES, preview_documented_experience
from .documented_memory import CONTEXT
from .indexer import (
    DEFAULT_EXCLUDED_DIRS, SourceFile, _excluded_directory, _index_lock,
    _is_document_candidate, _policy, _record_document_change, _resolve_links, _upsert_document,
)
from .parsing import parse_markdown
from .utils import contains_reparse_component, iso_now, path_key, safe_relative, sha256_text

ROOT = Path(__file__).resolve().parents[1]


def _inside(path: Path, root: Path, *, child=False):
    try:
        relative = path.absolute().relative_to(root.absolute())
        return not child or bool(relative.parts)
    except ValueError:
        return False


def _authorize_layout(settings):
    """Shared owned-storage boundary; no context-specific authorization or writes."""
    root = settings.root
    if any(not isinstance(settings.raw.get(key), str) or not settings.raw[key]
           for key in ('data_dir', 'knowledge_dir', 'database_path', 'vault_root', 'projects_root')):
        raise ValueError('invalid_documented_write_configuration')
    paths = (root, settings.data_dir, settings.knowledge_root, settings.database_path)
    if (not _inside(root, ROOT) or any(not p.is_absolute() or '..' in p.parts
            or str(p).startswith(('\\\\', '//')) or contains_reparse_component(p) for p in paths)
            or not _inside(settings.data_dir, root, child=True)
            or not _inside(settings.knowledge_root, root, child=True)
            or not _inside(settings.database_path, settings.data_dir, child=True)
            or _inside(settings.data_dir, settings.knowledge_root)
            or _inside(settings.knowledge_root, settings.data_dir)):
        raise ValueError('unsafe_documented_write_roots')
    for path in paths[1:]:
        _parts(path.relative_to(root).as_posix())
    if settings.database_path.suffix.casefold() not in {'.db', '.sqlite', '.sqlite3'}:
        raise ValueError('invalid_documented_database_name')
    # Neither canonical private storage root may overlap an imported source.
    for kind, source, _ in settings.source_roots(include_disabled=True):
        if kind == 'internal' and path_key(source) == path_key(settings.knowledge_root):
            continue
        if any(_inside(source, owned) or _inside(owned, source)
               for owned in (settings.knowledge_root, settings.data_dir)):
            raise ValueError('documented_write_source_overlap')


def _authorize(settings, preview):
    _authorize_layout(settings)
    excluded = settings.raw.get('excluded_memory_contexts', [])
    if (not isinstance(excluded, list) or len(excluded) > 500
            or any(not isinstance(v, str) or not CONTEXT.fullmatch(v) for v in excluded)):
        raise ValueError('invalid_excluded_memory_contexts')
    # Scope/date were strictly validated by the pure preview, not taken as paths.
    from .parsing import parse_frontmatter
    metadata, _ = parse_frontmatter(preview['content_markdown'].splitlines())
    context = metadata['scope_id']
    if context in excluded:
        raise ValueError('documented_context_excluded')
    filename = metadata['recorded_date'] + '-' + preview['approval_digest'] + '.md'
    path = settings.knowledge_root / 'decisions' / 'environments' / context / filename
    policy = _policy(settings, 'internal')
    excluded_dirs = DEFAULT_EXCLUDED_DIRS | {str(v).casefold() for v in policy.get('exclude_dirs', [])}
    if (not _is_document_candidate(path, policy)
            or path.suffix.casefold() in {str(v).casefold() for v in policy.get('exclude_extensions', [])}
            or any(_excluded_directory(p, excluded_dirs)
                   for p in path.relative_to(settings.knowledge_root).parts[:-1])
            or len(preview['content_markdown'].encode('utf-8')) >
               min(MAX_INPUT_BYTES, int(policy.get('max_file_bytes', settings.raw.get('max_document_bytes', 2_097_152))))):
        raise ValueError('documented_write_policy_denied')
    return path


@contextmanager
def _pin(path: Path, *, directory: bool, create=False):
    """Pin exact NTFS identity, denying delete/rename while allowing SQLite RW.

    OPEN_REPARSE_POINT + final HANDLE path + attributes/nlink fail closed before
    any content write. Parent directories are pinned first by _Tree below.
    """
    import ctypes
    from ctypes import wintypes
    class Information(ctypes.Structure):
        _fields_ = [('attrs', wintypes.DWORD), ('creation', wintypes.FILETIME),
                    ('access', wintypes.FILETIME), ('write', wintypes.FILETIME),
                    ('volume', wintypes.DWORD), ('size_high', wintypes.DWORD),
                    ('size_low', wintypes.DWORD), ('links', wintypes.DWORD),
                    ('index_high', wintypes.DWORD), ('index_low', wintypes.DWORD)]
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    create_file = api.CreateFileW
    create_file.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                           wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create_file.restype = wintypes.HANDLE
    final = api.GetFinalPathNameByHandleW
    final.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    final.restype = wintypes.DWORD
    information = api.GetFileInformationByHandle
    information.argtypes = [wintypes.HANDLE, ctypes.POINTER(Information)]
    information.restype = wintypes.BOOL
    close = api.CloseHandle
    close.argtypes, close.restype = [wintypes.HANDLE], wintypes.BOOL
    handle = create_file(str(path), 0x80000000, 3, None, 4 if create else 3,
                         0x00200000 | (0x02000000 if directory else 0), None)
    if handle == ctypes.c_void_p(-1).value:
        raise ValueError('documented_path_pin_failed')
    try:
        buffer, info = ctypes.create_unicode_buffer(32768), Information()
        length = final(handle, buffer, len(buffer), 0)
        actual = buffer.value
        if actual.startswith('\\\\?\\'):
            actual = actual[4:]
        if (not 0 < length < len(buffer) or path_key(actual) != path_key(path)
                or not information(handle, ctypes.byref(info)) or info.attrs & 0x400
                or bool(info.attrs & 0x10) != directory or not directory and info.links != 1):
            raise ValueError('unsafe_documented_path_identity')
        yield
    finally:
        close(handle)


class _Tree:
    def __init__(self, stack, root):
        self.stack, self.root, self.pinned = stack, root, set()

    def directory(self, path, *, create=False):
        for current in (*reversed(path.parents), path):
            if path_key(current) in self.pinned:
                continue
            if create and _inside(current, self.root, child=True):
                current.mkdir(exist_ok=True)
            self.stack.enter_context(_pin(current, directory=True))
            self.pinned.add(path_key(current))

    def file(self, path, *, create=False):
        self.directory(path.parent, create=create)
        self.stack.enter_context(_pin(path, directory=False, create=create))


def _current_config(settings, config_path):
    # Read while pinned against concurrent writes, without load_settings's mkdirs.
    if (not config_path.is_absolute() or not _inside(config_path, settings.root, child=True)
            or contains_reparse_component(config_path)):
        raise ValueError('unsafe_documented_config')
    _parts(config_path.relative_to(settings.root).as_posix())
    with _open_readonly(config_path) as stream:
        raw = stream.read(262145)
    if len(raw) > 262144:
        raise ValueError('documented_config_size_limit')
    try:
        value = json.loads(raw.decode('utf-8-sig'))
        project_root = Path(value.get('project_root') or config_path.parent.parent)
        if not project_root.is_absolute():
            project_root = config_path.parent.parent / project_root
        if contains_reparse_component(project_root) or path_key(project_root) != path_key(settings.root):
            raise ValueError
        value['project_root'] = str(settings.root)
        expected = {**settings.raw, 'project_root': str(settings.root)}
        if value != expected:
            raise ValueError
    except (ValueError, TypeError, AttributeError, UnicodeError, RecursionError):
        raise ValueError('documented_config_changed_reload_required') from None


def _same_file(path, body):
    # Each caller validates its candidate byte budget before publication. This
    # comparison also serves bounded generated reports, not only 64KiB notes.
    with _open_readonly(path) as stream:
        actual = stream.read(len(body) + 1)
    if actual != body:
        raise ValueError('documented_destination_conflict')


def _publish(path, body):
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    else:
        _same_file(path, body)
        return False
    # Windows rename is atomic within this directory and refuses an existing
    # destination. Never use replace(), a full-vault copy, or a truncating open.
    fd, temporary = tempfile.mkstemp(prefix='.documented-', suffix='.tmp', dir=path.parent)
    temporary = Path(temporary)
    identity = os.fstat(fd)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(temporary, path)
        _same_file(path, body)
        return True
    finally:
        if temporary.exists():
            current = temporary.lstat()
            if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                temporary.unlink()  # Only this operation's reserved temporary.


@contextmanager
def _index_database(settings):
    # Validate/pin existing sidecars until SQLite opens its own handles. Release
    # our sidecar pins BEFORE connection.close(), which needs to unlink WAL/SHM.
    # Keeping these pins for the whole save causes Windows SQLite delete retries.
    db = None
    try:
        with ExitStack() as guards:
            for suffix in ('-wal', '-shm', '-journal'):
                sidecar = Path(str(settings.database_path) + suffix)
                if sidecar.exists() or sidecar.is_symlink():
                    guards.enter_context(_pin(sidecar, directory=False))
            db = Database(settings.database_path, initialize=settings.database_path.stat().st_size == 0)
            # The no-DDL constructor is lazy: force a real schema read while
            # guards are still held so SQLite has opened its own WAL handles.
            db.one('PRAGMA schema_version')
    except BaseException:
        if db is not None:
            db.connection.close()  # Guards have already been released above.
        raise
    with db:
        yield db


def _payload_matches(db, document_id, parsed):
    """Bounded per-record comparison against the approved live parse, not FTS truth.

    A source hash/mtime match does not prove that its derived rows still exist.
    This checks logical payloads, not SQLite's internal FTS posting-tree integrity.
    """
    identity = str(document_id)
    fts = db.query('''SELECT substr(title,1,?),substr(tags,1,?),substr(body,1,?)
        FROM documents_fts WHERE document_id=? LIMIT 2''',
        (len(parsed.title)+1, len(' '.join(parsed.tags))+1, len(parsed.text)+1, identity))
    if len(fts) != 1 or tuple(fts[0]) != (parsed.title, ' '.join(parsed.tags), parsed.text):
        return False
    bound, limit = MAX_INPUT_BYTES+1, len(parsed.chunks)+1
    chunks = db.execute('''SELECT chunk_id,substr(heading,1,?),line_start,line_end,substr(text,1,?),text_hash
        FROM document_chunks WHERE document_id=? ORDER BY chunk_id LIMIT ?''', (bound, bound, document_id, limit))
    cached = db.execute('''SELECT substr(chunk_id,1,32),substr(heading,1,?),substr(text,1,?)
        FROM chunks_fts WHERE document_id=? ORDER BY CAST(chunk_id AS INTEGER),rowid LIMIT ?''',
        (bound, bound, identity, limit))
    for expected in parsed.chunks:
        chunk, indexed = chunks.fetchone(), cached.fetchone()
        fields = (expected['heading'], expected['line_start'], expected['line_end'], expected['text'], sha256_text(expected['text']))
        if (chunk is None or indexed is None or tuple(chunk)[1:] != fields
                or tuple(indexed) != (str(chunk['chunk_id']), expected['heading'], expected['text'])):
            return False
    if chunks.fetchone() is not None or cached.fetchone() is not None:
        return False
    tags = db.execute('SELECT substr(tag,1,?) FROM tags WHERE document_id=? ORDER BY tag LIMIT ?',
                      (bound, document_id, len(parsed.tags)+1))
    for tag in parsed.tags:
        actual = tags.fetchone()
        if actual is None or actual[0] != tag:
            return False
    if tags.fetchone() is not None:
        return False
    # Match the same first-occurrence uniqueness as INSERT OR IGNORE in indexer.
    unique_links = {}
    for link in parsed.links:
        unique_links.setdefault((link['target_raw'], link.get('line_number')),
            (link['target_raw'], link.get('label'), link.get('line_number'), link.get('relation_type', 'wikilink')))
    links = db.execute('''SELECT substr(target_raw,1,?),substr(label,1,?),line_number,substr(relation_type,1,32)
        FROM links WHERE source_document_id=? ORDER BY link_id LIMIT ?''', (bound, bound, document_id, len(unique_links)+1))
    for expected in unique_links.values():
        actual = links.fetchone()
        if actual is None or tuple(actual) != expected:
            return False
    return links.fetchone() is None


def _index_saved(settings, path, markdown):
    relative = path.relative_to(settings.knowledge_root).as_posix()
    parsed = parse_markdown(path, raw_text=markdown)
    if parsed.parse_error or parsed.content_hash != sha256_text(markdown):
        raise ValueError('documented_parse_failed')
    with _open_readonly(path) as stream, _index_database(settings) as db:
        if stream.read(MAX_INPUT_BYTES + 1) != markdown.encode('utf-8'):
            raise ValueError('documented_file_changed_before_index')
        info = os.fstat(stream.fileno())
        db.execute('BEGIN IMMEDIATE')  # Payload comparisons and repair share one snapshot.
        previous = db.one('SELECT * FROM documents WHERE path_key=?', (path_key(path),))
        repairing_payload = False
        if previous:
            if (previous['source_kind'] != 'internal' or path_key(previous['source_root']) != path_key(settings.knowledge_root)
                    or previous['project_root_path'] is not None or previous['relative_path'] != relative
                    or path_key(previous['absolute_path']) != path_key(path)
                    or previous['content_hash'] != parsed.content_hash):
                raise ValueError('documented_index_identity_conflict')
            if (previous['status'] == 'active' and (previous['size_bytes'], previous['mtime_ns']) == (info.st_size, info.st_mtime_ns)
                    and previous['frontmatter_json'] == json.dumps(parsed.frontmatter, ensure_ascii=False, sort_keys=True)
                    and previous['tags_json'] == json.dumps(parsed.tags, ensure_ascii=False)
                    and previous['title'] == parsed.title and previous['project_name'] is None
                    and previous['category'] == relative.split('/')[0]
                    and previous['parse_error'] is None):
                if _payload_matches(db, int(previous['document_id']), parsed):
                    return int(previous['document_id'])
                repairing_payload = True
        now = iso_now()
        scan_id = db.execute("INSERT INTO scan_runs(started_at,status) VALUES(?,'running')", (now,)).lastrowid
        source = SourceFile('internal', settings.knowledge_root, path, relative, None, None)
        document_id = _upsert_document(db, source, parsed, now, info)
        _resolve_links(db, source_document_id=document_id)
        if not _payload_matches(db, document_id, parsed):
            raise ValueError('documented_index_payload_verification_failed')
        action = ('restored' if previous['status'] != 'active' else 'modified') if previous else 'added'
        reason = 'documented_index_payload_repaired' if repairing_payload else 'approved_documented_experience'
        _record_document_change(db, scan_id, document_id, action, reason, now)
        summary = {'internal': {'seen': 1, 'added': int(not previous), 'modified': int(bool(previous)),
                                'unchanged': 0, 'skipped': 0, 'errors': 0}}
        # Existing consumers understand partial; do not invent a new status or
        # make the latest scan imply that all imported sources were refreshed.
        db.execute("""UPDATE scan_runs SET finished_at=?,status='partial',files_seen=1,added=?,modified=?,
            source_summary_json=?,error_message='scoped_documented_write_not_full_scan' WHERE scan_id=?""",
            (iso_now(), int(not previous), int(bool(previous)), json.dumps(summary), scan_id))
    return document_id


def save_documented_experience(settings: Settings, payload: dict, *, reviewed_on: str,
                              approve_digest: str, config_path: Path | None = None) -> dict:
    """Persist only after the caller has obtained human approval of exact preview.

    Digest equality detects a changed draft; it does NOT authenticate the human.
    No --yes, inferred approval from source text, history verification or repairs.
    """
    if os.name != 'nt':
        raise ValueError('documented_writer_requires_native_windows')
    if not isinstance(approve_digest, str) or not re.fullmatch('[a-f0-9]{64}', approve_digest):
        raise ValueError('exact_documented_approval_required')
    try:
        payload = copy.deepcopy(payload)
        preview = preview_documented_experience(payload, reviewed_on=reviewed_on)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise ValueError('invalid_documented_save_draft') from None
    if not hmac.compare_digest(approve_digest, preview['approval_digest']):
        raise ValueError('exact_documented_approval_required')
    path = _authorize(settings, preview)
    config_path = (config_path or default_config_path(settings.root)).absolute()
    _current_config(settings, config_path)
    with ExitStack() as stack:
        tree = _Tree(stack, settings.root)
        tree.directory(settings.root)
        tree.directory(settings.data_dir, create=True)
        tree.file(settings.data_dir / 'index.lock', create=True)
        with _index_lock(settings), SETTINGS_WRITE_LOCK, ExitStack() as operation:
            tree = _Tree(operation, settings.root)
            tree.directory(config_path.parent)
            # Keep config non-writable until publication/index transaction ends.
            operation.enter_context(_open_readonly(config_path))
            _current_config(settings, config_path)
            fresh = preview_documented_experience(payload, reviewed_on=reviewed_on)
            if fresh != preview or _authorize(settings, fresh) != path:
                raise ValueError('documented_draft_changed_under_lock')
            tree.directory(path.parent, create=True)
            created = _publish(path, preview['content_markdown'].encode('utf-8'))
            result = {'status': 'index_pending', 'persisted': True, 'indexed': False,
                      'created': created, 'citation': 'internal:' + path.relative_to(settings.knowledge_root).as_posix(),
                      'approval_digest': approve_digest, 'approval': 'caller_asserted_human_review_not_authenticated',
                      'fully_verified': False, 'historical_validation': 'pending', 'document_id': None,
                      'limitations': ['Human approval is not independent historical verification.',
                                      'Only this record is indexed; inbound link refresh and KG sync remain explicit.']}
            try:
                tree.file(settings.database_path, create=True)
                result['document_id'] = _index_saved(settings, path, preview['content_markdown'])
                result.update(status='indexed', indexed=True)
            except (OSError, ValueError, sqlite3.Error):
                result.update(error='documented_index_pending_retry_same_approved_draft', retry_safe=True)
            return result
