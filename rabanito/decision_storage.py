"""Windows-owned storage for the existing project decision writer.

Reuse the tested directory HANDLE pins and no-replace publisher. This is storage
authorization, not human consent or independent verification of recorded claims.
"""
from __future__ import annotations

import os
import stat
from contextlib import ExitStack, contextmanager
from pathlib import Path

from .config import SETTINGS_WRITE_LOCK
from .document_content import _open_readonly, _parts
from .documented_store import _Tree, _authorize_layout, _current_config, _publish
from .indexer import DEFAULT_EXCLUDED_DIRS, _excluded_directory, _index_lock, _is_document_candidate, _policy
from .utils import contains_reparse_component

MAX_NOTE_BYTES = 65_536


def validate_memory_storage(settings):
    """Fail before a lock, directory creation, database initialization or write."""
    if os.name != 'nt':
        raise ValueError('decision_writer_requires_native_windows')
    _authorize_layout(settings)
    base = settings.knowledge_root / 'decisions'
    _parts(base.relative_to(settings.root).as_posix())
    if contains_reparse_component(base):
        raise ValueError('unsafe_decision_write_path')
    protected = [settings.data_dir / 'index.lock', settings.database_path]
    protected.extend(Path(str(settings.database_path) + suffix) for suffix in ('-wal', '-shm', '-journal'))
    for path in protected:
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or contains_reparse_component(path)):
            raise ValueError('unsafe_decision_storage_identity')


def validate_memory_target(settings, path, body):
    relative = path.relative_to(settings.knowledge_root)
    _parts(relative.as_posix())
    policy = _policy(settings, 'internal')
    limit = policy.get('max_file_bytes', settings.raw.get('max_document_bytes', 2_097_152))
    excluded = DEFAULT_EXCLUDED_DIRS | {str(v).casefold() for v in policy.get('exclude_dirs', [])}
    if (len(relative.parts) != 3 or relative.parts[0] != 'decisions'
            or contains_reparse_component(path) or not _is_document_candidate(path, policy)
            or path.suffix.casefold() in {str(v).casefold() for v in policy.get('exclude_extensions', [])}
            or any(_excluded_directory(part, excluded) for part in relative.parts[:-1])
            or type(limit) is not int or not 0 < len(body) <= min(MAX_NOTE_BYTES, limit)):
        raise ValueError('decision_write_policy_denied')


@contextmanager
def memory_write_scope(settings, config_path: Path | None = None):
    validate_memory_storage(settings)
    with ExitStack() as outer:
        tree = _Tree(outer, settings.root)
        tree.directory(settings.root)
        tree.directory(settings.data_dir, create=True)
        tree.file(settings.data_dir / 'index.lock', create=True)
        with _index_lock(settings), SETTINGS_WRITE_LOCK, ExitStack() as operation:
            validate_memory_storage(settings)
            tree = _Tree(operation, settings.root)
            tree.file(settings.database_path)  # Existing index only; no DDL here.
            if config_path is not None:
                config_path = config_path.absolute()
                _current_config(settings, config_path)
                tree.directory(config_path.parent)
                operation.enter_context(_open_readonly(config_path))
                _current_config(settings, config_path)
            yield tree


def publish_note(path, body):
    return _publish(path, body)
