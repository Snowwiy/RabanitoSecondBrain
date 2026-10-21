"""Publish an already-reviewed interview in owned Windows storage, without SQLite.

The caller must obtain human approval first; these guards do not authenticate it.
"""
from __future__ import annotations

import os
from contextlib import ExitStack
from pathlib import Path

from .config import SETTINGS_WRITE_LOCK
from .document_content import _open_readonly, _parts
from .documented_store import _Tree, _authorize_layout, _current_config, _publish
from .indexer import DEFAULT_EXCLUDED_DIRS, _excluded_directory, _index_lock, _is_document_candidate, _policy
from .utils import contains_reparse_component, redact_sensitive_lines

MAX_NOTE_BYTES = 65_536


def _authorize(settings, path, body):
    if os.name != 'nt':
        raise ValueError('interview_writer_requires_native_windows')
    _authorize_layout(settings)
    relative = path.relative_to(settings.knowledge_root)
    _parts(relative.as_posix())
    policy = _policy(settings, 'internal')
    limit = policy.get('max_file_bytes', settings.raw.get('max_document_bytes', 2_097_152))
    excluded = DEFAULT_EXCLUDED_DIRS | {str(v).casefold() for v in policy.get('exclude_dirs', [])}
    if (len(relative.parts) != 3 or relative.parts[:2] != ('personal', 'interviews')
            or contains_reparse_component(path) or not _is_document_candidate(path, policy)
            or path.suffix.casefold() in {str(v).casefold() for v in policy.get('exclude_extensions', [])}
            or any(_excluded_directory(part, excluded) for part in relative.parts[:-1])
            or type(limit) is not int or not 0 < len(body) <= min(MAX_NOTE_BYTES, limit)):
        raise ValueError('interview_write_policy_denied')


def save_reviewed_interview(settings, stem: str, content: str, *, config_path: Path | None = None) -> Path:
    """Never index, overwrite a note, or save an unreviewed draft implicitly."""
    body = content.encode('utf-8')
    if redact_sensitive_lines(content).splitlines() != content.splitlines():
        raise ValueError('interview_sensitive_content')
    directory = settings.knowledge_root / 'personal/interviews'
    _authorize(settings, directory / f'{stem}.md', body)
    with ExitStack() as outer:
        tree = _Tree(outer, settings.root)
        tree.directory(settings.root)
        tree.directory(settings.data_dir, create=True)
        tree.file(settings.data_dir / 'index.lock', create=True)
        with _index_lock(settings), SETTINGS_WRITE_LOCK, ExitStack() as operation:
            tree = _Tree(operation, settings.root)
            if config_path is not None:
                config_path = config_path.absolute()
                _current_config(settings, config_path)
                tree.directory(config_path.parent)
                operation.enter_context(_open_readonly(config_path))
                _current_config(settings, config_path)
            _authorize(settings, directory / f'{stem}.md', body)
            tree.directory(directory, create=True)
            for suffix in range(1000):
                suffix_text = '' if suffix == 0 else f'-{suffix + 1:02d}'
                path = directory / f'{stem}{suffix_text}.md'
                _authorize(settings, path, body)
                try:
                    path.lstat()
                except FileNotFoundError:
                    pass
                else:
                    continue
                try:
                    if _publish(path, body):
                        return path
                except FileExistsError:
                    continue  # A concurrent foreign note wins; never replace it.
    raise FileExistsError('interview_free_filename_limit_reached')
