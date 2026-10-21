"""Bounded generated report pairs, never notes imported as agent instructions.

Each file is published atomically. Two filenames are not a filesystem transaction:
a failure between publications preserves a COMPLETE recoverable first artifact.
Never unlink published paths on failure; another actor may have replaced them.
"""
from __future__ import annotations

import copy
import json
import os
import re
from contextlib import ExitStack
from pathlib import Path

from .config import SETTINGS_WRITE_LOCK, Settings
from .document_content import _open_readonly, _parts
from .documented_store import _Tree, _authorize_layout, _current_config, _publish
from .indexer import _index_lock
from .utils import contains_reparse_component

MAX_REPORT_BYTES = 8_388_608


class ReportPublicationError(OSError):
    def __init__(self, published):
        super().__init__('generated_report_pair_incomplete')
        self.published = tuple(published)  # Relative artifacts, never source text.


def _authorize(settings, paths):
    if os.name != 'nt':
        raise ValueError('report_writer_requires_native_windows')
    _authorize_layout(settings)
    for path in paths:
        relative = path.relative_to(settings.knowledge_root)
        _parts(relative.as_posix())
        if (len(relative.parts) != 2 or relative.parts[0] != 'quality-reports'
                or path.suffix not in {'.json', '.md'} or contains_reparse_component(path)):
            raise ValueError('unsafe_generated_report_path')


def publish_report_pair(settings, stamp, stem, json_value, markdown_text, *, config_path=None):
    settings = Settings(settings.root, copy.deepcopy(settings.raw))
    if (not isinstance(stamp, str) or not re.fullmatch(r'\d{8}-\d{6}', stamp)
            or not isinstance(stem, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', stem)
            or not isinstance(markdown_text, str)):
        raise ValueError('invalid_generated_report_input')
    payloads = ((json.dumps(json_value, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode('utf-8'),
                markdown_text.encode('utf-8'))
    if any(len(body) > MAX_REPORT_BYTES for body in payloads):
        raise ValueError('generated_report_size_limit')
    directory = settings.knowledge_root / 'quality-reports'
    first_paths = (directory / f'{stamp}-{stem}.json', directory / f'{stamp}-{stem}.md')
    _authorize(settings, first_paths)
    with ExitStack() as outer:
        tree = _Tree(outer, settings.root)
        tree.directory(settings.root)
        tree.directory(settings.data_dir, create=True)
        tree.file(settings.data_dir / 'index.lock', create=True)
        with _index_lock(settings), SETTINGS_WRITE_LOCK, ExitStack() as operation:
            tree = _Tree(operation, settings.root)
            if config_path is not None:
                config_path = Path(config_path).absolute()
                _current_config(settings, config_path)
                tree.directory(config_path.parent)
                operation.enter_context(_open_readonly(config_path))
                _current_config(settings, config_path)
            _authorize(settings, first_paths)
            tree.directory(directory, create=True)
            for suffix in range(1000):
                tail = '' if suffix == 0 else f'-{suffix + 1:02d}'
                basename = f'{stamp}-{stem}{tail}'
                paths = (directory / f'{basename}.json', directory / f'{basename}.md')
                _authorize(settings, paths)
                if any(path.exists() for path in paths):
                    continue
                published = []
                try:
                    for path, body in zip(paths, payloads):
                        if _publish(path, body):
                            published.append(path.relative_to(settings.knowledge_root).as_posix())
                    return paths
                except FileExistsError:
                    if published: raise ReportPublicationError(published) from None
                    continue
                except (OSError, ValueError):
                    if published: raise ReportPublicationError(published) from None
                    raise
    raise FileExistsError('generated_report_free_filename_limit_reached')
