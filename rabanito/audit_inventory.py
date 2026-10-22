"""Bounded, metadata-only source census. Never call discovery or source readers here."""
from __future__ import annotations

import math
import os
import re
import stat
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from .config import Settings
from .db import Database
from .indexer import (
    DEFAULT_EXCLUDED_DIRS, _excluded_directory, _excluded_name, _has_vcs_marker,
    _is_document_candidate, _policy,
)
from .utils import contains_reparse_component, path_key, sha256_text, slugify
from .visibility import project_visibility_sql
from .source_policy import document_eligibility


LIMITS = {
    'max_entries': (20000, 1, 200000), 'max_roots': (64, 1, 1024),
    'max_depth': (32, 0, 128), 'max_findings': (100, 0, 500),
    'max_seconds': (5.0, 0.01, 30.0),
}
COUNT_FIELDS = (
    'roots_total', 'roots_started', 'entries_examined', 'eligible_files',
    'indexed_files', 'unindexed_files', 'new_project_roots', 'inactive_project_roots',
    'excluded_entries', 'reparse_entries_skipped', 'oversized_files',
    'unverifiable_project_files', 'roots_unavailable', 'directory_errors',
    'directories_changed', 'depth_limited_directories',
)
STATUSES = {'not_indexed', 'not_visible_in_index', 'project_not_registered', 'project_not_active'}


def _number(value: Any, default: float, minimum: float, maximum: float, *, integer=True):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    try:
        if isinstance(value, float) and (not math.isfinite(value) or (integer and int(value) != value)):
            return default
        bounded = min(maximum, max(minimum, value))
        return int(bounded) if integer else float(bounded)
    except (ValueError, OverflowError):
        return default


def empty_inventory() -> dict[str, Any]:
    return dict.fromkeys(COUNT_FIELDS, 0) | {
        'scope': 'metadata_only_eligible_files', 'performed': False,
        'budget_exhausted': False, 'coverage_complete': False,
        'findings_truncated': False, 'findings': [], 'limits': {}, 'review_only': True,
    }


def _absolute(path: Path) -> Path:
    # Lexical only: never resolve an untrusted reparse destination for identity.
    return Path(os.path.abspath(path))


def _under(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((path_key(path), path_key(root))) == path_key(root)
    except ValueError:
        return False


def _reparse(metadata) -> bool:
    return bool(stat.S_ISLNK(metadata.st_mode) or getattr(metadata, 'st_file_attributes', 0)
                & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400))


def inspect_source_inventory(db: Database, settings: Settings) -> dict[str, Any]:
    """Use the caller's read snapshot. Only stat/scandir and parameterized SELECTs."""
    return _Inventory(db, settings).run()


class _Inventory:
    def __init__(self, db: Database, settings: Settings):
        self.db, self.settings = db, settings
        self.eligible = document_eligibility(settings)
        self.result = empty_inventory()
        self.result.update(performed=True, coverage_complete=True)
        self.limits = {
            key: _number(settings.raw.get('audit_inventory_' + key), *values,
                         integer=key != 'max_seconds')
            for key, values in LIMITS.items()
        }
        self.result['limits'] = self.limits
        self.deadline = time.monotonic() + self.limits['max_seconds']
        self.seen_files: set[str] = set()
        self.seen_projects: set[str] = set()
        self.project_rows: dict[str, Any] = {}
        self.profile_folders: dict[str, set[str]] = defaultdict(set)
        self.decision_folders: dict[str, set[str]] = defaultdict(set)
        self.projects_root = _absolute(settings.projects_root)
        self.max_bytes = _number(settings.raw.get('max_document_bytes'), 2097152, 1, 2**63-1)

    def partial(self, key: str):
        self.result[key] += 1
        self.result['coverage_complete'] = False

    def expired(self) -> bool:
        if time.monotonic() >= self.deadline or self.result['budget_exhausted']:
            self.result.update(budget_exhausted=True, coverage_complete=False)
            return True
        return False

    def finding(self, kind: str, relative: str, status: str):
        if len(self.result['findings']) < self.limits['max_findings']:
            self.result['findings'].append({
                'source_kind': kind, 'relative_path': relative, 'status': status, 'review_only': True,
            })
        else:
            self.result['findings_truncated'] = True

    def bind_project(self, root: Path):
        key = path_key(root)
        slug, digest = slugify(root.name).casefold(), sha256_text(key)
        self.profile_folders[slug].add(key)
        for length in (8, 12, 16, 24, 32, 64):
            self.profile_folders[f'{slug}-{digest[:length]}'].add(key)
        self.decision_folders[f'{slug}-{digest[:8]}'].add(key)

    def excluded_project(self, root: Path) -> bool:
        # Excluding an ancestor excludes its nested repositories as well.
        current = root
        while current != self.projects_root and _under(current, self.projects_root):
            if self.settings.is_project_excluded(current):
                return True
            current = current.parent
        return not _under(root, self.projects_root) or root == self.projects_root

    def project(self, root: Path, source: Path):
        key = path_key(root)
        if key in self.seen_projects:
            return
        self.seen_projects.add(key)
        self.bind_project(root)
        row = self.project_rows.get(key)
        if row is None:
            self.result['new_project_roots'] += 1
            self.finding('projects', root.relative_to(source).as_posix(), 'project_not_registered')
        elif row['status'] != 'active':
            self.result['inactive_project_roots'] += 1
            self.finding('projects', root.relative_to(source).as_posix(), 'project_not_active')

    def internal_allowed(self, path: Path, relative: str, row) -> bool:
        parts = relative.split('/')
        namespace = (len(parts) == 3 and parts[0].casefold() == 'projects'
                     and parts[-1].casefold() == 'project_memory.md')
        decision = (len(parts) >= 3 and parts[0].casefold() == 'decisions'
                    and path.suffix.casefold() == '.md')
        root_value = row['project_root_path'] if row is not None else None
        if root_value:
            root = _absolute(Path(root_value))
            if self.excluded_project(root):
                self.result['excluded_entries'] += 1
                return False
            if path_key(root) in self.seen_projects:
                return True
            self.partial('unverifiable_project_files')
            return False
        if not namespace and not decision:
            return True
        folders = self.profile_folders if namespace else self.decision_folders
        candidates = folders.get(parts[1].casefold(), set())
        if candidates and all(self.excluded_project(Path(key)) for key in candidates):
            self.result['excluded_entries'] += 1
            return False
        # A slug shared by two roots cannot authorize a new profile without body reads.
        if len(candidates) == 1 and next(iter(candidates)) in self.seen_projects:
            return True
        self.partial('unverifiable_project_files')
        return False

    def file(self, kind: str, root: Path, path: Path, metadata, policy: dict, project: Path | None):
        if not _is_document_candidate(path, policy):
            self.result['excluded_entries'] += 1
            return
        if kind == 'projects':
            if project is None or path.suffix.casefold() in {
                str(ext).casefold() for ext in policy.get('exclude_extensions', [])
            }:
                self.result['excluded_entries'] += 1
                return
            limit = min(self.max_bytes, _number(policy.get('max_metadata_file_bytes'), 2097152, 1, 2**63-1))
        else:
            limit = self.max_bytes
        if metadata.st_size > limit:
            self.result['oversized_files'] += 1
            return
        key = path_key(path)
        if key in self.seen_files:
            return
        relative = path.relative_to(root).as_posix()
        if not self.eligible(kind, relative):
            self.result['excluded_entries'] += 1
            return
        row = self.db.one(
            'SELECT d.source_kind,d.source_root,d.status,d.project_root_path,'
            + project_visibility_sql('d', live_file=False, include_derived=False)
            + ' AND rabanito_file_visible(d.source_root,d.relative_path,d.absolute_path,d.path_key)=1'
            + ' AS visible FROM documents d WHERE d.path_key=?', (key,),
        )
        if kind == 'internal' and not self.internal_allowed(path, relative, row):
            return
        self.seen_files.add(key)
        self.result['eligible_files'] += 1
        expected_root = project if kind == 'projects' else root
        visible = (row is not None and row['status'] == 'active' and row['visible']
                   and row['source_kind'] == kind
                   and path_key(row['source_root']) == path_key(expected_root)
                   and (kind != 'projects' or path_key(row['project_root_path'] or '') == path_key(project)))
        if visible:
            self.result['indexed_files'] += 1
        else:
            self.result['unindexed_files'] += 1
            self.finding(kind, relative, 'not_indexed' if row is None else 'not_visible_in_index')

    def walk(self, kind: str, root: Path):
        policy = _policy(self.settings, kind)
        excluded_dirs = {str(v).casefold() for v in policy.get('exclude_dirs', [])} | DEFAULT_EXCLUDED_DIRS
        excluded_names = {str(v).casefold() for v in policy.get('exclude_names', [])}
        pending: list[tuple[Path, int, Path | None]] = [(root, 0, None)]
        started = False
        while pending and not self.expired():
            current, depth, project = pending.pop()
            try:
                if contains_reparse_component(current):
                    if current == root:
                        self.partial('roots_unavailable')
                    else:
                        self.partial('directory_errors')
                    continue
                before = current.lstat()
                if not stat.S_ISDIR(before.st_mode) or _reparse(before):
                    self.partial('roots_unavailable' if current == root else 'directory_errors')
                    continue
                with os.scandir(current) as entries:
                    if not started:
                        self.result['roots_started'] += 1
                        started = True
                    for entry in entries:
                        if self.expired():
                            break
                        if self.result['entries_examined'] >= self.limits['max_entries']:
                            self.result.update(budget_exhausted=True, coverage_complete=False)
                            break
                        self.result['entries_examined'] += 1
                        path = current / entry.name
                        try:
                            metadata = entry.stat(follow_symlinks=False)
                            if _reparse(metadata):
                                self.result['reparse_entries_skipped'] += 1
                                continue
                            if stat.S_ISDIR(metadata.st_mode):
                                if (_excluded_directory(entry.name, excluded_dirs)
                                        or _excluded_name(path, excluded_names)
                                        or (kind == 'projects' and self.excluded_project(path))):
                                    self.result['excluded_entries'] += 1
                                    continue
                                if depth >= self.limits['max_depth']:
                                    self.partial('depth_limited_directories')
                                    continue
                                associated = project
                                if kind == 'projects' and (depth == 0 or _has_vcs_marker(
                                    path, on_error=lambda _exc: self.partial('directory_errors'),
                                )):
                                    associated = path
                                    self.project(path, root)
                                pending.append((path, depth + 1, associated))
                            elif stat.S_ISREG(metadata.st_mode):
                                self.file(kind, root, path, metadata, policy, project)
                            else:
                                self.result['excluded_entries'] += 1
                        except OSError:
                            self.partial('directory_errors')
                after = current.lstat()
                if ((before.st_dev, before.st_ino, before.st_mtime_ns)
                        != (after.st_dev, after.st_ino, after.st_mtime_ns)) or _reparse(after):
                    self.partial('directories_changed')
            except OSError:
                self.partial('roots_unavailable' if current == root and not started else 'directory_errors')

    def run(self):
        # Cache metadata only; cap memory independently of an arbitrarily large index.
        for i, row in enumerate(self.db.execute(
            'SELECT root_path,status FROM projects LIMIT ?', (self.limits['max_entries'] + 1,),
        )):
            if self.expired():
                break
            if i >= self.limits['max_entries']:
                self.result.update(budget_exhausted=True, coverage_complete=False)
                break
            path = Path(row['root_path'])
            if path.is_absolute() and _under(path, self.projects_root) and path != self.projects_root:
                self.project_rows[path_key(path)] = row
                self.bind_project(path)
        roots = self.settings.source_roots()
        self.result['roots_total'] = len(roots)
        seen_roots: set[tuple[str, str]] = set()
        for ordinal, (kind, raw_root, _name) in enumerate(roots):
            if ordinal >= self.limits['max_roots']:
                self.result.update(budget_exhausted=True, coverage_complete=False)
                break
            if self.expired():
                break
            if not re.fullmatch(r'[a-z][a-z0-9_-]{0,39}', kind) or not raw_root.is_absolute() or '..' in raw_root.parts:
                self.partial('roots_unavailable')
                continue
            root = _absolute(raw_root)
            key = (kind, path_key(root))
            if key not in seen_roots:
                seen_roots.add(key)
                self.walk(kind, root)
        self.result['findings'].sort(key=lambda item: (
            item['source_kind'], item['relative_path'].casefold(), item['status'],
        ))
        return self.result
