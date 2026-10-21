"""Fail-closed retirement planning. No original-file writes or database restoration."""
from __future__ import annotations

import hashlib
import json
import re
import stat
from collections import Counter
from pathlib import Path

from .source_policy import document_eligibility
from .utils import contains_reparse_component, path_key, safe_relative


def configuration_signature(settings):
    return hashlib.sha256(json.dumps(settings.raw,sort_keys=True,ensure_ascii=True).encode()).hexdigest()


def source_id(kind, root):
    return hashlib.sha256(json.dumps([kind,root],ensure_ascii=True).encode()).hexdigest()


def load_bindings(db):
    row = db.one("SELECT value FROM meta WHERE key='index_source_bindings_v1'")
    if row is None:
        return {}
    if len(row[0]) > 1_048_576:
        raise ValueError('invalid_index_source_bindings')
    try:
        value = json.loads(row[0])
    except (ValueError, TypeError, RecursionError):
        raise ValueError('invalid_index_source_bindings') from None
    if (not isinstance(value,dict) or len(value)>4096 or any(
            not re.fullmatch('[0-9a-f]{64}',key) or not isinstance(identity,list) or len(identity)!=2
            or any(type(part) is not int or part<0 for part in identity) for key,identity in value.items())):
        raise ValueError('invalid_index_source_bindings')
    return value


def remember_bindings(db, state):
    value = dict(state['source_bindings'])
    for (kind,root),identity in state.get('source_identities',{}).items():
        value[source_id(kind,root)] = list(identity)
    if len(value)>4096:
        raise ValueError('index_source_binding_limit')
    db.execute("INSERT INTO meta(key,value) VALUES('index_source_bindings_v1',?) "
               "ON CONFLICT(key) DO UPDATE SET value=excluded.value",(json.dumps(value,sort_keys=True),))


def source_stamp(root: Path) -> tuple:
    if contains_reparse_component(root):
        raise OSError('source_unverifiable')
    value = root.lstat()
    if not stat.S_ISDIR(value.st_mode) or not value.st_ino:
        raise OSError('source_unverifiable')
    return value.st_dev, value.st_ino, value.st_mtime_ns


def complete_source(state, kind, root, before):
    try:
        if source_stamp(root) != before:
            raise OSError('source_changed_during_scan')
    except OSError:
        state['failed_kinds'].add(kind)
        return
    key = kind, path_key(root)
    state.setdefault('completed_sources', set()).add(key)
    state.setdefault('source_identities', {})[key] = before[:2]
    state.setdefault('source_stamps', {})[key] = before
    state['scanned_kinds'].add(kind)


def mass_change(count: int, population: int) -> bool:
    # A tiny, fully enumerated source can legitimately become empty. Larger
    # drops require explicit review even when the filesystem reports success.
    return count >= 100 or count >= 10 and count * 2 >= population


def _missing(root: Path, relative: str) -> bool:
    from .document_content import _parts
    current = root
    for part in _parts(relative):
        current = current / part
        try:
            value = current.lstat()
        except FileNotFoundError:
            return True
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
            return False
    return False


def plan_retirements(db, settings, state, marker, approval=None):
    expected = {(kind, path_key(root)) for kind, root, _ in state['expected_sources']}
    if (configuration_signature(settings) != state['configuration_signature']
            or expected != {(kind,path_key(root)) for kind,root,_ in settings.source_roots()}):
        state['failed_kinds'].update(kind for kind,_ in expected)
    complete = state.get('completed_sources', set()) & expected
    # A kind-wide failure remains deliberately conservative for sibling roots.
    usable = {key for key in complete if key[0] not in state['failed_kinds']}
    for kind, _ in expected - complete:
        state['failed_kinds'].add(kind)
    configured = {(kind, path_key(root)): root for kind, root, _ in state['expected_sources']}
    for key in complete:
        try:
            if source_stamp(configured[key]) != state['source_stamps'][key]:
                raise OSError('source_changed_before_retirement')
        except (OSError, KeyError):
            state['failed_kinds'].add(key[0])
    usable = {key for key in usable if key[0] not in state['failed_kinds']}
    disabled = {(str(item.get('kind', 'local')), path_key(item['path']))
                for item in settings.additional_sources() if item.get('path') and not item.get('enabled', True)}
    state['failed_kinds'].update(kind for kind,_ in disabled & expected)
    disabled -= expected  # Conflicting enabled/disabled declarations are not retirement authority.
    rows = db.query("SELECT document_id,source_kind,source_root,relative_path,project_root_path,content_hash,status,last_seen_scan "
                    "FROM documents WHERE status IN ('active','skipped') ORDER BY document_id")
    eligible = document_eligibility(settings)
    pending = state.get('missing_projects', [])
    missing_project_keys = {path_key(row['root_path']) for row in pending}
    candidates, population, orphaned = [], Counter(), 0
    for row in rows:
        kind, root = row['source_kind'], Path(row['source_root'])
        key = kind, path_key(root)
        origin = key
        if kind == 'projects':
            if (not row['project_root_path'] or path_key(row['project_root_path']) != key[1]
                    or safe_relative(root, settings.projects_root) in {None, '', '.'}):
                origin = None
            else:
                origin = kind, path_key(settings.projects_root)
        population[key] += 1
        if key in disabled:
            candidates.append((row, key, 'source_excluded'))
            continue
        if origin not in configured:
            if row['last_seen_scan'] != marker:
                orphaned += 1
            continue
        if row['last_seen_scan'] == marker or origin not in usable:
            continue
        try:
            excluded = (not eligible(kind, row['relative_path'])
                or row['project_root_path'] and (settings.is_project_excluded(row['project_root_path'])
                    or path_key(row['project_root_path']) in missing_project_keys))
            if not excluded and not _missing(root, row['relative_path']):
                raise OSError('unseen_file_not_confirmed_absent')
        except (OSError, ValueError):
            state['failed_kinds'].add(kind)
            continue
        candidates.append((row, key, 'not_seen_in_complete_scan'))
    # Do not partially retire a failed source just because some earlier paths
    # passed the absence check. Disabled roots are an explicit separate action.
    candidates = [(row,key,reason) for row,key,reason in candidates
                  if reason == 'source_excluded' or row['source_kind'] not in state['failed_kinds']]
    grouped = Counter(key for _,key,_ in candidates)
    total = len(candidates)
    risky = mass_change(total, len(rows)) or any(mass_change(count, population[key]) for key,count in grouped.items())
    risky = risky or mass_change(len(pending), state.get('previous_active_projects', 0))
    identity_changes = sum(
        source_id(kind,root) in state.get('source_bindings',{})
        and state['source_bindings'][source_id(kind,root)] != list(identity)
        for (kind,root),identity in state.get('source_identities',{}).items())
    risky = risky or bool(identity_changes and (total or pending))
    payload = {'version':1, 'configuration':state['configuration_signature'],
        'sources':sorted((kind, root, state.get('source_identities',{}).get((kind,root))) for kind,root in expected),
        'documents':[(row['document_id'],row['source_kind'],row['source_root'],row['relative_path'],row['content_hash'],
                      row['status'],reason) for row,_,reason in candidates],
        'projects':[(row['project_id'],row['root_path']) for row in pending]}
    digest = hashlib.sha256(json.dumps(payload,sort_keys=True,ensure_ascii=True).encode()).hexdigest() if risky else None
    hard_failure = bool(state['failed_kinds'] or orphaned or not expected)
    approved = bool(risky and approval == digest and not hard_failure)
    blocked = risky and not approved
    guard = {'status':'review_required' if blocked else 'approved' if approved else 'not_required',
        'proposed':total,'withheld':total if blocked else 0,'approval_digest':digest,
        'unconfigured_documents_preserved':orphaned,'approval_applied':approved,
        'scope_incomplete':hard_failure,'changed_source_identities':identity_changes}
    if approval is not None and not approved:
        guard['status'] = 'approval_rejected'
        blocked = True
        guard['withheld'] = total
    coverage = {'expected_sources':len(expected),'attempted_sources':len(state.get('attempted_sources',set()) & expected),
        'completed_sources':len(complete),
        'failed_sources':sum(key[0] in state['failed_kinds'] for key in expected),
        'unprocessed_sources':len(expected - state.get('attempted_sources',set())),
        'incomplete_sources':len(expected-complete),'complete':bool(expected) and not hard_failure}
    return ([] if blocked else candidates), ([] if blocked or hard_failure else pending), guard, coverage
