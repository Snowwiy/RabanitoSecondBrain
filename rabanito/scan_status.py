"""Bounded public scan diagnostics. No paths, document content or approval digests."""
from __future__ import annotations

import json
import re

LIMIT = 16_384
COUNT_KEYS = ('expected_sources', 'attempted_sources', 'completed_sources', 'failed_sources',
              'unprocessed_sources', 'incomplete_sources')
GUARD_COUNTS = ('proposed', 'withheld', 'unconfigured_documents_preserved', 'changed_source_identities')
GUARD_FLAGS = ('approval_applied', 'scope_incomplete')
GUARD_STATES = {'not_required', 'review_required', 'approved', 'approval_rejected'}


def _counts(value, keys):
    if not isinstance(value, dict) or any(type(value.get(k)) is not int or not 0 <= value[k] <= 9_007_199_254_740_991 for k in keys):
        return None
    return {k:value[k] for k in keys}


def public_diagnostics(value):
    if not isinstance(value, dict):
        return {}
    coverage, guard = value.get('scan_coverage'), value.get('retirement_guard')
    counts, withdrawals = _counts(coverage, COUNT_KEYS), _counts(guard, GUARD_COUNTS)
    if (counts is None or withdrawals is None or type(coverage.get('complete')) is not bool
            or not isinstance(guard.get('status'), str) or guard['status'] not in GUARD_STATES
            or any(type(guard.get(k)) is not bool for k in GUARD_FLAGS)):
        return {}
    expected, completed, attempted = (coverage[k] for k in ('expected_sources','completed_sources','attempted_sources'))
    if (completed > attempted or attempted > expected or coverage['failed_sources'] > expected
            or coverage['incomplete_sources'] != expected - completed
            or coverage['unprocessed_sources'] != expected - attempted
            or guard['withheld'] > guard['proposed']
            or coverage['complete'] and (not expected or completed != expected or coverage['failed_sources']
                                         or guard['scope_incomplete'])):
        return {}
    return {'scan_coverage':{**counts, 'complete':coverage['complete']},
            'retirement_guard':{**withdrawals, 'status':guard['status'], **{k:guard[k] for k in GUARD_FLAGS}}}


def _decode(raw):
    if not isinstance(raw, str) or len(raw) > LIMIT:
        return None
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        return None


def attach_report(db, scan):
    if not isinstance(scan, dict) or type(scan.get('scan_id')) is not int:
        return scan
    row = db.one('SELECT substr(value,1,?) FROM meta WHERE key=?',
                 (LIMIT + 1, 'index_scan_report:' + str(scan['scan_id'])))
    if row:
        payload = _decode(row[0])
        if isinstance(payload, dict) and type(payload.get('scan_id')) is int and payload['scan_id'] == scan['scan_id']:
            scan.update(public_diagnostics(payload))
    return scan


def last_complete_scan(db):
    row = db.one("SELECT substr(value,1,?) FROM meta WHERE key='index_last_complete_scan'", (LIMIT + 1,))
    value = _decode(row[0]) if row else None
    if (not isinstance(value, dict) or type(value.get('confirmation_version')) is not int or value['confirmation_version'] != 1
            or type(value.get('scan_id')) is not int or not 0 < value['scan_id'] < 2**53
            or any(not isinstance(value.get(k), str) or not re.fullmatch(r'[0-9T:+.Z-]{19,40}', value[k])
                   for k in ('started_at', 'finished_at'))):
        return None
    # A journal row and its complete coverage must still support the marker.
    run = db.one('SELECT status,errors,started_at,finished_at FROM scan_runs WHERE scan_id=?', (value['scan_id'],))
    report = attach_report(db, {'scan_id':value['scan_id']})
    if (not run or run['status'] != 'ok' or run['errors'] != 0
            or run['started_at'] != value['started_at'] or run['finished_at'] != value['finished_at']
            or not report.get('scan_coverage', {}).get('complete')
            or report.get('retirement_guard', {}).get('withheld') != 0):
        return None
    return {k:value[k] for k in ('scan_id', 'started_at', 'finished_at')}
