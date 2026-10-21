"""Real CLI roundtrip in an isolated synthetic root; never uses private memory.

No provider requests, source edits, global settings, installs or Git mutations.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rabanito.config import Settings, save_settings
from rabanito.db import Database, restore_database
from rabanito.documented_memory import HEADINGS, documented_experiences
from rabanito.utils import iso_now


def validate():
    if os.name != 'nt':
        raise ValueError('validation_requires_native_windows')
    started = time.perf_counter()
    parent = ROOT / 'tests' / '.test-temp'
    parent.mkdir(exist_ok=True)
    report = {'at': iso_now(), 'mode': 'isolated_synthetic_cli_not_production_approval',
              'provider_requests': 0, 'production_records_written': 0}
    with tempfile.TemporaryDirectory(prefix='documented-store-cli-', dir=parent) as directory:
        root = Path(directory)
        settings = Settings(root, {'project_root': str(root), 'data_dir': 'data', 'database_path': 'data/fixture.db',
            'knowledge_dir': 'knowledge', 'vault_root': 'vault', 'projects_root': 'projects',
            'source_policy': {'internal': {'extensions': ['.md']}}})
        for path in (settings.vault_root, settings.projects_root): path.mkdir(parents=True)
        save_settings(settings)
        config = root / 'config' / 'settings.json'
        payload = {'title': 'Synthetic CLI experiencia ñ', 'metadata': {'scope_id': 'fixture-cli',
            'project': 'Synthetic environment, not a registered repository', 'recorded_date': '2026-10-18',
            'validation': 'pending', 'current_state_validation': 'not_performed', 'technologies': ['Python']},
            'sections': {key: 'Synthetic CLI fixture only; no historical claim: ' + key for key in HEADINGS}}
        calls = []
        def cli(*args):
            calls.append(args[:2])
            completed = subprocess.run([sys.executable, '-B', '-m', 'rabanito', '--config', str(config), *args],
                input=json.dumps(payload, ensure_ascii=False), encoding='utf-8', capture_output=True,
                cwd=ROOT, timeout=30)
            return completed.returncode, json.loads(completed.stdout)
        code, preview = cli('coding', 'preview-documented', '--stdin', '--reviewed-on', '2026-10-18')
        if code or preview['persisted'] or settings.database_path.exists():
            raise ValueError('preview_wrote_or_failed')
        code, denied = cli('coding', 'save-documented', '--stdin', '--reviewed-on', '2026-10-18', '--approve-digest', '0'*64)
        if code != 1 or denied != {'error': 'exact_documented_approval_required'} or settings.database_path.exists():
            raise ValueError('unapproved_fixture_not_rejected')
        # Synthetic test authority only. Never reuse this as approval of real data.
        args = ('coding', 'save-documented', '--stdin', '--reviewed-on', '2026-10-18', '--approve-digest', preview['approval_digest'])
        code, first = cli(*args)
        code2, second = cli(*args)
        if code or code2 or not first['indexed'] or second['created'] or first['document_id'] != second['document_id']:
            raise ValueError('cli_index_or_idempotency_failed')
        # Fault injection is confined to this generated DB, not the live index.
        with Database(settings.database_path, initialize=False) as db:
            db.execute('DELETE FROM documents_fts WHERE document_id=?', (str(first['document_id']),))
            chunk = db.one('SELECT chunk_id FROM document_chunks WHERE document_id=? LIMIT 1', (first['document_id'],))
            db.execute('DELETE FROM document_chunks WHERE chunk_id=?', (chunk['chunk_id'],))
        code, missing = cli('coding', 'documented', 'Synthetic', '--context', 'fixture-cli')
        if code or missing['results']:
            raise ValueError('fixture_fault_not_observed')
        code, repaired = cli(*args)
        if code or not repaired['indexed'] or repaired['created'] or repaired['document_id'] != first['document_id']:
            raise ValueError('cli_payload_repair_failed')
        code, context = cli('coding', 'documented', 'Synthetic', '--context', 'fixture-cli', '--max-chars', '200')
        if code or len(context['results']) != 1 or context['used_chars'] > 200 or context['results'][0]['fully_verified']:
            raise ValueError('cli_context_failed')
        note = settings.knowledge_root / first['citation'].removeprefix('internal:')
        if note.read_bytes() != preview['content_markdown'].encode('utf-8'):
            raise ValueError('exact_reviewed_bytes_not_preserved')
        code, stats = cli('stats')
        if (code or stats['documents_active'] != 1 or stats['projects'] != 0
                or stats['latest_scan']['status'] != 'partial' or stats['latest_scan']['errors']):
            raise ValueError('scoped_cli_stats_failed')
        backup = settings.data_dir / 'backup.db'
        with Database(settings.database_path) as db:
            for table in ('documents_fts', 'chunks_fts'):
                db.execute(f"INSERT INTO {table}({table}) VALUES('integrity-check')")
            db.commit(); db.backup(backup)
            if db.one('SELECT count(*) FROM documents')[0] != 1 or db.one('SELECT count(*) FROM projects')[0]:
                raise ValueError('unexpected_full_source_scan')
            if db.one('''SELECT count(*) FROM chunks_fts f LEFT JOIN document_chunks c
                    ON c.chunk_id=CAST(f.chunk_id AS INTEGER) WHERE c.chunk_id IS NULL''')[0]:
                raise ValueError('owned_orphan_payload_survived_repair')
        restored = settings.data_dir / 'restored.db'; restore_database(backup, restored)
        restored_settings = Settings(root, {**settings.raw, 'database_path': str(restored)})
        restored_result = documented_experiences(restored_settings, 'Synthetic', context='fixture-cli', max_chars=200)
        if restored_result != context:
            raise ValueError('restored_context_mismatch')
        report.update(cli_processes=len(calls), preview_no_database=True, rejected_digest=True,
            exact_utf8_bytes=True, indexed=True, idempotent=True, cited_retrieval=True,
            context_chars=context['used_chars'], historical_validation='pending', fully_verified=False,
            sqlite_integrity='ok', fts_integrity_checks=2, backup_restored=True,
            restored_context_equal=True, source_directories_empty=not any(settings.vault_root.iterdir()) and not any(settings.projects_root.iterdir()))
        report.update(logical_payload_fault_observed=True, scoped_payload_repaired=True, orphan_chunk_cache_removed=True)
    report.update(temporary_cleaned=not root.exists(), seconds=round(time.perf_counter()-started, 3))
    return report


if __name__ == '__main__':
    print(json.dumps(validate(), ensure_ascii=True, indent=2))
