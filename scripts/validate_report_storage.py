"""Real report CLI/restore validation with synthetic metadata and local sources."""
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
from rabanito.search import retrieve_context


def validate():
    if os.name != 'nt': raise ValueError('validation_requires_native_windows')
    import _winapi
    started = time.perf_counter()
    parent = ROOT / 'tests/.test-temp'
    parent.mkdir(exist_ok=True)
    calls = 0
    with tempfile.TemporaryDirectory(prefix='report-storage-cli-', dir=parent) as directory:
        root = Path(directory)
        settings = Settings(root, {'project_root': str(root), 'database_path': 'data/fixture.db', 'data_dir': 'data',
            'knowledge_dir': 'knowledge', 'vault_root': 'vault', 'projects_root': 'projects',
            'source_policy': {'obsidian': {'extensions': ['.md']},
                              'internal': {'extensions': ['.md'], 'exclude_dirs': ['quality-reports', 'history']}}})
        for path in (settings.knowledge_root, settings.vault_root, settings.projects_root): path.mkdir()
        source = settings.vault_root / 'Synthetic ñ.md'
        original = '# Synthetic knowledge\nA synthetic local source for report storage validation.\n'
        source.write_text(original, encoding='utf-8')
        save_settings(settings)
        config = root / 'config/settings.json'
        def cli(*arguments):
            nonlocal calls
            calls += 1
            return subprocess.run([sys.executable, '-B', '-X', 'utf8', '-m', 'rabanito', '--config', str(config), *arguments],
                cwd=ROOT, capture_output=True, encoding='utf-8', timeout=30)
        if cli('index').returncode: raise ValueError('synthetic_index_failed')
        report_dir = settings.knowledge_root / 'quality-reports'
        readonly = cli('audit')
        if readonly.returncode or report_dir.exists(): raise ValueError('readonly_audit_created_report')
        target = settings.vault_root / 'not-authorized-for-writes'
        target.mkdir()
        _winapi.CreateJunction(str(target), str(report_dir))
        try:
            rejected = cli('audit', '--write')
            if rejected.returncode == 0 or list(target.iterdir()):
                raise ValueError('report_junction_was_not_rejected')
        finally:
            report_dir.rmdir()  # Generated junction only, never its target.
        with Database(settings.database_path, read_only=True) as db:
            before = [tuple(row) for row in db.query('SELECT document_id,content_hash,status FROM documents ORDER BY document_id')]
        for args in (('audit', '--write'), ('level-up',)):
            run = cli(*args)
            if run.returncode: raise ValueError('synthetic_report_cli_failed')
            response = json.loads(run.stdout)
            json_path = settings.knowledge_root / response['json_path']
            markdown_path = settings.knowledge_root / response['markdown_path']
            if json_path.parent != report_dir or markdown_path.parent != report_dir or json_path.stem != markdown_path.stem:
                raise ValueError('report_paths_not_a_pair')
            for path in (json_path, markdown_path):
                if not path.is_file() or str(root) in path.read_text(encoding='utf-8'):
                    raise ValueError('report_missing_or_contains_absolute_source_roots')
            json.loads(json_path.read_text(encoding='utf-8'))
        query = cli('context', 'Synthetic knowledge', '--source', 'obsidian', '--limit', '1', '--max-chars', '200')
        if query.returncode: raise ValueError('fixture_context_failed')
        context = json.loads(query.stdout)
        if not context['fragments'] or not 0 < context['characters'] <= 200: raise ValueError('fixture_context_empty')
        backup = settings.data_dir / 'backup.db'
        with Database(settings.database_path, initialize=False) as db:
            after = [tuple(row) for row in db.query('SELECT document_id,content_hash,status FROM documents ORDER BY document_id')]
            if before != after or db.one('PRAGMA integrity_check')[0] != 'ok' or db.query('PRAGMA foreign_key_check'):
                raise ValueError('report_changed_document_index')
            for table in ('documents_fts', 'chunks_fts'):
                db.execute(f"INSERT INTO {table}({table}) VALUES('integrity-check')")
            db.commit(); db.backup(backup)
        restored = settings.data_dir / 'restored.db'
        restore_database(backup, restored)
        observed = retrieve_context(Settings(root, settings.raw | {'database_path': str(restored)}),
            'Synthetic knowledge', source_kind='obsidian', limit=1, max_chars=200)
        if observed != context or source.read_text(encoding='utf-8') != original or list(target.iterdir()):
            raise ValueError('source_or_restore_mismatch')
        report = {'mode': 'synthetic_cli_metadata_not_production_memory', 'cli_processes': calls,
            'readonly_audit_no_report': True, 'junction_rejected': True, 'complete_pairs': 2,
            'report_roots_not_exposed': True, 'document_rows_unchanged': True,
            'context_chars': context['characters'], 'fts_integrity_checks': 2,
            'backup_restored': True, 'restored_context_equal': True,
            'production_records_written': 0, 'provider_requests': 0, 'source_unchanged': True}
    report.update(temporary_cleaned=not root.exists(), seconds=round(time.perf_counter()-started, 3))
    return report


if __name__ == '__main__': print(json.dumps(validate(), ensure_ascii=True, indent=2))
