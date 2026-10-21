"""Real CLI security/backup roundtrip with synthetic project data on Windows.

No provider calls, private config, production memories, source or global writes.
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
from rabanito.coding_memory import similar_experiences


def validate():
    if os.name != 'nt':
        raise ValueError('validation_requires_native_windows')
    import _winapi
    started = time.perf_counter()
    parent = ROOT / 'tests/.test-temp'
    parent.mkdir(exist_ok=True)
    calls = 0
    with tempfile.TemporaryDirectory(prefix='decision-storage-cli-', dir=parent) as directory:
        root = Path(directory)
        settings = Settings(root, {'project_root': str(root), 'database_path': 'data/fixture.db',
            'data_dir': 'data', 'knowledge_dir': 'knowledge', 'vault_root': 'vault', 'projects_root': 'projects',
            'source_policy': {'projects': {'extensions': ['.md']}, 'internal': {'extensions': ['.md']}}})
        project = settings.projects_root / 'Synthetic ñ'
        project.mkdir(parents=True)
        source = project / 'README.md'
        original = '# Synthetic ñ\nSynthetic CLI fixture: Unicode paths and storage boundaries.\n'
        source.write_text(original, encoding='utf-8')
        settings.vault_root.mkdir()
        settings.knowledge_root.mkdir()
        save_settings(settings)
        config = root / 'config/settings.json'

        def cli(*arguments):
            nonlocal calls
            calls += 1
            return subprocess.run([sys.executable, '-B', '-m', 'rabanito', '--config', str(config), *arguments],
                                  cwd=ROOT, capture_output=True, encoding='utf-8', timeout=30)

        args = ('decision', 'add', '--project', str(project), '--problem', 'Synthetic Unicode storage fixture',
                '--statement', 'Keep the synthetic note in owned knowledge', '--status', 'confirmed',
                '--record-type', 'fact', '--validation', 'passed', '--technology', 'Python',
                '--evidence', 'project:README.md', '--test', 'Synthetic storage check',
                '--result', 'Synthetic fixture only, not a historical production claim')
        target = settings.vault_root / 'not-authorized-for-writes'
        target.mkdir()
        link = settings.knowledge_root / 'decisions'
        _winapi.CreateJunction(str(target), str(link))
        try:
            blocked = cli(*args)
            if blocked.returncode == 0 or list(target.iterdir()) or settings.database_path.exists():
                raise ValueError('cli_storage_escape_not_blocked_before_index')
        finally:
            link.rmdir()  # Only this generated junction, not its target.

        added = cli(*args)
        if added.returncode:
            raise ValueError('cli_fixture_record_failed')
        record = json.loads(added.stdout)
        note = Path(record['path'])
        if not note.is_relative_to(settings.knowledge_root) or not note.is_file():
            raise ValueError('cli_destination_invalid')
        found = cli('coding', 'similar', 'Synthetic Unicode', '--project', str(project), '--max-chars', '256')
        listed = cli('decision', 'list', '--project', str(project))
        if found.returncode or listed.returncode:
            raise ValueError('cli_fixture_retrieval_failed')
        context = json.loads(found.stdout)
        records = json.loads(listed.stdout)
        if (len(context['results']) != 1 or len(records) != 1 or not 0 < context['used_chars'] <= 256
                or context['results'][0]['validation'] != 'passed_as_recorded_not_rerun'):
            raise ValueError('cli_fixture_context_invalid')
        lines = note.read_text(encoding='utf-8').splitlines()
        for fragment in context['results'][0]['fragments']:
            if not '\n'.join(lines[fragment['line_start']-1:fragment['line_end']]).startswith(fragment['text']):
                raise ValueError('cli_fixture_citation_mismatch')
        backup = settings.data_dir / 'backup.db'
        with Database(settings.database_path, initialize=False) as db:
            if db.one('PRAGMA integrity_check')[0] != 'ok' or db.query('PRAGMA foreign_key_check'):
                raise ValueError('fixture_integrity_failed')
            for table in ('documents_fts', 'chunks_fts'):
                db.execute(f"INSERT INTO {table}({table}) VALUES('integrity-check')")
            db.commit()
            db.backup(backup)
        restored = settings.data_dir / 'restored.db'
        restore_database(backup, restored)
        restored_settings = Settings(root, settings.raw | {'database_path': str(restored)})
        restored_context = similar_experiences(restored_settings, 'Synthetic Unicode', project=str(project), max_chars=256)
        if restored_context != context or source.read_text(encoding='utf-8') != original or list(target.iterdir()):
            raise ValueError('fixture_restore_or_source_mismatch')
        report = {'mode': 'synthetic_cli_not_production_confirmation', 'cli_processes': calls,
                  'junction_rejected_before_index': True, 'cited_retrieval': True,
                  'context_chars': context['used_chars'], 'backup_restored': True,
                  'restored_context_equal': True, 'fts_integrity_checks': 2,
                  'sqlite_integrity': 'ok', 'sources_unchanged': True, 'production_records_written': 0}
    report.update(temporary_cleaned=not root.exists(), seconds=round(time.perf_counter()-started, 3))
    return report


if __name__ == '__main__':
    print(json.dumps(validate(), ensure_ascii=True, indent=2))
