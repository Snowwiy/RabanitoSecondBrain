"""Real interactive CLI capture with synthetic input, no production memory.

Decline, secret rejection, junction denial, exact review, cited retrieval/restore.
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
from rabanito.interview import QUESTIONS
from rabanito.search import retrieve_context


def validate():
    if os.name != 'nt':
        raise ValueError('validation_requires_native_windows')
    import _winapi
    started = time.perf_counter()
    parent = ROOT / 'tests/.test-temp'
    parent.mkdir(exist_ok=True)
    calls = 0
    with tempfile.TemporaryDirectory(prefix='interview-storage-cli-', dir=parent) as directory:
        root = Path(directory)
        settings = Settings(root, {'project_root': str(root), 'database_path': 'data/fixture.db',
            'data_dir': 'data', 'knowledge_dir': 'knowledge', 'vault_root': 'vault', 'projects_root': 'projects',
            'source_policy': {'internal': {'extensions': ['.md']}}})
        for path in (settings.knowledge_root, settings.vault_root, settings.projects_root): path.mkdir()
        save_settings(settings)
        config = root / 'config/settings.json'
        topic = 'Synthetic entrevista ñ'
        answer = 'Synthetic Unicode ñ reviewed text, not a historical claim'
        def cli(*arguments, stdin=''):
            nonlocal calls
            calls += 1
            return subprocess.run([sys.executable, '-B', '-X', 'utf8', '-m', 'rabanito', '--config', str(config), *arguments],
                input=stdin, cwd=ROOT, capture_output=True, encoding='utf-8', timeout=30)
        def capture(approval, text=answer):
            return cli('interview', '--topic', topic, stdin='\n'.join([text]*len(QUESTIONS)+[approval])+'\n')
        def envelope(run):
            # Interactive prompts precede the existing final JSON envelope.
            start = run.stdout.rfind('\n{')
            if start < 0: raise ValueError('interactive_json_envelope_missing')
            return json.loads(run.stdout[start+1:])

        declined = capture('NO')
        if (declined.returncode or envelope(declined)['interview']['approved']
                or settings.database_path.exists() or list(settings.knowledge_root.rglob('*'))):
            raise ValueError('declined_capture_persisted')
        sensitive = capture('APROBAR', 'api_key = SYNTHETIC_INTERVIEW_CLI_MARKER')
        if (sensitive.returncode == 0 or 'SYNTHETIC_INTERVIEW_CLI_MARKER' in sensitive.stdout+sensitive.stderr
                or settings.database_path.exists() or list(settings.knowledge_root.rglob('*'))):
            raise ValueError('sensitive_capture_was_not_rejected_privately')
        target = settings.vault_root / 'not-authorized-for-writes'
        target.mkdir()
        link = settings.knowledge_root / 'personal'
        _winapi.CreateJunction(str(target), str(link))
        try:
            escaped = capture('APROBAR')
            if escaped.returncode == 0 or list(target.iterdir()) or settings.database_path.exists():
                raise ValueError('capture_junction_escape_not_rejected')
        finally:
            link.rmdir()  # Only this generated junction, never its target.

        approved = capture('APROBAR')
        if approved.returncode: raise ValueError('approved_capture_failed')
        result = envelope(approved)['interview']
        note = Path(result['path'])
        body = note.read_text(encoding='utf-8')
        marker = 'Los metadatos approved describen el estado propuesto solo si apruebas este texto exacto.\n'
        begin = approved.stdout.index(marker) + len(marker)
        end = approved.stdout.index('\nEscribe APROBAR', begin)
        shown = approved.stdout[begin:end]
        # print adds ONE newline after the exact Markdown candidate.
        if not shown.endswith('\n') or shown[:-1] != body:
            raise ValueError('cli_candidate_differs_from_saved_bytes')
        query = cli('context', 'Synthetic', '--source', 'internal', '--category', 'personal', '--limit', '1', '--max-chars', '256')
        if query.returncode: raise ValueError('capture_context_failed')
        context = json.loads(query.stdout)
        if not context['fragments'] or not 0 < context['characters'] <= 256:
            raise ValueError('capture_context_empty_or_unbounded')
        lines = body.splitlines()
        for fragment in context['fragments']:
            if (not fragment['relative_path'].startswith('personal/interviews/')
                    or not '\n'.join(lines[fragment['line_start']-1:fragment['line_end']]).startswith(fragment['text'])):
                raise ValueError('capture_citation_not_in_original')
        backup = settings.data_dir / 'backup.db'
        with Database(settings.database_path, initialize=False) as db:
            if db.one('PRAGMA integrity_check')[0] != 'ok' or db.query('PRAGMA foreign_key_check'):
                raise ValueError('fixture_integrity_failed')
            for table in ('documents_fts', 'chunks_fts'):
                db.execute(f"INSERT INTO {table}({table}) VALUES('integrity-check')")
            db.commit(); db.backup(backup)
        restored = settings.data_dir / 'restored.db'
        restore_database(backup, restored)
        restored_settings = Settings(root, settings.raw | {'database_path': str(restored)})
        observed = retrieve_context(restored_settings, 'Synthetic', source_kind='internal', category='personal', limit=1, max_chars=256)
        if observed != context or list(target.iterdir()):
            raise ValueError('capture_restore_or_source_mismatch')
        report = {'mode': 'synthetic_review_not_production_approval', 'cli_processes': calls,
            'declined_no_record': True, 'secret_rejected_before_preview': True,
            'junction_rejected_before_index': True, 'exact_preview_bytes': True,
            'approved_indexed_cited': True, 'context_chars': context['characters'],
            'fts_integrity_checks': 2, 'sqlite_integrity': 'ok', 'backup_restored': True,
            'restored_context_equal': True, 'source_target_unchanged': True,
            'production_records_written': 0, 'provider_requests': 0}
    report.update(temporary_cleaned=not root.exists(), seconds=round(time.perf_counter()-started, 3))
    return report


if __name__ == '__main__':
    print(json.dumps(validate(), ensure_ascii=True, indent=2))
