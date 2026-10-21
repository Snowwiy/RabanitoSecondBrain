"""Native CLI indexing/rotation/restore with synthetic sources only."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from rabanito.config import Settings,save_settings
from rabanito.db import Database
from rabanito.utils import slugify


def validate():
    if os.name!='nt': raise ValueError('validation_requires_native_windows')
    import _winapi
    started=time.perf_counter()
    parent=ROOT/'tests/.test-temp';parent.mkdir(exist_ok=True)
    calls=0
    with tempfile.TemporaryDirectory(prefix='index-storage-cli-',dir=parent) as directory:
        root=Path(directory)
        settings=Settings(root,{'project_root':str(root),'database_path':'data/fixture.db','data_dir':'data',
            'knowledge_dir':'knowledge','vault_root':'vault','projects_root':'projects',
            'source_policy':{'obsidian':{'extensions':['.md']},'projects':{'extensions':['.md']},
                             'internal':{'extensions':['.md'],'exclude_dirs':['history','quality-reports']}}})
        for path in (settings.knowledge_root,settings.vault_root,settings.projects_root):path.mkdir()
        project=settings.projects_root/'Synthetic ñ';project.mkdir()
        readme=project/'README.md'
        readme.write_text('# Synthetic project\nDocumented local architecture.\n',encoding='utf-8')
        note=settings.vault_root/'Witness ñ.md'
        note_body='# Synthetic witness\nThis source must remain read only.\n'
        note.write_text(note_body,encoding='utf-8')
        save_settings(settings)
        config=root/'config/settings.json'
        def cli(*arguments):
            nonlocal calls
            calls+=1
            return subprocess.run([sys.executable,'-B','-X','utf8','-m','rabanito','--config',str(config),*arguments],
                cwd=ROOT,capture_output=True,encoding='utf-8',timeout=30)
        target=settings.vault_root/'not-authorized-for-writes';target.mkdir()
        link=settings.knowledge_root/'projects'
        _winapi.CreateJunction(str(target),str(link))
        try:
            denied=cli('index')
            if denied.returncode==0 or list(target.iterdir()) or settings.database_path.exists():
                raise ValueError('unsafe_profile_root_not_rejected_before_database')
        finally:link.rmdir()
        inventory=cli('projects','--json')
        if inventory.returncode or len(json.loads(inventory.stdout))!=1:
            raise ValueError('controlled_project_discovery_failed')
        first=cli('index')
        if first.returncode:raise ValueError('first_synthetic_index_failed')
        profile=settings.knowledge_root/'projects'/slugify(project.name)/'PROJECT_MEMORY.md'
        with profile.open('a',encoding='utf-8') as stream:stream.write('\n## Manual text\nPreserve this reviewed synthetic note.\n')
        old=profile.read_bytes()
        with Database(settings.database_path,read_only=True) as db:
            document_id=db.one('SELECT document_id FROM documents WHERE absolute_path=?',(str(profile),))[0]
        updated='# Synthetic project\nUpdated SQLite architecture documented in this fixture.\n'
        readme.write_text(updated,encoding='utf-8')  # Deliberate fixture change, not application output.
        second=cli('index')
        if second.returncode or not json.loads(second.stdout)['modified']:raise ValueError('incremental_update_failed')
        if b'Preserve this reviewed synthetic note.' not in profile.read_bytes():raise ValueError('manual_text_lost')
        backups=list(profile.parent.glob('.rabanito-profile-*.bak'))
        if len(backups)!=1 or backups[0].read_bytes()!=old:raise ValueError('previous_profile_not_recoverable')
        stable=(profile.read_bytes(),profile.stat().st_mtime_ns)
        third=cli('index')
        if third.returncode or stable!=(profile.read_bytes(),profile.stat().st_mtime_ns):
            raise ValueError('unchanged_profile_rewritten')
        if len(list(profile.parent.glob('*.bak')))!=1:raise ValueError('unchanged_scan_created_backup')
        args=('context','Updated SQLite','--source','projects','--limit','1','--max-chars','200')
        retrieved=cli(*args)
        if retrieved.returncode:raise ValueError('cited_context_failed')
        context=json.loads(retrieved.stdout)
        if not context['fragments'] or not 0<context['characters']<=200:raise ValueError('context_empty_or_unbounded')
        for fragment in context['fragments']:
            lines=updated.splitlines()
            if not '\n'.join(lines[fragment['line_start']-1:fragment['line_end']]).startswith(fragment['text']):
                raise ValueError('citation_not_in_original')
        backup=settings.data_dir/'backup.db'
        saved=cli('backup','--path',str(backup))
        if saved.returncode:raise ValueError('cli_backup_failed')
        restored=cli('restore',str(backup),'--yes')
        if restored.returncode:raise ValueError('cli_restore_failed')
        check=cli(*args)
        if check.returncode or json.loads(check.stdout)!=context:raise ValueError('restored_context_mismatch')
        with Database(settings.database_path,initialize=False) as db:
            if db.one('PRAGMA integrity_check')[0]!='ok' or db.query('PRAGMA foreign_key_check'):
                raise ValueError('fixture_integrity_failed')
            if db.one('SELECT document_id FROM documents WHERE absolute_path=?',(str(profile),))[0]!=document_id:
                raise ValueError('profile_document_id_changed')
            if db.query("SELECT document_id FROM documents WHERE relative_path LIKE '%.bak'"):
                raise ValueError('previous_profile_backup_indexed_as_document')
            for table in ('documents_fts','chunks_fts'):db.execute(f"INSERT INTO {table}({table}) VALUES('integrity-check')")
        if note.read_text(encoding='utf-8')!=note_body or readme.read_text(encoding='utf-8')!=updated or list(target.iterdir()):
            raise ValueError('source_changed_by_indexer')
        report={'mode':'synthetic_cli_not_production_memory','cli_processes':calls,
            'unsafe_root_rejected_before_database':True,'project_discovery':True,'incremental_update':True,
            'profile_id_stable':True,'manual_text_preserved':True,'previous_profile_bytes_preserved':True,
            'unchanged_no_profile_write_or_backup':True,'backups_not_indexed':True,
            'context_chars':context['characters'],'backup_restored':True,'restored_context_equal':True,
            'fts_integrity_checks':2,'sqlite_integrity':'ok','source_unchanged':True,
            'production_records_written':0,'provider_requests':0}
    report.update(temporary_cleaned=not root.exists(),seconds=round(time.perf_counter()-started,3))
    return report


if __name__=='__main__':print(json.dumps(validate(),ensure_ascii=True,indent=2))
