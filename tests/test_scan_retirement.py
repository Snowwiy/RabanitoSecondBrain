from __future__ import annotations

import copy
import os
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

from rabanito.config import Settings
from rabanito.db import Database
from rabanito.indexer import index_all
from rabanito import indexer

ROOT = Path(__file__).resolve().parents[1]


class ScanRetirementTests(unittest.TestCase):
    def setUp(self):
        parent=ROOT/'tests/.test-temp'
        parent.mkdir(exist_ok=True)
        temporary=tempfile.TemporaryDirectory(prefix='scan-retirement-',dir=parent)
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        for folder in ('vault','projects','knowledge'):(self.root/folder).mkdir()
        self.settings=Settings(self.root,{'vault_root':'vault','projects_root':'projects','knowledge_dir':'knowledge',
            'data_dir':'data','database_path':'data/brain.db','additional_sources':[],
            'source_policy':{kind:{'extensions':['.md']} for kind in ('obsidian','projects','internal')}})

    def seed(self,count=1,links=False):
        for number in range(count):
            targets=range(1,10 if number<30 else 9) if links else []
            text='# Fixture '+str(number)+'\n\n'+''.join('[[Note'+str((number+n)%count).zfill(3)+']]\n' for n in targets)
            (self.root/'vault'/f'Note{number:03}.md').write_text(text,encoding='utf-8')
        return index_all(self.settings)

    def active(self):
        with Database(self.settings.database_path,query_only=True) as db:
            return db.one("SELECT count(*) FROM documents WHERE status='active'")[0]

    def test_wrong_existing_empty_roots_cannot_retire_previous_338_documents(self):
        first=self.seed(338,links=True)
        self.assertEqual((first['files_seen'],self.active()),(338,338))
        with Database(self.settings.database_path,query_only=True) as db:
            self.assertEqual(db.one("SELECT count(*) FROM links WHERE status='resolved'")[0],2734)
        raw=copy.deepcopy(self.settings.raw)
        for field in ('vault_root','projects_root','knowledge_dir'):
            folder=self.root/('empty-'+field)
            folder.mkdir();raw[field]=str(folder)
        second=index_all(Settings(self.root,raw))
        self.assertEqual(second['files_seen'],0)
        self.assertEqual(second['removed'],0)
        self.assertNotEqual(second['status'],'ok')
        self.assertEqual(self.active(),338)
        restored=index_all(self.settings)
        self.assertEqual((restored['status'],restored['added'],self.active()),('ok',0,338))
        with Database(self.settings.database_path,query_only=True) as db:
            self.assertEqual(db.one("SELECT count(*) FROM links WHERE status='resolved'")[0],2734)

    def test_unprocessed_iterator_is_not_successful(self):
        self.seed()
        with patch('rabanito.indexer.iter_source_files',return_value=iter(())):
            result=index_all(self.settings)
        self.assertEqual(result['removed'],0)
        self.assertEqual(self.active(),1)
        self.assertEqual(result['status'],'error')

    def test_silent_empty_walk_does_not_confirm_existing_note_absent(self):
        self.seed()
        with patch('rabanito.indexer._iter_tree',return_value=iter(())):
            result=index_all(self.settings)
        self.assertEqual(result['removed'],0)
        self.assertNotEqual(result['status'],'ok')
        self.assertEqual(self.active(),1)

    def test_empty_authorized_new_sources_are_complete_not_unprocessed(self):
        result=index_all(self.settings)
        self.assertEqual((result['status'],result['files_seen'],result['removed']),('ok',0,0))
        self.assertEqual(result['scan_coverage']['completed_sources'],3)
        self.assertTrue(result['scan_coverage']['complete'])

    def test_single_legitimate_absence_can_be_retired(self):
        self.seed()
        (self.root/'vault/Note000.md').unlink()
        result=index_all(self.settings)
        self.assertEqual((result['status'],result['removed'],self.active()),('ok',1,0))
        self.assertTrue(result['scan_coverage']['complete'])

    def remove_notes(self):
        for path in (self.root/'vault').glob('*.md'):path.unlink()

    def test_mass_empty_source_requires_exact_review_then_can_retire(self):
        self.seed(12)
        self.remove_notes()
        blocked=index_all(self.settings)
        self.assertEqual((blocked['status'],blocked['removed'],self.active()),('partial',0,12))
        self.assertEqual(blocked['retirement_guard']['status'],'review_required')
        digest=blocked['retirement_guard']['approval_digest']
        self.assertEqual(len(digest),64)
        approved=index_all(self.settings,approve_retirements=digest)
        self.assertEqual((approved['status'],approved['removed'],self.active()),('ok',12,0))
        self.assertTrue(approved['retirement_guard']['approval_applied'])

    def test_force_is_not_approval(self):
        self.seed(10);self.remove_notes()
        result=index_all(self.settings,force=True)
        self.assertEqual((result['removed'],self.active()),(0,10))

    def test_wrong_or_stale_digest_never_authorizes_retirement(self):
        self.seed(12);self.remove_notes()
        digest=index_all(self.settings)['retirement_guard']['approval_digest']
        for value in ('0'*64,digest):
            # A different candidate set must not reuse the previous review.
            if value==digest:(self.root/'vault/Note000.md').write_text('# Returned fixture\n',encoding='utf-8')
            result=index_all(self.settings,approve_retirements=value)
            self.assertEqual(result['removed'],0)
            self.assertEqual(result['retirement_guard']['status'],'approval_rejected')
            self.assertEqual(self.active(),12)

    def test_invalid_approval_rejected_before_database_creation(self):
        for value in (True,12,'yes','a'*65):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(ValueError):index_all(self.settings,approve_retirements=value)
        self.assertFalse(self.settings.database_path.exists())

    def test_missing_root_preserves_documents(self):
        self.seed()
        (self.root/'vault').rename(self.root/'offline-vault')
        result=index_all(self.settings)
        self.assertEqual((result['status'],result['removed'],self.active()),('partial',0,1))

    def test_permission_denial_after_probe_preserves_missing_sibling(self):
        self.seed(2)
        (self.root/'vault/Note001.md').unlink()
        original=os.scandir;calls=0
        def deny_after_probe(path):
            nonlocal calls
            if Path(path)==self.settings.vault_root:
                calls+=1
                if calls>1:raise PermissionError('synthetic enumeration denial')
            return original(path)
        with patch('rabanito.indexer.os.scandir',side_effect=deny_after_probe):
            result=index_all(self.settings)
        self.assertEqual((result['status'],result['removed'],self.active()),('partial',0,2))

    def test_failed_subdirectory_preserves_source(self):
        self.seed(2)
        blocked=self.root/'vault/blocked';blocked.mkdir()
        (self.root/'vault/Note001.md').unlink()
        original=os.scandir
        def deny(path):
            if Path(path)==blocked:raise PermissionError('synthetic subtree denial')
            return original(path)
        with patch('rabanito.indexer.os.scandir',side_effect=deny):result=index_all(self.settings)
        self.assertEqual((result['status'],result['removed'],self.active()),('partial',0,2))

    def test_read_error_prevents_other_absence_retirement(self):
        self.seed(2)
        (self.root/'vault/Note001.md').unlink()
        original=indexer.read_source
        def deny(path,*args,**kwargs):
            if path==self.root/'vault/Note000.md':raise PermissionError('synthetic note denial')
            return original(path,*args,**kwargs)
        with patch('rabanito.indexer.read_source',side_effect=deny):result=index_all(self.settings)
        self.assertEqual((result['status'],result['removed'],self.active()),('partial',0,2))

    def test_parse_error_prevents_other_absence_retirement(self):
        self.seed(2);(self.root/'vault/Note001.md').unlink()
        with patch('rabanito.indexer.parse_markdown',return_value=SimpleNamespace(parse_error='fixture parse failure')):
            result=index_all(self.settings,force=True)
        self.assertEqual((result['status'],result['removed'],self.active()),('partial',0,2))

    def test_same_kind_removed_root_is_not_covered_by_sibling(self):
        self.seed()
        extra=self.root/'extra';extra.mkdir()
        (extra/'Extra.md').write_text('# Extra fixture\n',encoding='utf-8')
        self.settings.raw['additional_sources']=[{'path':str(extra),'kind':'obsidian'}]
        index_all(self.settings)
        self.settings.raw['additional_sources']=[]
        result=index_all(self.settings)
        self.assertEqual((result['status'],result['removed'],self.active()),('partial',0,2))

    def test_source_policy_mass_reduction_requires_review(self):
        self.seed(12)
        self.settings.raw['source_policy']['obsidian']['extensions']=['.rst']
        result=index_all(self.settings)
        self.assertEqual((result['removed'],self.active()),(0,12))
        self.assertEqual(result['retirement_guard']['status'],'review_required')

    def test_mass_project_disappearance_preserves_project_status_until_review(self):
        for number in range(10):
            root=self.root/'projects'/f'Project{number:02}'
            root.mkdir();(root/'README.md').write_text('# Fixture project\n',encoding='utf-8')
        index_all(self.settings)
        (self.root/'projects').rename(self.root/'projects-offline')
        (self.root/'projects').mkdir()
        blocked=index_all(self.settings)
        self.assertEqual(blocked['removed'],0)
        with Database(self.settings.database_path,query_only=True) as db:
            self.assertEqual(db.one("SELECT count(*) FROM projects WHERE status='active'")[0],10)
        approved=index_all(self.settings,approve_retirements=blocked['retirement_guard']['approval_digest'])
        self.assertEqual(approved['status'],'ok')
        with Database(self.settings.database_path,query_only=True) as db:
            self.assertEqual(db.one("SELECT count(*) FROM projects WHERE status='missing'")[0],10)

    def test_source_replaced_after_walk_is_not_a_complete_origin(self):
        self.seed()
        original=indexer.iter_source_files
        def replace_after_walk(*args,**kwargs):
            yield from original(*args,**kwargs)
            (self.root/'vault').rename(self.root/'previous-vault')
            (self.root/'vault').mkdir()
        with patch('rabanito.indexer.iter_source_files',side_effect=replace_after_walk):
            result=index_all(self.settings)
        self.assertEqual((result['status'],result['removed'],self.active()),('partial',0,1))

    def test_no_configured_sources_is_error_even_on_new_database(self):
        with patch.object(Settings,'source_roots',return_value=[]):result=index_all(self.settings)
        self.assertEqual((result['status'],result['files_seen'],result['removed']),('error',0,0))
        self.assertFalse(result['scan_coverage']['complete'])

    def test_configuration_mutation_during_scan_cannot_authorize_removals(self):
        self.seed();(self.root/'vault/Note000.md').unlink()
        original=indexer.iter_source_files
        def mutate(*args,**kwargs):
            yield from original(*args,**kwargs)
            args[0].raw['source_policy']['obsidian']['extensions']=['.rst']
        with patch('rabanito.indexer.iter_source_files',side_effect=mutate):result=index_all(self.settings)
        self.assertNotEqual(result['status'],'ok')
        self.assertEqual((result['removed'],self.active()),(0,1))

    def test_pending_guard_persisted_without_private_paths(self):
        self.seed(10);self.remove_notes()
        result=index_all(self.settings)
        with Database(self.settings.database_path,query_only=True) as db:
            saved=db.one("SELECT value FROM meta WHERE key='index_retirement_guard'")[0]
            self.assertEqual(db.one("SELECT count(*) FROM document_changes WHERE change_type='removed'")[0],0)
        self.assertEqual(json.loads(saved)['retirement_guard'],result['retirement_guard'])
        self.assertNotIn(str(self.root),saved)

    def test_cli_review_and_approval_use_real_temporary_processes(self):
        self.seed(12);self.remove_notes()
        config=self.root/'config/settings.json';config.parent.mkdir()
        config.write_text(json.dumps(self.settings.raw),encoding='utf-8')
        command=[sys.executable,'-B','-m','rabanito','--config',str(config),'index']
        blocked=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=30)
        self.assertEqual(blocked.returncode,2,blocked.stderr)
        value=json.loads(blocked.stdout)
        self.assertEqual((value['removed'],self.active()),(0,12))
        approved=subprocess.run(command+['--approve-retirements',value['retirement_guard']['approval_digest']],
            cwd=ROOT,capture_output=True,text=True,timeout=30)
        self.assertEqual(approved.returncode,0,approved.stderr)
        self.assertEqual((json.loads(approved.stdout)['removed'],self.active()),(12,0))

    def test_approval_does_not_bypass_failed_source(self):
        self.seed(12);self.remove_notes()
        digest=index_all(self.settings)['retirement_guard']['approval_digest']
        original=os.scandir
        def deny(path):
            if Path(path)==self.settings.vault_root:raise PermissionError('fixture source unavailable')
            return original(path)
        with patch('rabanito.indexer.os.scandir',side_effect=deny):
            result=index_all(self.settings,approve_retirements=digest)
        self.assertEqual((result['removed'],self.active()),(0,12))
        self.assertEqual(result['retirement_guard']['status'],'approval_rejected')

    def test_failed_kind_does_not_prevent_small_legitimate_other_source_retirement(self):
        self.seed()
        internal=self.settings.knowledge_root/'Fixture.md';internal.write_text('# Internal fixture\n',encoding='utf-8')
        index_all(self.settings);internal.unlink()
        original=os.scandir
        def deny(path):
            if Path(path)==self.settings.vault_root:raise PermissionError('fixture vault unavailable')
            return original(path)
        with patch('rabanito.indexer.os.scandir',side_effect=deny):result=index_all(self.settings)
        self.assertEqual((result['status'],result['removed'],self.active()),('partial',1,1))

    def test_replaced_empty_source_identity_needs_review_even_for_one_document(self):
        self.seed()
        (self.root/'vault').rename(self.root/'previous-vault')
        (self.root/'vault').mkdir()
        blocked=index_all(self.settings)
        self.assertEqual((blocked['status'],blocked['removed'],self.active()),('partial',0,1))
        self.assertEqual(blocked['retirement_guard']['changed_source_identities'],1)
        approved=index_all(self.settings,approve_retirements=blocked['retirement_guard']['approval_digest'])
        self.assertEqual((approved['status'],approved['removed'],self.active()),('ok',1,0))

    def test_legacy_database_without_identity_baseline_still_blocks_mass_removal(self):
        self.seed(10)
        with Database(self.settings.database_path) as db:
            db.execute("DELETE FROM meta WHERE key='index_source_bindings_v1'");db.commit()
        self.remove_notes()
        result=index_all(self.settings)
        self.assertEqual((result['removed'],self.active()),(0,10))

    def test_corrupt_binding_state_fails_closed_without_retirements(self):
        self.seed();self.remove_notes()
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE meta SET value='[]' WHERE key='index_source_bindings_v1'");db.commit()
        with self.assertRaisesRegex(ValueError,'invalid_index_source_bindings'):index_all(self.settings)
        self.assertEqual(self.active(),1)

    def test_conflicting_disabled_alias_is_not_retirement_authority(self):
        self.seed()
        self.settings.raw['additional_sources']=[{'path':str(self.settings.vault_root),'kind':'obsidian','enabled':False}]
        result=index_all(self.settings)
        self.assertEqual((result['status'],result['removed'],self.active()),('partial',0,1))


if __name__=='__main__':unittest.main()
