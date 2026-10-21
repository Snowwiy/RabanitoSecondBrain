from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from rabanito.config import Settings
from unittest.mock import patch
from rabanito.db import Database
from rabanito.indexer import _index_lock, index_all, project_inventory
from rabanito.index_storage import ProfileRecoveryError
from rabanito.utils import slugify


@unittest.skipUnless(os.name == 'nt', 'Native Windows indexing storage')
class IndexStorageTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parent / '.test-temp'
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='index-storage-', dir=parent)
        self.root = Path(self.temporary.name)
        self.settings = Settings(self.root, {'project_root':str(self.root),'database_path':'data/test.db',
            'data_dir':'data','knowledge_dir':'knowledge','vault_root':'vault','projects_root':'projects',
            'source_policy':{'projects':{'extensions':['.md']},'internal':{'extensions':['.md']}}})
        for path in (self.settings.knowledge_root,self.settings.vault_root,self.settings.projects_root): path.mkdir()
        self.project = self.settings.projects_root / 'Synthetic ñ'
        self.project.mkdir()
        (self.project/'README.md').write_text('# Synthetic project\nDocumented local architecture.\n',encoding='utf-8')

    def tearDown(self): self.temporary.cleanup()

    def test_project_profile_junction_cannot_redirect_into_source(self):
        import _winapi
        target = self.settings.vault_root/'generated-profile-target'; target.mkdir()
        link = self.settings.knowledge_root/'projects'
        _winapi.CreateJunction(str(target),str(link))
        try:
            with self.assertRaises(ValueError): index_all(self.settings)
            self.assertEqual(list(target.iterdir()),[])
        finally: link.rmdir()

    def test_history_junction_cannot_redirect_into_source(self):
        import _winapi
        target = self.settings.vault_root/'generated-history-target'; target.mkdir()
        link = self.settings.knowledge_root/'history'
        _winapi.CreateJunction(str(target),str(link))
        try:
            with self.assertRaises(ValueError): index_all(self.settings)
            self.assertEqual(list(target.iterdir()),[])
        finally: link.rmdir()

    def test_imported_database_root_is_rejected_before_creating_sqlite(self):
        self.settings.raw['data_dir']=str(self.settings.vault_root)
        self.settings.raw['database_path']=str(self.settings.vault_root/'foreign.db')
        with self.assertRaises(ValueError): index_all(self.settings)
        self.assertEqual(list(self.settings.vault_root.iterdir()),[])

    def profile(self):
        return self.settings.knowledge_root/'projects'/slugify(self.project.name)/'PROJECT_MEMORY.md'

    def changed_profile(self):
        index_all(self.settings)
        path = self.profile()
        with path.open('a',encoding='utf-8') as stream: stream.write('\n## Manual note\nKeep this reviewed manual text.\n')
        before = path.read_bytes()
        (self.project/'README.md').write_text('# Synthetic project\nUpdated documented architecture with SQLite transactions.\n',encoding='utf-8')
        return path,before

    def test_generated_reparse_roots_fail_before_opening_database(self):
        import _winapi
        target=self.settings.vault_root/'generated-target';target.mkdir()
        link=self.settings.knowledge_root/'projects'
        _winapi.CreateJunction(str(target),str(link))
        try:
            with patch('rabanito.indexer.Database',side_effect=AssertionError('must reject before SQLite')):
                with self.assertRaises(ValueError): index_all(self.settings)
            self.assertFalse(self.settings.database_path.exists())
        finally: link.rmdir()

    def test_data_directory_swap_during_creation_cannot_redirect_lock_or_db(self):
        import _winapi
        data=self.settings.data_dir
        target=self.settings.vault_root/'generated-data-target';target.mkdir()
        actual=Path.mkdir
        def swap(path,*args,**kwargs):
            result=actual(path,*args,**kwargs)
            if path==data:
                path.rename(path.with_name('generated-preserved-data'))
                _winapi.CreateJunction(str(target),str(path))
            return result
        try:
            with patch('pathlib.Path.mkdir',swap):
                with self.assertRaises(ValueError): index_all(self.settings)
            self.assertEqual(list(target.iterdir()),[])
        finally:
            if data.is_junction(): data.rmdir()

    def test_profile_directory_swap_during_creation_fails_before_sqlite(self):
        import _winapi
        directory=self.settings.knowledge_root/'projects'
        target=self.settings.vault_root/'generated-profile-target';target.mkdir()
        actual=Path.mkdir
        def swap(path,*args,**kwargs):
            result=actual(path,*args,**kwargs)
            if path==directory:
                path.rename(path.with_name('generated-preserved-projects'))
                _winapi.CreateJunction(str(target),str(path))
            return result
        try:
            with patch('pathlib.Path.mkdir',swap):
                with self.assertRaises(ValueError): index_all(self.settings)
            self.assertFalse(self.settings.database_path.exists())
            self.assertEqual(list(target.iterdir()),[])
        finally:
            if directory.is_junction(): directory.rmdir()

    def test_hardlinked_database_is_rejected_without_changes(self):
        index_all(self.settings)
        alias=self.root/'generated-db-alias'
        os.link(self.settings.database_path,alias)
        original=alias.read_bytes()
        try:
            with self.assertRaises(ValueError): index_all(self.settings)
            self.assertEqual(alias.read_bytes(),original)
        finally: alias.unlink()

    def test_unsafe_sidecar_is_rejected_before_creating_database(self):
        self.settings.data_dir.mkdir()
        target=self.root/'generated-foreign-sidecar'
        target.write_bytes(b'Synthetic sidecar bytes')
        for suffix in ('-wal','-shm','-journal'):
            alias=Path(str(self.settings.database_path)+suffix)
            os.link(target,alias)
            try:
                with self.subTest(suffix=suffix),self.assertRaises(ValueError): index_all(self.settings)
                self.assertFalse(self.settings.database_path.exists())
                self.assertEqual(target.read_bytes(),b'Synthetic sidecar bytes')
            finally: alias.unlink()

    def test_hardlinked_profile_is_not_read_or_replaced(self):
        path=self.profile();path.parent.mkdir(parents=True)
        source=self.project/'README.md'
        before=source.read_bytes()
        os.link(source,path)
        try:
            with self.assertRaises(ValueError): index_all(self.settings)
            self.assertEqual(source.read_bytes(),before)
            self.assertEqual(path.read_bytes(),before)
        finally: path.unlink()

    def test_updates_preserve_manual_text_previous_bytes_and_document_id(self):
        path,before=self.changed_profile()
        with Database(self.settings.database_path,read_only=True) as db:
            document_id=db.one('SELECT document_id FROM documents WHERE absolute_path=?',(str(path),))[0]
        source=(self.project/'README.md').read_bytes()
        result=index_all(self.settings)
        self.assertEqual(result['status'],'ok')
        self.assertIn('Updated documented architecture',path.read_text(encoding='utf-8'))
        self.assertIn('Keep this reviewed manual text.',path.read_text(encoding='utf-8'))
        backups=list(path.parent.glob('.rabanito-profile-*.bak'))
        self.assertEqual(len(backups),1)
        self.assertEqual(backups[0].read_bytes(),before)
        with Database(self.settings.database_path,read_only=True) as db:
            self.assertEqual(document_id,db.one('SELECT document_id FROM documents WHERE absolute_path=?',(str(path),))[0])
            self.assertFalse(db.query("SELECT * FROM documents WHERE relative_path LIKE '%.bak'"))
        self.assertEqual((self.project/'README.md').read_bytes(),source)

    def test_unchanged_profile_has_no_new_backups_and_keeps_mtime(self):
        index_all(self.settings)
        path=self.profile();before=(path.read_bytes(),path.stat().st_mtime_ns)
        index_all(self.settings)
        self.assertEqual(before,(path.read_bytes(),path.stat().st_mtime_ns))
        self.assertEqual(list(path.parent.glob('*.bak')),[])

    def test_concurrent_leaf_change_is_restored_not_overwritten(self):
        path,before=self.changed_profile()
        rename=os.rename
        foreign=b'# Synthetic concurrent manual change\n'
        done=False
        def race(source,target):
            nonlocal done
            if Path(source)==path and not done:
                path.write_bytes(foreign);done=True
            return rename(source,target)
        with patch('rabanito.index_storage.os.rename',side_effect=race):
            with self.assertRaisesRegex(ValueError,'project_profile_changed_retry_required'): index_all(self.settings)
        self.assertEqual(path.read_bytes(),foreign)
        self.assertEqual(list(path.parent.glob('*.bak')),[])

    def test_failed_new_publication_restores_previous_full_profile(self):
        path,before=self.changed_profile()
        from rabanito.documented_store import _publish
        def fail(target,body):
            if target==path: raise OSError('synthetic profile publication failure')
            return _publish(target,body)
        with patch('rabanito.documented_store._publish',side_effect=fail):
            with self.assertRaises(OSError): index_all(self.settings)
        self.assertEqual(path.read_bytes(),before)
        self.assertEqual(list(path.parent.glob('*.bak')),[])

    def test_failed_restore_preserves_concurrent_target_and_old_backup(self):
        path,before=self.changed_profile()
        from rabanito.documented_store import _publish
        foreign=b'# Synthetic work created after rotation\n'
        def collide(target,body):
            if target==path: target.write_bytes(foreign)
            return _publish(target,body)
        with patch('rabanito.documented_store._publish',side_effect=collide):
            with self.assertRaises(ProfileRecoveryError) as raised: index_all(self.settings)
        self.assertEqual(path.read_bytes(),foreign)
        backup=self.settings.knowledge_root/raised.exception.backup
        self.assertEqual(backup.read_bytes(),before)

    def test_directory_pin_prevents_swap_during_profile_publication(self):
        from rabanito.documented_store import _publish
        def attempt(path,body):
            if path.name=='PROJECT_MEMORY.md':
                with self.assertRaises(OSError): path.parent.rename(path.parent.with_name('generated-swap'))
            return _publish(path,body)
        with patch('rabanito.documented_store._publish',side_effect=attempt): index_all(self.settings)
        self.assertTrue(self.profile().is_file())

    def test_history_collision_never_overwrites_the_previous_record(self):
        from datetime import datetime
        class FrozenHistory(datetime):
            def strftime(self,pattern):
                return '20261018-120000-000000' if pattern=='%Y%m%d-%H%M%S-%f' else super().strftime(pattern)
        with patch('rabanito.indexer.datetime',FrozenHistory):
            index_all(self.settings)
            folder=self.settings.knowledge_root/'history/index-runs'
            first=next(folder.glob('*.json'));before=first.read_bytes()
            index_all(self.settings)
        self.assertEqual(len(list(folder.glob('*.json'))),2)
        self.assertEqual(first.read_bytes(),before)

    def test_index_lock_supports_public_only_settings_without_private_sources(self):
        settings=Settings(self.root,{'data_dir':'public-data','database_path':'public-data/public.db'})
        with _index_lock(settings):
            self.assertTrue((settings.data_dir/'index.lock').is_file())
        self.assertFalse(settings.database_path.exists())

    def test_changed_storage_binding_after_waiting_for_lock_is_rejected(self):
        from contextlib import contextmanager
        @contextmanager
        def changed(_locked):
            self.settings.raw['database_path']='data/changed.db'
            yield
        with patch('rabanito.indexer._raw_index_lock',changed):
            with self.assertRaisesRegex(ValueError,'index_lock_configuration_changed_reload_required'):
                index_all(self.settings)
        self.assertFalse(self.settings.database_path.exists())

    def test_inventory_entry_uses_same_storage_guards(self):
        self.settings.raw['data_dir']=str(self.settings.vault_root)
        self.settings.raw['database_path']=str(self.settings.vault_root/'foreign.db')
        with self.assertRaises(ValueError): project_inventory(self.settings)
        self.assertEqual(list(self.settings.vault_root.iterdir()),[])

    def test_disabled_source_overlap_is_rejected_before_sqlite(self):
        self.settings.raw['additional_sources']=[{'path':str(self.settings.knowledge_root),'kind':'local','enabled':False}]
        with self.assertRaises(ValueError): index_all(self.settings)
        self.assertFalse(self.settings.database_path.exists())

    def test_minimal_lock_only_namespace_does_not_invent_a_database(self):
        from types import SimpleNamespace
        settings=SimpleNamespace(raw={'index_lock_timeout_seconds':1},data_dir=self.root/'lock-only')
        with _index_lock(settings): self.assertTrue((settings.data_dir/'index.lock').is_file())
        self.assertEqual({path.name for path in settings.data_dir.iterdir()},{'index.lock'})

    def test_restored_database_can_live_elsewhere_in_the_owned_root(self):
        index_all(self.settings)
        restored=self.root/'restored.db'
        with Database(self.settings.database_path,read_only=True) as db:
            db.backup(restored)
            before=db.one('SELECT count(*) FROM scan_runs')[0]
        settings=Settings(self.root,self.settings.raw|{'database_path':str(restored)})
        result=index_all(settings)
        self.assertEqual(result['status'],'ok')
        self.assertEqual(result['added'],0)
        with Database(self.settings.database_path,read_only=True) as db:
            self.assertEqual(before,db.one('SELECT count(*) FROM scan_runs')[0])
        with Database(restored,read_only=True) as db:
            self.assertEqual(before+1,db.one('SELECT count(*) FROM scan_runs')[0])

    def test_missing_internal_root_is_not_recreated_or_tombstoned(self):
        index_all(self.settings)
        previous=self.settings.knowledge_root
        missing=self.root/'unavailable-knowledge'
        self.settings.raw['knowledge_dir']=str(missing)
        result=index_all(self.settings)
        self.assertEqual(result['status'],'partial')
        self.assertFalse(missing.exists())
        self.assertTrue(previous.is_dir())
        with Database(self.settings.database_path,read_only=True) as db:
            self.assertTrue(db.one("SELECT count(*) FROM documents WHERE source_kind='internal' AND status='active'")[0])

    def test_racing_history_file_is_preserved_and_another_name_is_used(self):
        from rabanito.documented_store import _publish
        foreign=[]
        def collide(path,body):
            if path.parent.name=='index-runs' and not foreign:
                path.write_bytes(b'{"synthetic_foreign_history":true}\n')
                foreign.append(path)
            return _publish(path,body)
        with patch('rabanito.documented_store._publish',side_effect=collide):
            result=index_all(self.settings)
        self.assertEqual(result['status'],'ok')
        self.assertEqual(foreign[0].read_bytes(),b'{"synthetic_foreign_history":true}\n')
        self.assertEqual(len(list(foreign[0].parent.glob('*.json'))),2)


if __name__ == '__main__': unittest.main()
