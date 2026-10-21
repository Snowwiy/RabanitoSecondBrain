from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rabanito.config import load_settings


@unittest.skipUnless(os.name == 'nt', 'Native Windows configuration storage')
class ConfigStorageTests(unittest.TestCase):
    def setUp(self):
        parent=Path(__file__).resolve().parent/'.test-temp'
        parent.mkdir(exist_ok=True)
        self.temporary=tempfile.TemporaryDirectory(prefix='config-storage-',dir=parent)
        self.root=Path(self.temporary.name)
        self.vault=self.root/'vault';self.vault.mkdir()
        (self.root/'projects').mkdir()
        self.config=self.root/'settings.json'
        self.raw={'project_root':str(self.root),'data_dir':'data','database_path':'data/fixture.db',
                  'knowledge_dir':'knowledge','vault_root':'vault','projects_root':'projects'}

    def tearDown(self): self.temporary.cleanup()

    def save(self): self.config.write_text(json.dumps(self.raw),encoding='utf-8')

    def test_data_overlap_is_rejected_without_creating_source_directory(self):
        self.raw['data_dir']='vault/generated-not-authorized';self.save()
        with self.assertRaises(ValueError):load_settings(self.config)
        self.assertEqual(list(self.vault.iterdir()),[])
        self.assertFalse((self.root/'data').exists())
        self.assertFalse((self.root/'knowledge').exists())

    def test_knowledge_overlap_is_rejected_before_creating_any_storage(self):
        self.raw['knowledge_dir']='vault/generated-not-authorized';self.save()
        with self.assertRaises(ValueError):load_settings(self.config)
        self.assertEqual(list(self.vault.iterdir()),[])
        self.assertFalse((self.root/'data').exists())
        self.assertFalse((self.root/'knowledge').exists())

    def test_valid_startup_initializes_only_owned_roots_without_database_or_lock(self):
        self.save();before=(self.config.read_bytes(),self.config.stat().st_mtime_ns)
        settings=load_settings(self.config)
        self.assertTrue(settings.data_dir.is_dir())
        self.assertTrue(settings.knowledge_root.is_dir())
        self.assertEqual(list(settings.data_dir.iterdir()),[])
        self.assertEqual(list(settings.knowledge_root.iterdir()),[])
        self.assertEqual((self.config.read_bytes(),self.config.stat().st_mtime_ns),before)
        self.assertEqual(list(self.vault.iterdir()),[])

    def test_disabled_additional_source_overlap_is_rejected_before_creation(self):
        self.raw['additional_sources']=[{'path':str(self.root/'data'),'enabled':False}]
        self.save()
        with self.assertRaises(ValueError):load_settings(self.config)
        self.assertFalse((self.root/'data').exists())
        self.assertFalse((self.root/'knowledge').exists())

    def test_database_in_source_is_rejected_without_creating_roots(self):
        self.raw['database_path']='vault/generated-not-authorized.db';self.save()
        with self.assertRaises(ValueError):load_settings(self.config)
        self.assertEqual(list(self.vault.iterdir()),[])
        self.assertFalse((self.root/'data').exists())

    def test_existing_data_junction_is_rejected_without_following_it(self):
        import _winapi
        target=self.vault/'synthetic-target';target.mkdir()
        link=self.root/'data'
        _winapi.CreateJunction(str(target),str(link));self.save()
        try:
            with self.assertRaises(ValueError):load_settings(self.config)
            self.assertEqual(list(target.iterdir()),[])
            self.assertFalse((self.root/'knowledge').exists())
        finally:link.rmdir()

    def test_directory_swaps_during_creation_cannot_redirect_startup_writes(self):
        import _winapi
        target=self.vault/'synthetic-target';target.mkdir()
        actual=Path.mkdir
        for name in ('data','knowledge'):
            with self.subTest(name=name):
                link=self.root/name
                preserved=self.root/(name+'-preserved')
                def swap(path,*args,**kwargs):
                    result=actual(path,*args,**kwargs)
                    if path==link:
                        path.rename(preserved)
                        _winapi.CreateJunction(str(target),str(path))
                    return result
                self.save()
                try:
                    with patch('pathlib.Path.mkdir',swap),self.assertRaises(ValueError):load_settings(self.config)
                    self.assertEqual(list(target.iterdir()),[])
                finally:
                    if link.is_junction():link.rmdir()
                    if preserved.exists():preserved.rename(link)

    def test_parents_remain_pinned_while_other_root_is_created(self):
        actual=Path.mkdir;observed=[];knowledge=self.root/'knowledge';data=self.root/'data'
        def check(path,*args,**kwargs):
            if path==knowledge:
                for pinned in (self.root,data):
                    with self.assertRaises(OSError):pinned.rename(pinned.with_name(pinned.name+'-moved'))
                    observed.append(pinned)
            return actual(path,*args,**kwargs)
        self.save()
        with patch('pathlib.Path.mkdir',check):load_settings(self.config)
        self.assertEqual(observed,[self.root,data])

    def test_restored_database_outside_data_stays_authorized_without_being_opened(self):
        self.raw['database_path']='restored.db';self.save()
        settings=load_settings(self.config)
        self.assertEqual(settings.database_path,self.root/'restored.db')
        self.assertFalse(settings.database_path.exists())

    def test_database_identity_is_left_to_caller_without_startup_mutation(self):
        data=self.root/'data';data.mkdir()
        database=data/'fixture.db';database.write_bytes(b'Synthetic not-opened bytes')
        alias=self.root/'database-alias';os.link(database,alias)
        self.save()
        load_settings(self.config)
        self.assertEqual(alias.read_bytes(),b'Synthetic not-opened bytes')
        self.assertFalse((data/'index.lock').exists())

    def test_malformed_storage_values_are_rejected_before_any_directory_creation(self):
        for field,value in (('knowledge_dir',42),('vault_root',[]),('data_dir',None),
                            ('additional_sources',{}),('additional_sources',[42]),
                            ('additional_sources',[{'path':42}]),('project_root',42)):
            with self.subTest(field=field,value=value):
                original=dict(self.raw);self.raw[field]=value;self.save()
                try:
                    with self.assertRaises(ValueError):load_settings(self.config)
                    self.assertFalse((self.root/'data').exists())
                    self.assertFalse((self.root/'knowledge').exists())
                finally:self.raw=original

    def test_non_object_json_is_rejected_without_creating_storage(self):
        for value in ([],None,42,'synthetic'):
            with self.subTest(value=value):
                self.config.write_text(json.dumps(value),encoding='utf-8')
                with self.assertRaises(ValueError):load_settings(self.config)
                self.assertFalse((self.root/'data').exists())
                self.assertFalse((self.root/'knowledge').exists())

    def test_relative_root_with_unicode_and_spaces_preserves_existing_metadata(self):
        directory=self.root/'Configuración ñ';directory.mkdir()
        # Relative project_root is based on config.parent.parent, not the
        # directory containing the JSON. This is the existing portable contract.
        self.config=directory/'settings.json';self.raw['project_root']='.';self.save()
        first=load_settings(self.config)
        before=(first.data_dir.stat().st_mtime_ns,first.knowledge_root.stat().st_mtime_ns)
        second=load_settings(self.config)
        self.assertEqual(second.root,self.root)
        self.assertEqual(before,(second.data_dir.stat().st_mtime_ns,second.knowledge_root.stat().st_mtime_ns))

    def test_public_only_configuration_does_not_require_or_invent_private_roots(self):
        del self.raw['vault_root'];del self.raw['projects_root'];self.save()
        settings=load_settings(self.config)
        self.assertTrue(settings.data_dir.is_dir())
        self.assertTrue(settings.knowledge_root.is_dir())
        self.assertNotIn('vault_root',settings.raw)
        self.assertNotIn('projects_root',settings.raw)
        self.assertFalse(settings.database_path.exists())
        self.assertEqual(list(settings.data_dir.iterdir()),[])
