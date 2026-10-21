from __future__ import annotations

import copy
import os
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from rabanito.cli import main
from rabanito.config import Settings, save_settings
from rabanito.db import Database
from rabanito.decisions import add_memory_record
from rabanito.indexer import index_all
from rabanito.utils import sha256_text
import tests.test_coding_retrieval as fixtures


@unittest.skipUnless(os.name == 'nt', 'Native Windows decision writer')
class DecisionStorageTests(unittest.TestCase):
    setUp = fixtures.CodingMemoryTests.setUp
    tearDown = fixtures.CodingMemoryTests.tearDown

    def save(self, **overrides):
        values = dict(project=str(self.alpha), problem='Synthetic storage isolation test',
                      statement='Keep this synthetic record inside owned knowledge', status='proposed')
        values.update(overrides)
        return add_memory_record(self.settings, **values)

    def test_existing_junction_cannot_redirect_decision_into_a_source(self):
        import _winapi
        target = self.settings.vault_root / 'not-authorized-for-writes'
        target.mkdir()
        link = self.settings.knowledge_root / 'decisions'
        _winapi.CreateJunction(str(target), str(link))
        try:
            with self.assertRaises(ValueError):
                self.save()
            self.assertEqual(list(target.iterdir()), [])
        finally:
            link.rmdir()  # Only the generated junction, never its target.

    def test_project_directory_junction_is_rejected(self):
        import _winapi
        from rabanito.utils import path_key, slugify
        directory = self.settings.knowledge_root / 'decisions'
        directory.mkdir()
        link = directory / (slugify(self.alpha.name) + '-' + sha256_text(path_key(self.alpha))[:8])
        target = self.root / 'foreign-generated-target'
        target.mkdir()
        _winapi.CreateJunction(str(target), str(link))
        try:
            with self.assertRaises(ValueError): self.save()
            self.assertEqual(list(target.iterdir()), [])
        finally:
            link.rmdir()

    def test_pin_prevents_directory_swap_during_publish(self):
        from rabanito.decision_storage import publish_note
        def attempt(path, body):
            with self.assertRaises(OSError):
                path.parent.rename(path.parent.with_name('swapped-generated-directory'))
            return publish_note(path, body)
        with patch('rabanito.decisions.publish_note', side_effect=attempt):
            record = self.save()
        self.assertTrue(Path(record['path']).is_file())

    def test_racing_destination_is_not_overwritten(self):
        actual = os.rename
        foreign = b'# Synthetic work from a different writer\n'
        def race(source, destination):
            Path(destination).write_bytes(foreign)
            return actual(source, destination)
        with patch('rabanito.documented_store.os.rename', side_effect=race):
            with self.assertRaises(FileExistsError): self.save()
        notes = list(self.settings.knowledge_root.glob('decisions/*/*.md'))
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0].read_bytes(), foreign)
        self.assertFalse(list(notes[0].parent.glob('*.tmp')))

    def test_publish_failure_preserves_foreign_file_and_cleans_owned_temp(self):
        existing = self.settings.knowledge_root / 'keep.md'
        existing.write_text('# Synthetic existing knowledge\n', encoding='utf-8')
        with patch('rabanito.documented_store.os.rename', side_effect=OSError('fixture disk failure')):
            with self.assertRaises(OSError): self.save()
        self.assertEqual(existing.read_text(encoding='utf-8'), '# Synthetic existing knowledge\n')
        self.assertFalse(list(self.settings.knowledge_root.glob('decisions/*/*')))

    def test_storage_may_not_overlap_any_imported_source_even_if_disabled(self):
        raw = copy.deepcopy(self.settings.raw)
        cases = [
            {'knowledge_dir': str(self.settings.vault_root)},
            {'data_dir': str(self.settings.projects_root),
             'database_path': str(self.settings.projects_root / 'test.db')},
            {'additional_sources': [{'path': str(self.settings.knowledge_root), 'kind': 'local', 'enabled': False}]},
        ]
        for values in cases:
            with self.subTest(values=tuple(values)):
                current = Settings(self.root, raw | values)
                with self.assertRaises(ValueError):
                    add_memory_record(current, project=str(self.alpha), problem='Synthetic', statement='Synthetic')
        self.assertFalse((self.settings.knowledge_root / 'decisions').exists())

    def test_knowledge_and_data_must_be_inside_this_owned_root(self):
        outside = self.root.parent / (self.root.name + '-not-owned')
        for values in ({'knowledge_dir': str(outside)},
                       {'data_dir': str(outside), 'database_path': str(outside / 'test.db')}):
            with self.subTest(values=tuple(values)):
                with self.assertRaises(ValueError):
                    add_memory_record(Settings(self.root, self.settings.raw | values), project=str(self.alpha),
                                      problem='Synthetic', statement='Synthetic')
        self.assertFalse(outside.exists())

    def test_hardlinked_lock_and_database_are_rejected_before_changes(self):
        for original in (self.settings.data_dir / 'index.lock', self.settings.database_path):
            alias = self.root / 'generated-hardlink-copy'
            os.link(original, alias)
            before = alias.read_bytes()
            try:
                with self.subTest(original=original.name), self.assertRaises(ValueError): self.save()
                self.assertEqual(alias.read_bytes(), before)
            finally:
                alias.unlink()
        self.assertFalse((self.settings.knowledge_root / 'decisions').exists())

    def test_unsafe_sqlite_sidecar_is_rejected_before_database_access(self):
        target = self.root / 'foreign-generated-sidecar'
        target.write_bytes(b'Synthetic sidecar target, never a real database')
        for suffix in ('-wal', '-shm', '-journal'):
            link = Path(str(self.settings.database_path) + suffix)
            self.assertFalse(link.exists())
            os.link(target, link)
            try:
                with patch('rabanito.decisions._project_row', side_effect=AssertionError('must not open DB')):
                    with self.assertRaises(ValueError): self.save()
                self.assertEqual(target.read_bytes(), b'Synthetic sidecar target, never a real database')
            finally:
                link.unlink()

    def test_policy_denied_or_oversized_notes_do_not_create_knowledge(self):
        original = copy.deepcopy(self.settings.raw)
        cases = [({'exclude_dirs': ['decisions']}, {}), ({'extensions': ['.rst']}, {}),
                 ({'exclude_extensions': ['.md']}, {}), ({'max_file_bytes': 100}, {}),
                 ({}, {'alternatives': ['Synthetic ' + 'x'*8000] * 10})]
        for policy, arguments in cases:
            self.settings.raw.clear(); self.settings.raw.update(copy.deepcopy(original))
            self.settings.raw['source_policy']['internal'].update(policy)
            with self.subTest(policy=policy.keys()), self.assertRaises(ValueError): self.save(**arguments)
        self.assertFalse((self.settings.knowledge_root / 'decisions').exists())

    def test_invalid_windows_names_and_unsafe_root_types_are_rejected(self):
        for key, value in (('data_dir', True), ('database_path', None), ('database_path', 'data/CON.db'),
                           ('database_path', 'data/private:stream.db'), ('knowledge_dir', 'knowledge. ')):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                add_memory_record(Settings(self.root, self.settings.raw | {key: value}), project=str(self.alpha),
                                  problem='Synthetic', statement='Synthetic')

    def test_stale_cli_configuration_is_rejected_before_publication(self):
        save_settings(self.settings)
        path = self.root / 'config/settings.json'
        changed = copy.deepcopy(self.settings.raw)
        changed['source_policy']['internal']['exclude_dirs'] = ['decisions']
        save_settings(Settings(self.root, changed))
        with self.assertRaisesRegex(ValueError, 'config_changed_reload_required'):
            self.save(config_path=path)
        self.assertFalse((self.settings.knowledge_root / 'decisions').exists())

    def test_configuration_rechecked_after_waiting_for_lock(self):
        from contextlib import contextmanager
        from rabanito.indexer import _index_lock
        save_settings(self.settings)
        @contextmanager
        def change_before_lock(settings):
            raw = copy.deepcopy(settings.raw)
            raw['source_policy']['internal']['exclude_dirs'] = ['decisions']
            save_settings(Settings(settings.root, raw))
            with _index_lock(settings): yield
        with patch('rabanito.decision_storage._index_lock', change_before_lock):
            with self.assertRaisesRegex(ValueError, 'config_changed_reload_required'):
                self.save(config_path=self.root / 'config/settings.json')
        self.assertFalse((self.settings.knowledge_root / 'decisions').exists())

    def test_missing_index_is_not_initialized(self):
        other = self.root / 'data/missing.db'
        with self.assertRaises(ValueError):
            add_memory_record(Settings(self.root, self.settings.raw | {'database_path': str(other)}),
                              project=str(self.alpha), problem='Synthetic', statement='Synthetic')
        self.assertFalse(other.exists())

    def test_project_disappearing_under_lock_is_rejected(self):
        from contextlib import contextmanager
        from rabanito.decision_storage import memory_write_scope
        @contextmanager
        def disappear(*args, **kwargs):
            with Database(self.settings.database_path) as db:
                db.execute("UPDATE projects SET status='missing'")
            with memory_write_scope(*args, **kwargs) as tree: yield tree
        with patch('rabanito.decisions.memory_write_scope', disappear):
            with self.assertRaises(ValueError): self.save()
        self.assertFalse((self.settings.knowledge_root / 'decisions').exists())

    def test_concurrent_records_stay_distinct_and_sources_are_unchanged(self):
        before = {path: path.read_bytes() for path in self.settings.projects_root.glob('*/README.md')}
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda n: self.save(statement=f'Synthetic concurrent record {n}'), range(6)))
        self.assertEqual(len({row['path'] for row in results}), 6)
        self.assertTrue(all(Path(row['path']).is_file() for row in results))
        self.assertEqual(before, {path: path.read_bytes() for path in before})

    def test_cli_rejects_junction_before_implicit_index(self):
        import _winapi
        save_settings(self.settings)
        target = self.settings.vault_root / 'generated-target'
        target.mkdir()
        link = self.settings.knowledge_root / 'decisions'
        _winapi.CreateJunction(str(target), str(link))
        try:
            with patch('rabanito.cli.index_all', side_effect=AssertionError('must not index unsafe storage')):
                with self.assertRaises(ValueError):
                    main(['--config', str(self.root / 'config/settings.json'), 'decision', 'add',
                          '--project', str(self.alpha), '--problem', 'Synthetic', '--statement', 'Synthetic'])
            self.assertEqual(list(target.iterdir()), [])
        finally:
            link.rmdir()

    def test_roundtrip_remains_cited_and_store_does_not_implicitly_index(self):
        with Database(self.settings.database_path, read_only=True) as db:
            before = db.one('SELECT count(*) FROM documents')[0]
        record = self.save(status='confirmed', validation='passed', evidence=['project:README.md'])
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(before, db.one('SELECT count(*) FROM documents')[0])
            self.assertEqual(db.one('PRAGMA integrity_check')[0], 'ok')
        self.assertIn('kind: verified-memory', Path(record['path']).read_text(encoding='utf-8'))
        index_all(self.settings)
        from rabanito.coding_memory import similar_experiences
        found = similar_experiences(self.settings, 'Synthetic', project=str(self.alpha))
        self.assertEqual(len(found['results']), 1)
        self.assertEqual(found['results'][0]['validation'], 'passed_as_recorded_not_rerun')
        self.assertTrue(found['results'][0]['fragments'][0]['citation'].startswith('internal:decisions/'))


if __name__ == '__main__':
    unittest.main()
