from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rabanito.capabilities import _write_report_pair
from rabanito.config import Settings, save_settings
from rabanito.report_storage import MAX_REPORT_BYTES, ReportPublicationError, publish_report_pair


@unittest.skipUnless(os.name == 'nt', 'Native Windows report storage')
class ReportStorageTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parent / '.test-temp'
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='report-storage-', dir=parent)
        self.root = Path(self.temporary.name)
        self.settings = Settings(self.root, {'project_root': str(self.root), 'database_path': 'data/test.db',
            'data_dir': 'data', 'knowledge_dir': 'knowledge', 'vault_root': 'vault', 'projects_root': 'projects'})
        for path in (self.settings.knowledge_root, self.settings.vault_root, self.settings.projects_root): path.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def write(self):
        return _write_report_pair(self.settings, 'audit', {'fixture': 'synthetic metadata'}, '# Synthetic report\n')

    def test_reports_cannot_overlap_an_imported_source(self):
        self.settings.raw['knowledge_dir'] = str(self.settings.vault_root)
        with self.assertRaises(ValueError): self.write()
        self.assertEqual(list(self.settings.vault_root.iterdir()), [])

    def test_directory_swap_after_initial_check_is_rejected(self):
        import _winapi
        directory = self.settings.knowledge_root / 'quality-reports'
        target = self.settings.vault_root / 'not-authorized-for-writes'
        target.mkdir()
        original = Path.mkdir
        def swap(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path == directory:
                path.rename(path.with_name('generated-preserved-directory'))
                _winapi.CreateJunction(str(target), str(path))
            return result
        try:
            with patch('pathlib.Path.mkdir', swap):
                with self.assertRaises(ValueError): self.write()
            self.assertEqual(list(target.iterdir()), [])
        finally:
            if directory.is_junction(): directory.rmdir()  # Generated junction only.

    def test_existing_junction_is_rejected_without_writes(self):
        import _winapi
        target = self.settings.vault_root / 'generated-target'
        target.mkdir()
        link = self.settings.knowledge_root / 'quality-reports'
        _winapi.CreateJunction(str(target), str(link))
        try:
            with self.assertRaises(ValueError): self.write()
            self.assertEqual(list(target.iterdir()), [])
        finally:
            link.rmdir()

    def test_directory_pin_blocks_swap_during_each_publication(self):
        from rabanito.report_storage import _publish
        def attempt(path, body):
            with self.assertRaises(OSError): path.parent.rename(path.parent.with_name('swapped-generated'))
            return _publish(path, body)
        with patch('rabanito.report_storage._publish', side_effect=attempt):
            pair = self.write()
        self.assertTrue(all(path.is_file() for path in pair))

    def test_disabled_sources_and_external_owned_roots_are_rejected(self):
        outside = self.root.parent / (self.root.name + '-outside-owned')
        cases = [
            {'knowledge_dir': str(outside)},
            {'data_dir': str(outside), 'database_path': str(outside / 'test.db')},
            {'additional_sources': [{'path': str(self.settings.knowledge_root), 'kind': 'local', 'enabled': False}]},
        ]
        original = copy.deepcopy(self.settings.raw)
        for values in cases:
            self.settings.raw.clear(); self.settings.raw.update(copy.deepcopy(original) | values)
            with self.subTest(values=tuple(values)), self.assertRaises(ValueError): self.write()
        self.assertFalse(outside.exists())

    def test_hardlinked_lock_is_not_modified(self):
        self.settings.data_dir.mkdir()
        lock = self.settings.data_dir / 'index.lock'
        lock.write_bytes(b'Synthetic foreign lock')
        alias = self.root / 'generated-lock-alias'
        os.link(lock, alias)
        try:
            with self.assertRaises(ValueError): self.write()
            self.assertEqual(alias.read_bytes(), b'Synthetic foreign lock')
        finally:
            alias.unlink()
        self.assertFalse((self.settings.knowledge_root / 'quality-reports').exists())

    def test_serialization_and_text_fail_before_creating_files(self):
        before = sorted(path.relative_to(self.root).as_posix() for path in self.root.rglob('*'))
        for value, markdown in (({'unsupported': object()}, '# Synthetic'), ({'invalid': float('nan')}, '# Synthetic'),
                                ({'valid': True}, 'Synthetic \ud800 invalid UTF-8'), ({'valid': True}, None)):
            with self.subTest(markdown_type=type(markdown).__name__), self.assertRaises((ValueError, TypeError)):
                _write_report_pair(self.settings, 'audit', value, markdown)
            self.assertEqual(before, sorted(path.relative_to(self.root).as_posix() for path in self.root.rglob('*')))

    def test_each_encoded_file_has_a_bounded_size(self):
        for value, markdown in (({'large': 'x'*MAX_REPORT_BYTES}, '# Synthetic'),
                                ({'valid': True}, 'x'*(MAX_REPORT_BYTES+1))):
            with self.assertRaisesRegex(ValueError, 'generated_report_size_limit'):
                _write_report_pair(self.settings, 'audit', value, markdown)
        self.assertFalse(self.settings.data_dir.exists())
        self.assertFalse(list(self.settings.knowledge_root.rglob('*')))

    def test_reports_larger_than_documented_note_budget_remain_supported(self):
        value = {'synthetic': 'x'*100000}
        pair = _write_report_pair(self.settings, 'audit', value, '# Synthetic ñ\n')
        self.assertGreater(pair[0].stat().st_size, 65536)
        self.assertEqual(json.loads(pair[0].read_text(encoding='utf-8')), value)
        self.assertEqual(pair[1].read_text(encoding='utf-8'), '# Synthetic ñ\n')

    def test_invalid_stem_or_stamp_never_creates_paths(self):
        for stem in ('', '../outside', 'x\\outside', 'x:stream', 'CON', 'a'*65):
            with self.subTest(stem=stem), self.assertRaises(ValueError):
                _write_report_pair(self.settings, stem, {}, '# Synthetic')
        with self.assertRaises(ValueError):
            publish_report_pair(self.settings, '../outside', 'audit', {}, '# Synthetic')
        self.assertFalse(list(self.settings.knowledge_root.rglob('*')))

    def test_second_publish_failure_preserves_complete_recoverable_artifact(self):
        from rabanito.report_storage import _publish
        def fail_second(path, body):
            if path.suffix == '.md': raise OSError('synthetic second publication failure')
            return _publish(path, body)
        with patch('rabanito.report_storage._publish', side_effect=fail_second):
            with self.assertRaises(ReportPublicationError) as raised: self.write()
        self.assertEqual(str(raised.exception), 'generated_report_pair_incomplete')
        self.assertEqual(len(raised.exception.published), 1)
        preserved = self.settings.knowledge_root / raised.exception.published[0]
        self.assertEqual(json.loads(preserved.read_text(encoding='utf-8')), {'fixture': 'synthetic metadata'})
        self.assertFalse(list(preserved.parent.glob('*.md')))
        self.assertFalse(list(preserved.parent.glob('*.tmp')))
        retry = self.write()
        self.assertNotEqual(preserved, retry[0])
        self.assertTrue(preserved.is_file())

    def test_racing_foreign_markdown_is_never_deleted_during_failure(self):
        from rabanito.report_storage import _publish
        foreign = []
        def race(path, body):
            if path.suffix == '.md':
                path.write_bytes(b'# Synthetic work by another actor\n')
                foreign.append(path)
            return _publish(path, body)
        with patch('rabanito.report_storage._publish', side_effect=race):
            with self.assertRaises(ReportPublicationError): self.write()
        self.assertEqual(foreign[0].read_bytes(), b'# Synthetic work by another actor\n')
        self.assertTrue(foreign[0].with_suffix('.json').is_file())

    def test_first_publish_failure_leaves_no_report_or_partial_file(self):
        with patch('rabanito.documented_store.os.rename', side_effect=OSError('synthetic disk failure')):
            with self.assertRaises(OSError): self.write()
        self.assertFalse(list(self.settings.knowledge_root.glob('quality-reports/*')))

    def test_existing_one_sided_pair_is_preserved_and_next_name_is_selected(self):
        directory = self.settings.knowledge_root / 'quality-reports'
        directory.mkdir()
        existing = directory / '20261018-120000-audit.md'
        existing.write_bytes(b'# Synthetic previous work\n')
        with patch('rabanito.capabilities.datetime') as clock:
            clock.now.return_value.strftime.return_value = '20261018-120000'
            pair = self.write()
        self.assertEqual(existing.read_bytes(), b'# Synthetic previous work\n')
        self.assertNotEqual(pair[1], existing)
        self.assertFalse(existing.with_suffix('.json').exists())

    def test_stale_configuration_is_rejected_before_report_creation(self):
        save_settings(self.settings)
        raw = copy.deepcopy(self.settings.raw)
        raw['stale_days'] = 123
        save_settings(Settings(self.root, raw))
        with self.assertRaisesRegex(ValueError, 'config_changed_reload_required'):
            _write_report_pair(self.settings, 'audit', {}, '# Synthetic', config_path=self.root/'config/settings.json')
        self.assertFalse(list(self.settings.knowledge_root.rglob('*')))

    def test_configuration_is_rechecked_after_waiting_for_index_lock(self):
        from contextlib import contextmanager
        from rabanito.indexer import _index_lock
        save_settings(self.settings)
        @contextmanager
        def changed(settings):
            raw = copy.deepcopy(settings.raw)
            raw['stale_days'] = 123
            save_settings(Settings(settings.root, raw))
            with _index_lock(settings): yield
        with patch('rabanito.report_storage._index_lock', changed):
            with self.assertRaisesRegex(ValueError, 'config_changed_reload_required'):
                _write_report_pair(self.settings, 'audit', {}, '# Synthetic', config_path=self.root/'config/settings.json')
        self.assertFalse(list(self.settings.knowledge_root.rglob('*')))

    def test_config_file_is_pinned_read_only_during_publication(self):
        from rabanito.report_storage import _publish
        save_settings(self.settings)
        config = self.root / 'config/settings.json'
        original = config.read_bytes()
        def attempt(path, body):
            with self.assertRaises(OSError): config.write_bytes(b'synthetic denied change')
            return _publish(path, body)
        with patch('rabanito.report_storage._publish', side_effect=attempt):
            pair = _write_report_pair(self.settings, 'audit', {}, '# Synthetic', config_path=config)
        self.assertEqual(config.read_bytes(), original)
        self.assertTrue(all(path.is_file() for path in pair))

    def test_reporting_does_not_require_or_initialize_sqlite(self):
        with patch('rabanito.documented_store.Database', side_effect=AssertionError('no SQLite')):
            pair = self.write()
        self.assertTrue(all(path.is_file() for path in pair))
        self.assertFalse(self.settings.database_path.exists())

    def test_index_exclusion_of_generated_reports_does_not_disable_the_export(self):
        self.settings.raw['source_policy'] = {'internal': {'extensions': ['.md'], 'exclude_dirs': ['quality-reports']}}
        pair = self.write()
        self.assertTrue(all(path.is_file() for path in pair))


if __name__ == '__main__':
    unittest.main()
