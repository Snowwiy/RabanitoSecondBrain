from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from rabanito.capabilities import collect_audit, dashboard_audit_view, level_up, write_audit
from rabanito.audit_inventory import inspect_source_inventory
from rabanito.config import Settings
from rabanito.db import Database
from rabanito.indexer import index_all
from rabanito.utils import path_key, sha256_text
from rabanito.visibility import register_project_visibility


ROOT = Path(__file__).resolve().parents[1]


class AuditInventoryTests(unittest.TestCase):
    def setUp(self):
        parent = ROOT / 'tests/.test-temp'
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='audit-inventory-', dir=parent)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ('vault', 'projects', 'knowledge'):
            (self.root / name).mkdir()
        self.settings = Settings(self.root, {
            'vault_root': 'vault', 'projects_root': 'projects', 'knowledge_dir': 'knowledge',
            'data_dir': 'data', 'database_path': 'data/brain.db', 'additional_sources': [],
            'source_policy': {kind: {
                'extensions': ['.md'], 'exclude_dirs': ['private', 'quality-reports'],
                'exclude_names': ['confidential.md'],
            } for kind in ('obsidian', 'projects', 'internal')},
        })

    def put(self, relative, content='# Example\n'):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
        return path

    def inventory(self):
        return collect_audit(self.settings)['source_inventory']

    def direct(self):
        with Database(self.settings.database_path, query_only=True, empty_if_missing=True) as db:
            db.execute('BEGIN')
            register_project_visibility(db, self.settings)
            return inspect_source_inventory(db, self.settings)

    def test_new_note_detected_without_sync(self):
        self.put('vault/Indexed.md')
        index_all(self.settings)
        before = collect_audit(self.settings)
        self.put('vault/Nueva raíz ñ.md', '# Private fixture body\n')
        after = collect_audit(self.settings)
        inventory = after['source_inventory']
        self.assertEqual(before['counts'], after['counts'])
        self.assertEqual(inventory['unindexed_files'], 1)
        self.assertTrue(inventory['coverage_complete'])
        self.assertEqual(inventory['findings'], [{
            'source_kind': 'obsidian', 'relative_path': 'Nueva raíz ñ.md',
            'status': 'not_indexed', 'review_only': True,
        }])
        self.assertNotIn('Private fixture body', json.dumps(after))
        self.assertNotIn(str(self.root), json.dumps(after))

    def test_first_use_no_database_or_profiles_created(self):
        self.put('projects/NewProject/README.md')
        self.put('vault/First.md')
        result = self.inventory()
        self.assertEqual(result['new_project_roots'], 1)
        self.assertEqual(result['unindexed_files'], 2)
        self.assertFalse(self.settings.database_path.exists())
        self.assertEqual(list(self.settings.knowledge_root.iterdir()), [])

    def test_exclusions_and_large_files(self):
        self.put('vault/.env', 'secret fixture')
        self.put('vault/confidential.md')
        self.put('vault/private/Private.md')
        self.put('vault/.git/Private.md')
        self.put('vault/Allowed.md')
        self.put('vault/Large.md', 'x' * 101)
        self.settings.raw['max_document_bytes'] = 100
        result = self.inventory()
        self.assertEqual(result['eligible_files'], 1)
        self.assertEqual(result['oversized_files'], 1)
        self.assertTrue(result['coverage_complete'])
        self.assertEqual([f['relative_path'] for f in result['findings']], ['Allowed.md'])

    def test_project_root_rule_and_no_registration(self):
        self.put('projects/Root/README.md')
        self.put('projects/Root/Component/package.json', '{}')
        self.put('projects/Root/Component/README.md')
        self.put('projects/Root/Nested/.git', 'gitdir: not read')
        self.put('projects/Root/Nested/README.md')
        self.put('projects/Loose.md')
        result = self.inventory()
        self.assertEqual(result['new_project_roots'], 2)
        self.assertEqual(result['eligible_files'], 3)
        self.assertFalse(self.settings.database_path.exists())

    def test_missing_root_is_partial_without_absolute_error(self):
        self.settings.raw['vault_root'] = 'absent'
        result = self.inventory()
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['roots_unavailable'], 1)
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_dashboard_exposes_additive_section(self):
        self.put('vault/New.md')
        report = collect_audit(self.settings)
        self.assertEqual(dashboard_audit_view(report)['source_inventory'], report['source_inventory'])
        legacy = dict(report)
        legacy.pop('source_inventory')
        self.assertFalse(dashboard_audit_view(legacy)['source_inventory']['performed'])
        self.assertFalse(dashboard_audit_view(legacy)['source_inventory']['coverage_complete'])

    def test_existing_rows_not_written(self):
        self.put('vault/Indexed.md')
        index_all(self.settings)
        with Database(self.settings.database_path, query_only=True) as db:
            before = list(db.connection.iterdump())
        self.put('vault/New.md')
        self.assertEqual(self.inventory()['unindexed_files'], 1)
        with Database(self.settings.database_path, query_only=True) as db:
            self.assertEqual(before, list(db.connection.iterdump()))

    def test_repeat_inventory_does_not_consume_new_note(self):
        self.put('vault/New.md')
        self.assertEqual(self.inventory(), self.inventory())
        index_all(self.settings)
        after = self.inventory()
        self.assertEqual(after['unindexed_files'], 0)
        self.assertEqual(after['indexed_files'], 1)

    def test_no_note_manifest_or_marker_content_opened(self):
        self.put('projects/P/.git', 'private fixture marker, not instructions')
        self.put('projects/P/README.md', 'private fixture content')
        self.put('projects/P/package.json', '{}')
        self.put('vault/New.md', 'private fixture content')
        self.settings.raw['source_policy']['projects']['metadata_names'] = ['package.json']
        with patch.object(Path, 'open', side_effect=AssertionError('content opened')), \
                patch('builtins.open', side_effect=AssertionError('content opened')):
            result = self.inventory()
        self.assertEqual(result['unindexed_files'], 3)
        self.assertFalse(self.settings.database_path.exists())

    def test_disabled_source_is_not_enumerated(self):
        other = self.root / 'disabled'
        self.put('disabled/Private.md')
        self.settings.raw['additional_sources'] = [
            {'kind': 'local', 'path': str(other), 'enabled': False},
        ]
        original = os.scandir
        def guarded(path):
            self.assertNotEqual(Path(path), other)
            return original(path)
        with patch('rabanito.audit_inventory.os.scandir', side_effect=guarded):
            result = self.inventory()
        self.assertEqual(result['roots_total'], 3)
        self.assertEqual(result['eligible_files'], 0)

    def test_duplicate_source_is_not_double_counted(self):
        self.put('vault/New.md')
        self.settings.raw['additional_sources'] = [
            {'kind': 'obsidian', 'path': str(self.settings.vault_root)},
            {'kind': 'local', 'path': str(self.settings.vault_root)},
        ]
        result = self.inventory()
        self.assertEqual(result['eligible_files'], 1)
        self.assertEqual(result['unindexed_files'], 1)

    def test_project_exclusion_hides_profile_and_nested_repository(self):
        self.put('projects/Restricted/Nested/.git', 'not opened')
        self.put('projects/Restricted/Nested/README.md')
        index_all(self.settings)
        with Database(self.settings.database_path, query_only=True) as db:
            self.assertEqual(db.one('SELECT count(*) FROM projects')[0], 2)
        self.settings.raw['excluded_projects'] = ['Restricted']
        result = self.inventory()
        self.assertEqual(result['eligible_files'], 0)
        self.assertEqual(result['new_project_roots'], 0)
        self.assertNotIn('Restricted', json.dumps(result))

    def test_unknown_internal_project_namespace_is_partial_not_disclosed(self):
        self.put('knowledge/projects/unknown/PROJECT_MEMORY.md', '# Not opened')
        self.put('knowledge/decisions/unknown/Private.md')
        self.put('knowledge/projects/ordinary/Guide.md')
        result = self.inventory()
        self.assertEqual(result['unverifiable_project_files'], 2)
        self.assertEqual(result['eligible_files'], 1)
        self.assertFalse(result['coverage_complete'])
        self.assertNotIn('unknown', json.dumps(result))

    def test_known_metadata_profile_and_decision_authorized_without_body_reads(self):
        root = self.root / 'projects/Project'
        self.put('projects/Project/README.md')
        index_all(self.settings)
        folder = 'project-' + sha256_text(path_key(root))[:8]
        self.put(f'knowledge/decisions/{folder}/New.md')
        with patch.object(Path, 'open', side_effect=AssertionError('source body read')):
            result = self.direct()
        self.assertTrue(result['coverage_complete'])
        self.assertEqual(result['unindexed_files'], 1)
        self.assertEqual(result['unverifiable_project_files'], 0)

    def test_ambiguous_profile_slug_not_guessed(self):
        self.put('projects/Same Name/README.md')
        self.put('projects/Same-Name/README.md')
        self.put('knowledge/projects/same-name/PROJECT_MEMORY.md')
        result = self.inventory()
        self.assertEqual(result['new_project_roots'], 2)
        self.assertEqual(result['unverifiable_project_files'], 1)
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['eligible_files'], 2)

    def test_existing_profile_metadata_disambiguates_slug(self):
        self.put('projects/Same Name/README.md')
        self.put('projects/Same-Name/README.md')
        index_all(self.settings)
        result = self.inventory()
        self.assertEqual(result['unverifiable_project_files'], 0)
        self.assertTrue(result['coverage_complete'])
        self.assertEqual(result['unindexed_files'], 0)

    def test_inactive_project_observed_without_changing_status(self):
        self.put('projects/Project/README.md')
        index_all(self.settings)
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE projects SET status='missing'")
            db.commit()
        result = self.inventory()
        self.assertEqual(result['inactive_project_roots'], 1)
        self.assertTrue(any(f['status'] == 'project_not_active' for f in result['findings']))
        with Database(self.settings.database_path, query_only=True) as db:
            self.assertEqual(db.one('SELECT status FROM projects')[0], 'missing')

    def test_hidden_tombstone_is_not_currently_indexed(self):
        self.put('vault/Old.md')
        index_all(self.settings)
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE documents SET status='deleted'")
            db.commit()
        result = self.inventory()
        self.assertEqual(result['unindexed_files'], 1)
        self.assertEqual(result['findings'][0]['status'], 'not_visible_in_index')

    def test_cached_source_origin_must_match_current_root(self):
        self.put('vault/Old.md')
        index_all(self.settings)
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE documents SET source_root=?", (str(self.root / 'wrong'),))
            db.commit()
        result = self.inventory()
        self.assertEqual(result['unindexed_files'], 1)
        self.assertEqual(result['findings'][0]['status'], 'not_visible_in_index')

    def test_entry_budget_is_global_and_bounded(self):
        for i in range(6):
            self.put(f'vault/{i}.md')
        self.settings.raw['audit_inventory_max_entries'] = 2
        result = self.inventory()
        self.assertEqual(result['entries_examined'], 2)
        self.assertEqual(result['eligible_files'], 2)
        self.assertTrue(result['budget_exhausted'])
        self.assertFalse(result['coverage_complete'])

    def test_exact_entry_budget_with_no_remaining_entries_is_complete(self):
        self.put('vault/Only.md')
        self.settings.raw['audit_inventory_max_entries'] = 1
        result = self.inventory()
        self.assertTrue(result['coverage_complete'])
        self.assertFalse(result['budget_exhausted'])

    def test_findings_cap_does_not_limit_counts_or_claim_partial_coverage(self):
        for i in range(4):
            self.put(f'vault/{i}.md')
        self.settings.raw['audit_inventory_max_findings'] = 1
        result = self.inventory()
        self.assertEqual(result['unindexed_files'], 4)
        self.assertEqual(len(result['findings']), 1)
        self.assertTrue(result['findings_truncated'])
        self.assertTrue(result['coverage_complete'])

    def test_zero_findings_is_supported(self):
        self.put('vault/Only.md')
        self.settings.raw['audit_inventory_max_findings'] = 0
        result = self.inventory()
        self.assertEqual(result['findings'], [])
        self.assertTrue(result['findings_truncated'])
        self.assertEqual(result['unindexed_files'], 1)

    def test_depth_limit_is_partial(self):
        self.put('vault/Folder/Note.md')
        self.put('vault/Root.md')
        self.settings.raw['audit_inventory_max_depth'] = 0
        result = self.inventory()
        self.assertEqual(result['depth_limited_directories'], 1)
        self.assertEqual(result['eligible_files'], 1)
        self.assertFalse(result['coverage_complete'])

    def test_root_limit_is_partial(self):
        self.settings.raw['audit_inventory_max_roots'] = 1
        result = self.inventory()
        self.assertEqual(result['roots_started'], 1)
        self.assertTrue(result['budget_exhausted'])

    def test_cooperative_deadline_is_explicit(self):
        with patch('rabanito.audit_inventory.time.monotonic', side_effect=[0, 10]):
            result = self.direct()
        self.assertTrue(result['budget_exhausted'])
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['entries_examined'], 0)

    def test_invalid_limits_default_and_out_of_range_clamp(self):
        for value in (True, False, '2', None, float('nan'), float('inf'), 1.5):
            with self.subTest(value_type=type(value).__name__):
                self.settings.raw['audit_inventory_max_entries'] = value
                self.assertEqual(self.inventory()['limits']['max_entries'], 20000)
        self.settings.raw.update(audit_inventory_max_entries=-7, audit_inventory_max_seconds=99,
                                 audit_inventory_max_depth=900)
        result = self.inventory()
        self.assertEqual(result['limits']['max_entries'], 1)
        self.assertEqual(result['limits']['max_seconds'], 30)
        self.assertEqual(result['limits']['max_depth'], 128)
        self.settings.raw['audit_inventory_max_entries'] = 10**999
        self.assertEqual(self.inventory()['limits']['max_entries'], 200000)

    def test_directory_error_is_partial_and_error_value_not_exposed(self):
        self.put('vault/Blocked/Secret.md')
        original = os.scandir
        def blocked(path):
            if Path(path).name == 'Blocked':
                raise PermissionError('secret fixture error with absolute root ' + str(self.root))
            return original(path)
        with patch('rabanito.audit_inventory.os.scandir', side_effect=blocked):
            result = self.inventory()
        self.assertEqual(result['directory_errors'], 1)
        self.assertFalse(result['coverage_complete'])
        self.assertNotIn('secret fixture error', json.dumps(result))
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_streaming_enumeration_error_is_partial(self):
        self.put('vault/One.md')
        self.put('vault/Two.md')
        original = os.scandir
        @contextmanager
        def failing(path):
            with original(path) as entries:
                if Path(path) != self.settings.vault_root:
                    yield entries
                else:
                    def stream():
                        yield next(entries)
                        raise OSError('private fixture failure')
                    yield stream()
        with patch('rabanito.audit_inventory.os.scandir', side_effect=failing):
            result = self.inventory()
        self.assertEqual(result['entries_examined'], 1)
        self.assertEqual(result['directory_errors'], 1)
        self.assertFalse(result['coverage_complete'])

    def test_observed_directory_change_marks_coverage_partial(self):
        original = os.scandir
        @contextmanager
        def changed(path):
            with original(path) as entries:
                yield entries
            if Path(path) == self.settings.vault_root:
                metadata = Path(path).stat()
                os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1000000000))
        with patch('rabanito.audit_inventory.os.scandir', side_effect=changed):
            result = self.inventory()
        self.assertEqual(result['directories_changed'], 1)
        self.assertFalse(result['coverage_complete'])

    def test_invalid_or_relative_extra_root_is_not_followed(self):
        self.settings.raw['additional_sources'] = [
            {'kind': 'bad/name', 'path': str(self.root / 'knowledge')},
            {'kind': 'local', 'path': 'relative-not-authorized'},
        ]
        result = self.inventory()
        self.assertEqual(result['roots_unavailable'], 2)
        self.assertFalse(result['coverage_complete'])

    @unittest.skipUnless(os.name == 'nt', 'Native Windows junction')
    def test_junction_directory_is_not_followed(self):
        import _winapi
        target = self.root / 'outside'
        self.put('outside/Private.md')
        link = self.settings.vault_root / 'Redirect'
        _winapi.CreateJunction(str(target), str(link))
        try:
            result = self.inventory()
            self.assertEqual(result['reparse_entries_skipped'], 1)
            self.assertEqual(result['eligible_files'], 0)
            self.assertTrue(result['coverage_complete'])
        finally:
            link.rmdir()  # Only this fixture's junction, never the destination.

    @unittest.skipUnless(os.name == 'nt', 'Native Windows junction')
    def test_junction_source_root_is_unavailable(self):
        import _winapi
        target = self.root / 'outside'
        self.put('outside/Private.md')
        link = self.root / 'redirect-root'
        _winapi.CreateJunction(str(target), str(link))
        self.settings.raw['vault_root'] = str(link)
        try:
            result = self.inventory()
            self.assertEqual(result['roots_unavailable'], 1)
            self.assertFalse(result['coverage_complete'])
            self.assertEqual(result['eligible_files'], 0)
        finally:
            link.rmdir()

    def test_project_metadata_file_size_limit(self):
        self.put('projects/P/package.json', 'x' * 50)
        policy = self.settings.raw['source_policy']['projects']
        policy.update(metadata_names=['package.json'], max_metadata_file_bytes=10)
        result = self.inventory()
        self.assertEqual(result['oversized_files'], 1)
        self.assertEqual(result['eligible_files'], 0)

    def test_inventory_uses_callers_sql_snapshot_with_concurrent_writer(self):
        self.put('vault/Indexed.md')
        index_all(self.settings)
        with Database(self.settings.database_path, query_only=True) as reader:
            register_project_visibility(reader, self.settings)
            reader.execute('BEGIN')
            self.assertEqual(reader.one("SELECT count(*) FROM documents WHERE status='active'")[0], 1)
            with Database(self.settings.database_path) as writer:
                writer.execute("UPDATE documents SET status='deleted'")
                writer.commit()
            result = inspect_source_inventory(reader, self.settings)
            self.assertEqual(result['indexed_files'], 1)
        self.assertEqual(self.inventory()['unindexed_files'], 1)

    def test_inventory_does_not_issue_writes_or_select_content(self):
        self.put('projects/Project/README.md')
        index_all(self.settings)
        forbidden = {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE,
                     sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_ALTER_TABLE}
        with Database(self.settings.database_path, query_only=True) as db:
            register_project_visibility(db, self.settings)
            db.execute('BEGIN')
            statements = []
            db.connection.set_trace_callback(statements.append)
            def authorize(operation, arg1, arg2, *_rest):
                self.assertNotIn(operation, forbidden)
                if operation == sqlite3.SQLITE_READ:
                    self.assertNotIn(arg2, {'frontmatter_json', 'text', 'body', 'title', 'content_hash'})
                return sqlite3.SQLITE_OK
            db.connection.set_authorizer(authorize)
            try:
                result = inspect_source_inventory(db, self.settings)
            finally:
                db.connection.set_authorizer(None)
            self.assertEqual(result['unindexed_files'], 0)
            self.assertTrue(all(s.lstrip().upper().startswith('SELECT') for s in statements))

    def test_bounded_project_metadata_cache_is_partial(self):
        for name in ('One', 'Two'):
            self.put(f'projects/{name}/README.md')
        index_all(self.settings)
        self.settings.raw['audit_inventory_max_entries'] = 1
        result = self.inventory()
        self.assertTrue(result['budget_exhausted'])
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['entries_examined'], 0)

    def test_collect_audit_clones_settings_for_consistent_policy(self):
        self.put('projects/Work/README.md')
        index_all(self.settings)
        def changed(db, snapshot):
            self.settings.raw['excluded_projects'] = ['Work']
            return inspect_source_inventory(db, snapshot)
        with patch('rabanito.capabilities.inspect_source_inventory', side_effect=changed):
            result = collect_audit(self.settings)
        self.assertEqual(result['counts']['projects'], 1)
        self.assertEqual(result['source_inventory']['indexed_files'], 2)
        self.assertEqual(self.inventory()['eligible_files'], 0)

    @unittest.skipUnless(os.name == 'nt', 'Native Windows queued junction race')
    def test_queued_directory_replaced_by_junction_is_not_traversed(self):
        import _winapi
        self.put('vault/Queued/Normal.md')
        self.put('outside/Private.md')
        link = self.settings.vault_root / 'Queued'
        original = os.scandir
        @contextmanager
        def swapped(path):
            with original(path) as entries:
                yield entries
            if Path(path) == self.settings.vault_root:
                link.rename(link.with_name('saved-fixture-directory'))
                _winapi.CreateJunction(str(self.root / 'outside'), str(link))
        try:
            with patch('rabanito.audit_inventory.os.scandir', side_effect=swapped):
                result = self.inventory()
            self.assertEqual(result['directory_errors'], 1)
            self.assertEqual(result['eligible_files'], 0)
            self.assertFalse(result['coverage_complete'])
            self.assertNotIn('Private.md', json.dumps(result))
        finally:
            if link.is_junction():
                link.rmdir()

    def test_markdown_and_json_reports_include_sanitized_metadata(self):
        self.put('vault/Token=fixture-private.md')
        report = write_audit(self.settings)
        text = (self.settings.knowledge_root / report['markdown_path']).read_text(encoding='utf-8')
        raw = (self.settings.knowledge_root / report['json_path']).read_text(encoding='utf-8')
        self.assertIn('Source inventory', text)
        self.assertIn('source_inventory', raw)
        self.assertNotIn('fixture-private', raw + text)
        self.assertNotIn(str(self.root), raw + text)
        self.assertFalse(self.settings.database_path.exists())

    def test_level_up_reviews_unindexed_files_instead_of_recommending_more_sources(self):
        self.put('vault/Existing.md')
        index_all(self.settings)
        self.put('vault/New.md')
        result = level_up(self.settings)
        matches = [r for r in result['recommendations'] if r['action'] == 'Revisar archivos pendientes de indexar']
        self.assertEqual(len(matches), 1)
        self.assertIn('1', matches[0]['why'])
        self.assertEqual(matches[0]['command'], 'python -m rabanito audit')
        self.assertFalse(any('Agregar fuentes' in r['action'] for r in result['recommendations']))
        with Database(self.settings.database_path, query_only=True) as db:
            self.assertEqual(db.one('SELECT count(*) FROM documents')[0], 1)

    def test_level_up_warns_partial_inventory_without_recommending_force_index(self):
        self.put('knowledge/projects/unknown/PROJECT_MEMORY.md')
        result = level_up(self.settings)
        matches = [r for r in result['recommendations'] if r['action'] == 'Revisar cobertura del inventario']
        self.assertEqual(len(matches), 1)
        self.assertIn('parcial', matches[0]['why'])
        self.assertNotIn('--force', json.dumps(result))
        self.assertFalse(self.settings.database_path.exists())

    def test_level_up_warns_empty_new_project_without_registering_it(self):
        (self.settings.projects_root / 'EmptyProject').mkdir()
        result = level_up(self.settings)
        matches = [r for r in result['recommendations'] if r['action'] == 'Revisar proyectos detectados']
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['command'], 'python -m rabanito audit')
        self.assertFalse(self.settings.database_path.exists())

    def test_level_up_clean_empty_inventory_keeps_existing_fallback(self):
        result = level_up(self.settings)
        self.assertEqual(len(result['recommendations']), 1)
        self.assertEqual(result['recommendations'][0]['action'], 'Agregar fuentes aprobadas o ejecutar una entrevista')
        self.assertEqual(set(result['recommendations'][0]), {'priority', 'action', 'why', 'command'})

    def test_level_up_preserves_bounded_summary_and_full_inventory_evidence(self):
        self.put('vault/New.md')
        result = level_up(self.settings)
        self.assertNotIn('source_inventory', result['based_on'])
        artifact = json.loads((self.settings.knowledge_root / result['json_path']).read_text(encoding='utf-8'))
        self.assertEqual(artifact['based_on']['source_inventory']['unindexed_files'], 1)
        self.assertEqual(artifact['recommendations'], result['recommendations'])
        self.assertNotIn(str(self.root), json.dumps(result) + json.dumps(artifact))


if __name__ == '__main__':
    unittest.main()
