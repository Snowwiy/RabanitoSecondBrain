from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rabanito.config import Settings
from rabanito.db import Database
from rabanito.capabilities import collect_audit
from rabanito.coding_memory import similar_experiences
from rabanito.decisions import add_memory_record, list_memory_records
from rabanito.document_content import DocumentContentError, document_content
from rabanito.indexer import index_all
from rabanito.knowledge_graph import graph_neighbors, graph_page, sync_graph
from rabanito.knowledge_graph import query
from rabanito.knowledge_graph.store import configure
from rabanito.search import get_document, recent_documents, related_documents, retrieve_context, search_documents, stats
from rabanito.source_policy import document_eligibility
from rabanito.visibility import project_visibility_sql, register_project_visibility


ROOT = Path(__file__).resolve().parents[1]


class DocumentPolicyTests(unittest.TestCase):
    def setUp(self):
        parent = ROOT / 'tests/.test-temp'
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='document-policy-', dir=parent)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ('vault/Folder', 'projects', 'knowledge', 'vault-next'):
            (self.root / name).mkdir(parents=True)
        self.settings = Settings(self.root, {
            'vault_root':'vault', 'projects_root':'projects', 'knowledge_dir':'knowledge',
            'data_dir':'data', 'database_path':'data/brain.db', 'additional_sources':[],
            'source_policy':{kind:{'extensions':['.md']} for kind in ('obsidian','projects','internal')},
        })
        self.note = self.root / 'vault/Folder/Article.md'
        self.note.write_text('# PolicyScopeMarker\n\nSynthetic selection fixture.\n', encoding='utf-8')
        index_all(self.settings)
        with Database(self.settings.database_path, query_only=True) as db:
            self.document_id = db.one('SELECT document_id FROM documents')[0]
        self.assertTrue(search_documents(self.settings, 'PolicyScopeMarker'))

    def changed(self, **policy):
        raw = copy.deepcopy(self.settings.raw)
        raw['source_policy']['obsidian'].update(policy)
        return Settings(self.root, raw)

    def assert_hidden(self, settings):
        self.assertEqual(search_documents(settings, 'PolicyScopeMarker'), [])
        self.assertEqual(retrieve_context(settings, 'PolicyScopeMarker', max_chars=200)['fragments'], [])
        self.assertEqual(recent_documents(settings), [])
        self.assertIsNone(get_document(settings, self.document_id))
        with self.assertRaises(DocumentContentError) as error:
            document_content(settings, self.document_id, 1024)
        self.assertEqual(error.exception.status, 404)

    def test_excluded_filename_revokes_cached_document(self):
        self.assert_hidden(self.changed(exclude_names=['Article.md']))

    def test_graph_manifest_eligibility_is_not_document_selection(self):
        with Database(self.settings.database_path, query_only=True) as db:
            configure(db, self.settings)
            for manifest in ('uv.lock', 'pylock.toml', 'inventory.json'):
                self.assertEqual(db.one("SELECT kg_path_visible('projects',?)", (manifest,))[0], 1)
                self.assertEqual(db.one("SELECT kg_document_path_visible('projects',?)", (manifest,))[0], 0)

    def test_graph_manifest_exclusions_still_apply(self):
        raw = copy.deepcopy(self.settings.raw)
        raw['source_policy']['projects'].update(exclude_names=['uv.lock'], exclude_extensions=['.json'], exclude_dirs=['private'])
        changed = Settings(self.root, raw)
        with Database(self.settings.database_path, query_only=True) as db:
            configure(db, changed)
            for manifest in ('uv.lock', 'inventory.json', 'private/pylock.toml'):
                self.assertEqual(db.one("SELECT kg_path_visible('projects',?)", (manifest,))[0], 0)

    def test_excluded_directory_revokes_cached_document(self):
        self.assert_hidden(self.changed(exclude_dirs=['Folder']))

    def test_excluded_extension_revokes_cached_document(self):
        self.assert_hidden(self.changed(exclude_extensions=['.md']))

    def test_narrowed_extension_allowlist_revokes_cached_document(self):
        self.assert_hidden(self.changed(extensions=['.rst']))

    def test_narrowed_allowlist_also_revokes_graph_node_without_sync(self):
        self.assertEqual(sync_graph(self.settings, max_inputs=1000)['status'], 'ok')
        before = graph_page(self.settings, kind='document', limit=5)
        self.assertTrue(before['nodes'])
        anchor = before['nodes'][0]['id']
        changed = self.changed(extensions=['.rst'])
        self.assertEqual(graph_page(changed, kind='document', limit=5)['nodes'], [])
        self.assertFalse(graph_neighbors(changed, anchor, limit=5)['anchor_visible'])

    def test_environment_context_exclusion_revokes_generic_recall(self):
        path = self.root / 'knowledge/decisions/environments/fixture-scope/Example.md'
        path.parent.mkdir(parents=True)
        path.write_text('# EnvironmentScopeMarker\n\nSynthetic scope fixture.\n', encoding='utf-8')
        index_all(self.settings)
        self.assertTrue(search_documents(self.settings, 'EnvironmentScopeMarker'))
        changed = Settings(self.root, copy.deepcopy(self.settings.raw) | {'excluded_memory_contexts':['fixture-scope']})
        self.assertEqual(search_documents(changed, 'EnvironmentScopeMarker'), [])
        self.assertEqual(retrieve_context(changed, 'EnvironmentScopeMarker', max_chars=200)['fragments'], [])

    def test_warm_graph_proof_cannot_bypass_environment_context_exclusion(self):
        path = self.root / 'knowledge/decisions/environments/fixture-scope/Example.md'
        path.parent.mkdir(parents=True)
        path.write_text('# EnvironmentScopeMarker\n', encoding='utf-8')
        index_all(self.settings)
        self.assertEqual(sync_graph(self.settings, max_inputs=1000)['status'], 'ok')
        self.assertTrue(graph_page(self.settings, kind='document', query='EnvironmentScopeMarker', limit=5)['nodes'])
        changed = Settings(self.root, copy.deepcopy(self.settings.raw) | {'excluded_memory_contexts':['fixture-scope']})
        self.assertEqual(graph_page(changed, kind='document', query='EnvironmentScopeMarker', limit=5)['nodes'], [])

    def test_graph_configuration_snapshot_cannot_poison_next_request_proof(self):
        self.assertEqual(sync_graph(self.settings, max_inputs=1000)['status'], 'ok')
        with query._PROOF_LOCK:
            query._CLEAN_PROOFS.clear()
        original = query.configure
        def mutate_caller_settings(db, snapshot):
            result = original(db, snapshot)
            self.settings.raw['vault_root'] = 'vault-next'
            return result
        with patch.object(query, 'configure', side_effect=mutate_caller_settings):
            graph_page(self.settings, kind='document', limit=5)
        self.assertEqual(graph_page(self.settings, kind='document', limit=5)['nodes'], [])

    def test_graph_neighbor_snapshot_cannot_poison_next_request_proof(self):
        self.assertEqual(sync_graph(self.settings, max_inputs=1000)['status'], 'ok')
        anchor = graph_page(self.settings, kind='document', limit=5)['nodes'][0]['id']
        with query._PROOF_LOCK:
            query._CLEAN_PROOFS.clear()
        original = query.configure
        def mutate(db, snapshot):
            result = original(db, snapshot)
            self.settings.raw['vault_root'] = 'vault-next'
            return result
        with patch.object(query, 'configure', side_effect=mutate):
            graph_neighbors(self.settings, anchor, limit=5)
        self.assertEqual(graph_page(self.settings, kind='document', limit=5)['nodes'], [])

    def test_metadata_name_can_explicitly_allow_other_extension(self):
        changed = self.changed(extensions=['.rst'], metadata_names=['Article.md'])
        self.assertTrue(search_documents(changed, 'PolicyScopeMarker'))
        self.assertEqual(document_content(changed, self.document_id, 1024)['document_id'], self.document_id)

    def test_explicit_exclusion_overrides_metadata_name(self):
        self.assert_hidden(self.changed(extensions=[], metadata_names=['Article.md'], exclude_extensions=['.md']))

    def test_removing_exclusion_restores_same_cached_id_without_index(self):
        changed = self.changed(exclude_names=['Article.md'])
        self.assert_hidden(changed)
        changed.raw['source_policy']['obsidian']['exclude_names'] = []
        self.assertEqual(search_documents(changed, 'PolicyScopeMarker')[0]['document_id'], self.document_id)

    def test_exclusion_decision_does_not_open_sources(self):
        changed = self.changed(exclude_dirs=['Folder'])
        with patch.object(Path, 'open', side_effect=AssertionError('source content opened')):
            self.assertEqual(search_documents(changed, 'PolicyScopeMarker'), [])
            self.assertEqual(retrieve_context(changed, 'PolicyScopeMarker', max_chars=200)['fragments'], [])
            self.assertIsNone(get_document(changed, self.document_id))

    def test_revocation_keeps_all_database_rows_and_source_bytes(self):
        with Database(self.settings.database_path, query_only=True) as db:
            before = list(db.connection.iterdump())
        original = self.note.read_bytes()
        self.assert_hidden(self.changed(exclude_dirs=['Folder']))
        with Database(self.settings.database_path, query_only=True) as db:
            self.assertEqual(before, list(db.connection.iterdump()))
        self.assertEqual(self.note.read_bytes(), original)

    def test_connection_policy_snapshot_includes_nested_policy_lists(self):
        with Database(self.settings.database_path, query_only=True) as db:
            register_project_visibility(db, self.settings)
            self.settings.raw['source_policy']['obsidian']['exclude_names'] = ['Article.md']
            self.assertEqual(db.one('SELECT ' + project_visibility_sql('d') + ' FROM documents d')[0], 1)
        self.assertEqual(search_documents(self.settings, 'PolicyScopeMarker'), [])

    def test_lexical_path_validation_and_unicode_without_source_reads(self):
        eligible = document_eligibility(self.settings)
        for path in ('Carpeta/Nota ñ con espacios.md', 'Folder/Article.md', 'Folder\\Article.md'):
            self.assertEqual(eligible('obsidian', path), 1)
        for path in ('../Article.md', '/Article.md', 'C:/Article.md', 'Folder//Article.md',
                     'Folder/../Article.md', 'Article.md:stream', 'Folder/con.md', 'Folder/Article.md ',
                     'Folder/Article\x00.md', 'x' * 4001, None, 17):
            with self.subTest(path_type=type(path).__name__):
                self.assertEqual(eligible('obsidian', path), 0)

    def test_sensitive_filename_cannot_be_allowed_as_metadata(self):
        changed = self.changed(metadata_names=['id_rsa.md', 'credentials.json'])
        eligible = document_eligibility(changed)
        self.assertEqual(eligible('obsidian', 'id_rsa.md'), 0)
        self.assertEqual(eligible('obsidian', 'credentials.json'), 0)

    def test_policy_filter_applies_before_result_limit(self):
        path = self.root / 'vault/Allowed.md'
        path.write_text('# Allowed\n\nPolicyScopeMarker is a fixture term.\n', encoding='utf-8')
        index_all(self.settings)
        changed = self.changed(exclude_names=['Article.md'])
        result = search_documents(changed, 'PolicyScopeMarker', limit=1)
        self.assertEqual([r['relative_path'] for r in result], ['Allowed.md'])
        context = retrieve_context(changed, 'PolicyScopeMarker', limit=1, max_chars=200)
        self.assertEqual([r['relative_path'] for r in context['fragments']], ['Allowed.md'])

    def test_neighbor_cannot_disclose_excluded_target(self):
        note = self.root / 'vault/Allowed.md'
        note.write_text('# Allowed\n\n[[Folder/Article]]\n', encoding='utf-8')
        index_all(self.settings)
        with Database(self.settings.database_path, query_only=True) as db:
            anchor = db.one("SELECT document_id FROM documents WHERE relative_path='Allowed.md'")[0]
        self.assertEqual(get_document(self.settings, anchor)['links'][0]['target_document_id'], self.document_id)
        changed = self.changed(exclude_names=['Article.md'])
        self.assertEqual(get_document(changed, anchor)['links'], [])
        self.assertEqual(related_documents(changed, anchor), [])

    def test_audit_and_stats_only_cover_currently_eligible_documents(self):
        changed = self.changed(exclude_names=['Article.md'])
        self.assertEqual(stats(changed)['documents_active'], 0)
        report = collect_audit(changed)
        self.assertEqual(report['counts']['documents_active'], 0)
        self.assertEqual(report['index_drift_summary']['active_documents'], 0)
        self.assertEqual(report['source_inventory']['eligible_files'], 0)

    def test_context_exclusion_is_not_an_unindexed_inventory_candidate(self):
        path = self.root / 'knowledge/decisions/environments/fixture-scope/Example.md'
        path.parent.mkdir(parents=True)
        path.write_text('# EnvironmentScopeMarker\n', encoding='utf-8')
        changed = Settings(self.root, copy.deepcopy(self.settings.raw) | {'excluded_memory_contexts':['fixture-scope']})
        report = collect_audit(changed)
        self.assertEqual(report['source_inventory']['unverifiable_project_files'], 0)
        self.assertEqual(report['source_inventory']['unindexed_files'], 0)

    def test_decisions_and_verified_experiences_obey_current_policy(self):
        project = self.root / 'projects/FixtureProject'
        project.mkdir()
        (project / 'README.md').write_text('# Fixture\nSynthetic evidence.\n', encoding='utf-8')
        index_all(self.settings)
        add_memory_record(self.settings, project=str(project), problem='SyntheticPolicyProblem',
            statement='SyntheticPolicySolution', technologies=['Python'], status='confirmed',
            evidence=['project:README.md'], validation='passed', tests=['Synthetic fixture test'], result='Fixture only')
        index_all(self.settings)
        self.assertTrue(list_memory_records(self.settings, project=str(project)))
        self.assertTrue(similar_experiences(self.settings, 'SyntheticPolicyProblem', max_chars=200)['results'])
        raw = copy.deepcopy(self.settings.raw)
        raw['source_policy']['internal']['exclude_dirs'] = ['decisions']
        changed = Settings(self.root, raw)
        self.assertEqual(list_memory_records(changed, project=str(project)), [])
        self.assertEqual(similar_experiences(changed, 'SyntheticPolicyProblem', max_chars=200)['results'], [])


if __name__ == '__main__':
    unittest.main()
