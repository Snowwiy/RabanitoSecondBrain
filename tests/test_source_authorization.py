from __future__ import annotations

import copy
import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

from rabanito.capabilities import collect_audit
from rabanito.config import Settings
from rabanito.db import Database
from rabanito.decisions import add_memory_record, list_memory_records
from rabanito.document_content import DocumentContentError, document_content
from rabanito.indexer import index_all
from rabanito.knowledge_graph import graph_neighbors, graph_page, sync_graph
from rabanito.changes import recent_document_changes
from rabanito.server import RabanitoHandler, ThreadingHTTPServer
from rabanito.visibility import register_project_visibility
from rabanito.search import (
    get_document, recent_documents, related_documents, retrieve_context, search_documents, stats,
)


ROOT = Path(__file__).resolve().parents[1]


class SourceAuthorizationTests(unittest.TestCase):
    def setUp(self):
        parent = ROOT / 'tests/.test-temp'
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='source-authorization-', dir=parent)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ('vault', 'projects', 'knowledge', 'vault-next', 'knowledge-next'):
            (self.root / name).mkdir()
        self.settings = Settings(self.root, {
            'vault_root': 'vault', 'projects_root': 'projects', 'knowledge_dir': 'knowledge',
            'data_dir': 'data', 'database_path': 'data/brain.db', 'additional_sources': [],
            'source_policy': {kind: {'extensions': ['.md']} for kind in ('obsidian', 'projects', 'internal')},
        })
        self.note = self.settings.vault_root / 'Scope.md'
        self.note.write_text('# ScopeMarker\n\nSynthetic scoped knowledge.\n', encoding='utf-8')
        index_all(self.settings)
        with Database(self.settings.database_path, query_only=True) as db:
            self.document_id = db.one("SELECT document_id FROM documents WHERE source_kind='obsidian'")[0]

    def changed(self, **values):
        return Settings(self.root, copy.deepcopy(self.settings.raw) | values)

    def test_switching_vault_root_revokes_cached_search(self):
        self.assertTrue(search_documents(self.settings, 'ScopeMarker'))
        changed = self.changed(vault_root='vault-next')
        self.assertEqual(search_documents(changed, 'ScopeMarker'), [])

    def test_switching_vault_root_revokes_cached_context(self):
        result = retrieve_context(self.changed(vault_root='vault-next'), 'ScopeMarker', max_chars=200)
        self.assertEqual(result['fragments'], [])

    def test_switching_vault_root_revokes_detail_recent_relations_and_counts(self):
        changed = self.changed(vault_root='vault-next')
        self.assertIsNone(get_document(changed, self.document_id))
        self.assertEqual(recent_documents(changed), [])
        self.assertEqual(related_documents(changed, self.document_id), [])
        self.assertEqual(stats(changed)['documents_active'], 0)

    def test_switching_vault_root_already_revokes_native_reader_control(self):
        with self.assertRaises(DocumentContentError) as error:
            document_content(self.changed(vault_root='vault-next'), self.document_id, 1024)
        self.assertEqual(error.exception.status, 404)

    def test_switching_knowledge_root_revokes_cached_internal_note(self):
        note = self.settings.knowledge_root / 'Environment.md'
        note.write_text('# InternalScopeMarker\n\nSynthetic internal note.\n', encoding='utf-8')
        index_all(self.settings)
        changed = self.changed(knowledge_dir='knowledge-next')
        self.assertEqual(search_documents(changed, 'InternalScopeMarker'), [])

    def test_removing_additional_source_revokes_cache_without_index(self):
        root = self.root / 'extra'
        root.mkdir()
        (root / 'Extra.md').write_text('# ExtraScopeMarker\n', encoding='utf-8')
        self.settings.raw['additional_sources'] = [{'kind': 'research', 'path': str(root)}]
        index_all(self.settings)
        self.assertTrue(search_documents(self.settings, 'ExtraScopeMarker'))
        self.assertEqual(search_documents(self.changed(additional_sources=[]), 'ExtraScopeMarker'), [])

    def test_changing_source_kind_does_not_inherit_old_authorization(self):
        root = self.root / 'extra'
        root.mkdir()
        (root / 'Extra.md').write_text('# ExtraScopeMarker\n', encoding='utf-8')
        self.settings.raw['additional_sources'] = [{'kind': 'research', 'path': str(root)}]
        index_all(self.settings)
        changed = self.changed(additional_sources=[{'kind': 'reference', 'path': str(root)}])
        self.assertEqual(search_documents(changed, 'ExtraScopeMarker'), [])

    def test_audit_does_not_review_or_count_revoked_vault(self):
        report = collect_audit(self.changed(vault_root='vault-next'))
        self.assertEqual(report['counts']['documents_active'], 0)
        self.assertEqual(report['index_drift_summary']['active_documents'], 0)

    def test_reauthorization_restores_same_cached_id_without_indexing(self):
        changed = self.changed(vault_root='vault-next')
        self.assertEqual(search_documents(changed, 'ScopeMarker'), [])
        changed.raw['vault_root'] = self.settings.raw['vault_root']
        restored = search_documents(changed, 'ScopeMarker')
        self.assertEqual([r['document_id'] for r in restored], [self.document_id])
        self.assertEqual(stats(changed)['latest_scan']['scan_id'], stats(self.settings)['latest_scan']['scan_id'])

    def test_authorized_but_unavailable_root_keeps_offline_cache(self):
        self.note.unlink()  # Own synthetic source only, never the real vault.
        self.settings.vault_root.rmdir()
        self.assertTrue(search_documents(self.settings, 'ScopeMarker'))
        self.assertTrue(retrieve_context(self.settings, 'ScopeMarker', max_chars=200)['fragments'])

    def test_authorized_sibling_root_does_not_authorize_old_prefix(self):
        self.assertEqual(search_documents(self.changed(vault_root='vault-next'), 'ScopeMarker'), [])

    def test_authorized_subdirectory_does_not_authorize_old_parent(self):
        (self.settings.vault_root / 'selected').mkdir()
        changed = self.changed(vault_root='vault/selected')
        self.assertEqual(search_documents(changed, 'ScopeMarker'), [])

    @unittest.skipUnless(os.name == 'nt', 'Windows case-insensitive identity')
    def test_windows_path_case_does_not_revoke_same_root(self):
        changed = self.changed(vault_root=str(self.settings.vault_root).swapcase())
        self.assertTrue(search_documents(changed, 'ScopeMarker'))

    def test_current_source_set_is_a_connection_policy_snapshot(self):
        with Database(self.settings.database_path, query_only=True) as db:
            register_project_visibility(db, self.settings)
            self.settings.raw['vault_root'] = 'vault-next'
            self.assertEqual(db.one("SELECT rabanito_project_visible(source_kind,project_name,project_root_path,source_root) FROM documents")[0], 1)
        self.assertEqual(search_documents(self.settings, 'ScopeMarker'), [])

    def test_four_argument_document_predicate_requires_absolute_origin(self):
        with Database(self.settings.database_path, query_only=True) as db:
            register_project_visibility(db, self.settings)
            for root in ('', None, 'vault'):
                with self.subTest(root=root):
                    self.assertEqual(db.one("SELECT rabanito_project_visible('obsidian',NULL,NULL,?)", (root,))[0], 0)

    def test_disabling_one_custom_source_preserves_other_same_kind(self):
        sources = []
        for name in ('Primera ñ', 'Segunda'):
            folder = self.root / name
            folder.mkdir()
            (folder / 'Note.md').write_text('# CustomScopeMarker\n', encoding='utf-8')
            sources.append({'kind':'research','path':str(folder),'enabled':True})
        self.settings.raw['additional_sources'] = sources
        index_all(self.settings)
        changed = self.changed()
        changed.raw['additional_sources'][0]['enabled'] = False
        result = search_documents(changed, 'CustomScopeMarker')
        self.assertEqual(len(result), 1)
        self.assertIn('Segunda', result[0]['absolute_path'])

    def test_authorized_neighbor_does_not_expose_links_to_revoked_source(self):
        note = self.settings.knowledge_root / 'Neighbor.md'
        note.write_text('# Neighbor\n\n[[Scope]]\n', encoding='utf-8')
        index_all(self.settings)
        # Wikilink resolution is source-scoped. Seed an explicit cross-source
        # fixture relation to exercise readers, not to change that resolver.
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE links SET target_document_id=?,status='resolved',resolution_reason='fixture_explicit' "
                       "WHERE target_raw='Scope'", (self.document_id,))
            db.commit()
        with Database(self.settings.database_path, query_only=True) as db:
            neighbor = db.one("SELECT document_id FROM documents WHERE relative_path='Neighbor.md'")[0]
        self.assertEqual(get_document(self.settings, neighbor)['links'][0]['target_document_id'], self.document_id)
        changed = self.changed(vault_root='vault-next')
        self.assertEqual(get_document(changed, neighbor)['links'], [])
        self.assertEqual(related_documents(changed, neighbor), [])
        self.assertEqual(stats(changed)['relations_resolved'], 0)

    def test_change_history_does_not_disclose_revoked_document(self):
        result = recent_document_changes(self.changed(vault_root='vault-next'))
        self.assertNotIn('ScopeMarker', json.dumps(result))

    def test_revocation_does_not_mutate_database_or_original(self):
        with Database(self.settings.database_path, query_only=True) as db:
            before = list(db.connection.iterdump())
        source_before = self.note.read_bytes()
        changed = self.changed(vault_root='vault-next')
        search_documents(changed, 'ScopeMarker')
        retrieve_context(changed, 'ScopeMarker', max_chars=200)
        collect_audit(changed)
        get_document(changed, self.document_id)
        with Database(self.settings.database_path, query_only=True) as db:
            self.assertEqual(before, list(db.connection.iterdump()))
        self.assertEqual(self.note.read_bytes(), source_before)

    def test_revoked_high_ranking_match_does_not_starve_authorized_result(self):
        note = self.settings.knowledge_root / 'Allowed.md'
        note.write_text('# Allowed\n\nScopeMarker is an authorized fixture term.\n', encoding='utf-8')
        index_all(self.settings)
        changed = self.changed(vault_root='vault-next')
        result = search_documents(changed, 'ScopeMarker', limit=1)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['source_kind'], 'internal')
        context = retrieve_context(changed, 'ScopeMarker', limit=1, max_chars=200)
        self.assertEqual(len(context['fragments']), 1)
        self.assertEqual(context['fragments'][0]['source_kind'], 'internal')

    def test_decision_listing_does_not_bypass_revoked_knowledge_origin(self):
        project = self.settings.projects_root / 'FixtureProject'
        project.mkdir()
        (project / 'README.md').write_text('# Fixture project\n', encoding='utf-8')
        index_all(self.settings)
        add_memory_record(self.settings, project=str(project), problem='Synthetic scope problem',
                          statement='Synthetic proposed decision', status='proposed')
        index_all(self.settings)
        self.assertTrue(list_memory_records(self.settings, project=str(project)))
        self.assertEqual(list_memory_records(self.changed(knowledge_dir='knowledge-next'), project=str(project)), [])

    def test_unified_graph_also_hides_revoked_source_without_sync(self):
        self.assertEqual(sync_graph(self.settings, max_inputs=1000)['status'], 'ok')
        page = graph_page(self.settings, kind='document', limit=5)
        self.assertTrue(page['nodes'])
        anchor = page['nodes'][0]['id']
        changed = self.changed(vault_root='vault-next')
        self.assertEqual(graph_page(changed, kind='document', limit=5)['nodes'], [])
        self.assertFalse(graph_neighbors(changed, anchor, limit=5)['anchor_visible'])

    def test_http_search_context_detail_recent_tags_and_stats_hide_revoked_source(self):
        class Handler(RabanitoHandler):
            def log_message(self, *_args):
                pass
        Handler.settings = self.changed(vault_root='vault-next')
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for endpoint, payload in (
                ('/api/search', {'q':'ScopeMarker'}), ('/api/context', {'q':'ScopeMarker','max_chars':200}),
                ('/api/stats', None), ('/api/tags', None), ('/api/categories', None), ('/api/changes', None),
                ('/api/doc/content', {'document_id':self.document_id,'max_bytes':1024}),
            ):
                with self.subTest(endpoint=endpoint):
                    connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=10)
                    try:
                        connection.request('POST' if payload is not None else 'GET', endpoint,
                            json.dumps(payload) if payload is not None else None,
                            {'Content-Type':'application/json', 'Origin':f'http://127.0.0.1:{server.server_port}'})
                        response = connection.getresponse()
                        body = response.read().decode('utf-8')
                        self.assertEqual(response.status, 404 if endpoint == '/api/doc/content' else 200)
                        self.assertNotIn('ScopeMarker', body)
                        self.assertNotIn('Synthetic scoped knowledge', body)
                    finally:
                        connection.close()
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=10)


if __name__ == '__main__':
    unittest.main()
