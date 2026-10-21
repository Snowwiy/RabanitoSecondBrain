from __future__ import annotations

import copy
import http.client
import json
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from rabanito import changes
from rabanito.changes import recent_document_changes
from rabanito.config import Settings
from rabanito.db import Database
from rabanito.indexer import index_all
from rabanito.server import RabanitoHandler, ThreadingHTTPServer
from tests import test_document_policy as fixtures


class ChangePolicyTests(unittest.TestCase):
    setUp = fixtures.DocumentPolicyTests.setUp
    changed = fixtures.DocumentPolicyTests.changed

    def assert_hidden(self, settings):
        self.assertTrue(recent_document_changes(self.settings))
        self.assertEqual(recent_document_changes(settings), [])

    def test_filename_exclusion_revokes_history(self):
        self.assert_hidden(self.changed(exclude_names=['Article.md']))

    def test_directory_exclusion_revokes_history(self):
        self.assert_hidden(self.changed(exclude_dirs=['Folder']))

    def test_extension_policy_revokes_history(self):
        for policy in ({'exclude_extensions':['.md']}, {'extensions':['.rst']}):
            with self.subTest(policy=list(policy)):
                self.assert_hidden(self.changed(**policy))

    def test_metadata_name_exception_preserves_authorized_history(self):
        changed = self.changed(extensions=['.rst'],metadata_names=['Article.md'])
        self.assertTrue(any(row['document_id']==self.document_id for row in recent_document_changes(changed)))

    def test_mutating_caller_settings_does_not_mix_permission_snapshots(self):
        original = changes.register_project_visibility
        def mutate(db,snapshot):
            original(db,snapshot)
            self.settings.raw['vault_root'] = 'vault-next'
        with patch.object(changes,'register_project_visibility',side_effect=mutate):
            result = recent_document_changes(self.settings)
        self.assertTrue(any(row['document_id']==self.document_id for row in result))
        self.assertEqual(recent_document_changes(self.settings), [])

    def environment(self):
        path = self.root/'knowledge/decisions/environments/fixture-scope/Example.md'
        path.parent.mkdir(parents=True)
        path.write_text('# Private environment fixture\nSynthetic only.\n', encoding='utf-8')
        index_all(self.settings)
        raw = copy.deepcopy(self.settings.raw)
        raw['excluded_memory_contexts'] = ['fixture-scope']
        return Settings(self.root, raw)

    def test_environment_context_exclusion_revokes_history(self):
        changed = self.environment()
        self.assertTrue(any(row['source_kind']=='internal' for row in recent_document_changes(self.settings)))
        self.assertFalse(any(row['source_kind']=='internal' for row in recent_document_changes(changed)))

    def test_filter_precedes_event_limit(self):
        note = self.settings.vault_root/'Allowed.md'
        note.write_text('# Allowed fixture\n', encoding='utf-8')
        index_all(self.settings)
        self.note.write_text('# PolicyScopeMarker\nModified fixture.\n', encoding='utf-8')
        index_all(self.settings)
        self.assertEqual(recent_document_changes(self.settings,limit=1)[0]['document_id'], self.document_id)
        rows = recent_document_changes(self.changed(exclude_names=['Article.md']),limit=1)
        self.assertEqual([row['relative_path'] for row in rows], ['Allowed.md'])

    def test_history_revocation_is_metadata_only_and_preserves_rows(self):
        with Database(self.settings.database_path,query_only=True) as db:
            before = list(db.connection.iterdump())
        original = self.note.read_bytes()
        with patch.object(Path,'open',side_effect=AssertionError('source opened')):
            self.assertEqual(recent_document_changes(self.changed(exclude_names=['Article.md'])), [])
        with Database(self.settings.database_path,query_only=True) as db:
            self.assertEqual(before, list(db.connection.iterdump()))
        self.assertEqual(original, self.note.read_bytes())
        self.assertTrue(any(row['document_id']==self.document_id for row in recent_document_changes(self.settings)))

    def test_http_history_hides_excluded_context_without_reindex(self):
        changed = self.environment()
        class Handler(RabanitoHandler):
            def log_message(self,*args):pass
        Handler.settings = changed
        server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
        worker = threading.Thread(target=server.serve_forever,daemon=True)
        worker.start()
        connection = http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=10)
        try:
            connection.request('GET','/api/changes?limit=100')
            response = connection.getresponse()
            result = json.loads(response.read())
            self.assertEqual(response.status,200)
            self.assertEqual(response.getheader('Cache-Control'),'no-store')
            self.assertIsNone(response.getheader('Access-Control-Allow-Origin'))
            self.assertTrue(result['changes'])
            self.assertTrue(all(row['source_kind']=='obsidian' for row in result['changes']))
            self.assertNotIn('Private environment fixture',json.dumps(result))
            self.assertNotIn(str(self.root),json.dumps(result))
        finally:
            connection.close();server.shutdown();server.server_close();worker.join(timeout=5)

    def test_authorized_deletion_history_is_not_removed(self):
        self.note.unlink()
        index_all(self.settings)
        rows = recent_document_changes(self.settings)
        self.assertTrue(any(row['document_id']==self.document_id and row['change_type']=='removed' for row in rows))
        self.assertEqual(recent_document_changes(self.changed(exclude_names=['Article.md'])), [])

    def test_project_history_requires_coherent_source_root(self):
        project = self.settings.projects_root/'FixtureProject'
        project.mkdir()
        (project/'README.md').write_text('# Fixture project\n',encoding='utf-8')
        index_all(self.settings)
        self.assertTrue(any(row['source_kind']=='projects' for row in recent_document_changes(self.settings)))
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE documents SET source_root=? WHERE source_kind='projects'",(str(self.root/'unrelated'),))
            db.commit()
        self.assertFalse(any(row['source_kind']=='projects' for row in recent_document_changes(self.settings)))


if __name__ == '__main__':
    unittest.main()
