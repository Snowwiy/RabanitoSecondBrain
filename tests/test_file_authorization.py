from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import csv
import io
import stat
from types import SimpleNamespace
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from rabanito.config import Settings
from rabanito.db import Database
from rabanito.document_content import DocumentContentError, document_content
from rabanito.indexer import index_all
from rabanito.search import get_document, retrieve_context, search_documents
from rabanito.knowledge_graph import graph_page, sync_graph
from rabanito.capabilities import collect_audit
from rabanito.coding_memory import similar_experiences
from rabanito.decisions import list_memory_records
from rabanito.changes import recent_document_changes
import tests.test_coding_retrieval as coding_fixtures

ROOT = Path(__file__).resolve().parents[1]


class FileAuthorizationTests(unittest.TestCase):
    def setUp(self):
        parent = ROOT / 'tests/.test-temp'
        parent.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='file-authorization-', dir=parent)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ('vault', 'projects', 'knowledge', 'outside'):
            (self.root / name).mkdir()
        self.settings = Settings(self.root, {
            'vault_root':'vault', 'projects_root':'projects', 'knowledge_dir':'knowledge',
            'data_dir':'data', 'database_path':'data/brain.db', 'additional_sources':[],
            'source_policy':{kind:{'extensions':['.md']} for kind in ('obsidian','projects','internal')},
        })
        self.note = self.root / 'vault/Note.md'
        self.marker = 'IdentityFixtureMarker'

    def seed(self):
        self.note.write_text('# ' + self.marker + '\n\nSynthetic fixture.\n', encoding='utf-8')
        index_all(self.settings)
        with Database(self.settings.database_path, query_only=True) as db:
            return db.one("SELECT document_id FROM documents WHERE source_kind='obsidian'")[0]

    def hidden(self, document_id):
        self.assertEqual(search_documents(self.settings, self.marker), [])
        self.assertEqual(retrieve_context(self.settings, self.marker)['fragments'], [])
        self.assertIsNone(get_document(self.settings, document_id))
        self.assertNotIn(self.marker, json.dumps(collect_audit(self.settings)))
        self.assertNotIn(self.marker, json.dumps(recent_document_changes(self.settings)))
        with self.assertRaises(DocumentContentError):
            document_content(self.settings, document_id, 1024)

    def test_normal_document_initial_incremental_and_reader(self):
        document_id = self.seed()
        self.assertEqual(index_all(self.settings)['unchanged'], 1)
        self.assertTrue(search_documents(self.settings, self.marker))
        self.assertTrue(retrieve_context(self.settings, self.marker)['fragments'])
        self.assertIsNotNone(get_document(self.settings, document_id))
        self.assertIn(self.marker, document_content(self.settings, document_id, 1024)['content_markdown'])

    def test_initial_hardlink_never_enters_fts_or_chunks(self):
        external = self.root / 'outside/External.md'
        external.write_text('# ' + self.marker + '\n', encoding='utf-8')
        os.link(external, self.note)
        index_all(self.settings)
        with Database(self.settings.database_path, query_only=True) as db:
            self.assertEqual(db.one("SELECT count(*) FROM documents_fts WHERE documents_fts MATCH ?", (self.marker,))[0], 0)
            self.assertEqual(db.one("SELECT count(*) FROM chunks_fts WHERE chunks_fts MATCH ?", (self.marker,))[0], 0)

    def test_oversize_hardlink_is_not_authorized_by_size_skip(self):
        external = self.root / 'outside/External.md'
        external.write_text('# ' + self.marker + '\n', encoding='utf-8')
        os.link(external, self.note)
        self.settings.raw['source_policy']['obsidian']['max_file_bytes'] = 1
        result = index_all(self.settings)
        self.assertNotEqual(result['status'], 'ok')
        self.assertEqual(search_documents(self.settings, self.marker), [])

    def test_cached_hardlink_is_hidden_before_any_reindex(self):
        document_id = self.seed()
        os.link(self.note, self.root / 'outside/Alias.md')
        self.hidden(document_id)
        self.assertNotIn(self.marker, json.dumps(collect_audit(self.settings)))

    def test_incremental_hardlink_is_not_accepted_as_unchanged(self):
        document_id = self.seed()
        os.link(self.note, self.root / 'outside/Alias.md')
        result = index_all(self.settings)
        self.assertNotEqual(result['status'], 'ok')
        self.assertEqual(result['unchanged'], 0)
        self.hidden(document_id)

    def test_excluded_cached_file_remains_hidden(self):
        document_id = self.seed()
        self.settings.raw['source_policy']['obsidian']['exclude_names'] = ['Note.md']
        self.hidden(document_id)

    def test_renamed_or_missing_source_does_not_authorize_cached_payload(self):
        document_id = self.seed()
        self.note.rename(self.root / 'outside/Moved.md')
        self.hidden(document_id)

    def test_hardlink_revocation_survives_new_cli_process(self):
        self.seed()
        os.link(self.note, self.root / 'outside/Alias.md')
        config = self.root / 'config/settings.json'
        config.parent.mkdir()
        config.write_text(json.dumps(self.settings.raw), encoding='utf-8')
        result = subprocess.run([sys.executable, '-B', '-m', 'rabanito', '--config', str(config),
                                 'search', self.marker], cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(self.marker, result.stdout)

    def test_cached_graph_proof_does_not_bypass_new_hardlink(self):
        self.seed()
        sync_graph(self.settings, max_inputs=1000)
        self.assertTrue(graph_page(self.settings, kind='document')['nodes'])
        graph_page(self.settings, kind='document')  # Warm the clean-proof cache.
        os.link(self.note, self.root / 'outside/Alias.md')
        self.assertEqual(graph_page(self.settings, kind='document')['nodes'], [])

    def test_project_readme_hardlink_is_not_copied_into_derived_profile(self):
        external = self.root / 'outside/External.md'
        external.write_text('# ' + self.marker + '\n\nExternal fixture paragraph.\n', encoding='utf-8')
        project = self.root / 'projects/FixtureProject'
        project.mkdir()
        os.link(external, project / 'README.md')
        index_all(self.settings)
        self.assertEqual(search_documents(self.settings, self.marker), [])

    def test_symlink_to_external_fixture_is_never_indexed(self):
        external = self.root / 'outside/External.md'
        external.write_text('# ' + self.marker + '\n', encoding='utf-8')
        try:
            os.symlink(external, self.note)
        except OSError as exc:
            self.skipTest('Native symlink creation unavailable: ' + type(exc).__name__)
        index_all(self.settings)
        self.assertEqual(search_documents(self.settings, self.marker), [])
        with Database(self.settings.database_path, query_only=True) as db:
            self.assertEqual(db.one('SELECT count(*) FROM documents_fts')[0], 0)

    @unittest.skipUnless(os.name == 'nt', 'Windows junction fixture')
    def test_windows_junction_revokes_existing_cached_document(self):
        folder = self.root / 'vault/Folder'
        folder.mkdir()
        self.note = folder / 'Note.md'
        document_id = self.seed()
        previous = self.root / 'outside/PreviousFolder'
        folder.rename(previous)
        result = subprocess.run(['cmd', '/d', '/c', 'mklink', '/J', str(folder), str(previous)],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        try:
            self.hidden(document_id)
            index_all(self.settings)
            self.hidden(document_id)
        finally:
            folder.rmdir()  # The exact generated junction only; never its target.
        self.assertTrue((previous / 'Note.md').exists())

    @unittest.skipUnless(os.name == 'nt', 'Windows NTFS permission fixture')
    def test_actual_read_permission_revocation_hides_cache_then_restores(self):
        document_id = self.seed()
        identity = subprocess.check_output(['whoami', '/user', '/fo', 'csv', '/nh'], text=True)
        sid = next(csv.reader(io.StringIO(identity.strip())))[1]
        self.assertTrue(sid.startswith('S-1-'))
        # Deny data reads only, preserving READ_CONTROL/WRITE_DAC so the test
        # owner can reliably undo exactly this synthetic deny entry.
        result = subprocess.run(['icacls', str(self.note), '/deny', '*' + sid + ':(RD)'], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        try:
            self.hidden(document_id)
            result = index_all(self.settings)
            self.assertNotEqual(result['status'], 'ok')
            self.hidden(document_id)
        finally:
            restored = subprocess.run(['icacls', str(self.note), '/remove:d', '*' + sid], capture_output=True)
            self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertTrue(search_documents(self.settings, self.marker))

    def test_replaced_file_between_metadata_and_handle_is_not_indexed(self):
        from rabanito import source_files
        self.note.write_text('# Original fixture\n', encoding='utf-8')
        external = self.root / 'outside/Replacement.md'
        external.write_text('# ' + self.marker + '\n', encoding='utf-8')
        original = source_files._native_open
        replaced = False
        @contextmanager
        def race(path):
            nonlocal replaced
            if path == self.note and not replaced:
                replaced = True
                self.note.unlink()
                external.rename(self.note)
            with original(path) as stream:
                yield stream
        with patch.object(source_files, '_native_open', race):
            result = index_all(self.settings)
        self.assertTrue(replaced)
        self.assertNotEqual(result['status'], 'ok')
        with Database(self.settings.database_path, query_only=True) as db:
            self.assertEqual(db.one('SELECT count(*) FROM documents_fts')[0], 0)

    def test_simulated_symlink_identity_is_rejected_without_content_read(self):
        from rabanito.source_files import open_source, UnsafeSourceError
        self.note.write_text('# Fixture\n', encoding='utf-8')
        original = Path.lstat
        def linked(path, *args, **kwargs):
            if path == self.note:
                return SimpleNamespace(st_mode=stat.S_IFLNK, st_nlink=1, st_ino=1, st_file_attributes=0)
            return original(path, *args, **kwargs)
        with patch.object(Path, 'lstat', linked), patch('rabanito.source_files._native_open') as opened:
            with self.assertRaises(UnsafeSourceError):
                with open_source(self.note): pass
            opened.assert_not_called()

    def test_cached_derived_project_profile_cannot_launder_revoked_readme(self):
        project = self.root / 'projects/FixtureProject'
        project.mkdir()
        readme = project / 'README.md'
        readme.write_text('# Fixture\n\n' + self.marker + ' project description.\n', encoding='utf-8')
        index_all(self.settings)
        before = search_documents(self.settings, self.marker)
        self.assertTrue(any(row['source_kind'] == 'internal' for row in before))
        os.link(readme, self.root / 'outside/ReadmeAlias.md')
        self.assertEqual(search_documents(self.settings, self.marker), [])
        self.assertEqual(retrieve_context(self.settings, self.marker)['fragments'], [])
        for row in before:
            self.assertIsNone(get_document(self.settings, row['document_id']))
            with self.assertRaises(DocumentContentError):
                document_content(self.settings, row['document_id'], 1024)

    def test_legacy_cache_does_not_authorize_different_replacement_content(self):
        document_id = self.seed()
        info = self.note.stat()
        body = self.note.read_bytes()
        with Database(self.settings.database_path) as db:
            db.execute("DELETE FROM meta WHERE key LIKE 'document_file_identity:%'")
        # Same length and mtime cannot prove correspondence with old FTS text.
        self.note.write_bytes(b'Z' * len(body))
        os.utime(self.note, ns=(info.st_atime_ns, info.st_mtime_ns))
        self.assertEqual(search_documents(self.settings, self.marker), [])
        self.assertEqual(retrieve_context(self.settings, self.marker)['fragments'], [])
        self.assertIsNone(get_document(self.settings, document_id))

    def test_current_cache_detects_same_metadata_in_place_replacement(self):
        document_id = self.seed()
        info = self.note.stat()
        body = self.note.read_bytes()
        self.note.write_bytes(b'Z' * len(body))
        os.utime(self.note, ns=(info.st_atime_ns, info.st_mtime_ns))
        self.assertEqual(search_documents(self.settings, self.marker), [])
        self.assertIsNone(get_document(self.settings, document_id))
        with self.assertRaises(DocumentContentError):
            document_content(self.settings, document_id, 8)


class CodingFileAuthorizationTests(unittest.TestCase):
    setUp = coding_fixtures.CodingMemoryTests.setUp
    tearDown = coding_fixtures.CodingMemoryTests.tearDown
    memory = coding_fixtures.CodingMemoryTests.memory

    def test_cached_decision_and_coding_memory_are_revoked_by_hardlink(self):
        self.memory()
        index_all(self.settings)
        self.assertTrue(list_memory_records(self.settings))
        self.assertTrue(similar_experiences(self.settings, 'rollback')['results'])
        note = next(self.settings.knowledge_root.glob('decisions/*/*.md'))
        os.link(note, self.root / 'fixture-alias.md')
        self.assertEqual(list_memory_records(self.settings), [])
        self.assertEqual(similar_experiences(self.settings, 'rollback')['results'], [])


if __name__ == '__main__':
    unittest.main()
