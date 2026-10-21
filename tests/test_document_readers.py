from __future__ import annotations

import http.client
import json
import os
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from contextlib import contextmanager, redirect_stdout
from http.server import ThreadingHTTPServer
from io import StringIO
from pathlib import Path

from rabanito.capabilities import collect_audit
from rabanito.changes import recent_document_changes, resolve_active_project_root
from rabanito.cli import _graph_export, main as cli_main
from rabanito.config import Settings
from rabanito.decisions import list_memory_records
from rabanito.db import Database
from rabanito.indexer import index_all
from rabanito.search import (
    get_document, recent_documents, related_documents, retrieve_context, search_documents, stats,
)
from rabanito.server import RabanitoHandler
from rabanito.utils import write_json_atomic


ROOT = Path(__file__).resolve().parents[1]


class DocumentReaderTests(unittest.TestCase):
    def setUp(self):
        parent = ROOT / 'tests/.test-temp'
        parent.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='reader-ro-', dir=parent)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for folder in ('vault', 'projects', 'knowledge'):
            (self.root / folder).mkdir()
        self.project = self.root / 'projects/Fixture'
        self.project.mkdir()
        (self.project / 'README.md').write_text('# Fixture\n\nReader fixture project.\n', encoding='utf-8')
        (self.root / 'vault/Reader.md').write_text('# Reader\n\nReader fixture [[Other]].\n', encoding='utf-8')
        (self.root / 'vault/Other.md').write_text('# Other\n\nReader fixture target.\n', encoding='utf-8')
        self.settings = Settings(self.root, {
            'project_root': str(self.root), 'vault_root': str(self.root / 'vault'),
            'projects_root': str(self.root / 'projects'), 'knowledge_dir': str(self.root / 'knowledge'),
            'data_dir': str(self.root / 'data'), 'database_path': str(self.root / 'data/brain.db'),
            'source_policy': {kind: {'extensions': ['.md']} for kind in ('obsidian', 'projects', 'internal')},
            'additional_sources': [], 'max_search_results': 20, 'max_context_chars': 3000,
        })
        index_all(self.settings)
        with self.raw() as db:
            self.document_id = db.execute("SELECT document_id FROM documents WHERE relative_path='Reader.md'").fetchone()[0]
        self.make_legacy_row()

    @contextmanager
    def raw(self):
        # Fixture setup/inspection must not call the potentially initializing wrapper.
        connection = sqlite3.connect(self.settings.database_path)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def make_legacy_row(self):
        with self.raw() as db:
            db.execute("UPDATE documents SET project_root_path=NULL WHERE source_kind='projects'")
        self.assertEqual(self.null_project_roots(), 1)

    def null_project_roots(self):
        with self.raw() as db:
            return db.execute("SELECT COUNT(*) FROM documents WHERE source_kind='projects' AND project_root_path IS NULL").fetchone()[0]

    def check_reader(self, operation):
        operation()
        self.assertEqual(self.null_project_roots(), 1, 'A read silently ran a persistent project-root backfill')

    def test_stats_does_not_backfill(self):
        self.check_reader(lambda: stats(self.settings))

    def test_audit_does_not_backfill(self):
        self.check_reader(lambda: collect_audit(self.settings))

    def test_search_does_not_backfill(self):
        self.check_reader(lambda: search_documents(self.settings, 'Reader'))

    def test_recent_documents_does_not_backfill(self):
        self.check_reader(lambda: recent_documents(self.settings))

    def test_context_does_not_backfill(self):
        self.check_reader(lambda: retrieve_context(self.settings, 'Reader', max_chars=300))

    def test_document_detail_does_not_backfill(self):
        self.check_reader(lambda: get_document(self.settings, self.document_id))

    def test_related_does_not_backfill(self):
        self.check_reader(lambda: related_documents(self.settings, self.document_id))

    def test_decision_list_does_not_backfill(self):
        self.check_reader(lambda: list_memory_records(self.settings))

    def test_changes_do_not_backfill(self):
        self.check_reader(lambda: recent_document_changes(self.settings))

    def test_project_resolution_does_not_backfill(self):
        self.check_reader(lambda: resolve_active_project_root(self.settings, 'Fixture'))

    def test_cli_graph_export_does_not_backfill(self):
        self.check_reader(lambda: _graph_export(self.settings, 30, False))

    def test_read_does_not_recreate_missing_index(self):
        with self.raw() as db:
            db.execute('DROP INDEX idx_documents_project_root')
        stats(self.settings)
        with self.raw() as db:
            self.assertIsNone(db.execute("SELECT 1 FROM sqlite_master WHERE name='idx_documents_project_root'").fetchone())

    def empty_settings(self):
        return Settings(self.root, {
            **self.settings.raw, 'data_dir': str(self.root / 'uncreated'),
            'database_path': str(self.root / 'uncreated/empty.db'),
        })

    def test_empty_stats_preserves_output_without_creating_database(self):
        settings = self.empty_settings()
        result = stats(settings)
        self.assertEqual(result['documents_active'], 0)
        self.assertIsNone(result['parser_version'])
        self.assertIsNone(result['latest_scan'])
        self.assertFalse(settings.data_dir.exists(), 'Stats initialized an on-disk database tree')

    def test_empty_audit_preserves_output_without_creating_database(self):
        settings = self.empty_settings()
        result = collect_audit(settings)
        self.assertEqual(result['counts']['documents_active'], 0)
        self.assertFalse(settings.data_dir.exists(), 'Audit initialized an on-disk database tree')

    def test_other_empty_document_queries_do_not_create_database(self):
        settings = self.empty_settings()
        self.assertEqual(search_documents(settings, 'Reader'), [])
        self.assertEqual(recent_documents(settings), [])
        self.assertEqual(retrieve_context(settings, 'Reader')['fragments'], [])
        self.assertIsNone(get_document(settings, 1))
        self.assertEqual(related_documents(settings, 1), [])
        self.assertEqual(list_memory_records(settings), [])
        self.assertEqual(recent_document_changes(settings), [])
        self.assertEqual(_graph_export(settings, 10, False)['nodes'], [])
        self.assertFalse(settings.data_dir.exists())

    def test_empty_view_enforces_query_only_and_never_creates_path(self):
        path = self.root / 'missing/brain.db'
        with Database(path, read_only=True, empty_if_missing=True) as db:
            self.assertEqual(db.one('PRAGMA query_only')[0], 1)
            self.assertEqual(db.one('SELECT COUNT(*) FROM documents')[0], 0)
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("INSERT INTO meta VALUES('must_not_write','x')")
            with self.assertRaises(sqlite3.OperationalError):
                db.execute('CREATE TABLE must_not_write(x)')
        self.assertFalse(path.parent.exists())

    def test_existing_view_is_readonly_even_for_direct_sql(self):
        with Database(self.settings.database_path, read_only=True, empty_if_missing=True) as db:
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("UPDATE documents SET project_root_path='must_not_write'")
        self.assertEqual(self.null_project_roots(), 1)

    def test_empty_fallback_cannot_be_requested_for_a_writer(self):
        path = self.root / 'never-created/brain.db'
        for value in (True, 1, 'yes', None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    Database(path, empty_if_missing=value)
                self.assertFalse(path.parent.exists())

    def test_existing_empty_file_is_not_treated_as_absent(self):
        settings = self.empty_settings()
        settings.data_dir.mkdir()
        settings.database_path.write_bytes(b'')
        with self.assertRaises(sqlite3.OperationalError):
            stats(settings)
        self.assertEqual(settings.database_path.read_bytes(), b'')

    def test_existing_wrong_schema_is_not_repaired_or_hidden(self):
        settings = self.empty_settings()
        settings.data_dir.mkdir()
        connection = sqlite3.connect(settings.database_path)
        try:
            connection.execute('CREATE TABLE sentinel(x)')
            connection.commit()
        finally:
            connection.close()
        before = settings.database_path.read_bytes()
        with self.assertRaises(sqlite3.OperationalError):
            stats(settings)
        self.assertEqual(settings.database_path.read_bytes(), before)

    def test_missing_parent_view_is_not_persistently_cached(self):
        settings = self.empty_settings()
        self.assertEqual(stats(settings)['documents_active'], 0)
        self.assertFalse(settings.database_path.exists())
        with Database(settings.database_path) as db:
            db.execute("INSERT INTO meta VALUES('parser_version','77')")
        self.assertEqual(stats(settings)['parser_version'], 77)

    def test_redirected_parent_is_not_used_for_empty_fallback(self):
        destination = self.root / 'destination'
        alias = self.root / 'alias'
        destination.mkdir()
        if os.name == 'nt':
            result = subprocess.run(['cmd', '/c', 'mklink', '/J', str(alias), str(destination)],
                                    capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            alias.symlink_to(destination, target_is_directory=True)
        with self.assertRaises(sqlite3.OperationalError):
            Database(alias / 'missing.db', read_only=True, empty_if_missing=True)
        self.assertEqual(list(destination.iterdir()), [])

    def test_query_only_view_observes_committed_live_wal(self):
        with self.raw() as writer:
            writer.execute("UPDATE meta SET value='78' WHERE key='parser_version'")
            writer.commit()
            wal = Path(str(self.settings.database_path) + '-wal')
            self.assertTrue(wal.is_file())
            self.assertGreater(wal.stat().st_size, 0)
            main_before = self.settings.database_path.read_bytes()
            self.assertEqual(stats(self.settings)['parser_version'], 78)
            self.assertTrue(wal.exists(), 'Do not remove sidecars owned by a live connection')
            self.assertEqual(self.settings.database_path.read_bytes(), main_before)

    def test_query_only_last_close_does_not_leave_idle_sidecars(self):
        wal = Path(str(self.settings.database_path) + '-wal')
        shm = Path(str(self.settings.database_path) + '-shm')
        self.assertFalse(wal.exists())
        self.assertFalse(shm.exists())
        stats(self.settings)
        self.assertFalse(wal.exists())
        self.assertFalse(shm.exists())

    def test_query_only_sql_writes_are_rejected_for_existing_and_empty_views(self):
        for path in (self.settings.database_path, self.root / 'never-created/brain.db'):
            with self.subTest(path=path.name):
                with Database(path, query_only=True, empty_if_missing=True) as db:
                    self.assertEqual(db.one('PRAGMA query_only')[0], 1)
                    with self.assertRaises(sqlite3.OperationalError):
                        db.execute("INSERT INTO meta VALUES('readonly-test','x')")
                    with self.assertRaises(sqlite3.OperationalError):
                        db.execute('CREATE TABLE not_allowed(x)')
        self.assertFalse((self.root / 'never-created').exists())

    def cli(self, *arguments):
        config = self.root / 'config/settings.example.json'
        write_json_atomic(config, self.settings.raw)
        output = StringIO()
        with redirect_stdout(output):
            cli_main(['--config', str(config), *map(str, arguments)])
        return json.loads(output.getvalue())

    def test_cli_backup_does_not_backfill_its_source(self):
        backup = self.root / 'saved.db'
        self.cli('backup', '--path', backup)
        self.assertEqual(self.null_project_roots(), 1)
        connection = sqlite3.connect(backup)
        try:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM documents WHERE source_kind='projects' AND project_root_path IS NULL").fetchone()[0], 1)
        finally:
            connection.close()

    def test_pre_restore_backup_preserves_exact_legacy_metadata(self):
        backup = self.root / 'saved.db'
        with Database(self.settings.database_path, query_only=True) as db:
            db.backup(backup)
        result = self.cli('restore', backup, '--yes')
        connection = sqlite3.connect(result['pre_restore_backup'])
        try:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM documents WHERE source_kind='projects' AND project_root_path IS NULL").fetchone()[0], 1)
        finally:
            connection.close()

    def test_backup_requires_a_persistent_index_and_does_not_create_one(self):
        self.settings = self.empty_settings()
        backup = self.root / 'not-created-backup.db'
        with self.assertRaises(sqlite3.OperationalError):
            self.cli('backup', '--path', backup)
        self.assertFalse(self.settings.database_path.exists())
        self.assertFalse(backup.exists())

    def test_query_only_flag_rejects_non_boolean_values_before_io(self):
        path = self.root / 'never-created/brain.db'
        for value in (1, 'yes', None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    Database(path, query_only=value)
        self.assertFalse(path.parent.exists())

    def test_non_sqlite_index_is_not_replaced(self):
        settings = self.empty_settings()
        settings.data_dir.mkdir()
        settings.database_path.write_bytes(b'not a database fixture')
        before = settings.database_path.read_bytes()
        with self.assertRaises(sqlite3.DatabaseError):
            stats(settings)
        self.assertEqual(settings.database_path.read_bytes(), before)

    def test_invalid_schema_http_errors_are_structured_and_do_not_repair(self):
        self.settings = self.empty_settings()
        self.settings.data_dir.mkdir()
        connection = sqlite3.connect(self.settings.database_path)
        try:
            connection.execute('CREATE TABLE sentinel(x)')
            connection.commit()
        finally:
            connection.close()
        before = self.settings.database_path.read_bytes()
        with self.http_server() as server:
            for method, path, payload in (
                ('GET', '/api/stats', None), ('POST', '/api/search', {'q': 'Reader'}),
            ):
                with self.subTest(method=method):
                    client = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=15)
                    try:
                        client.request(method, path, None if payload is None else json.dumps(payload), {
                            'Content-Type': 'application/json',
                            'Origin': f'http://127.0.0.1:{server.server_port}',
                        })
                        response = client.getresponse()
                        data = json.loads(response.read())
                        self.assertEqual(response.status, 400)
                        self.assertIsInstance(data['error'], str)
                        self.assertNotIn(str(self.settings.database_path), json.dumps(data))
                    finally:
                        client.close()
        self.assertEqual(self.settings.database_path.read_bytes(), before)

    @contextmanager
    def http_server(self):
        class Handler(RabanitoHandler):
            def log_message(self, *args):
                pass
        Handler.settings = self.settings
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield server
        finally:
            server.shutdown()
            server.server_close()
            worker.join(5)
        self.assertFalse(worker.is_alive())

    def test_http_read_routes_do_not_backfill(self):
        with self.http_server() as server:
            for path in ('/api/health', '/api/stats', '/api/categories', '/api/tags',
                         '/api/scans', '/api/projects', '/api/audit/latest', '/api/changes'):
                with self.subTest(path=path):
                    self.make_legacy_row()
                    connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=15)
                    try:
                        connection.request('GET', path)
                        response = connection.getresponse()
                        payload = json.loads(response.read())
                        self.assertEqual(response.status, 200, payload)
                    finally:
                        connection.close()
                    self.assertEqual(self.null_project_roots(), 1, 'HTTP read ran a persistent backfill')

    def test_post_retrieval_and_impact_previews_do_not_backfill(self):
        additional = self.root / 'additional'
        additional.mkdir()
        self.settings.raw['additional_sources'] = [
            {'path': str(additional), 'kind': 'local', 'enabled': True},
        ]
        with self.raw() as db:
            project_id = db.execute('SELECT project_id FROM projects LIMIT 1').fetchone()[0]
        cases = [
            ('/api/search', {'q': 'Reader', 'limit': 3, 'project_id': project_id}),
            ('/api/context', {'q': 'Reader', 'max_chars': 100}),
            ('/api/decisions', {}),
            ('/api/graph', {'limit': 20}),
            ('/api/source-impact', {'source_id': 'additional-0', 'enabled': False}),
        ]
        with self.http_server() as server:
            for path, payload in cases:
                with self.subTest(path=path):
                    self.make_legacy_row()
                    connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=15)
                    try:
                        connection.request('POST', path, json.dumps(payload), {
                            'Content-Type': 'application/json',
                            'Origin': f'http://127.0.0.1:{server.server_port}',
                        })
                        response = connection.getresponse()
                        body = json.loads(response.read())
                        self.assertEqual(response.status, 200, body)
                    finally:
                        connection.close()
                    self.assertEqual(self.null_project_roots(), 1)


if __name__ == '__main__':
    unittest.main()
