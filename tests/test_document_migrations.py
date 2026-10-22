from __future__ import annotations

import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from rabanito.db import Database, SCHEMA

ROOT = Path(__file__).resolve().parents[1]


class DocumentaryMigrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='migration-p0-', dir=ROOT / 'tests/.test-temp')
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / 'fixture.db'

    def legacy(self):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.executescript(SCHEMA.replace('    project_root_path TEXT,\n', ''))
            connection.execute("INSERT INTO documents(source_kind,source_root,relative_path,absolute_path,path_key,title,category,indexed_at,last_seen_scan) VALUES('projects','fixture-project','README.md','fixture-project/README.md','fixture-project/readme.md','Fixture','projects','fixture','fixture')")
            connection.commit()

    def snapshot(self):
        with closing(sqlite3.connect(self.path)) as connection:
            return (connection.execute("SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall(),
                    connection.execute('SELECT * FROM documents').fetchall())

    def test_backfill_failure_rolls_back_alter_and_closes_connection(self):
        self.legacy()
        before = self.snapshot()
        original = sqlite3.connect
        closed = []
        class Interrupted(sqlite3.Connection):
            def execute(self, sql, *args, **kwargs):
                if sql.startswith('UPDATE documents SET project_root_path'):
                    raise RuntimeError('synthetic interruption after ALTER')
                return super().execute(sql, *args, **kwargs)
            def close(self):
                closed.append(True)
                return super().close()
        with patch('rabanito.db.sqlite3.connect', side_effect=lambda *a, **kw: original(*a, factory=Interrupted, **kw)):
            with self.assertRaises(RuntimeError): Database(self.path)
        self.assertTrue(closed)
        self.assertEqual(before, self.snapshot())
        with Database(self.path) as db:
            self.assertEqual(db.one('SELECT project_root_path FROM documents')[0], 'fixture-project')
            self.assertEqual(db.one('PRAGMA integrity_check')[0], 'ok')
            self.assertEqual(db.query('PRAGMA foreign_key_check'), [])

    def test_new_database_failure_leaves_no_partial_schema(self):
        import rabanito.db as module
        with patch.object(module, 'SCHEMA', SCHEMA + '\nINVALID SQL;'):
            with self.assertRaises(sqlite3.Error): Database(self.path)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall(), [])
        with Database(self.path) as db:
            self.assertEqual(db.one('PRAGMA integrity_check')[0], 'ok')

    def test_process_exit_during_backfill_rolls_back_schema(self):
        self.legacy()
        before = self.snapshot()
        code = '''import os,sqlite3,sys
from pathlib import Path
from rabanito.db import Database
real=sqlite3.connect
class Interrupted(sqlite3.Connection):
 def execute(self,sql,*args,**kwargs):
  if sql.startswith('UPDATE documents SET project_root_path'):os._exit(73)
  return super().execute(sql,*args,**kwargs)
sqlite3.connect=lambda *a,**k:real(*a,factory=Interrupted,**k)
Database(Path(sys.argv[1]))
'''
        process = subprocess.run([sys.executable, '-B', '-c', code, str(self.path)], cwd=ROOT, capture_output=True, timeout=30)
        self.assertEqual(process.returncode, 73)
        self.assertEqual(before, self.snapshot())
        with Database(self.path): pass

    def test_repeated_initialization_is_idempotent(self):
        self.legacy()
        with Database(self.path): pass
        before = self.snapshot()
        for _ in range(3):
            with Database(self.path): pass
        self.assertEqual(before, self.snapshot())

    def test_specialized_schema_failures_are_atomic(self):
        from rabanito.cyber import store as cyber
        from rabanito import security, attack_store, dependency_memory
        from rabanito.knowledge_graph import store as graph
        cases = [(cyber, 'DDL', cyber.ensure_schema), (security, 'SCHEMA', security._schema),
                 (attack_store, 'DDL', lambda db: attack_store.schema(db, create=True)),
                 (dependency_memory, 'SCHEMA', lambda db: dependency_memory._schema(db, create=True)),
                 (graph, 'DDL', lambda db: graph.schema(db, create=True))]
        for module, attribute, migrate in cases:
            with self.subTest(module=module.__name__), Database(self.path) as db:
                before = [tuple(row) for row in db.query("SELECT name,sql FROM sqlite_master ORDER BY name")]
                with patch.object(module, attribute, getattr(module, attribute) + '\nINVALID SQL;'):
                    with self.assertRaises(sqlite3.Error): migrate(db)
                self.assertEqual(before, [tuple(row) for row in db.query("SELECT name,sql FROM sqlite_master ORDER BY name")])
                migrate(db)
                migrate(db)
                self.assertEqual(db.one('PRAGMA integrity_check')[0], 'ok')
                self.assertEqual(db.query('PRAGMA foreign_key_check'), [])


if __name__ == '__main__': unittest.main()
