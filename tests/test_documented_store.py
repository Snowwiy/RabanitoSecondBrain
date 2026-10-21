from __future__ import annotations

import copy
import io
import json
import os
import sqlite3
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from rabanito.cli import main
from rabanito.config import Settings, save_settings
from rabanito.db import Database, restore_database
from rabanito.document_content import document_content
from rabanito.documented_draft import preview_documented_experience
from rabanito.documented_memory import documented_experiences
from rabanito.documented_store import save_documented_experience
from rabanito.indexer import index_all
from rabanito.coding_memory import similar_experiences
import tests.test_coding_retrieval as fixtures
import tests.test_documented_draft as draft_fixtures


@unittest.skipUnless(os.name == 'nt', 'Native Windows writer; other platforms fail closed')
class DocumentedStoreTests(unittest.TestCase):
    setUp = fixtures.CodingMemoryTests.setUp
    tearDown = fixtures.CodingMemoryTests.tearDown

    def payload(self):
        return draft_fixtures.DocumentedDraftTests().payload()

    def prepare(self):
        save_settings(self.settings)
        payload = self.payload()
        preview = preview_documented_experience(payload, reviewed_on='2026-10-17')
        return payload, preview

    def save(self, payload=None, digest=None):
        payload = payload or self.payload()
        if digest is None:
            digest = preview_documented_experience(payload, reviewed_on='2026-10-17')['approval_digest']
        return save_documented_experience(self.settings, payload, reviewed_on='2026-10-17', approve_digest=digest)

    def path(self, result):
        return self.settings.knowledge_root / result['citation'].removeprefix('internal:')

    def database_snapshot(self):
        with Database(self.settings.database_path, read_only=True) as db:
            return {table: [tuple(row) for row in db.query('SELECT * FROM '+table)]
                    for table in ('documents', 'document_chunks', 'links', 'projects', 'scan_runs', 'document_changes')}

    def test_wrong_or_missing_exact_approval_writes_nothing(self):
        payload, preview = self.prepare()
        before = self.database_snapshot()
        files = sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob('*'))
        for digest in (None, '', True, 'x'*64, '0'*64, preview['approval_digest'].upper()):
            with self.subTest(digest_type=type(digest).__name__), self.assertRaises(ValueError):
                save_documented_experience(self.settings, payload, reviewed_on='2026-10-17', approve_digest=digest)
        self.assertEqual(self.database_snapshot(), before)
        self.assertEqual(files, sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob('*')))

    def test_changed_draft_cannot_reuse_approval(self):
        payload, preview = self.prepare()
        for change in ('title', 'context', 'problem', 'validation'):
            value = copy.deepcopy(payload)
            if change == 'title': value['title'] += ' changed'
            elif change == 'context': value['metadata']['scope_id'] = 'another'
            elif change == 'problem': value['sections']['Problema'] += ' changed'
            else: value['metadata']['validation'] = 'pending'
            with self.assertRaises(ValueError): self.save(value, preview['approval_digest'])

    def test_exact_unicode_note_is_indexed_cited_without_historical_promotion(self):
        payload, preview = self.prepare()
        before = {p: p.read_bytes() for root in (self.settings.vault_root, self.settings.projects_root)
                  for p in root.rglob('*') if p.is_file()}
        with patch('socket.socket', side_effect=AssertionError('offline')), patch('subprocess.run', side_effect=AssertionError('no commands')):
            result = self.save(payload)
        self.assertTrue(result['persisted']); self.assertTrue(result['indexed']); self.assertTrue(result['created'])
        self.assertEqual(self.path(result).read_bytes(), preview['content_markdown'].encode('utf-8'))
        self.assertFalse(result['fully_verified']); self.assertEqual(result['historical_validation'], 'pending')
        self.assertNotIn(str(self.root), json.dumps(result))
        retrieved = documented_experiences(self.settings, context='fixture-windows', max_chars=200)
        self.assertEqual(len(retrieved['results']), 1)
        self.assertEqual(retrieved['results'][0]['document_id'], result['document_id'])
        self.assertTrue(retrieved['results'][0]['fragments'][0]['citation'].startswith(result['citation']))
        self.assertFalse(retrieved['results'][0]['fully_verified'])
        self.assertEqual(similar_experiences(self.settings, 'Synthetic Python')['results'], [])
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        self.assertIn('Synthetic', document_content(self.settings, result['document_id'], 65536)['content_markdown'])

    def test_identical_retry_has_same_id_and_no_duplicate_scan_or_document(self):
        self.prepare(); first = self.save(); before = self.database_snapshot()
        second = self.save()
        self.assertFalse(second['created']); self.assertEqual(first['document_id'], second['document_id'])
        self.assertEqual(before, self.database_snapshot())
        self.assertEqual(len(list(self.path(first).parent.glob('*.md'))), 1)

    def test_retry_repairs_missing_document_fts_without_changing_source_or_identity(self):
        self.prepare(); first = self.save(); path = self.path(first)
        original, mtime = path.read_bytes(), path.stat().st_mtime_ns
        before = self.database_snapshot()
        with Database(self.settings.database_path, initialize=False) as db:
            db.execute('DELETE FROM documents_fts WHERE document_id=?', (str(first['document_id']),))
        self.assertEqual(documented_experiences(self.settings, 'Synthetic')['results'], [])
        repaired = self.save()
        self.assertTrue(repaired['indexed']); self.assertFalse(repaired['created'])
        self.assertEqual(repaired['document_id'], first['document_id'])
        results = documented_experiences(self.settings, 'Synthetic')['results']
        self.assertEqual(len(results), 1); self.assertFalse(results[0]['fully_verified'])
        self.assertEqual(original, path.read_bytes()); self.assertEqual(mtime, path.stat().st_mtime_ns)
        after = self.database_snapshot()
        self.assertEqual(before['projects'], after['projects'])
        self.assertEqual([r for r in before['documents'] if r[0] != first['document_id']],
                         [r for r in after['documents'] if r[0] != first['document_id']])
        self.assertEqual(len(after['scan_runs']), len(before['scan_runs'])+1)
        stable = self.database_snapshot(); self.save(); self.assertEqual(stable, self.database_snapshot())

    def test_retry_repairs_tampered_and_duplicate_document_fts_payloads(self):
        self.prepare(); first = self.save(); identity = str(first['document_id'])
        for fault in ('wrong_body', 'duplicate', 'wrong_title_or_tags'):
            with self.subTest(fault=fault):
                with Database(self.settings.database_path, initialize=False) as db:
                    if fault == 'wrong_body':
                        db.execute("UPDATE documents_fts SET body='No matching content' WHERE document_id=?", (identity,))
                    elif fault == 'duplicate':
                        db.execute('''INSERT INTO documents_fts(document_id,title,tags,body)
                            SELECT document_id,title,tags,body FROM documents_fts WHERE document_id=?''', (identity,))
                    else:
                        db.execute("UPDATE documents_fts SET title='Wrong',tags='wrong' WHERE document_id=?", (identity,))
                result = self.save(); self.assertTrue(result['indexed']); self.assertEqual(result['document_id'], first['document_id'])
                self.assertEqual(len(documented_experiences(self.settings, 'Synthetic')['results']), 1)
                with Database(self.settings.database_path, read_only=True) as db:
                    self.assertEqual(db.one('SELECT count(*) FROM documents_fts WHERE document_id=?', (identity,))[0], 1)
                    self.assertEqual(db.one('SELECT reason FROM document_changes ORDER BY change_id DESC')[0], 'documented_index_payload_repaired')

    def test_retry_repairs_missing_chunk_rows_and_removes_their_orphan_fts(self):
        self.prepare(); first = self.save(); identity = str(first['document_id'])
        with Database(self.settings.database_path, initialize=False) as db:
            old = db.query('SELECT chunk_id FROM document_chunks WHERE document_id=?', (first['document_id'],))
            self.assertTrue(old)
            db.execute('DELETE FROM document_chunks WHERE chunk_id=?', (old[0]['chunk_id'],))
        self.assertTrue(self.save()['indexed'])
        with Database(self.settings.database_path, read_only=True) as db:
            actual = db.one('SELECT count(*) FROM document_chunks WHERE document_id=?', (first['document_id'],))[0]
            self.assertEqual(actual, len(old))
            self.assertEqual(db.one('SELECT count(*) FROM chunks_fts WHERE document_id=?', (identity,))[0], actual)
            self.assertEqual(db.one('''SELECT count(*) FROM chunks_fts f LEFT JOIN document_chunks c
                ON c.chunk_id=CAST(f.chunk_id AS INTEGER) WHERE f.document_id=? AND c.chunk_id IS NULL''', (identity,))[0], 0)

    def test_retry_repairs_missing_corrupted_duplicate_and_orphan_chunk_fts(self):
        self.prepare(); first = self.save(); identity = str(first['document_id'])
        for fault in ('missing', 'wrong_text', 'duplicate', 'orphan'):
            with self.subTest(fault=fault):
                with Database(self.settings.database_path, initialize=False) as db:
                    if fault == 'missing': db.execute('DELETE FROM chunks_fts WHERE document_id=?', (identity,))
                    elif fault == 'wrong_text': db.execute("UPDATE chunks_fts SET text='Wrong',heading='Wrong' WHERE document_id=?", (identity,))
                    elif fault == 'duplicate':
                        db.execute('''INSERT INTO chunks_fts(chunk_id,document_id,heading,text)
                            SELECT chunk_id,document_id,heading,text FROM chunks_fts WHERE document_id=? LIMIT 1''', (identity,))
                    else:
                        db.execute("INSERT INTO chunks_fts(chunk_id,document_id,heading,text) VALUES('99999999',?,'Orphan','Orphan')", (identity,))
                result = self.save(); self.assertTrue(result['indexed']); self.assertEqual(result['document_id'], first['document_id'])
                with Database(self.settings.database_path, read_only=True) as db:
                    self.assertEqual(db.one('SELECT count(*) FROM chunks_fts WHERE document_id=?', (identity,))[0],
                                     db.one('SELECT count(*) FROM document_chunks WHERE document_id=?', (first['document_id'],))[0])

    def test_retry_repairs_tags_and_raw_links_matching_parser_deduplication(self):
        self.prepare(); payload = self.payload()
        payload['sections']['Problema'] += '\n#fixture-tag [[Missing|First]] [[Missing|Second]]'
        first = self.save(payload)
        with Database(self.settings.database_path, initialize=False) as db:
            db.execute('DELETE FROM tags WHERE document_id=?', (first['document_id'],))
            db.execute("UPDATE links SET label='Wrong' WHERE source_document_id=?", (first['document_id'],))
        self.assertTrue(self.save(payload)['indexed'])
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertIn('fixture-tag', [r[0] for r in db.query('SELECT tag FROM tags WHERE document_id=?', (first['document_id'],))])
            links = db.query('SELECT label FROM links WHERE source_document_id=?', (first['document_id'],))
            self.assertEqual([r[0] for r in links], ['First'])
        stable = self.database_snapshot(); self.save(payload); self.assertEqual(stable, self.database_snapshot())

    def test_retry_repairs_derived_display_metadata_but_not_unowned_identity(self):
        self.prepare(); first = self.save()
        for column, value in (('title', 'Wrong'), ('tags_json', '[] changed'), ('category', 'Wrong'), ('project_name', 'Wrong')):
            with self.subTest(column=column):
                with Database(self.settings.database_path, initialize=False) as db:
                    db.execute('UPDATE documents SET '+column+'=? WHERE document_id=?', (value, first['document_id']))
                self.assertTrue(self.save()['indexed'])
        path = self.path(first); original = path.read_bytes()
        with Database(self.settings.database_path, initialize=False) as db:
            db.execute('UPDATE documents SET absolute_path=? WHERE document_id=?', (str(self.root/'unowned.md'), first['document_id']))
        result = self.save(); self.assertTrue(result['persisted']); self.assertFalse(result['indexed'])
        self.assertEqual(path.read_bytes(), original)
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(db.one('SELECT absolute_path FROM documents WHERE document_id=?', (first['document_id'],))[0], str(self.root/'unowned.md'))

    def test_payload_repair_postcheck_failure_rolls_back_and_leaves_source_retryable(self):
        self.prepare(); first = self.save(); original = self.path(first).read_bytes()
        with Database(self.settings.database_path, initialize=False) as db:
            db.execute('DELETE FROM documents_fts WHERE document_id=?', (str(first['document_id']),))
        before = self.database_snapshot()
        with patch('rabanito.documented_store._payload_matches', return_value=False):
            pending = self.save()
        self.assertTrue(pending['persisted']); self.assertFalse(pending['indexed'])
        self.assertEqual(before, self.database_snapshot()); self.assertEqual(original, self.path(first).read_bytes())
        self.assertEqual(documented_experiences(self.settings, 'Synthetic')['results'], [])
        self.assertTrue(self.save()['indexed'])
        self.assertEqual(len(documented_experiences(self.settings, 'Synthetic')['results']), 1)

    def test_regular_index_purges_only_owned_orphan_chunk_cache_after_source_change(self):
        self.prepare(); first = self.save(); identity = str(first['document_id'])
        with Database(self.settings.database_path, initialize=False) as db:
            db.execute("INSERT INTO chunks_fts(chunk_id,document_id,heading,text) VALUES('99999999',?,'Orphan','Orphan')", (identity,))
            unrelated = [tuple(r) for r in db.query('SELECT * FROM chunks_fts WHERE document_id<>?', (identity,))]
        path = self.path(first); path.write_bytes(path.read_bytes()+b'\nExtra fixture line for ordinary incremental index.\n')
        index_all(self.settings)
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertIsNone(db.one("SELECT 1 FROM chunks_fts WHERE chunk_id='99999999'"))
            self.assertEqual(unrelated, [tuple(r) for r in db.query('SELECT * FROM chunks_fts WHERE document_id<>?', (identity,))])

    def test_existing_conflicting_note_is_never_overwritten(self):
        self.prepare(); result = self.save(); path = self.path(result)
        path.write_bytes(b'# Synthetic different content\n')
        before = self.database_snapshot()
        with self.assertRaisesRegex(ValueError, 'documented_destination_conflict'): self.save()
        self.assertEqual(path.read_bytes(), b'# Synthetic different content\n')
        self.assertEqual(before, self.database_snapshot())

    def test_index_failure_preserves_approved_note_and_retry_recovers(self):
        self.prepare(); before = self.database_snapshot()
        with patch('rabanito.documented_store._index_saved', side_effect=OSError('private path must not escape')):
            pending = self.save()
        self.assertTrue(pending['persisted']); self.assertFalse(pending['indexed']); self.assertTrue(pending['retry_safe'])
        self.assertTrue(self.path(pending).is_file()); self.assertEqual(before, self.database_snapshot())
        self.assertNotIn('private path', json.dumps(pending))
        final = self.save(); self.assertFalse(final['created']); self.assertTrue(final['indexed'])

    def test_transaction_failure_rolls_back_scoped_index_but_not_the_note(self):
        self.prepare(); before = self.database_snapshot()
        with patch('rabanito.documented_store._resolve_links', side_effect=ValueError('fixture transaction failure')):
            pending = self.save()
        self.assertFalse(pending['indexed']); self.assertTrue(self.path(pending).is_file())
        self.assertEqual(before, self.database_snapshot()); self.assertTrue(self.save()['indexed'])

    def test_only_new_record_and_outgoing_links_are_indexed(self):
        payload, _ = self.prepare()
        unrelated = self.settings.vault_root / 'unindexed.md'; unrelated.write_text('# Not indexed by scoped writer\n', encoding='utf-8')
        target = self.settings.knowledge_root / 'target.md'; target.write_text('# Synthetic target\n', encoding='utf-8')
        index_all(self.settings)
        unrelated.write_text('# Changed original must remain untouched\n', encoding='utf-8')
        payload['sections']['Problema'] += '\n[[target]]'
        before = self.database_snapshot()
        result = self.save(payload); after = self.database_snapshot()
        self.assertEqual(before['projects'], after['projects'])
        self.assertEqual(before['documents'], [r for r in after['documents'] if r[0] != result['document_id']])
        with Database(self.settings.database_path, read_only=True) as db:
            link = db.one('SELECT status FROM links WHERE source_document_id=?', (result['document_id'],))
            self.assertEqual(link['status'], 'resolved')
            self.assertEqual(db.one('SELECT status FROM scan_runs ORDER BY scan_id DESC')['status'], 'partial')

    def test_excluded_context_policy_directory_extension_and_size_are_enforced(self):
        mutations = ({'excluded_memory_contexts': ['fixture-windows']},
                     {'excluded_memory_contexts': [True]},
                     {'source_policy': {'internal': {'extensions': ['.txt']}}},
                     {'source_policy': {'internal': {'extensions': ['.md'], 'exclude_dirs': ['environments']}}},
                     {'source_policy': {'internal': {'extensions': ['.md'], 'exclude_extensions': ['.md']}}},
                     {'source_policy': {'internal': {'extensions': ['.md'], 'max_file_bytes': 1}}})
        original = copy.deepcopy(self.settings.raw)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.settings.raw.clear(); self.settings.raw.update(copy.deepcopy(original)); self.settings.raw.update(mutation)
                save_settings(self.settings)
                with self.assertRaises(ValueError): self.save()
        self.assertFalse((self.settings.knowledge_root / 'decisions' / 'environments').exists())

    def test_root_escape_source_overlap_and_database_outside_data_are_denied(self):
        original = copy.deepcopy(self.settings.raw)
        for mutation in ({'knowledge_dir': '../elsewhere'}, {'data_dir': str(self.root.parent)},
                         {'database_path': 'unowned.db'}, {'knowledge_dir': 'vault'},
                         {'data_dir': 'projects'}, {'knowledge_dir': 'data/notes'}):
            with self.subTest(mutation=mutation):
                self.settings.raw.clear(); self.settings.raw.update(copy.deepcopy(original)); self.settings.raw.update(mutation)
                with self.assertRaises(ValueError): self.save()

    def test_device_ads_invalid_storage_names_and_types_are_denied(self):
        original = copy.deepcopy(self.settings.raw)
        for key, value in (('database_path', 'data/index.lock'), ('database_path', 'data/note:stream.db'),
                           ('database_path', 'data/CON.db'), ('knowledge_dir', 'knowledge. '),
                           ('data_dir', True), ('database_path', None)):
            with self.subTest(key=key, value=value):
                self.settings.raw.clear(); self.settings.raw.update(copy.deepcopy(original)); self.settings.raw[key] = value
                with self.assertRaises(ValueError): self.save()

    def test_current_configuration_change_requires_reload(self):
        self.prepare(); changed = copy.deepcopy(self.settings.raw)
        changed['excluded_memory_contexts'] = ['fixture-windows']
        save_settings(Settings(self.root, changed))
        with self.assertRaisesRegex(ValueError, 'documented_config_changed_reload_required'): self.save()
        self.assertFalse((self.settings.knowledge_root / 'decisions' / 'environments').exists())

    def test_configuration_rechecked_after_waiting_for_index_lock(self):
        from contextlib import contextmanager
        from rabanito.indexer import _index_lock
        self.prepare()
        @contextmanager
        def change_before_lock(settings):
            changed = copy.deepcopy(settings.raw); changed['excluded_memory_contexts'] = ['fixture-windows']
            save_settings(Settings(self.root, changed))
            with _index_lock(settings): yield
        with patch('rabanito.documented_store._index_lock', change_before_lock):
            with self.assertRaisesRegex(ValueError, 'documented_config_changed_reload_required'): self.save()

    def test_actual_junction_parent_cannot_redirect_writes(self):
        self.prepare()
        target = self.root / 'not-authorized'; target.mkdir()
        link = self.settings.knowledge_root / 'decisions'
        import _winapi
        _winapi.CreateJunction(str(target), str(link))
        try:
            with self.assertRaises(ValueError): self.save()
            self.assertEqual(list(target.iterdir()), [])
        finally: link.rmdir()

    def test_pinned_directory_cannot_be_swapped_during_publication(self):
        self.prepare()
        from rabanito.documented_store import _publish
        def attempt(path, body):
            with self.assertRaises(OSError): path.parent.rename(path.parent.with_name('replaced'))
            return _publish(path, body)
        with patch('rabanito.documented_store._publish', side_effect=attempt):
            self.assertTrue(self.save()['indexed'])

    def test_existing_hardlinked_lock_and_database_are_denied_without_external_changes(self):
        self.prepare()
        lock = self.settings.data_dir / 'index.lock'
        alias = self.root / 'lock-copy'; os.link(lock, alias)
        before = alias.read_bytes()
        try:
            with self.assertRaises(ValueError): self.save()
            self.assertEqual(before, alias.read_bytes())
        finally: alias.unlink()
        alias = self.root / 'db-copy'; os.link(self.settings.database_path, alias)
        before = alias.read_bytes()
        try:
            result = self.save(); self.assertTrue(result['persisted']); self.assertFalse(result['indexed'])
            self.assertEqual(before, alias.read_bytes())
        finally: alias.unlink()
        self.assertTrue(self.save()['indexed'])

    def test_existing_hardlinked_destination_is_not_accepted(self):
        self.prepare(); result = self.save(); alias = self.root / 'note-copy'
        os.link(self.path(result), alias)
        try:
            with self.assertRaises(ValueError): self.save()
        finally: alias.unlink()

    def test_atomic_publish_failure_cleans_only_its_own_temporary(self):
        self.prepare()
        with patch('rabanito.documented_store.os.rename', side_effect=OSError('fixture disk failure')):
            with self.assertRaises(OSError): self.save()
        self.assertEqual(list(self.settings.knowledge_root.glob('decisions/environments/*/*')), [])
        self.assertTrue(self.save()['indexed'])

    def test_racing_destination_is_not_replaced_and_foreign_file_survives(self):
        self.prepare()
        real_rename = os.rename
        foreign = b'# Synthetic concurrent work\n'
        def collide(source, destination):
            Path(destination).write_bytes(foreign)
            return real_rename(source, destination)
        with patch('rabanito.documented_store.os.rename', side_effect=collide):
            with self.assertRaises(FileExistsError): self.save()
        notes = list(self.settings.knowledge_root.glob('decisions/environments/*/*.md'))
        self.assertEqual(len(notes), 1); self.assertEqual(notes[0].read_bytes(), foreign)
        self.assertEqual(list(notes[0].parent.glob('*.tmp')), [])

    def test_sidecar_pins_released_before_sqlite_cleanup(self):
        self.prepare(); self.save(); self.database_snapshot()
        from contextlib import contextmanager
        from rabanito.documented_store import _pin
        active = Counter()
        @contextmanager
        def track(path, **kwargs):
            with _pin(path, **kwargs):
                active[path] += 1
                try: yield
                finally:
                    active[path] -= 1
                    if not active[path]: del active[path]
        owner = self
        opened_under_guard = []
        class CheckedDatabase(Database):
            def one(inner, sql, params=()):
                if sql == 'PRAGMA schema_version':
                    owner.assertTrue(any(str(p).endswith(('-wal', '-shm')) for p in active))
                    opened_under_guard.append(True)
                return super().one(sql, params)
            def __exit__(inner, *args):
                owner.assertFalse(any(str(p).endswith(('-wal', '-shm', '-journal')) for p in active))
                return super().__exit__(*args)
        with patch('rabanito.documented_store._pin', track), patch('rabanito.documented_store.Database', CheckedDatabase):
            self.assertTrue(self.save()['indexed'])
        self.assertEqual(opened_under_guard, [True])

    def test_first_save_bootstraps_a_new_local_index_without_scanning_sources(self):
        self.settings.raw['database_path'] = 'data/new-index.db'
        self.prepare()
        self.assertFalse(self.settings.database_path.exists())
        result = self.save(); self.assertTrue(result['indexed'])
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(db.one('SELECT count(*) FROM documents')[0], 1)
            self.assertEqual(db.one('SELECT count(*) FROM projects')[0], 0)

    def test_longest_context_and_unicode_title_are_supported(self):
        self.prepare(); payload = self.payload()
        payload['metadata']['scope_id'] = 'f' * 64
        payload['title'] = 'Unicode ñ 漢字 ' * 10
        self.assertTrue(self.save(payload)['indexed'])

    def test_stale_derived_metadata_can_be_repaired_without_promoting_the_source(self):
        self.prepare(); original = self.save()
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE documents SET frontmatter_json='{}' WHERE document_id=?", (original['document_id'],))
        repaired = self.save()
        self.assertEqual(repaired['document_id'], original['document_id'])
        retrieved = documented_experiences(self.settings, context='fixture-windows')['results']
        self.assertEqual(len(retrieved), 1); self.assertFalse(retrieved[0]['fully_verified'])

    def test_existing_index_does_not_backfill_unrelated_legacy_rows(self):
        self.prepare()
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE documents SET project_root_path=NULL WHERE source_kind='projects'")
        before = self.database_snapshot()
        result = self.save(); after = self.database_snapshot()
        self.assertEqual(before['documents'], [r for r in after['documents'] if r[0] != result['document_id']])

    def test_existing_incompatible_index_is_not_implicitly_migrated(self):
        self.prepare()
        with Database(self.settings.database_path) as db: db.execute('DROP TABLE documents_fts')
        result = self.save(); self.assertTrue(result['persisted']); self.assertFalse(result['indexed'])
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertIsNone(db.one("SELECT 1 FROM sqlite_master WHERE name='documents_fts'"))

    def test_scoped_database_mode_never_creates_an_absent_database(self):
        self.prepare(); missing = self.settings.data_dir / 'must-not-exist.db'
        with self.assertRaises(sqlite3.OperationalError): Database(missing, initialize=False)
        self.assertFalse(missing.exists())

    def test_concurrent_identical_writers_serialize_to_one_note_and_scan(self):
        self.prepare(); before = len(self.database_snapshot()['scan_runs'])
        barrier = threading.Barrier(2)
        def write(): barrier.wait(timeout=5); return self.save()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: write(), range(2)))
        self.assertEqual(sum(r['created'] for r in results), 1)
        self.assertEqual(len({r['document_id'] for r in results}), 1)
        self.assertEqual(len(self.database_snapshot()['scan_runs']), before+1)

    def test_cli_save_success_exact_digest_and_safe_error_contract(self):
        payload, preview = self.prepare()
        argv = ['coding', 'save-documented', '--stdin', '--reviewed-on', '2026-10-17', '--approve-digest', preview['approval_digest']]
        output = io.StringIO()
        with patch('rabanito.cli.load_settings', return_value=self.settings), patch('sys.stdin', io.StringIO(json.dumps(payload))), redirect_stdout(output):
            main(argv)
        self.assertTrue(json.loads(output.getvalue())['indexed'])
        output = io.StringIO()
        with patch('rabanito.cli.load_settings', return_value=self.settings), patch('sys.stdin', io.StringIO(json.dumps(payload))), redirect_stdout(output), self.assertRaises(SystemExit) as caught:
            main([*argv[:-1], '0'*64])
        self.assertEqual(caught.exception.code, 1)
        self.assertEqual(json.loads(output.getvalue()), {'error': 'exact_documented_approval_required'})

    def test_cli_pending_index_exits_two_and_no_http_writer_is_added(self):
        payload, preview = self.prepare(); output = io.StringIO()
        with patch('rabanito.cli.load_settings', return_value=self.settings), patch('sys.stdin', io.StringIO(json.dumps(payload))), patch('rabanito.documented_store._index_saved', side_effect=OSError('fixture')), redirect_stdout(output), self.assertRaises(SystemExit) as caught:
            main(['coding', 'save-documented', '--stdin', '--reviewed-on', '2026-10-17', '--approve-digest', preview['approval_digest']])
        self.assertEqual(caught.exception.code, 2); self.assertFalse(json.loads(output.getvalue())['indexed'])
        server = (Path(__file__).resolve().parents[1] / 'rabanito/server.py').read_text(encoding='utf-8')
        self.assertNotIn('save_documented_experience', server)

    def test_malformed_types_and_deep_payload_fail_with_fixed_cli_errors(self):
        self.prepare()
        malformed = self.payload(); malformed['metadata']['validation'] = []
        deep = 'synthetic private value'
        for _ in range(600): deep = [deep]
        for payload in (malformed, {'unexpected': deep}):
            output = io.StringIO()
            with patch('rabanito.cli.load_settings', return_value=self.settings), patch('sys.stdin', io.StringIO(json.dumps(payload))), redirect_stdout(output), self.assertRaises(SystemExit) as caught:
                main(['coding', 'save-documented', '--stdin', '--reviewed-on', '2026-10-17', '--approve-digest', '0'*64])
            self.assertEqual(caught.exception.code, 1)
            self.assertEqual(json.loads(output.getvalue()), {'error': 'invalid_documented_save_draft'})

    def test_backup_restore_preserves_citations_fts_and_pending_evidence(self):
        self.prepare(); result = self.save(); backup = self.settings.data_dir / 'writer-backup.db'
        with Database(self.settings.database_path, read_only=True) as db:
            db.backup(backup)
        restored = self.settings.data_dir / 'writer-restored.db'; restore_database(backup, restored)
        settings = Settings(self.root, {**self.settings.raw, 'database_path': str(restored)})
        response = documented_experiences(settings, context='fixture-windows')
        self.assertEqual(response['results'][0]['document_id'], result['document_id'])
        self.assertFalse(response['results'][0]['fully_verified'])
        with Database(restored, read_only=True) as db:
            self.assertEqual(db.one('PRAGMA integrity_check')[0], 'ok')
            self.assertEqual(db.query('PRAGMA foreign_key_check'), [])
            self.assertEqual(db.one('SELECT count(*) FROM documents_fts WHERE document_id=?', (str(result['document_id']),))[0], 1)


class WriterPortabilityTests(unittest.TestCase):
    def test_unsupported_platform_fails_before_any_storage_access(self):
        with patch('rabanito.documented_store.os.name', 'posix'), patch('builtins.open', side_effect=AssertionError('no access')):
            with self.assertRaisesRegex(ValueError, 'documented_writer_requires_native_windows'):
                save_documented_experience(None, {}, reviewed_on='2026-10-17', approve_digest='0'*64)
