from __future__ import annotations

import http.client
import json
import threading
import unittest

from rabanito.db import Database
from rabanito.indexer import index_all
from rabanito.scan_status import attach_report, last_complete_scan, public_diagnostics
from rabanito.search import stats
from rabanito.server import RabanitoHandler, ThreadingHTTPServer
import tests.test_file_authorization as fixtures


class ScanContractTests(unittest.TestCase):
    setUp = fixtures.FileAuthorizationTests.setUp

    def seed(self, count=1):
        for number in range(count):
            (self.root / 'vault' / f'Note{number:02}.md').write_text('# Fixture\n', encoding='utf-8')
        return index_all(self.settings)

    def test_complete_scan_is_confirmed_and_partial_does_not_replace_it(self):
        first = self.seed(12)
        confirmed = stats(self.settings)['last_complete_scan']
        self.assertEqual(confirmed['scan_id'], first['scan_id'])
        for path in (self.root / 'vault').glob('*.md'): path.unlink()
        blocked = index_all(self.settings)
        result = stats(self.settings)
        self.assertEqual(result['last_complete_scan'], confirmed)
        self.assertEqual(result['latest_scan']['scan_id'], blocked['scan_id'])
        self.assertEqual(result['latest_scan']['status'], 'partial')
        self.assertEqual(result['latest_scan']['retirement_guard']['withheld'], 12)
        self.assertEqual(result['latest_scan']['retirement_guard']['status'], 'review_required')
        self.assertTrue(result['latest_scan']['scan_coverage']['complete'])

    def test_failed_unavailable_source_exposes_incomplete_coverage(self):
        self.seed()
        (self.root / 'vault').rename(self.root / 'offline')
        index_all(self.settings)
        scan = stats(self.settings)['latest_scan']
        self.assertEqual(scan['status'], 'partial')
        self.assertFalse(scan['scan_coverage']['complete'])
        self.assertGreater(scan['scan_coverage']['failed_sources'], 0)
        self.assertGreater(scan['source_summary']['obsidian']['errors'], 0)

    def test_zero_processed_sources_cannot_confirm_success(self):
        for name in ('vault','projects','knowledge'): (self.root / name).rmdir()
        result = index_all(self.settings)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['scan_coverage']['completed_sources'], 0)
        self.assertIsNone(stats(self.settings)['last_complete_scan'])

    def test_legacy_ok_without_coverage_is_not_a_confirmed_complete_scan(self):
        with Database(self.settings.database_path) as db:
            db.execute("INSERT INTO scan_runs(started_at,finished_at,status) VALUES('fixture','fixture','ok')")
        result = stats(self.settings)
        self.assertEqual(result['latest_scan']['status'], 'ok')
        self.assertNotIn('scan_coverage', result['latest_scan'])
        self.assertIsNone(result['last_complete_scan'])

    def test_public_diagnostics_omit_private_paths_and_approval_digest(self):
        first = self.seed()
        first['scan_coverage']['private_path'] = str(self.root)
        first['retirement_guard']['approval_digest'] = 'a'*64
        projected = public_diagnostics(first)
        self.assertNotIn(str(self.root), json.dumps(projected))
        self.assertNotIn('approval_digest', json.dumps(projected))
        for mutation in ({'scan_coverage':[]}, {'retirement_guard':{'status':True}},
                         {'retirement_guard':first['retirement_guard'] | {'withheld':True}},
                         {'retirement_guard':first['retirement_guard'] | {'status':[]}},
                         {'scan_coverage':first['scan_coverage'] | {'completed_sources':999}}):
            self.assertEqual(public_diagnostics(first | mutation), {})

    def test_invalid_or_oversize_report_is_unknown_not_success(self):
        first = self.seed()
        with Database(self.settings.database_path) as db:
            for value in ('[', '{}', 'x'*16385):
                db.execute('UPDATE meta SET value=? WHERE key=?', (value,'index_scan_report:'+str(first['scan_id'])))
                self.assertNotIn('scan_coverage', attach_report(db, {'scan_id':first['scan_id']}))
                self.assertIsNone(last_complete_scan(db))

    def test_http_200_partial_and_persisted_history_have_same_diagnostics(self):
        complete = self.seed(12)
        for path in (self.root / 'vault').glob('*.md'): path.unlink()
        handler = type('FixtureHandler', (RabanitoHandler,), {'settings':self.settings, 'log_message':lambda *a:None})
        server = ThreadingHTTPServer(('127.0.0.1',0), handler)
        worker = threading.Thread(target=server.serve_forever,daemon=True)
        worker.start()
        try:
            origin = 'http://127.0.0.1:' + str(server.server_port)
            client = http.client.HTTPConnection('127.0.0.1', server.server_port,timeout=5)
            client.request('POST','/api/index',body='{}',headers={'Origin':origin,'Content-Type':'application/json'})
            response = client.getresponse()
            self.assertEqual(response.status, 200)
            indexed = json.loads(response.read())
            client.close()
            self.assertEqual(indexed['status'],'partial')
            self.assertEqual(indexed['retirement_guard']['withheld'],12)
            self.assertNotIn('approval_digest',json.dumps(indexed))
            client = http.client.HTTPConnection('127.0.0.1', server.server_port,timeout=5)
            client.request('GET','/api/scans')
            response = client.getresponse()
            history = json.loads(response.read())
            client.close()
            self.assertEqual(history['last_complete_scan']['scan_id'],complete['scan_id'])
            self.assertEqual(history['scans'][0]['retirement_guard'],indexed['retirement_guard'])
            self.assertEqual(history['scans'][0]['scan_coverage'],indexed['scan_coverage'])
        finally:
            server.shutdown(); server.server_close(); worker.join(timeout=2)


if __name__ == '__main__': unittest.main()
