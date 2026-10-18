from __future__ import annotations

import copy
import io
import json
import socket
import sqlite3
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from urllib.error import HTTPError,URLError
from urllib.request import Request,urlopen

from rabanito.asvs import FRAMEWORK,normalize,import_payload
from rabanito.asvs_capture import capture,read_capture,source_url,BASE
from rabanito.cli import main
from rabanito.cyber.model import InvalidFeed
from rabanito.cyber.transport import FetchError
from rabanito.db import Database,restore_database
from rabanito.knowledge_graph import graph_page,sync_graph
from rabanito.public_capture import transfer
from rabanito.security import index_security_catalog,search_security,security_context,get_security_entry
from rabanito.security_imports import KEY,read_imports,summaries
from tests import test_security as fixtures
from tests import test_cyber as http_fixtures
from tests.attack_fixture import Response,blob


COMMIT='b'*40
NOTICE=b'Attribution-ShareAlike 4.0 International\nSynthetic fixture notice, not the publisher license.'


def document():
    return {'Name':'ASVS fixture','ShortName':'ASVS','Version':'5.0.0','Description':'Synthetic requirements, no real assessment.',
            'Requirements':[{'Shortcode':'V1','Ordinal':1,'ShortName':'Fixture','Name':'Unicode ñ grouping','Items':[
                {'Shortcode':'V1.2','Ordinal':2,'Name':'Synthetic section','Items':[
                    {'Shortcode':'V1.2.5','Ordinal':5,'Description':'Verify synthetic parameterization constraint.','L':'1'},
                    {'Shortcode':'V1.2.6','Ordinal':6,'Description':'Verify synthetic higher assurance constraint.','L':'3'}]}]}]}


class Opener:
    def __init__(self,raw=None,notice=NOTICE,headers=None):
        self.raw=raw if raw is not None else json.dumps(document(),ensure_ascii=False).encode()
        self.notice,self.headers,self.requests=notice,headers,[]
    def open(self,request,timeout):
        self.requests.append(request)
        return Response(self.notice) if request.full_url.endswith('/LICENSE.md') else Response(self.raw,self.headers)


class AsvsTests(unittest.TestCase):
    setUp=fixtures.SecurityKnowledgeTests.setUp
    tearDown=fixtures.SecurityKnowledgeTests.tearDown
    save_catalog=fixtures.SecurityKnowledgeTests.save_catalog
    server=http_fixtures.CyberTests.server

    def capture(self,value=None,commit=COMMIT,opener=None,**kwargs):
        raw=json.dumps(value if value is not None else document(),ensure_ascii=False).encode()
        return capture(self.settings,commit,blob(raw),len(raw),blob(NOTICE),len(NOTICE),opener=opener or Opener(raw),**kwargs)

    def install(self,value=None,commit=COMMIT,**kwargs):
        return index_security_catalog(self.settings,asvs_capture=self.capture(value,commit)['manifest'],**kwargs)

    def test_normalize_preserves_official_versioned_id_levels_and_json_pointers(self):
        r=normalize(json.dumps(document()).encode())
        self.assertEqual(r['coverage'],{'chapters':1,'sections':1,'requirements':2,'assessment_performed':False})
        self.assertEqual(r['requirements'][0]['id'],'v5.0.0-1.2.5')
        self.assertEqual(r['requirements'][0]['level'],1)
        self.assertEqual(r['requirements'][0]['pointer'],'/Requirements/0/Items/0/Items/0')
        self.assertEqual(r['groups'][1]['parent'],'ASVS-5.0.0/chapter/1')

    def test_wrong_version_unknown_fields_and_false_ordinals_fail_closed(self):
        for mutate in (lambda d:d.update(Version='5.0.1'),lambda d:d.update(extra='ignored'),
                       lambda d:d['Requirements'][0].update(Ordinal=True),lambda d:d['Requirements'][0].update(Shortcode='V2'),
                       lambda d:d['Requirements'][0]['Items'][0]['Items'][0].update(L=1),
                       lambda d:d['Requirements'][0]['Items'][0]['Items'][0].update(L='4')):
            d=document();mutate(d)
            with self.assertRaises(InvalidFeed):normalize(json.dumps(d).encode())

    def test_duplicate_ids_nonfinite_bad_json_utf8_and_empty_groups_rejected(self):
        d=document();items=d['Requirements'][0]['Items'][0]['Items'];items.append(copy.deepcopy(items[0]))
        with self.assertRaises(InvalidFeed):normalize(json.dumps(d).encode())
        for raw in (b'{"Version":"5.0.0","Version":"x"}',b'{"x":NaN}',b'\xff',b'[]',b'{} trailing'):
            with self.assertRaises(InvalidFeed):normalize(raw)
        d=document();d['Requirements'][0]['Items']=[]
        with self.assertRaises(InvalidFeed):normalize(json.dumps(d).encode())

    def test_shared_capture_transport_get_only_pinned_body_and_license(self):
        opener=Opener();c=self.capture(opener=opener)
        self.assertEqual(len(opener.requests),2)
        for request in opener.requests:
            self.assertEqual(request.method,'GET');self.assertIsNone(request.data)
            self.assertNotIn('Authorization',request.headers)
            self.assertNotIn('Cookie',request.headers)
        self.assertEqual(opener.requests[0].full_url,source_url(COMMIT))
        self.assertEqual(opener.requests[1].full_url,BASE+COMMIT+'/LICENSE.md')
        with patch.object(socket,'socket',side_effect=AssertionError('offline replay')):
            raw,meta,notice=read_capture(self.settings,c['manifest'])
        self.assertEqual(blob(raw),meta['git_blob_sha1']);self.assertEqual(notice,NOTICE.decode())
        self.assertFalse(self.settings.database_path.exists())

    def test_capture_refuses_mutable_refs_private_hosts_and_bad_budgets(self):
        for commit in ('master','v5.0.0','../other',None):
            with self.assertRaises(ValueError):source_url(commit)
        for kwargs in ({'size':True},{'license_size':65537},{'max_seconds':True}):
            raw=json.dumps(document()).encode();args={'size':len(raw),'license_size':len(NOTICE),'max_seconds':120,**kwargs}
            with self.assertRaises(ValueError):capture(self.settings,COMMIT,blob(raw),args['size'],blob(NOTICE),args['license_size'],opener=Opener(raw),max_seconds=args['max_seconds'])
        for url in ('http://127.0.0.1/private','https://example.invalid/x',BASE+COMMIT+'/other.json'):
            with self.assertRaises(ValueError):transfer(Opener(),url,self.root/'not-created',limit=1,expected_size=1,started=0,seconds=1,monotonic=lambda:0,prefix='asvs')

    def test_wrong_blob_truncation_html_and_license_do_not_publish_manifest(self):
        for opener in (Opener(raw=b'{}'),Opener(headers={'Content-Type':'text/html'}),Opener(notice=b'not license')):
            with self.assertRaises(InvalidFeed):self.capture(opener=opener)
        self.assertEqual(list((self.settings.data_dir/'asvs-captures').iterdir()),[])

    def test_rate_limit_and_network_errors_are_stable_without_retries(self):
        for error,expected in ((HTTPError('https://public.invalid',429,'body',{'Retry-After':'30'},None),'asvs_http_error'),(URLError('private detail'),'asvs_transport_error')):
            opener=Opener()
            with patch.object(opener,'open',side_effect=error) as mocked,self.assertRaises(FetchError) as caught:
                self.capture(opener=opener)
            self.assertEqual(str(caught.exception),expected);self.assertEqual(mocked.call_count,1)

    def test_corrupt_capture_and_traversal_fail_before_normalization(self):
        for name in ('../secret.json','C:/private.json','x.metadata.json'):
            with self.assertRaises(ValueError):read_capture(self.settings,name)
        c=self.capture();path=self.settings.data_dir/'asvs-captures'/c['license'];path.write_bytes(b'x'*len(NOTICE))
        with patch('rabanito.asvs.normalize',side_effect=AssertionError('must reject first')):
            with self.assertRaisesRegex(ValueError,'hash_or_stat'):import_payload(self.settings,c['manifest'])

    def test_new_import_is_atomic_offline_and_preserves_every_legacy_entry(self):
        index_security_catalog(self.settings)
        before=[get_security_entry(self.settings,e['id']) for e in self.catalog['entries']]
        manifest=self.capture()['manifest']
        with patch.object(socket,'socket',side_effect=AssertionError('offline index')):
            result=index_security_catalog(self.settings,asvs_capture=manifest)
        self.assertEqual((result['added'],result['modified'],result['unchanged'],result['retired']),(4,0,72,0))
        self.assertEqual(result['relations'],70)
        for entry,old in zip(self.catalog['entries'],before):
            now=get_security_entry(self.settings,entry['id'])
            self.assertEqual({k:v for k,v in now.items() if k!='relations'},{k:v for k,v in old.items() if k!='relations'})
        self.assertTrue(result['migration_backup'])
        self.assertEqual(search_security(self.settings,framework=FRAMEWORK,kind='control')['total'],2)

    def test_plain_reindex_preserves_import_when_capture_is_unavailable(self):
        c=self.capture();index_security_catalog(self.settings,asvs_capture=c['manifest'])
        for field in ('body','license'):(self.settings.data_dir/'asvs-captures'/c[field]).unlink()
        first=get_security_entry(self.settings,'v5.0.0-1.2.5')
        result=index_security_catalog(self.settings)
        self.assertEqual((result['unchanged'],result['added'],result['retired']),(76,0,0))
        self.assertFalse(result['registry_changed'])
        self.assertEqual(first,get_security_entry(self.settings,'v5.0.0-1.2.5'))

    def test_idempotence_does_not_rewrite_fts_relations_or_epoch(self):
        c=self.capture();index_security_catalog(self.settings,asvs_capture=c['manifest']);sync_graph(self.settings,max_inputs=5000)
        with Database(self.settings.database_path,read_only=True) as db:
            epoch=db.one('SELECT value FROM kg_epoch')[0]
        result=index_security_catalog(self.settings)
        self.assertEqual(result['unchanged'],76)
        with Database(self.settings.database_path,read_only=True) as db:
            self.assertEqual(db.one('SELECT value FROM kg_epoch')[0],epoch)

    def test_explicit_snapshot_replacement_has_backup_and_no_silent_overwrite(self):
        self.install();changed=document();changed['Requirements'][0]['Items'][0]['Items'][0]['Description']='Verify changed fixture constraint.'
        c=self.capture(changed,'c'*40)
        with self.assertRaisesRegex(ValueError,'explicit_replace'):index_security_catalog(self.settings,asvs_capture=c['manifest'])
        self.assertIn('parameterization',get_security_entry(self.settings,'v5.0.0-1.2.5')['summary'])
        result=index_security_catalog(self.settings,asvs_capture=c['manifest'],replace_asvs=True)
        self.assertEqual(result['modified'],4)
        self.assertTrue(result['migration_backup'])

    def test_failure_rolls_back_import_registry_entries_fts_and_relations(self):
        index_security_catalog(self.settings);c=self.capture()
        with patch.object(Database,'executemany',side_effect=sqlite3.OperationalError('fixture failure')),self.assertRaises(sqlite3.Error):
            index_security_catalog(self.settings,asvs_capture=c['manifest'])
        self.assertEqual(search_security(self.settings)['total'],72)
        with Database(self.settings.database_path,read_only=True) as db:
            self.assertIsNone(db.one('SELECT value FROM meta WHERE key=?',(KEY,)))
            self.assertEqual(db.one('SELECT count(*) FROM security_relations')[0],66)

    def test_registry_license_tampering_fails_without_retiring_imported_entries(self):
        self.install()
        with Database(self.settings.database_path) as db:
            value=json.loads(db.one('SELECT value FROM meta WHERE key=?',(KEY,))[0]);value['imports'][FRAMEWORK]['license_text']='tampered'
            db.execute('UPDATE meta SET value=? WHERE key=?',(json.dumps(value),KEY))
        with self.assertRaisesRegex(ValueError,'license'):index_security_catalog(self.settings)
        self.assertEqual(search_security(self.settings,kind='control')['total'],28)

    def test_level_filter_is_exact_not_cumulative_and_requires_integer(self):
        self.install()
        self.assertEqual(search_security(self.settings,framework=FRAMEWORK,level=1)['total'],1)
        self.assertEqual(search_security(self.settings,framework=FRAMEWORK,level=2)['total'],0)
        self.assertEqual(search_security(self.settings,framework=FRAMEWORK,level=3)['total'],1)
        for level in (True,'1',0,4):
            with self.assertRaises(ValueError):search_security(self.settings,level=level)

    def test_context_preserves_publisher_rights_pin_level_and_not_assessed(self):
        self.install();r=security_context(self.settings,'parameterization',framework=FRAMEWORK,level=1,max_chars=17)
        self.assertEqual(r['used_chars'],17)
        item=r['fragments'][0]
        self.assertEqual(item['knowledge_type'],'licensed_publisher_requirement')
        self.assertEqual(item['asvs']['assessment'],'not_performed')
        self.assertEqual(item['source_dataset']['commit'],COMMIT)
        self.assertEqual(item['source_license']['id'],'CC-BY-SA-4.0')
        self.assertEqual(item['source_release']['published_on'],'2025-05')
        self.assertEqual(item['source_release']['published_on_precision'],'month')

    def test_invalid_licensed_metadata_cannot_broaden_official_host_policy(self):
        from rabanito.security import validate_catalog
        self.install();p=import_payload(self.settings,self.capture()['manifest'])
        merged={**self.catalog,'entries':self.catalog['entries']+p['entries'],'relations':self.catalog['relations']+p['relations'],
                'source_releases':{**self.catalog['source_releases'],**p['source_releases']}}
        for field,value in (('source_url','https://example.invalid'),('edition_status','rolling')):
            d=copy.deepcopy(merged);d['entries'][-1][field]=value
            with self.assertRaises(ValueError):validate_catalog(d)
        d=copy.deepcopy(merged);d['entries'][-1]['asvs']['level']=True
        with self.assertRaises(ValueError):validate_catalog(d)

    def test_backup_restore_keeps_license_registry_and_cited_context(self):
        self.install();expected=get_security_entry(self.settings,'v5.0.0-1.2.5')
        backup,restored=self.root/'saved.db',self.root/'restored.db'
        with Database(self.settings.database_path,read_only=True) as db:db.backup(backup)
        restore_database(backup,restored)
        from rabanito.config import Settings
        settings=Settings(self.root,{**self.settings.raw,'database_path':str(restored)})
        self.assertEqual(get_security_entry(settings,'v5.0.0-1.2.5'),expected)
        with Database(restored) as db:
            self.assertIn(FRAMEWORK,read_imports(db));self.assertEqual(summaries(db)[0]['coverage']['requirements'],2)
            self.assertEqual(db.one('PRAGMA integrity_check')[0],'ok');self.assertEqual(db.query('PRAGMA foreign_key_check'),[])
            db.execute("INSERT INTO security_fts(security_fts) VALUES ('integrity-check')")

    def test_graph_reuses_control_kind_and_conserves_license_without_compliance(self):
        self.install();result=sync_graph(self.settings,max_inputs=5000);self.assertEqual(result['status'],'ok')
        page=graph_page(self.settings,kind='control',category=FRAMEWORK)
        self.assertEqual(len(page['nodes']),2)
        for node in page['nodes']:
            self.assertEqual(node['data']['asvs']['assessment'],'not_performed')
            self.assertEqual(node['data']['source_license']['id'],'CC-BY-SA-4.0')

    def test_cli_import_level_query_and_import_metadata_are_actual_operations(self):
        c=self.capture()
        for argv in (['security','index','--asvs-capture',c['manifest']],['security','imports'],
                     ['security','search','parameterization','--level','1'],['security','context','parameterization','--level','1','--max-chars','12'],
                     ['asvs','inspect','--capture',c['manifest']]):
            output=io.StringIO()
            with patch('rabanito.cli.load_settings',return_value=self.settings),redirect_stdout(output):main(argv)
            self.assertIsInstance(json.loads(output.getvalue()),dict)

    def test_http_level_returns_pinned_licensed_requirements_not_assessment(self):
        self.install()
        with self.server() as origin:
            for payload,expected in (({'framework':FRAMEWORK,'kind':'control','level':1},200),({'level':True},400)):
                request=Request(origin+'/api/security/search',data=json.dumps(payload).encode(),headers={'Origin':origin,'Content-Type':'application/json'},method='POST')
                try:
                    with urlopen(request) as response:
                        result=json.load(response);self.assertEqual(response.status,expected)
                        self.assertEqual(result['total'],1);self.assertIn('source_license',result['results'][0])
                except HTTPError as exc:
                    try:self.assertEqual(exc.code,expected)
                    finally:exc.close()

    def test_import_status_cli_reports_corrupt_registry_as_bounded_error(self):
        self.install()
        with Database(self.settings.database_path) as db:
            db.execute('UPDATE meta SET value=? WHERE key=?',('{"schema":1,"imports":[]}',KEY))
        output=io.StringIO()
        with patch('rabanito.cli.load_settings',return_value=self.settings),redirect_stdout(output),self.assertRaises(SystemExit) as caught:
            main(['security','imports'])
        self.assertEqual(caught.exception.code,1)
        self.assertEqual(json.loads(output.getvalue()),{'error':'unsupported_security_import_provider'})
