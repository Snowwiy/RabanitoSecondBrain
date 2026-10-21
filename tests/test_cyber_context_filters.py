from __future__ import annotations

import tempfile
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from rabanito.config import Settings
from rabanito.cyber.store import vulnerability_context
from rabanito.cyber.sync import KEV_URL,OSV_URL,sync_source
from tests.test_cyber import CVE,GHSA,NOW,FakeClient,kev,nvd,osv
from rabanito.cli import main


class CyberContextFilterTests(unittest.TestCase):
    def setUp(self):
        parent=Path(__file__).resolve().parent/'.test-temp';parent.mkdir(exist_ok=True)
        self.temporary=tempfile.TemporaryDirectory(prefix='cyber-context-filter-',dir=parent)
        self.root=Path(self.temporary.name)
        self.settings=Settings(self.root,{'data_dir':'data','database_path':'data/test.db',
            'knowledge_dir':'knowledge','vault_root':'vault','projects_root':'projects'})
        for folder in (self.settings.knowledge_root,self.settings.vault_root,self.settings.projects_root):folder.mkdir()
        for source,payload,ids in (('nvd',nvd(),[CVE]),('kev',kev(),None),('osv',osv(),[GHSA])):
            result=sync_source(self.settings,source,ids,client=FakeClient([payload]),now=NOW)
            self.assertEqual(result['status'],'ok')

    def tearDown(self):self.temporary.cleanup()

    def test_selected_kev_source_owns_the_context_budget_and_citation(self):
        result=vulnerability_context(self.settings,CVE,source='kev',limit=1,max_chars=8)
        self.assertEqual([f['source'] for f in result['fragments']],['kev'])
        self.assertEqual(result['fragments'][0]['citation'],KEV_URL)
        self.assertEqual(result['fragments'][0]['text'],kev()['vulnerabilities'][0]['shortDescription'][:8])
        self.assertEqual(result['used_chars'],8)

    def test_selected_osv_source_does_not_return_other_provider_observations(self):
        result=vulnerability_context(self.settings,CVE,source='osv',limit=1,max_chars=1000)
        self.assertEqual([f['source'] for f in result['fragments']],['osv'])
        self.assertEqual(result['fragments'][0]['citation'],OSV_URL+GHSA)

    def test_unfiltered_and_kev_predicate_preserve_merged_provider_context(self):
        unfiltered=vulnerability_context(self.settings,CVE,max_chars=1000,limit=1)
        self.assertEqual([f['source'] for f in unfiltered['fragments']],['nvd','osv','kev'])
        self.assertEqual(vulnerability_context(self.settings,CVE,max_chars=1000,limit=1,kev_only=True),unfiltered)

    def test_valid_source_without_an_observation_does_not_fall_back_to_others(self):
        result=vulnerability_context(self.settings,CVE,source='epss',max_chars=40)
        self.assertEqual(result['fragments'],[])
        self.assertEqual(result['used_chars'],0)
        self.assertEqual(result['total_matches'],0)

    def test_missing_selected_observation_after_lookup_does_not_leak_another_source(self):
        record={'observations':[{'source':'nvd','description':'Other source text','title':'Other title'}]}
        with patch('rabanito.cyber.store.search_vulnerabilities',return_value={'results':[{'id':CVE}],'total':1}),\
             patch('rabanito.cyber.store.get_vulnerability',return_value=record):
            result=vulnerability_context(self.settings,CVE,source='kev',max_chars=100)
        self.assertEqual(result['fragments'],[])
        self.assertEqual(result['used_chars'],0)

    def test_unknown_source_rejected_even_with_zero_context_budget(self):
        for source in ('unknown','',[],True):
            with self.subTest(source=source),self.assertRaises(ValueError):
                vulnerability_context(self.settings,CVE,source=source,max_chars=0)

    def test_zero_budget_keeps_existing_shape_without_reading_database(self):
        with patch('rabanito.cyber.store.search_vulnerabilities',side_effect=AssertionError('No query for zero budget')):
            self.assertEqual(vulnerability_context(self.settings,CVE,source='kev',max_chars=0),
                             {'fragments':[],'used_chars':0,'max_chars':0})

    def test_cli_optional_source_is_offline_and_default_remains_multisource(self):
        for extra,expected in ((['--source','kev'],['kev']),([],['nvd','osv','kev'])):
            output=io.StringIO()
            with patch('rabanito.cli.load_settings',return_value=self.settings),\
                 patch('urllib.request.OpenerDirector.open',side_effect=AssertionError('No network for retrieval')),\
                 redirect_stdout(output):
                main(['cyber','context',CVE,'--max-chars','1000','--limit','1',*extra])
            self.assertEqual([f['source'] for f in json.loads(output.getvalue())['fragments']],expected)

    def test_fragment_and_envelope_fields_unchanged_by_filter(self):
        default=vulnerability_context(self.settings,CVE,max_chars=1000,limit=1)
        selected=vulnerability_context(self.settings,CVE,source='kev',max_chars=1000,limit=1)
        self.assertEqual(set(default),set(selected))
        self.assertEqual(set(default['fragments'][0]),set(selected['fragments'][0]))
