from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.validate_hermes_terminal import (
    CALLS,accepted,cited_context,render_command,shell_process,standard_secrets,
    summarize_call,terminal_environment,
)


class HermesTerminalProbeTests(unittest.TestCase):
    """Pure contract/fixture tests: never import Hermes or run a provider."""

    def complete(self):
        return dict.fromkeys(('full_module_imported','native_registry_handler','guards_not_bypassed',
            'home_isolated','native_skill_body_equal','requirements','temporary_cleaned',
            'runtime_selection_unchanged','source_originals_unchanged','stats_unchanged',
            'hermes_code_unchanged','git_startup_unchanged','guard_write_rejected'),True) | {
            'child_exit_code':0,'bootstrap_modules':[],'active_environments_after_cleanup':0,
            'calls':[{'exit_code':0,'equals_direct_cli':True},
                *[{'exit_code':0,'equals_direct_cli':True,'citations_verified':True,'fragments':1,'characters':100} for _ in range(2)],
                {'exit_code':0,'equals_direct_cli':True,'records':1,'characters':200,'evidence_limits_preserved':True}]}

    def test_complete_report_is_accepted(self):self.assertTrue(accepted(self.complete()))

    def test_missing_or_false_required_evidence_rejects(self):
        complete=self.complete()
        for name,value in complete.items():
            with self.subTest(name=name):
                self.assertFalse(accepted({k:v for k,v in complete.items() if k!=name}))
                if value is True:self.assertFalse(accepted({**complete,name:False}))

    def test_bad_child_bootstrap_or_remaining_environment_rejects(self):
        for change in ({'child_exit_code':1},{'child_exit_code':False},
                       {'bootstrap_modules':['hermes_cli.main']},{'active_environments_after_cleanup':1},
                       {'error':'PermissionError'}):
            with self.subTest(change=change):self.assertFalse(accepted({**self.complete(),**change}))

    def test_missing_extra_failed_or_different_calls_reject(self):
        for calls in ([],self.complete()['calls'][:-1],self.complete()['calls']+[{}],[None]*4):
            self.assertFalse(accepted({**self.complete(),'calls':calls}))
        for index in range(4):
            for change in ({'exit_code':1},{'exit_code':False},{'equals_direct_cli':False}):
                report=self.complete();report['calls'][index].update(change)
                self.assertFalse(accepted(report))

    def test_missing_citations_or_unbounded_context_rejects(self):
        for index in (1,2):
            for change in ({'citations_verified':False},{'fragments':0},{'fragments':None},{'fragments':'private'},{'characters':0},
                           {'characters':161},{'characters':True},{'characters':None}):
                report=self.complete();report['calls'][index].update(change)
                self.assertFalse(accepted(report))

    def test_no_documented_record_or_lost_historical_limits_rejects(self):
        for change in ({'records':0},{'records':None},{'records':'private'},{'evidence_limits_preserved':False},{'characters':201}):
            report=self.complete();report['calls'][3].update(change)
            self.assertFalse(accepted(report))

    def test_non_object_report_rejects(self):
        for value in (None,[],42,'synthetic'):
            self.assertFalse(accepted(value))

    def test_only_fixed_queries_can_be_rendered(self):
        for args in CALLS:
            command=render_command(Path(sys.executable),args)
            self.assertIn(' -B -X utf8 -m rabanito ',command)
            self.assertNotIn('--force',command)
        for args in (('index',),('cyber','sync'),('stats',';','arbitrary')):
            with self.assertRaises(ValueError):render_command(Path(sys.executable),args)

    def test_windows_none_executable_and_rendered_arguments_are_classified(self):
        root=Path('C:/Inspected Git')
        args=[str(root/'bin/bash.exe'),'-c','exit 0']
        result=shell_process(None,subprocess.list2cmdline(args),root)
        self.assertEqual(result,{'name':'bash.exe','login':False,'readiness_probe':True})

    def test_login_shell_and_list_arguments_are_classified(self):
        root=Path('C:/Inspected Git')
        self.assertTrue(shell_process(None,[str(root/'bin/bash.exe'),'-l','-c','synthetic'],root)['login'])

    def test_other_shell_stubs_and_prefix_lookalikes_are_denied(self):
        root=Path('C:/Inspected Git')
        for binary in ('C:/Windows/System32/bash.exe',str(root/'bin/bash.exe-other'),str(root/'elsewhere/bash.exe'),'cmd.exe'):
            self.assertIsNone(shell_process(None,[binary,'-c','exit 0'],root))
        self.assertIsNone(shell_process('different.exe',[str(root/'bin/bash.exe'),'-c','exit 0'],root))

    def test_secret_guard_exception_is_exact_standard_library_module(self):
        runtime=Path('runtime')
        self.assertTrue(standard_secrets(runtime/'Lib/secrets.py',runtime))
        self.assertTrue(standard_secrets(runtime/'Lib/__pycache__/secrets.cpython-314.pyc',runtime))
        for path in (runtime/'credentials/secrets.py',runtime/'Lib/secrets-helper.py',Path('outside/Lib/secrets.py')):
            self.assertFalse(standard_secrets(path,runtime))

    def test_environment_isolated_without_credentials_or_force_mode(self):
        result=terminal_environment({'SYSTEMROOT':'C:/Windows','API_KEY':'synthetic',
            'PYTHONPATH':'outside','BASH_ENV':'outside-script','HERMES_YOLO_MODE':'1','HERMES_HOME':'actual-profile','PATH':'outside'},
            Path('temporary/home'),Path('temporary/scratch'),Path('hermes'),Path('git'))
        for key in ('API_KEY','PYTHONPATH','BASH_ENV','HERMES_YOLO_MODE'):self.assertNotIn(key,result)
        self.assertEqual(result['TERMINAL_HOME_MODE'],'profile')
        self.assertEqual(result['HERMES_HOME'],'temporary'+os.sep+'home')
        self.assertEqual(result['TEMP'],'temporary'+os.sep+'scratch')
        self.assertNotIn('outside',result['PATH'])

    def test_summary_never_contains_raw_record_or_untrusted_scalar(self):
        payload={'used_chars':'synthetic private value','results':[{'text':'synthetic private note',
            'fully_verified':True,'validation':'confirmed','historical_validation':'passed'}]}
        result=summarize_call(3,{'exit_code':'private','payload':payload},payload,None)
        self.assertNotIn('synthetic private',json.dumps(result))
        self.assertIsNone(result['characters']);self.assertIsNone(result['exit_code'])
        self.assertFalse(result['evidence_limits_preserved'])

    @unittest.skipUnless(os.name=='nt','Native fixture index storage')
    def test_physical_citations_validated_and_tampering_rejected(self):
        from rabanito.config import Settings
        from rabanito.indexer import index_all
        from rabanito.search import retrieve_context
        parent=Path(__file__).resolve().parent/'.test-temp';parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='terminal-citations-',dir=parent) as folder:
            root=Path(folder)
            settings=Settings(root,{'data_dir':'data','database_path':'data/test.db','knowledge_dir':'knowledge',
                'vault_root':'vault','projects_root':'projects','source_policy':{'obsidian':{'extensions':['.md']}}})
            for p in (settings.knowledge_root,settings.vault_root,settings.projects_root):p.mkdir()
            (settings.vault_root/'Synthetic ñ.md').write_text('# Architecture\nDocumented SQLite architecture.\n',encoding='utf-8')
            index_all(settings)
            body=retrieve_context(settings,'architecture',source_kind='obsidian',limit=1,max_chars=40)
            self.assertTrue(cited_context(settings,body,'obsidian'))
            for change in ({'document_id':True},{'absolute_path':'outside'},
                           {'citation':'made-up'},{'relative_path':'../elsewhere'},
                           {'line_start':0},{'text':'not-in-original'},{'source_kind':'projects'}):
                bad=copy.deepcopy(body);bad['fragments'][0].update(change)
                self.assertFalse(cited_context(settings,bad,'obsidian'))
            self.assertFalse(cited_context(settings,{'fragments':['not-an-object']},'obsidian'))


if __name__=='__main__':unittest.main()
