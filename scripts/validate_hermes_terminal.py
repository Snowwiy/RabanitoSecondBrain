"""Opt-in real Hermes tools with a disposable home and metadata-only results.

Inspect the local Hermes revision and Git Bash startup scripts before invoking.
No Hermes CLI/bootstrap, activation, provider, global Skill or profile changes.
The audit hook is defense in depth, NOT an OS sandbox for native descendants.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.validate_hermes_skill import child_environment,selected_environment

SKILL=ROOT/'skills/rabanito-second-brain/SKILL.md'
CALLS=(('stats',),
       ('context','arquitectura','--source','obsidian','--limit','1','--max-chars','160'),
       ('context','arquitectura','--source','projects','--limit','1','--max-chars','160'),
       ('coding','documented','Python permisos','--limit','1','--max-chars','200'))


def render_command(python: Path, arguments: tuple[str,...]) -> str:
    if arguments not in CALLS:raise ValueError('unsupported_validation_command')
    return shlex.join([python.as_posix(),'-B','-X','utf8','-m','rabanito',*arguments])


def shell_process(executable,arguments,git_root: Path):
    """Classify Windows Popen audit data, including executable=None/string args.

    The caller only invokes fixed commands through the real Hermes builders.
    This restriction is not a claim to understand/sandbox arbitrary Bash code.
    """
    rendered=arguments if isinstance(arguments,str) else subprocess.list2cmdline(arguments)
    binaries=(git_root/'bin/bash.exe',git_root/'usr/bin/bash.exe')
    binary=next((p for p in binaries if rendered.startswith(subprocess.list2cmdline([str(p)])+' ')),None)
    if binary is None:return None
    if executable is not None and Path(executable).resolve()!=binary.resolve():return None
    return {'name':'bash.exe','login':' -l -c ' in rendered,
            'readiness_probe':rendered.endswith('"exit 0"')}


def standard_secrets(path: Path,runtime: Path) -> bool:
    # A credential-filename guard must not block the standard-library module.
    return (path==runtime/'Lib/secrets.py' or path.parent==runtime/'Lib/__pycache__'
            and path.name.startswith('secrets.cpython-') and path.suffix=='.pyc')


def terminal_environment(original,home: Path,scratch: Path,repo: Path,git_root: Path):
    env=child_environment(original,home)
    env.update({'PATH':os.pathsep.join((str(git_root/'cmd'),str(Path(sys.executable).parent),
                                      str(Path(original['SYSTEMROOT'])/'System32'))),
        'TERMINAL_ENV':'local','TERMINAL_CWD':str(ROOT),'TERMINAL_LOCAL_PERSISTENT':'false',
        'TERMINAL_HOME_MODE':'profile','TERMINAL_TEMP_DIR':str(scratch),
        'TMPDIR':str(scratch),'TMP':str(scratch),'TEMP':str(scratch),
        'HERMES_RUNTIME_DIR':str(repo.parent/'tools'),'GIT_OPTIONAL_LOCKS':'0'})
    return env


def accepted(report):
    if not isinstance(report,dict):return False
    booleans=('full_module_imported','native_registry_handler','guards_not_bypassed',
              'home_isolated','native_skill_body_equal','requirements','temporary_cleaned',
              'runtime_selection_unchanged','source_originals_unchanged','stats_unchanged',
              'hermes_code_unchanged','git_startup_unchanged','guard_write_rejected')
    if (any(report.get(key) is not True for key in booleans) or type(report.get('child_exit_code')) is not int or report['child_exit_code']!=0
            or report.get('bootstrap_modules')!=[] or report.get('active_environments_after_cleanup')!=0
            or 'error' in report):return False
    calls=report.get('calls')
    return (isinstance(calls,list) and len(calls)==4
            and all(isinstance(c,dict) and type(c.get('exit_code')) is int and c['exit_code']==0
                    and c.get('equals_direct_cli') is True for c in calls)
            and all(calls[i].get('citations_verified') is True and type(calls[i].get('fragments')) is int
                    and calls[i]['fragments']>0
                    and type(calls[i].get('characters')) is int and 0<calls[i]['characters']<=160 for i in (1,2))
            and type(calls[3].get('records')) is int and calls[3]['records']>0
            and calls[3].get('evidence_limits_preserved') is True
            and type(calls[3].get('characters')) is int and 0<calls[3]['characters']<=200)


def probe_child(value):
    temporary=Path(value['temporary']).resolve(strict=True);home=temporary/'home'
    repo=Path(value['repo']).resolve(strict=True);site=Path(value['site']).resolve(strict=True)
    git_root=Path(value['git_root']).resolve(strict=True);runtime=Path(sys.base_prefix).resolve(strict=True)
    facts=Path(value['facts']).resolve(strict=True)
    denied={};processes=[]
    def reject(kind):
        denied[kind]=denied.get(kind,0)+1
        raise PermissionError('isolated_terminal_probe_'+kind)
    def check(name,write=False):
        if isinstance(name,int):return
        if isinstance(name,(str,bytes)) and os.fsdecode(name).casefold()==os.devnull.casefold():return
        path=(Path.cwd() if name is None else Path(os.fsdecode(name))).resolve()
        if write:
            if not path.is_relative_to(temporary):reject('external_write')
            return
        if (not standard_secrets(path,runtime)
                and (path.name.casefold().startswith(('.env','credentials','secrets'))
                     or path.name.casefold() in {'config.yaml','auth.json','token.json','tokens.json'})
                and not path.is_relative_to(temporary)):reject('sensitive_read')
        allowed=(temporary,repo,site,runtime,ROOT/'scripts')
        if not any(path.is_relative_to(p) for p in allowed) and path not in {facts,repo.parent/'tools/facts.json',SKILL}:
            reject('external_read')
    def audit(event,args):
        if event=='open':
            name,mode,flags=args
            check(name,bool(flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)))
        elif event in {'os.mkdir','os.remove','os.rmdir','os.chmod','os.utime','os.truncate'}:check(args[0],True)
        elif event in {'os.rename','os.link'}:check(args[0],True);check(args[1],True)
        elif event=='os.symlink':reject('symlink')
        elif event in {'os.listdir','os.scandir'}:check(args[0])
        elif event.startswith(('socket.connect','socket.getaddrinfo')) or event=='socket.bind':reject('network')
        elif event=='subprocess.Popen':
            executable,argv,cwd,env=args
            process=shell_process(executable,argv,git_root)
            if process is None:reject('unexpected_process')
            if cwd is not None and Path(cwd).resolve()!=ROOT:reject('unexpected_cwd')
            if env is not None:
                if env.get('HERMES_HOME')!=str(home):reject('unexpected_home')
                if process['login'] and not Path(env.get('HOME','')).resolve().is_relative_to(temporary):reject('shell_home')
            processes.append(process)
        elif event in {'os.system','os.exec','os.posix_spawn'}:reject('unexpected_process')
    sys.addaudithook(audit)
    try:(ROOT/'tests/.test-temp/terminal-probe-outside-policy.marker').write_text('synthetic',encoding='utf-8')
    except PermissionError:guard_rejected=True
    else:raise RuntimeError('write_guard_failed')
    sys.path[:0]=[str(repo),str(site)]  # Do not execute .pth files or activate PM.
    log=io.StringIO();report={'guard_write_rejected':guard_rejected}
    try:
        with contextlib.redirect_stdout(log),contextlib.redirect_stderr(log):
            import tools.terminal_tool as terminal
            import tools.skills_tool as skills
            from hermes_constants import get_hermes_home
            report.update(full_module_imported=True,home_isolated=get_hermes_home().resolve()==home,
                          requirements=terminal.check_terminal_requirements())
            if not report['home_isolated']:raise ValueError('home_not_isolated')
            viewed=json.loads(skills.skill_view('rabanito-second-brain',preprocess=False))
            report['native_skill_body_equal']=viewed.get('success') is True and viewed.get('content')==SKILL.read_text(encoding='utf-8')
            report['calls']=[]
            for args in CALLS:
                # Exact model-facing handler; no force, host-local override,
                # YOLO, guardian model, alternate backend or mock executor.
                response=json.loads(terminal._handle_terminal({'command':render_command(Path(sys.executable),args),
                    'timeout':15,'background':False,'workdir':str(ROOT)},task_id='second-brain-isolated-probe'))
                observed={'exit_code':response.get('exit_code'),'error_present':bool(response.get('error'))}
                try:observed['payload']=json.loads(response.get('output',''))
                except ValueError:observed['json_output']=False
                report['calls'].append(observed)
                if observed['error_present'] or observed['exit_code']!=0:break
            report.update(native_registry_handler=True,guards_not_bypassed=True)
            terminal._atexit_cleanup()
            report['active_environments_after_cleanup']=len(terminal._active_environments)
    except Exception as exc:report['error']=type(exc).__name__
    report.update(denied_events=denied,processes=processes,captured_log_chars=len(log.getvalue()),
        bootstrap_modules=[m for m in ('hermes_bootstrap','hermes_cli.main') if m in sys.modules])
    return report


def cited_context(settings,body,source):
    """Check IDs/current authorization/physical lines, never trust returned paths."""
    from rabanito.db import Database
    from rabanito.document_content import _authorize,_open_readonly
    from rabanito.utils import redact_sensitive_lines
    if not isinstance(body,dict) or not isinstance(body.get('fragments'),list) or not body['fragments']:return False
    with Database(settings.database_path,read_only=True) as db:
        projects=db.query('SELECT root_path,status FROM projects')
        for fragment in body['fragments']:
            if not isinstance(fragment,dict):return False
            identity=fragment.get('document_id')
            if type(identity) is not int or identity<1:return False
            row=db.one("SELECT * FROM documents WHERE document_id=? AND status='active'",(identity,))
            if row is None or row['source_kind']!=source or fragment.get('source_kind')!=source:return False
            path=_authorize(settings,row,projects)
            if fragment.get('absolute_path')!=str(path):return False
            with _open_readonly(path) as stream:raw=stream.read(2_097_153)
            if len(raw)>2_097_152:return False
            lines=redact_sensitive_lines(raw.decode('utf-8-sig').replace('\r\n','\n').replace('\r','\n')).splitlines()
            start,end=fragment.get('line_start'),fragment.get('line_end')
            if type(start) is not int or type(end) is not int or not 1<=start<=end<=len(lines):return False
            if (fragment.get('citation')!=f'{path}:{start}-{end}'
                    or fragment.get('relative_path')!=row['relative_path']):return False
            text=fragment.get('text')
            if not isinstance(text,str) or not text or not '\n'.join(lines[start-1:end]).strip().startswith(text):return False
    return True


def summarize_call(position,observed,expected,settings):
    body=observed.get('payload')
    code=observed.get('exit_code')
    result={'exit_code':code if type(code) is int else None,'equals_direct_cli':body==expected}
    def count(key):
        value=body.get(key)
        return value if type(value) is int else None
    if position in (1,2) and isinstance(body,dict):
        fragments=body.get('fragments')
        result.update(fragments=len(fragments) if isinstance(fragments,list) else 0,characters=count('characters'),
                      citations_verified=cited_context(settings,body,'obsidian' if position==1 else 'projects'))
    elif position==3 and isinstance(body,dict):
        records=body.get('results',[])
        records=records if isinstance(records,list) else []
        result.update(records=len(records),characters=count('used_chars'),evidence_limits_preserved=bool(records)
            and all(isinstance(r,dict) and r.get('fully_verified') is False and r.get('validation') in {'pending','partial'}
                    and r.get('historical_validation')=='pending_documentation_user_reported' for r in records))
    return result


def fingerprints(root,paths):
    return {p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in paths}


def validate(repo: Path,git_root: Path):
    from rabanito.config import load_settings
    from scripts.validate_document_content import originals
    if os.name!='nt' or not (3,11)<=sys.version_info[:2]<(3,15):raise ValueError('compatible_native_windows_required')
    started=time.perf_counter();repo=repo.resolve(strict=True);git_root=git_root.resolve(strict=True)
    if not (git_root/'bin/bash.exe').is_file():raise ValueError('inspected_native_git_bash_required')
    facts,original_facts,site=selected_environment(repo,sys.version_info[:3])
    settings=load_settings()
    if settings.root!=ROOT:raise ValueError('validation_requires_current_checkout_config')
    before=originals(settings)
    hermes_files=('tools/terminal_tool.py','tools/terminal_tool_backends.py','tools/terminal_tool_guards.py',
        'tools/terminal_tool_result.py','tools/environments/local.py','tools/environments/base.py',
        'tools/environments/base_session_env.py','tools/skills_tool.py','hermes_constants.py','pm/shell.py')
    git_files=('bin/bash.exe','etc/profile','etc/bash.bashrc',
               *(p.relative_to(git_root).as_posix() for p in (git_root/'etc/profile.d').glob('*.sh')))
    hermes_before=fingerprints(repo,hermes_files);git_before=fingerprints(git_root,git_files)
    expected=[]
    for args in CALLS:
        direct=subprocess.run([sys.executable,'-B','-X','utf8','-m','rabanito',*args],cwd=ROOT,
                              capture_output=True,encoding='utf-8',timeout=20)
        if direct.returncode:raise ValueError('baseline_cli_failed')
        expected.append(json.loads(direct.stdout))
    parent=ROOT/'tests/.test-temp';parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='hermes-native-terminal-',dir=parent) as folder:
        temporary=Path(folder);home=temporary/'home';home.mkdir();(home/'home').mkdir()
        scratch=temporary/'scratch';scratch.mkdir()
        target=home/'skills/rabanito-second-brain/SKILL.md';target.parent.mkdir(parents=True);shutil.copyfile(SKILL,target)
        (home/'config.yaml').write_text('skills:\n  external_dirs: []\n',encoding='utf-8')
        run=subprocess.run([sys.executable,'-B','-S','-X','utf8',str(Path(__file__).resolve()),'--_probe-child'],
            input=json.dumps({'temporary':str(temporary),'repo':str(repo),'site':str(site),
                              'git_root':str(git_root),'facts':str(facts)}),cwd=ROOT,
            env=terminal_environment(dict(os.environ),home,scratch,repo,git_root),
            capture_output=True,encoding='utf-8',timeout=60)
        try:report=json.loads(run.stdout) if run.returncode==0 else {'error':'child_failed'}
        except ValueError:report={'error':'invalid_child_report'}
        # Strip ALL raw bodies before returning/logging/persisting the report.
        report['calls']=[summarize_call(i,c,expected[i],settings) for i,c in enumerate(report.get('calls',[]))]
        report['child_exit_code']=run.returncode
    after=subprocess.run([sys.executable,'-B','-m','rabanito','stats'],cwd=ROOT,capture_output=True,encoding='utf-8',timeout=20)
    report.update(mode='real_tools_temporary_home_not_live_agent',temporary_cleaned=not temporary.exists(),
        runtime_selection_unchanged=facts.read_bytes()==original_facts,source_originals_unchanged=originals(settings)==before,
        stats_unchanged=after.returncode==0 and json.loads(after.stdout)==expected[0],
        hermes_code_unchanged=fingerprints(repo,hermes_files)==hermes_before,
        git_startup_unchanged=fingerprints(git_root,git_files)==git_before,
        hermes_source_fingerprints=hermes_before,git_startup_fingerprints=git_before,
        runtime_facts_sha256=hashlib.sha256(original_facts).hexdigest(),provider_calls=0,
        original_source_count=sum(v['files'] for v in before.values()),seconds=round(time.perf_counter()-started,3))
    report['accepted']=accepted(report)
    return report


def main():
    if sys.argv[1:]==['--_probe-child']:
        print(json.dumps(probe_child(json.loads(sys.stdin.read())),ensure_ascii=True));return 0
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hermes-repo',type=Path,required=True)
    parser.add_argument('--git-root',type=Path,required=True,help='already-inspected native Git for Windows root')
    args=parser.parse_args()
    try:report=validate(args.hermes_repo,args.git_root)
    except Exception as exc:report={'accepted':False,'error':type(exc).__name__}
    print(json.dumps(report,ensure_ascii=True,indent=2))
    return 0 if report.get('accepted') is True else 1


if __name__=='__main__':raise SystemExit(main())
