"""Owned Windows storage for indexing, profiles and the index-run journal.

Imports of existing native guards are lazy: those guards also use parser/indexer
services. Never execute commands found in project documentation or profiles.
"""
from __future__ import annotations

import copy
import json
import os
import stat
import uuid
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from pathlib import Path
from types import SimpleNamespace

from .config import Settings
from .utils import contains_reparse_component, path_key

ROOT = Path(__file__).resolve().parents[1]
MAX_PROFILE_BYTES = 2_097_152
MAX_HISTORY_BYTES = 8_388_608
_ACTIVE = ContextVar('rabanito_index_storage', default=None)


def _native():
    from .documented_store import _Tree, _pin, _publish, _authorize_layout, _inside
    from .document_content import _open_readonly, _parts
    return _Tree, _pin, _publish, _authorize_layout, _inside, _open_readonly, _parts


def _lock_snapshot(settings):
    if isinstance(settings,Settings): return Settings(settings.root,copy.deepcopy(settings.raw))
    # The reusable mutex also supports a minimal lock-only caller. No fake DB is
    # invented or initialized; its directory must still stay in this checkout.
    raw=copy.deepcopy(settings.raw)
    data=Path(settings.data_dir)
    raw['data_dir']=str(data)
    return SimpleNamespace(root=Path(getattr(settings,'root',ROOT)),raw=raw,data_dir=data,
                           database_path=getattr(settings,'database_path',None))


def validate_data_storage(settings, *, database_files=True):
    if os.name != 'nt': raise ValueError('index_writer_requires_native_windows')
    _Tree, _pin, _publish, _layout, inside, _open, parts = _native()
    if not isinstance(settings.raw.get('data_dir'),str) or not settings.raw['data_dir']:
        raise ValueError('invalid_index_data_configuration')
    if isinstance(settings,Settings) and (not isinstance(settings.raw.get('database_path'),str) or not settings.raw['database_path']):
        raise ValueError('invalid_index_data_configuration')
    root, data, database = settings.root, settings.data_dir, settings.database_path
    paths=(root,data) if database is None else (root,data,database)
    if (not inside(root,ROOT) or any(not p.is_absolute() or '..' in p.parts
            or str(p).startswith(('\\\\','//')) or contains_reparse_component(p) for p in paths)
            or not inside(data,root,child=True) or database is not None and not inside(database,root,child=True)):
        raise ValueError('unsafe_index_data_roots')
    parts(data.relative_to(root).as_posix())
    if database is not None:
        parts(database.relative_to(root).as_posix())
        if database.suffix.casefold() not in {'.db','.sqlite','.sqlite3'}:
            raise ValueError('invalid_index_database_name')
    sources = []
    for key, attribute in (('vault_root','vault_root'),('projects_root','projects_root'),('knowledge_dir','knowledge_root')):
        if key in settings.raw:
            if not isinstance(settings.raw[key],str) or not settings.raw[key]:
                raise ValueError('invalid_index_source_configuration')
            value=Path(settings.raw[key])
            sources.append(value if value.is_absolute() else root/value)
    sources.extend(Path(item['path']) for item in settings.raw.get('additional_sources',[]) if item.get('path'))
    if any(inside(source,owned) or inside(owned,source) for source in sources
           for owned in (data, *((database,) if database is not None else ()))):
        raise ValueError('index_data_source_overlap')
    checked=[data/'index.lock']
    if database_files and database is not None:
        checked.extend([database,*(Path(str(database)+s) for s in ('-wal','-shm','-journal'))])
    for path in checked:
        try: info = path.lstat()
        except FileNotFoundError: continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or contains_reparse_component(path):
            raise ValueError('unsafe_index_data_identity')


@contextmanager
def data_lock_scope(settings):
    snapshot = _lock_snapshot(settings)
    validate_data_storage(snapshot,database_files=False)
    Tree,*_ = _native()
    with ExitStack() as stack:
        tree = Tree(stack,snapshot.root)
        tree.directory(snapshot.root)
        tree.directory(snapshot.data_dir,create=True)
        if snapshot.database_path is not None: tree.directory(snapshot.database_path.parent,create=True)
        tree.file(snapshot.data_dir/'index.lock',create=True)
        yield snapshot


def check_lock_binding(settings, locked):
    settings=_lock_snapshot(settings)
    validate_data_storage(settings,database_files=False)
    if any((None if getattr(settings,key) is None else path_key(getattr(settings,key))) !=
           (None if getattr(locked,key) is None else path_key(getattr(locked,key)))
           for key in ('root','data_dir','database_path')):
        raise ValueError('index_lock_configuration_changed_reload_required')


def validate_layout(settings, *, database_files=True, require_private_sources=True):
    validate_data_storage(settings,database_files=database_files)
    inside,parts=_native()[4],_native()[6]
    required=('knowledge_dir','vault_root','projects_root') if require_private_sources else ('knowledge_dir',)
    if any(not isinstance(settings.raw.get(k),str) or not settings.raw[k] for k in required):
        raise ValueError('invalid_index_source_configuration')
    knowledge=settings.knowledge_root
    if (not knowledge.is_absolute() or '..' in knowledge.parts or str(knowledge).startswith(('\\\\','//'))
            or contains_reparse_component(knowledge) or not inside(knowledge,settings.root,child=True)
            or inside(knowledge,settings.data_dir) or inside(settings.data_dir,knowledge)):
        raise ValueError('unsafe_index_knowledge_root')
    parts(knowledge.relative_to(settings.root).as_posix())
    sources=[settings._path(settings.raw[k]) for k in ('vault_root','projects_root') if k in settings.raw]
    sources.extend(Path(item['path']) for item in settings.raw.get('additional_sources',[]) if item.get('path'))
    for source in sources:
        if inside(source,knowledge) or inside(knowledge,source): raise ValueError('index_knowledge_source_overlap')
    for relative in ('projects','history','history/index-runs'):
        if contains_reparse_component(settings.knowledge_root/relative):
            raise ValueError('unsafe_index_generated_directory')


def prepare_settings_storage(settings):
    """Preserve startup initialization, but never create into an imported source.

    No SQLite, lock-file creation or generated-note publication. Checking DB
    identity belongs to its caller, including save-then-index_pending recovery.
    """
    additional=settings.raw.get('additional_sources',[])
    if (not isinstance(additional,list) or any(not isinstance(item,dict) or
            'path' in item and not isinstance(item['path'],str) for item in additional)):
        raise ValueError('invalid_index_source_configuration')
    validate_layout(settings,database_files=False,require_private_sources=False)
    with ExitStack() as stack:
        tree=_native()[0](stack,settings.root)
        tree.directory(settings.root)
        tree.directory(settings.data_dir,create=True)
        tree.directory(settings.knowledge_root,create=True)


def check_profile(settings,path):
    _Tree,_pin,_publish,_layout,_inside,_open,parts = _native()
    relative = path.relative_to(settings.knowledge_root)
    parts(relative.as_posix())
    if (len(relative.parts) != 3 or relative.parts[0] != 'projects'
            or relative.parts[-1] != 'PROJECT_MEMORY.md' or contains_reparse_component(path)):
        raise ValueError('unsafe_project_profile_path')


def read_profile(settings,path):
    check_profile(settings,path)
    with _native()[5](path) as stream: body = stream.read(MAX_PROFILE_BYTES+1)
    if len(body)>MAX_PROFILE_BYTES: raise ValueError('project_profile_size_limit')
    return body


class ProfileRecoveryError(OSError):
    def __init__(self,backup):
        super().__init__('project_profile_recovery_required')
        self.backup = backup


class IndexScope:
    def __init__(self,settings,stack):
        self.settings = Settings(settings.root,copy.deepcopy(settings.raw))
        self.tree = _native()[0](stack,self.settings.root)
        self.expected = {}
        self.knowledge_available=self.settings.knowledge_root.is_dir()

    def profile_parent(self,path):
        if not self.knowledge_available: raise ValueError('internal_memory_storage_unavailable')
        check_profile(self.settings,path)
        self.tree.directory(path.parent,create=True)

    def profile_text(self,path):
        body = read_profile(self.settings,path)
        self.expected[path_key(path)] = body
        return body.decode('utf-8').replace('\r\n','\n').replace('\r','\n')

    def write_profile(self,path,text):
        self.profile_parent(path)
        body = text.encode('utf-8')
        if len(body)>MAX_PROFILE_BYTES: raise ValueError('project_profile_size_limit')
        expected = self.expected.get(path_key(path))
        publish = _native()[2]
        if expected is None:
            publish(path,body)
            self.expected[path_key(path)] = body
            return
        if read_profile(self.settings,path) != expected: raise ValueError('project_profile_changed_retry_required')
        # Never replace a filename that another actor may have just populated.
        # Rotate the old file, verify its bytes again, publish with no-replace.
        backup = path.parent / ('.rabanito-profile-'+uuid.uuid4().hex+'.bak')
        os.rename(path,backup)
        try:
            with _native()[5](backup) as stream:
                if stream.read(MAX_PROFILE_BYTES+1) != expected:
                    raise ValueError('project_profile_changed_retry_required')
                publish(path,body)
        except BaseException:
            try: os.rename(backup,path)  # Restore only if the name is still free.
            except OSError:
                raise ProfileRecoveryError(backup.relative_to(self.settings.knowledge_root).as_posix()) from None
            raise
        # Keep the complete previous profile, including any manual prefix/suffix.
        # Never purge backups implicitly or overwrite concurrent work on recovery.
        self.expected[path_key(path)] = body

    @contextmanager
    def database(self,factory):
        _Tree,pin,*_ = _native()
        db = None
        try:
            with ExitStack() as guards:
                guards.enter_context(pin(self.settings.database_path,directory=False,create=True))
                for suffix in ('-wal','-shm','-journal'):
                    path = Path(str(self.settings.database_path)+suffix)
                    if path.exists() or path.is_symlink(): guards.enter_context(pin(path,directory=False))
                db = factory(self.settings.database_path)
                db.one('PRAGMA schema_version')
        except BaseException:
            if db is not None: db.connection.close()
            raise
        # Release our sidecar pins before SQLite closes/removes its own files.
        with db: yield db

    def history(self,path,value):
        if not self.knowledge_available: return  # scan_runs still records inaccessible-source status.
        relative = path.relative_to(self.settings.knowledge_root)
        _native()[6](relative.as_posix())
        if (len(relative.parts)!=3 or relative.parts[:2]!=('history','index-runs')
                or path.suffix!='.json' or contains_reparse_component(path)):
            raise ValueError('unsafe_index_history_path')
        body = (json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode('utf-8')
        if len(body)>MAX_HISTORY_BYTES: raise ValueError('index_history_size_limit')
        for suffix in range(1000):
            candidate = path if suffix==0 else path.with_stem(path.stem+f'-{suffix+1:02d}')
            if candidate.exists(): continue
            try:
                if _native()[2](candidate,body): return
            except FileExistsError:
                continue
            except ValueError as exc:
                if str(exc)=='documented_destination_conflict': continue
                raise
        raise FileExistsError('index_history_filename_limit_reached')


@contextmanager
def index_scope(settings):
    active = _ACTIVE.get()
    if active is not None:
        if active.settings.root != settings.root or active.settings.raw != settings.raw:
            raise ValueError('nested_index_configuration_mismatch')
        yield active
        return
    validate_layout(settings)
    with ExitStack() as stack:
        scope = IndexScope(settings,stack)
        scope.tree.directory(scope.settings.root)
        scope.tree.directory(scope.settings.data_dir,create=True)
        if scope.knowledge_available:
            for relative in ('projects','history/index-runs'):
                scope.tree.directory(scope.settings.knowledge_root/relative,create=True)
        token = _ACTIVE.set(scope)
        try: yield scope
        finally: _ACTIVE.reset(token)


def current_scope():
    scope = _ACTIVE.get()
    if scope is None: raise ValueError('index_storage_scope_required')
    return scope


def active_scope(): return _ACTIVE.get()
