"""Licensed normalized catalogs in SQLite metadata; no new schema or remote IO."""
from __future__ import annotations

import hashlib
import json

from .asvs import FRAMEWORK, VERSION, validate_metadata
from .asvs_capture import MANIFEST
from .cyber.transport import _unique_object

KEY = 'security_registered_imports'
MAX_BYTES = 2*1024*1024


def encode(value):
    result=json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)
    if len(result.encode('utf-8'))>MAX_BYTES:
        raise ValueError('security_import_registry_limit')
    return result


def read_imports(db):
    row=db.one('SELECT value FROM meta WHERE key=?',(KEY,))
    if row is None:return {}
    if len(row[0].encode('utf-8'))>MAX_BYTES:raise ValueError('security_import_registry_limit')
    value=json.loads(row[0],object_pairs_hook=_unique_object)
    if not isinstance(value,dict) or set(value)!={'schema','imports'} or type(value['schema']) is not int or value['schema']!=1:
        raise ValueError('invalid_security_import_registry')
    imports=value['imports']
    if not isinstance(imports,dict) or set(imports)-{FRAMEWORK}:
        raise ValueError('unsupported_security_import_provider')
    for payload in imports.values():
        if (not isinstance(payload,dict) or set(payload)!={'provider','version','capture_manifest','source_dataset','license_text','entries','relations','source_releases','coverage'}
                or payload['provider']!='owasp-asvs' or payload['version']!=VERSION or not isinstance(payload['entries'],list)
                or not 1<=len(payload['entries'])<=9000 or not isinstance(payload['license_text'],str)
                or len(payload['license_text'])>65536 or not isinstance(payload['capture_manifest'],str)
                or not MANIFEST.fullmatch(payload['capture_manifest']) or not isinstance(payload['coverage'],dict)
                or set(payload['coverage'])!={'chapters','sections','requirements','assessment_performed'}
                or payload['coverage']['assessment_performed'] is not False):
            raise ValueError('invalid_security_import_payload')
        c=payload['coverage']
        if (any(type(c[k]) is not int or not 1<=c[k]<=5000 for k in ('chapters','sections','requirements'))
                or sum(c[k] for k in ('chapters','sections','requirements'))!=len(payload['entries'])):
            raise ValueError('invalid_security_import_coverage')
        digest=hashlib.sha256(payload['license_text'].encode('utf-8')).hexdigest()
        for entry in payload['entries']:
            if (not isinstance(entry,dict) or entry.get('source_dataset')!=payload['source_dataset']
                    or not isinstance(entry.get('source_license'),dict)
                    or entry['source_license'].get('sha256')!=digest or entry.get('framework')!=FRAMEWORK):
                raise ValueError('security_import_license_or_dataset_mismatch')
            validate_metadata(entry)
    return imports


def merge(base, imports):
    result={**base,'entries':list(base['entries']),'relations':list(base.get('relations',[])),
            'source_releases':dict(base.get('source_releases',{}))}
    for payload in imports.values():
        result['entries']+=payload['entries'];result['relations']+=payload['relations']
        for key,release in payload['source_releases'].items():
            if key in result['source_releases'] and result['source_releases'][key]!=release:
                raise ValueError('conflicting_registered_security_release')
            result['source_releases'][key]=release
    if imports:
        result['catalog_version']=base['catalog_version']+'+imports.'+hashlib.sha256(encode(imports).encode()).hexdigest()[:12]
    return result


def summaries(db):
    return [{'id':key,'provider':p['provider'],'version':p['version'],'source_dataset':p['source_dataset'],
             'coverage':p['coverage'],'license_id':'CC-BY-SA-4.0','license_sha256':hashlib.sha256(p['license_text'].encode()).hexdigest()}
            for key,p in read_imports(db).items()]
