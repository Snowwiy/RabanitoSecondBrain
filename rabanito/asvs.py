"""ASVS5.0.0 publisher JSON to licensed Security entries; no assessment claims."""
from __future__ import annotations

import json
import re
from datetime import datetime

from .asvs_capture import VERSION, MAX_BYTES, BASE, source_url, read_capture
from .cyber.model import InvalidFeed
from .cyber.transport import _unique_object


FRAMEWORK = "OWASP-ASVS-5.0.0"
LICENSE_URL = "https://creativecommons.org/licenses/by-sa/4.0/"


def _text(value, maximum=3000, single=False):
    if (not isinstance(value,str) or not value.strip() or len(value)>maximum
            or any((ord(c)<32 and (single or c not in "\n\t\r")) or 0xD800<=ord(c)<=0xDFFF for c in value)):
        raise InvalidFeed("invalid_asvs_text")
    return value


def normalize(raw):
    if not isinstance(raw,bytes) or not 1<=len(raw)<=MAX_BYTES:
        raise InvalidFeed("asvs_json_byte_limit")
    try:
        data=json.loads(raw.decode('utf-8-sig'),object_pairs_hook=_unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(InvalidFeed("nonfinite_asvs_json")))
    except InvalidFeed:
        raise
    except (ValueError,UnicodeError,RecursionError):
        raise InvalidFeed("invalid_asvs_json") from None
    if (not isinstance(data,dict) or set(data)!={"Name","ShortName","Version","Description","Requirements"}
            or data['ShortName']!='ASVS' or data['Version']!=VERSION):
        raise InvalidFeed("unsupported_asvs_document")
    _text(data['Name'],300,True);_text(data['Description'])
    groups,requirements,seen=[],[],set()
    def children(items,maximum):
        if not isinstance(items,list) or not 1<=len(items)<=maximum:
            raise InvalidFeed("asvs_children_limit")
        return items
    def identity(item,prefix,fields):
        if not isinstance(item,dict) or set(item)!=fields:
            raise InvalidFeed("unsupported_asvs_fields")
        ordinal=item['Ordinal']
        if type(ordinal) is not int or not 1<=ordinal<=999:
            raise InvalidFeed("invalid_asvs_ordinal")
        shortcode=prefix+str(ordinal)
        if item['Shortcode']!=shortcode or shortcode in seen:
            raise InvalidFeed("duplicate_or_mismatched_asvs_id")
        seen.add(shortcode)
        if len(seen)>9000:
            raise InvalidFeed("asvs_record_limit")
        return shortcode
    for c,chapter in enumerate(children(data['Requirements'],100)):
        code=identity(chapter,'V',{"Shortcode","Ordinal","ShortName","Name","Items"})
        _text(chapter['ShortName'],150,True);name=_text(chapter['Name'],150,True)
        chapter_id="ASVS-5.0.0/chapter/"+code[1:]
        groups.append({'id':chapter_id,'shortcode':code,'name':name,'parent':FRAMEWORK,'group_kind':'chapter','pointer':f'/Requirements/{c}'})
        for s,section in enumerate(children(chapter['Items'],100)):
            section_code=identity(section,code+'.',{"Shortcode","Ordinal","Name","Items"})
            section_name=_text(section['Name'],150,True);section_id="ASVS-5.0.0/section/"+section_code[1:]
            groups.append({'id':section_id,'shortcode':section_code,'name':section_name,'parent':chapter_id,'group_kind':'section','pointer':f'/Requirements/{c}/Items/{s}'})
            for i,item in enumerate(children(section['Items'],500)):
                req_code=identity(item,section_code+'.',{"Shortcode","Ordinal","Description","L"})
                if item['L'] not in ('1','2','3'):
                    raise InvalidFeed("invalid_asvs_level")
                requirement_id='v5.0.0-'+req_code[1:]
                requirements.append({'id':requirement_id,'shortcode':req_code,'level':int(item['L']),
                    'description':_text(item['Description']),'section':section_name,'parent':section_id,
                    'pointer':f'/Requirements/{c}/Items/{s}/Items/{i}'})
                if len(requirements)>5000:
                    raise InvalidFeed("asvs_requirement_limit")
    return {'version':VERSION,'groups':groups,'requirements':requirements,
            'coverage':{'chapters':len(data['Requirements']),'sections':sum(g['group_kind']=='section' for g in groups),
                        'requirements':len(requirements),'assessment_performed':False}}


def import_payload(settings,name):
    raw,meta,notice=read_capture(settings,name)
    normalized=normalize(raw)
    dataset={'provider':'owasp-asvs','version':VERSION,'commit':meta['commit'],'sha256':meta['sha256'],
             'git_blob_sha1':meta['git_blob_sha1'],'captured_at':meta['captured_at'],'source_url':meta['source_url']}
    license={'id':'CC-BY-SA-4.0','url':LICENSE_URL,'source_url':meta['license_url'],'sha256':meta['license_sha256'],
             'attribution':'OWASP ASVS Project and contributors',
             'changes':'Publisher requirement wording unchanged; normalized identifiers and local navigation summaries.'}
    entries,relations=[],[]
    for item in normalized['groups']+normalized['requirements']:
        requirement='level' in item
        asvs={'shortcode':item['shortcode'],'type':'requirement' if requirement else item['group_kind'],
              'level':item.get('level'),'assessment':'not_performed'}
        entry={'id':item['id'],'framework':FRAMEWORK,'kind':'control' if requirement else 'concept','edition_status':'published',
            'edition':VERSION,'title':item['id']+' · '+item['section'] if requirement else item['shortcode']+' · '+item['name'],
            'summary':item['description'] if requirement else 'Publisher grouping: '+item['name']+'. Navigation only, not an assessed control.',
            'source_url':meta['source_url'],'locator':item['pointer'],'reviewed_on':meta['captured_at'][:10],
            'release_id':FRAMEWORK,'tags':['ASVS',item['shortcode'],'requirement' if requirement else 'publisher-group']+(['level-'+str(item['level'])] if requirement else []),
            'asvs':asvs,'source_dataset':dataset,'source_license':license}
        entries.append(entry)
        relations.append({'source':item['id'],'target':item['parent'],'type':'part_of',
                          'rationale':'Membership in the publisher JSON hierarchy; not implementation or equivalence.'})
    return {'provider':'owasp-asvs','version':VERSION,'capture_manifest':name,'source_dataset':dataset,'license_text':notice,
            'entries':entries,'relations':relations,'source_releases':{FRAMEWORK:{'version':VERSION,'published_on':'2025-05',
              'verified_on':meta['captured_at'][:10],'reference_url':'https://owasp.org/projects/asvs','pinning':'publisher_version_reference'}},
            'coverage':normalized['coverage']}


def validate_metadata(raw):
    """Keep rights and publisher levels distinct from own summaries/assessments."""
    a,d,l=raw.get('asvs'),raw.get('source_dataset'),raw.get('source_license')
    if (not isinstance(a,dict) or set(a)!={'shortcode','type','level','assessment'}
            or a['type'] not in ('chapter','section','requirement') or a['assessment']!='not_performed'
            or not isinstance(d,dict) or set(d)!={'provider','version','commit','sha256','git_blob_sha1','captured_at','source_url'}
            or d['provider']!='owasp-asvs' or d['version']!=VERSION or d['source_url']!=source_url(d.get('commit'))
            or raw.get('source_url')!=d['source_url'] or raw.get('framework')!=FRAMEWORK or raw.get('edition')!=VERSION
            or raw.get('edition_status')!='published' or raw.get('release_id')!=FRAMEWORK
            or not isinstance(l,dict) or set(l)!={'id','url','source_url','sha256','attribution','changes'}
            or l['id']!='CC-BY-SA-4.0' or l['url']!=LICENSE_URL or l['source_url']!=BASE+d['commit']+'/LICENSE.md'):
        raise ValueError('invalid_asvs_catalog_metadata')
    for value,length in ((d['sha256'],64),(d['git_blob_sha1'],40),(l['sha256'],64)):
        if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{'+str(length)+'}',value):
            raise ValueError('invalid_asvs_source_digest')
    try:
        if datetime.fromisoformat(d['captured_at']).tzinfo is None:raise ValueError()
    except (ValueError,TypeError):
        raise ValueError('invalid_asvs_catalog_date') from None
    code=a['shortcode']
    if not isinstance(code,str) or not re.fullmatch(r'V[1-9][0-9]{0,2}(?:\.[1-9][0-9]{0,2}){0,2}',code):
        raise ValueError('invalid_asvs_catalog_shortcode')
    parts=code[1:].split('.')
    expected_id='v5.0.0-'+code[1:] if a['type']=='requirement' else 'ASVS-5.0.0/'+a['type']+'/'+code[1:]
    if (raw.get('id')!=expected_id or len(parts)!={'chapter':1,'section':2,'requirement':3}[a['type']]
            or raw.get('kind')!=('control' if a['type']=='requirement' else 'concept')
            or a['type']=='requirement' and (type(a['level']) is not int or a['level'] not in (1,2,3))
            or a['type']!='requirement' and a['level'] is not None):
        raise ValueError('invalid_asvs_catalog_classification')
    _text(l['attribution'],300,True);_text(l['changes'],1000)
    return {'asvs':a,'source_dataset':d,'source_license':l,'knowledge_type':'licensed_publisher_requirement' if a['type']=='requirement' else 'licensed_heading_with_local_navigation_summary',
            'rights':'CC-BY-SA-4.0 applies to imported OWASP material; retain attribution and license. No assessment or endorsement.'}
