"""Rehearse reviewed security catalog updates on a disposable real-DB copy.

Offline: no downloaded standards, private knowledge uploads or live replacement.
"""
from __future__ import annotations

import json
import argparse
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rabanito.config import Settings, load_settings
from rabanito.db import Database, restore_database
from rabanito.knowledge_graph import graph_page, sync_graph
from rabanito.public_graph import public_graph
from rabanito.security import get_security_entry, index_security_catalog, search_security, security_context
from rabanito.utils import contains_reparse_component, iso_now, safe_relative, write_json_atomic
from scripts.validate_msrc_sync import check_db


def rehearse(asvs_capture=None):
    settings = load_settings()
    if settings.root.resolve() != ROOT or contains_reparse_component(settings.database_path) or safe_relative(settings.database_path, ROOT) is None:
        raise ValueError("unexpected_validation_root")
    result = {"at": iso_now(), "scope": "temporary_copy_of_real_database", "external_requests": 0, "live_database_replaced": False}
    parent = ROOT / "tests/.test-temp"
    if safe_relative(parent, ROOT) in {None, "", "."} or contains_reparse_component(parent):
        raise ValueError("unsafe_security_rehearsal_temporary_directory")
    parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="security-rehearsal-", dir=parent) as temporary:
        folder, copied = Path(temporary), Path(temporary) / "copy.db"
        with Database(settings.database_path, read_only=True) as db:
            db.backup(copied)
        isolated = Settings(ROOT, {**settings.raw, "database_path": str(copied), "data_dir": str(folder / "data")})
        if asvs_capture is not None:
            from rabanito.asvs_capture import read_capture,folder as capture_folder
            _,metadata,_=read_capture(settings,asvs_capture)
            target=capture_folder(isolated);target.mkdir(parents=True)
            for name in (asvs_capture,metadata['body'],metadata['license']):
                shutil.copyfile(capture_folder(settings)/name,target/name)
        result["first_index"] = index_security_catalog(isolated,asvs_capture=asvs_capture)
        result["second_index"] = index_security_catalog(isolated)
        if any(result["second_index"][k] for k in ("added", "modified", "retired")):
            raise ValueError("security_rehearsal_not_idempotent")
        csf = search_security(isolated, release="NIST-CSF-2.0", kind="control", limit=100)
        result["csf_outcomes"] = csf["total"]
        context = security_context(isolated, "respaldo", release="NIST-CSF-2.0", kind="control", max_chars=90)
        if not context["fragments"] or context["used_chars"] > 90 or not all(f.get("source_release") for f in context["fragments"]):
            raise ValueError("security_rehearsal_citation_missing")
        result["cited_context_chars"] = context["used_chars"]
        nist = search_security(isolated, release="NIST-800-207-2020", kind="concept", limit=100)
        cisa = search_security(isolated, release="CISA-ZTMM-2.0", kind="concept", limit=100)
        if (nist["total"], cisa["total"]) != (10, 12):
            raise ValueError("security_rehearsal_zero_trust_coverage")
        zero_context = security_context(isolated, "madurez", release="CISA-ZTMM-2.0", max_chars=90)
        if (not zero_context["fragments"] or zero_context["used_chars"] > 90 or any(
                f["source_release"].get("published_on") != "2023-04" or f["source_release"].get("published_on_precision") != "month"
                for f in zero_context["fragments"])):
            raise ValueError("security_rehearsal_publication_precision")
        result["zero_trust"] = {"nist_new_concepts": nist["total"], "cisa_concepts": cisa["total"],
                                "context_chars": zero_context["used_chars"], "cisa_publication_month": "2023-04"}
        item = get_security_entry(isolated, "MITRE-ATTACK-20.0")
        if not item or item["source_release"]["pinning"] != "publisher_version_reference":
            raise ValueError("security_rehearsal_release_missing")
        legacy = public_graph(isolated, "security", limit=100)
        result["legacy_graph"] = {"nodes": len(legacy["nodes"]), "edges": len(legacy["edges"])}
        asvs_item=None
        if asvs_capture is not None:
            from rabanito.asvs import FRAMEWORK
            from rabanito.security_imports import summaries
            with Database(copied,read_only=True) as db: result['registered_imports']=summaries(db)
            asvs_item=get_security_entry(isolated,'v5.0.0-1.2.5')
            licensed=security_context(isolated,'v5.0.0-1.2.5',framework=FRAMEWORK,kind='control',max_chars=120,level=1)
            counts={str(level):search_security(isolated,framework=FRAMEWORK,kind='control',level=level)['total'] for level in (1,2,3)}
            if (not asvs_item or not licensed['fragments'] or licensed['used_chars']>120
                    or asvs_item['knowledge_type']!='licensed_publisher_requirement'
                    or asvs_item['asvs']['assessment']!='not_performed' or sum(counts.values())!=345):
                raise ValueError('security_rehearsal_asvs_content')
            result['asvs']={'requirements':sum(counts.values()),'levels':counts,'context':licensed}
        batches, started = [], time.perf_counter()
        for i in range(64):
            batch = sync_graph(isolated, max_inputs=2000)
            summary = {k: batch[k] for k in ("examined", "changed", "unchanged", "errors", "status")}
            batches.append(summary)
            print(json.dumps({"phase": "graph", "batch": i + 1, **summary}), flush=True)
            if batch["errors"]:
                raise ValueError("security_rehearsal_graph_error")
            if batch["status"] == "ok":
                break
        else:
            raise ValueError("security_rehearsal_graph_not_converged")
        result.update(graph_batches=batches, graph_seconds=round(time.perf_counter() - started, 3),
                      graph_controls=graph_page(isolated, kind="control", limit=100)['total_candidates'],
                      graph_concepts=graph_page(isolated, kind="security_concept", limit=100)['total_candidates'])
        if asvs_item is not None:
            graph=graph_page(isolated,kind='control',category='OWASP-ASVS-5.0.0',query='v5.0.0-1.2.5',limit=2)
            if not graph['nodes'] or graph['nodes'][0]['data']['source_license']['id']!='CC-BY-SA-4.0':
                raise ValueError('security_rehearsal_asvs_graph_rights')
            result['asvs']['graph_nodes']=graph['nodes']
        result["database"] = check_db(copied)
        backup, restored = folder / "backup.db", folder / "restored.db"
        with Database(copied, read_only=True) as db:
            db.backup(backup)
        restore_database(backup, restored)
        result["restored_database"] = check_db(restored)
        recovered = Settings(ROOT, {**isolated.raw, "database_path": str(restored)})
        result["restored_entry_equal"] = get_security_entry(recovered, "MITRE-ATTACK-20.0") == item
        result["restored_month_precision_equal"] = get_security_entry(recovered, "CISA-ZTMM-2.0") == get_security_entry(isolated, "CISA-ZTMM-2.0")
        if not result["restored_entry_equal"] or not result["restored_month_precision_equal"]:
            raise ValueError("security_rehearsal_restore_mismatch")
        if asvs_item is not None:
            result['restored_asvs_equal']=get_security_entry(recovered,'v5.0.0-1.2.5')==asvs_item
            from rabanito.security_imports import summaries
            with Database(restored,read_only=True) as db:
                result['restored_imports_equal']=summaries(db)==result['registered_imports']
            if not result['restored_asvs_equal'] or not result['restored_imports_equal']:
                raise ValueError('security_rehearsal_asvs_restore')
    result["temporary_copy_cleaned"] = True
    write_json_atomic(settings.data_dir / "security-catalog-rehearsal.json", result)
    return result


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--asvs-capture')
    args=parser.parse_args()
    try:
        print(json.dumps(rehearse(args.asvs_capture), ensure_ascii=True, indent=2))
    except (ValueError, OSError) as exc:
        print(json.dumps({"error": str(exc) if isinstance(exc, ValueError) else "security_rehearsal_io_error"}))
        raise SystemExit(1) from None
