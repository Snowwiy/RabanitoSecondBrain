"""Offline ATT&CK publication/retrieval/restore on a disposable real-DB copy.

No provider requests, live replacement, private memories or graph reprojection.
The original verified public capture is reused, never downloaded again.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rabanito.attack import inspect_capture
from rabanito.attack_capture import read_capture, _folder
from rabanito.attack_store import index_capture, schema
from rabanito.attack_query import attack_status, get_attack_object, attack_context, attack_relations, attack_history
from rabanito.config import Settings, load_settings
from rabanito.db import Database, restore_database
from rabanito.knowledge_graph.store import check_source_schemas, schema as graph_schema
from rabanito.utils import contains_reparse_component, safe_relative, write_json_atomic, iso_now
from scripts.validate_msrc_sync import check_db


def check_attack_db(path):
    result = check_db(path)
    with Database(path) as db:
        schema(db)
        graph_schema(db)
        check_source_schemas(db)
        db.execute("INSERT INTO attack_fts(attack_fts) VALUES ('integrity-check')")
        result["fts"].append("attack_fts")
        result["attack_revisions"] = db.one("SELECT count(*) FROM attack_revisions")[0]
        result["attack_fts_rows"] = db.one("SELECT count(*) FROM attack_fts")[0]
    return result


def rehearse(manifest, probe="T1059.001"):
    settings = load_settings()
    if (settings.root.resolve() != ROOT or contains_reparse_component(settings.database_path)
            or safe_relative(settings.database_path, ROOT) in {None, "", "."}):
        raise ValueError("unexpected_attack_rehearsal_root")
    _, metadata = read_capture(settings, manifest)
    expected = inspect_capture(settings, manifest)
    result = {"at": iso_now(), "scope": "temporary_copy_of_real_database", "external_requests": 0,
              "live_database_replaced": False, "capture": expected}
    parent = ROOT / "tests/.test-temp"
    if safe_relative(parent, ROOT) in {None, "", "."} or contains_reparse_component(parent):
        raise ValueError("unsafe_attack_rehearsal_temporary_directory")
    parent.mkdir(exist_ok=True)
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="attack-rehearsal-", dir=parent) as temporary:
        folder, copied = Path(temporary), Path(temporary)/"copy.db"
        with Database(settings.database_path, read_only=True) as db:
            db.backup(copied)
        isolated = Settings(ROOT, {**settings.raw, "database_path": str(copied), "data_dir": str(folder/"data")})
        quarantine = _folder(isolated)
        quarantine.mkdir(parents=True)
        for name in (manifest, metadata["body"], metadata["license"]):
            shutil.copyfile(_folder(settings)/name, quarantine/name)
        print(json.dumps({"phase": "copy_publication"}), flush=True)
        result["first_index"] = index_capture(isolated, manifest)
        result["first_database"] = check_attack_db(copied)
        print(json.dumps({"phase": "copy_idempotence", **result["first_index"]}), flush=True)
        result["second_index"] = index_capture(isolated, manifest)
        if (any(result["second_index"][k] for k in ("added", "modified", "reactivated", "retired"))
                or not result["second_index"]["content_reused"]):
            raise ValueError("attack_rehearsal_not_idempotent")
        result["status"] = attack_status(isolated, domain=metadata["domain"])
        context = attack_context(isolated, probe, domain=metadata["domain"], kind="attack-pattern", limit=1, max_chars=240)
        lookup = get_attack_object(isolated, probe, domain=metadata["domain"], kind="attack-pattern")
        if not lookup["matches"] or lookup["ambiguous"] or not context["fragments"] or context["used_chars"]>240:
            raise ValueError("attack_rehearsal_context_or_lookup")
        entry = lookup["matches"][0]
        if (context["fragments"][0]["id"] != entry["id"] or entry["source_sha256"]!=metadata["sha256"]
                or entry["source_commit"]!=metadata["commit"] or not entry["locator"].startswith("/objects/")):
            raise ValueError("attack_rehearsal_source_citation")
        result["context"] = context
        result["history"] = attack_history(isolated, entry["id"], domain=metadata["domain"])
        relations = attack_relations(isolated, entry["id"], domain=metadata["domain"], limit=2)
        next_page = attack_relations(isolated, entry["id"], domain=metadata["domain"], limit=2, offset=2)
        if ({r["id"] for r in relations["relations"]} & {r["id"] for r in next_page["relations"]}
                or any(r["validation"]!="source_documented" for r in relations["relations"])):
            raise ValueError("attack_rehearsal_relation_pagination")
        result["relations"] = {"total": relations["total"], "page_ids": [r["id"] for r in relations["relations"]],
                               "next_ids": [r["id"] for r in next_page["relations"]]}
        backup, restored = folder/"saved.db", folder/"restored.db"
        with Database(copied, read_only=True) as db:
            db.backup(backup)
        restore_database(backup, restored)
        result["restore"] = check_attack_db(restored)
        recovered = Settings(ROOT, {**isolated.raw, "database_path": str(restored)})
        result["restored_lookup_equal"] = get_attack_object(recovered, probe, domain=metadata["domain"], kind="attack-pattern")==lookup
        if not result["restored_lookup_equal"]:
            raise ValueError("attack_rehearsal_restore_mismatch")
    result.update(temporary_copy_cleaned=True, seconds=round(time.perf_counter()-started, 3))
    write_json_atomic(settings.data_dir/"attack-index-rehearsal.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest")
    parser.add_argument("--probe", default="T1059.001")
    args = parser.parse_args()
    print(json.dumps(rehearse(args.manifest, args.probe), ensure_ascii=True, indent=2))
