"""Rehearse graph migrations/performance on a temporary copy, never the live DB.

Output is aggregate metadata only. No notes, project names or private paths.
"""
from __future__ import annotations

import json
import statistics
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rabanito.config import Settings, load_settings
from rabanito.db import Database, restore_database
from rabanito.knowledge_graph import graph_neighbors, graph_page, sync_graph
from rabanito.knowledge_graph.store import check_source_schemas, epoch_proof, schema
from rabanito.utils import contains_reparse_component, safe_relative, write_json_atomic, iso_now


def validate() -> dict:
    settings = load_settings()
    if settings.root.resolve() != ROOT or contains_reparse_component(settings.database_path) or safe_relative(settings.database_path, ROOT) is None:
        raise ValueError("unexpected_validation_root")
    parent = ROOT / "tests/.test-temp"
    if contains_reparse_component(parent) or safe_relative(parent, ROOT) in {None, "", "."}:
        raise ValueError("unsafe_graph_rehearsal_temporary_directory")
    parent.mkdir(exist_ok=True)
    result = {"at": iso_now(), "scope": "temporary_copy_of_real_database", "live_database_replaced": False, "external_requests": 0}
    with tempfile.TemporaryDirectory(prefix="kg-real-rehearsal-", dir=parent) as temporary:
        folder = Path(temporary)
        copied = folder / "copy.db"
        with Database(settings.database_path, read_only=True) as db:
            db.backup(copied)
        isolated = Settings(settings.root, {**settings.raw, "database_path": str(copied), "data_dir": str(folder / "data")})
        syncs, started = [], time.perf_counter()
        for _ in range(64):
            batch = sync_graph(isolated, max_inputs=2000)
            syncs.append({key: batch[key] for key in ("examined", "changed", "unchanged", "errors", "status", "missing_or_stale_inputs")})
            print(json.dumps({"phase": "first_cycle", "batch": len(syncs), **syncs[-1]}), flush=True)
            if batch["errors"]:
                with Database(copied, read_only=True) as db:
                    result["rejected_input_families"] = [dict(r) for r in db.query("SELECT family,error_code,count(*) n FROM kg_inputs WHERE error_code IS NOT NULL GROUP BY family,error_code")]
                raise ValueError("graph_projection_rehearsal_rejected_inputs")
            if batch["status"] == "ok":
                break
        else:
            raise ValueError("graph_projection_rehearsal_did_not_converge")
        result.update(sync_batches=syncs, sync_seconds=round(time.perf_counter() - started, 3))
        second = []
        for _ in range(64):
            batch = sync_graph(isolated, max_inputs=2000)
            summary = {k: batch[k] for k in ("examined", "changed", "unchanged", "retired", "errors", "status")}
            second.append(summary)
            print(json.dumps({"phase": "idempotent_cycle", "batch": len(second), **summary}), flush=True)
            if batch["changed"] or batch["retired"] or batch["errors"]:
                raise ValueError("graph_rehearsal_complete_cycle_not_idempotent")
            if batch["status"] == "ok":
                break
        else:
            raise ValueError("graph_rehearsal_second_cycle_did_not_converge")
        result["idempotent_cycle"] = second
        times, validation_modes = [], []
        for _ in range(3):
            started = time.perf_counter()
            page = graph_page(isolated, kind="vulnerability", limit=50)
            times.append((time.perf_counter() - started) * 1000)
            validation_modes.append(page["coverage"]["source_validation"])
        result.update(query_median_ms=round(statistics.median(times), 2), query_max_ms=round(max(times), 2),
                      query_samples_ms=[round(t, 2) for t in times], validation_modes=validation_modes,
                      root_page_nodes=len(page["nodes"]), root_candidates=page["total_candidates"], page_has_more=page["has_more"])
        if page["has_more"]:
            following = graph_page(isolated, kind="vulnerability", limit=50, cursor=page["next_cursor"])
            if {n["id"] for n in page["nodes"]} & {n["id"] for n in following["nodes"]}:
                raise ValueError("graph_projection_rehearsal_page_overlap")
            result["second_page_nodes"] = len(following["nodes"])
        projects = graph_page(isolated, kind="project", limit=10)
        if projects["nodes"]:
            project = projects["nodes"][0]
            started = time.perf_counter()
            nearby = graph_neighbors(isolated, project["id"], project=project["contributor_project_id"], limit=50)
            result.update(project_neighbor_ms=round((time.perf_counter() - started) * 1000, 2),
                          project_neighbor_nodes=len(nearby["nodes"]), project_neighbor_edges=len(nearby["edges"]))
        attack = graph_page(isolated, source="attack", kind="attack_technique", query="T1059.001", limit=5)
        if attack["nodes"]:
            anchor = attack["nodes"][0]
            nearby = graph_neighbors(isolated, anchor["id"], source="attack", limit=3)
            more = graph_neighbors(isolated, anchor["id"], source="attack", limit=3, cursor=nearby["next_cursor"]) if nearby["has_more"] else None
            if (not nearby["anchor_visible"] or not nearby["edges"] or any(e["validation"]!="source_documented" for e in nearby["edges"])
                    or more and {e["id"] for e in nearby["edges"]} & {e["id"] for e in more["edges"]}):
                raise ValueError("graph_rehearsal_attack_neighbors")
            hidden = graph_page(isolated, source="attack", kind="attack_technique", limit=1)
            all_states = graph_page(isolated, source="attack", kind="attack_technique", include_inactive=True, limit=1)
            result["attack"] = {"anchor": anchor, "neighbor_edges": len(nearby["edges"]), "has_more": nearby["has_more"],
                                "current_techniques": hidden["total_candidates"], "including_inactive_techniques": all_states["total_candidates"]}
            if not all_states["total_candidates"] >= hidden["total_candidates"]:
                raise ValueError("graph_rehearsal_attack_states")
            saved, restored = folder/"backup.db", folder/"restored.db"
            with Database(copied, read_only=True) as db:
                db.backup(saved)
            restore_database(saved, restored)
            recovered = Settings(ROOT, {**isolated.raw, "database_path": str(restored)})
            restored_page = graph_page(recovered, source="attack", kind="attack_technique", query="T1059.001", limit=5)
            result["restored_attack_nodes_equal"] = restored_page["nodes"] == attack["nodes"]
            if not result["restored_attack_nodes_equal"]:
                raise ValueError("graph_rehearsal_attack_restore_mismatch")
            with Database(restored, read_only=True) as db:
                check_source_schemas(db); schema(db)
                if db.one("PRAGMA integrity_check")[0]!="ok" or db.query("PRAGMA foreign_key_check"):
                    raise ValueError("graph_rehearsal_restored_integrity")
        with Database(copied, read_only=True) as db:
            result.update(integrity=db.one("PRAGMA integrity_check")[0], fk_errors=len(db.query("PRAGMA foreign_key_check")),
                          projected_node_identities=db.one("SELECT count(DISTINCT node_id) FROM kg_nodes")[0],
                          projected_edge_identities=db.one("SELECT count(DISTINCT edge_id) FROM kg_edges")[0])
            schema(db); check_source_schemas(db)
            proof = epoch_proof(db)
            result["watcher_coverage_complete"] = proof is not None
            result["watched_tables"] = len(proof[1]) if proof else 0
        if result["integrity"] != "ok" or result["fk_errors"]:
            raise ValueError("graph_projection_rehearsal_integrity_failed")
    result["temporary_copy_cleaned"] = True
    write_json_atomic(settings.data_dir / "knowledge-graph-rehearsal.json", result)
    return result


if __name__ == "__main__":
    try:
        print(json.dumps(validate(), ensure_ascii=True, indent=2))
    except (ValueError, OSError) as exc:
        print(json.dumps({"error": str(exc) if isinstance(exc, ValueError) else "graph_rehearsal_io_error"}))
        raise SystemExit(1) from None
