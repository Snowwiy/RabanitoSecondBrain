"""Incremental, explicitly requested projection of cited facts and labelled claims."""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from ..coding_memory import _verified_records
from ..config import Settings
from ..db import Database
from ..dependencies import package_key
from ..indexer import _index_lock
from ..utils import iso_now, path_key, redact_sensitive_lines
from .store import check_source_schemas, configure, descriptors, encode, fingerprint, migrate, own_outputs, set_state, source_version, state


def stamp(value) -> str | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError):
        return None


def relative(value: str) -> str:
    if (not isinstance(value, str) or not value or len(value) > 2000 or ":" in value or "\\" in value
            or PurePosixPath(value).is_absolute() or any(p in {"", ".", ".."} for p in value.split("/"))
            or re.search(r"[\x00-\x1f\x7f]", value)):
        raise ValueError("unsafe_graph_relative_reference")
    return value


def doc_citation(row, pid=None) -> str:
    scope = str(pid) + ":" if row["source_kind"] == "projects" and pid is not None else ""
    return str(row["source_kind"]) + ":" + scope + relative(row["relative_path"])


def dependency_id(pid, component) -> str:
    key = package_key(component.get("ecosystem", ""), component.get("name", ""))
    identity = [key or (component.get("ecosystem"), component.get("name")), component.get("version"), component.get("identity_issue")]
    if "inventory_scope_sha256" in component:
        identity.append(component["inventory_scope_sha256"])
    return "dependency:" + str(pid) + ":" + fingerprint(*identity)


class Builder:
    def __init__(self, item: dict):
        self.item, self.nodes, self.edges, self.byte_count = item, {}, {}, 0

    def _bytes(self, value) -> None:
        self.byte_count += len(encode(value).encode())
        if self.byte_count > 16 * 1024 * 1024:
            raise ValueError("graph_input_output_limit")

    def node(self, key, kind, title, citation, *, data=None, public=False, rank=0, updated=None, category=None):
        if not isinstance(title, str) or not title or re.search(r"[\x00-\x1f\x7f]", title):
            raise ValueError("invalid_graph_label")
        if not public and redact_sensitive_lines(title).splitlines() != title.splitlines():
            raise ValueError("sensitive_graph_label")
        if len(key) > 2000 or len(citation) > 4000:
            raise ValueError("graph_identity_or_citation_limit")
        payload = {"privacy": "public" if public else "local", **(data or {})}
        value = (key, kind, title[:500], self.item["origin"], category or kind, stamp(updated), citation,
                 self.item["pid"], encode(payload), rank)
        if key not in self.nodes or rank < self.nodes[key][-1]:
            self._bytes(value)
            self.nodes[key] = value

    def edge(self, source, target, relation, citation, *, validation="source_documented", data=None, identity=None):
        key = fingerprint("explicit-source-identity", identity) if identity is not None else fingerprint(source, target, relation, citation, data or {})
        value = (key, source, target, relation, validation, citation, self.item["pid"], encode(data or {}))
        if key not in self.edges:
            self._bytes(value)
            self.edges[key] = value


def load(db: Database, item: dict) -> dict:
    family, native = item["family"], item["native"]
    if family.startswith("attack-"):
        from .attack import load_attack
        return load_attack(db, item)
    sql = {
        "project": "SELECT * FROM projects WHERE project_id=?",
        "document": "SELECT document_id,title,source_kind,source_root,project_root_path,relative_path,frontmatter_json,category,mtime_iso,content_hash FROM documents WHERE document_id=?",
        "link": "SELECT l.*,d.source_kind,d.relative_path FROM links l JOIN documents d ON d.document_id=l.source_document_id WHERE link_id=?",
        "suggestion": "SELECT s.*,d.source_kind,d.relative_path FROM link_suggestions s JOIN documents d ON d.document_id=s.source_document_id WHERE suggestion_id=?",
        "observation": "SELECT data_json,retrieved_at FROM cyber_records WHERE source=? AND source_id=?",
        "vulnerability": "SELECT vulnerability_id,title,status,kev,cvss,epss,published,modified,retrieved_at,"
                         "json_extract(data_json,'$.record_kind') record_kind,json_extract(data_json,'$.exploitation') exploitation "
                         "FROM cyber_entities WHERE vulnerability_id=?",
        "security": "SELECT data_json,indexed_at FROM security_entries WHERE entry_id=?",
        "snapshot": "SELECT * FROM dependency_analyses WHERE analysis_id=?",
        "review": "SELECT * FROM dependency_reviews WHERE review_id=?",
        "security-relation": "SELECT r.*,s.data_json FROM security_relations r JOIN security_entries s ON s.entry_id=r.source_id WHERE r.source_id=? AND r.target_id=? AND r.relation_type=?",
    }[family]
    params = (item["origin"], native) if family == "observation" else tuple(json.loads(native)) if family == "security-relation" else (native,)
    row = db.one(sql, params)
    if row is None:
        raise ValueError("graph_source_disappeared")
    payload = dict(row)
    if family == "vulnerability":
        sources = db.query("SELECT r.source,json_extract(r.data_json,'$.source_url') url "
                           "FROM cyber_aliases a JOIN cyber_records r USING(source,source_id) WHERE a.vulnerability_id=? AND r.active=1 "
                           "ORDER BY CASE r.source WHEN 'kev' THEN 0 WHEN 'epss' THEN 1 ELSE 2 END,r.source,r.source_id LIMIT 101", (native,))
        payload["citations"] = [dict(r) for r in sources[:100]]
        payload["citations_truncated"] = len(sources) > 100
    if len(encode(payload).encode()) > 8 * 1024 * 1024:
        raise ValueError("graph_source_size_limit")
    return payload


def build(settings: Settings, db: Database, item: dict, row: dict) -> Builder:
    out = Builder(item)
    family, native, pid = item["family"], item["native"], item["pid"]
    project = "project:" + str(pid)
    if family.startswith("attack-"):
        from .attack import build_attack
        build_attack(out, item, row)
    elif family == "project":
        out.node(project, "project", row["name"], "index:projects/" + str(pid), updated=row["last_seen"],
                 data={"project_id": pid, "freshness": "indexed_metadata_not_live_filesystem_audit"})
        for number, value in enumerate(json.loads(row["technology_json"])):
            if not isinstance(value, str) or not value.strip():
                continue
            key, citation = "technology:" + fingerprint(value), "index:projects/" + str(pid) + "/technology/" + str(number)
            out.node(key, "technology", value, citation, rank=5)
            out.edge(project, key, "detected_technology", citation, validation="inferred_from_indexed_metadata")
        for declaration in json.loads(row["dependencies_json"]):
            key = "declaration:" + str(pid) + ":" + fingerprint(declaration["name"])
            citation = "index:projects/" + str(pid) + "/dependencies"
            sources = [relative(v) for v in declaration.get("sources", [])[:20]]
            out.node(key, "dependency_declaration", declaration["name"], citation,
                     data={"version": None, "ecosystem": None, "manifests": sources, "scope": "names_only_not_installed_or_versioned"})
            out.edge(project, key, "declares_dependency_name", citation)
    elif family == "document":
        fm = json.loads(row["frontmatter_json"])
        fm = fm if isinstance(fm, dict) else {}
        reviewed = (row["source_kind"] == "internal" and row["relative_path"].startswith("decisions/")
                    and fm.get("kind") == "verified-memory")
        key, citation = "document:" + native, doc_citation(row, pid)
        out.node(key, "decision" if reviewed else "document", row["title"], citation, category=row["category"], updated=row["mtime_iso"],
                 data={"document_id": int(native), "relative_path": row["relative_path"], "record_type": fm.get("record_type") if reviewed else None,
                       "record_status": fm.get("status") if reviewed else None, "validation": "indexed_record_not_independently_validated"})
        if pid is not None:
            out.edge(project, key, "has_indexed_document", citation)
        if reviewed and fm.get("status") == "confirmed" and fm.get("validation") == "passed":
            records, _ = _verified_records(settings, "", None, None, document_id=int(native))
            if records:
                from ..decisions import _resolve_evidence
                solution = "solution:" + native
                out.node(solution, "solution", row["title"], citation, updated=row["mtime_iso"],
                         data={"document_id": int(native), "validation": "passed_as_recorded_not_rerun", "evidence": records[0]["evidence"]})
                out.edge(key, solution, "documents_reviewed_experience", citation, validation="reviewed_record")
                for reference in records[0]["evidence"]:
                    try:
                        resolved, _ = _resolve_evidence(settings, Path(row["project_root_path"]), reference)
                    except (ValueError, OSError):
                        continue
                    target = db.one("SELECT document_id FROM documents WHERE path_key=? AND status='active'", (path_key(resolved),))
                    if target:
                        out.edge(key, "document:" + str(target[0]), "reviewed_record_cites_evidence", citation,
                                 validation="reviewed_record", data={"reference": reference})
    elif family in {"link", "suggestion"}:
        source = "document:" + str(row["source_document_id"])
        citation = doc_citation(row, pid)
        if family == "suggestion":
            out.edge(source, "document:" + str(row["target_document_id"]), "suggested_document_connection", citation,
                     validation="suggested", data={"score": row["score"]})
        elif row["status"] == "resolved" and row["target_document_id"] is not None:
            out.edge(source, "document:" + str(row["target_document_id"]), "explicit_document_link", citation,
                     data={"line": row["line_number"], "syntax": row["relation_type"]})
        elif row["status"] == "external":
            target = row["target_raw"]
            if target.startswith("https://nvd.nist.gov/vuln/detail/"):
                value = target.removeprefix("https://nvd.nist.gov/vuln/detail/")
                if re.fullmatch(r"CVE-\d{4}-\d{4,}", value):
                    out.edge(source, "vulnerability:" + value, "cites_public_vulnerability", citation, data={"line": row["line_number"]})
            if db.one("SELECT 1 FROM sqlite_master WHERE name='security_entries'"):
                for entry in db.query("SELECT entry_id FROM security_entries WHERE active=1 AND kind IN ('framework','reference') AND json_extract(data_json,'$.source_url')=?", (target,)):
                    out.edge(source, "security:" + entry[0], "cites_security_publication_not_compliance", citation, data={"line": row["line_number"]})
    elif family == "vulnerability":
        key = "vulnerability:" + native
        priority = "known_exploited" if row["kev"] or row["exploitation"] == "known_exploited" else "high_prediction" if row["epss"] is not None and row["epss"] >= .1 else "published"
        if row["status"] != "published":
            priority = None  # Retained/withdrawn records are not active risk findings.
        citation = row["citations"][0]["url"] if row["citations"] else "index:cyber/" + native
        out.node(key, "security_advisory" if row["record_kind"] == "security_advisory" else "vulnerability", native, citation, public=True, updated=row["modified"] or row["retrieved_at"],
                 data={"risk": priority, "risk_basis": "public_priority_not_project_applicability", "record_status": row["status"],
                       "kev": bool(row["kev"]), "exploitation": row["exploitation"],
                       "cvss": row["cvss"], "epss": row["epss"], "date_basis": "provider_modified_else_retrieved",
                       "citations": row["citations"], "citations_truncated": row["citations_truncated"]})
    elif family == "observation":
        data = json.loads(row["data_json"])
        key, citation = item["k"], data["source_url"]
        out.node(key, "observation", data["id"], citation, public=True, updated=data.get("modified") or row["retrieved_at"],
                 data={"provider": item["origin"], "record_status": data["record_status"], "source_id": data["id"]})
        for entity in db.query("SELECT vulnerability_id FROM cyber_aliases WHERE source=? AND source_id=?", (item["origin"], native)):
            target = "vulnerability:" + entity[0]
            out.node(target, "security_advisory" if data.get("record_kind") == "security_advisory" else "vulnerability", entity[0], citation, public=True, rank=10,
                     data={"validation": "provider_identifier_reference_only", "risk": None})
            out.edge(key, target, "observation_references_identifier_not_equivalence", citation)
        if data["record_status"] == "published":
            for cwe in data["cwes"]:
                target = "weakness:" + cwe
                out.node(target, "weakness", cwe, "https://cwe.mitre.org/data/definitions/" + cwe[4:] + ".html", public=True)
                out.edge(key, target, "classified_as", citation)
            for number, affected in enumerate(data["affected"]):
                pkey = package_key(affected.get("ecosystem", ""), affected.get("package", ""))
                if pkey:
                    target = "package:" + fingerprint(pkey)
                    out.node(target, "package", pkey[0] + ":" + pkey[1], citation, public=True,
                             data={"ecosystem": pkey[0], "name": pkey[1]})
                    relation = "advisory_reports_package_not_project_applicability"
                elif affected.get("product") or affected.get("criteria"):
                    target = "product-condition:" + fingerprint(affected)
                    label = affected.get("criteria") or (affected.get("vendor", "") + ":" + affected["product"])
                    out.node(target, "product_condition", label, citation, public=True, data={"scope": "provider_condition_not_project_applicability"})
                    relation = "provider_product_or_configuration_condition"
                else:
                    continue
                out.edge(key, target, relation, citation, data={"locator": "/affected/" + str(number)})
    elif family in {"security", "security-relation"}:
        data = json.loads(row["data_json"])
        if family == "security":
            licensed = {k:data[k] for k in ('asvs','source_dataset','source_license','knowledge_type','rights') if k in data} if 'asvs' in data else {}
            out.node("security:" + native, {"control": "control", "framework": "standard", "concept": "security_concept", "reference": "reference"}[data["kind"]], data["title"], data["source_url"], public=True,
                     category=data["framework"], updated=data["reviewed_on"],
                     data={"edition_status": data["edition_status"], "locator": data["locator"], "entry_kind": data["kind"],**licensed})
        else:
            out.edge("security:" + row["source_id"], "security:" + row["target_id"], row["relation_type"], data["source_url"],
                     validation="suggested" if row["validation"] == "unvalidated_editorial" else "source_documented")
    elif family == "snapshot":
        data = json.loads(row["report_json"])
        if data["analysis_id"] != native or data["source"]["sha256"] != row["source_sha256"]:
            raise ValueError("invalid_graph_analysis_identity")
        key, citation = "snapshot:" + native, "projects:" + str(pid) + ":" + relative(row["relative_path"])
        out.node(key, "snapshot", row["relative_path"], citation, updated=row["created_at"],
                 data={"analysis_id": native, "inventory_sha256": row["source_sha256"], "validation": "saved_analysis_not_revalidated"})
        out.edge(project, key, "has_saved_inventory_analysis", citation)
        component_ids = {}
        for component in data["components"]:
            target = dependency_id(pid, component)
            component_ids[component["pointer"]] = target
            detail = {"ecosystem": component["ecosystem"], "name": component["name"], "version": component["version"],
                      "validation": "declared_inventory_not_installed_state"}
            if "inventory_scope_sha256" in component:
                detail.update(inventory_scope_sha256=component["inventory_scope_sha256"], source_kind=component["source_kind"],
                              environment_selection=component["environment_selection"])
            out.node(target, "dependency", component["name"] + "@" + component["version"], citation, updated=row["created_at"], data=detail)
            out.edge(key, target, "inventory_declares_component", citation, data={"locator": component["pointer"]})
        for finding in data["findings"]:
            target = component_ids.get(finding["component_pointer"])
            if target:
                candidate = finding["assessment"] in {"potentially_affected", "needs_review"}
                out.edge(target, "observation:osv:" + finding["advisory"], "saved_inventory_applicability_candidate" if candidate else "saved_inventory_advisory_evaluation", finding["citation"],
                         validation="inferred_candidate" if candidate else "documented_evaluation",
                         data={"assessment": finding["assessment"], "analysis_id": native,
                               "validation": "saved_assessment_not_current_or_installed"})
    elif family == "review":
        from ..dependency_memory import _digest
        data = json.loads(row["payload_json"])
        if _digest(data) != native or data["project_id"] != pid:
            raise ValueError("invalid_graph_review_checksum_or_scope")
        key, citation = "review:" + native, "index:dependency_reviews/" + native
        out.node(key, "review", data["status"] + " — " + data["advisory"], citation, updated=row["created_at"],
                 data={"claim_status": data["status"], "expires": data["expires"], "revoked_at": row["revoked_at"],
                       "validation": "reviewed_claim_validity_not_rechecked"})
        out.edge(project, key, "has_recorded_review", citation)
        out.edge(key, "observation:osv:" + data["advisory"], "review_claim_for_advisory", citation, validation="reviewed_claim")
        target = dependency_id(pid, data["component"])
        out.node(target, "dependency", data["component"]["name"] + "@" + data["component"]["version"], citation, rank=5,
                 data={"validation": "version_in_review_not_revalidated"})
        out.edge(key, target, "review_claim_about_version", citation, validation="reviewed_claim")
    return out


def sync_graph(settings: Settings, *, max_inputs: int = 1000, max_bytes: int = 32 * 1024 * 1024) -> dict:
    if type(max_inputs) is not int or not 1 <= max_inputs <= 5000 or type(max_bytes) is not int or not 8 * 1024 * 1024 <= max_bytes <= 64 * 1024 * 1024:
        raise ValueError("invalid_graph_sync_budget")
    own_outputs(settings)
    if sqlite3.sqlite_version_info < (3, 35, 0):
        raise ValueError("knowledge_graph_requires_sqlite_335_or_newer")
    started = iso_now()
    with _index_lock(settings), Database(settings.database_path) as db:
        db.execute("PRAGMA temp_store=MEMORY")
        check_source_schemas(db)
        backup = migrate(settings, db)
        configure(db, settings)
        sql, version = descriptors(db), source_version(db, settings)
        previous = state(db, "next_key") if state(db, "cycle_source_version") == version else ""
        rows = db.query(sql + "SELECT * FROM U WHERE k>? ORDER BY k LIMIT ?", (previous, max_inputs + 1))
        result = {"examined": 0, "changed": 0, "unchanged": 0, "retired": 0, "errors": 0, "input_bytes": 0,
                  "migration_backup": backup, "next_key": previous or None}
        db.execute("BEGIN IMMEDIATE")
        exhausted = len(rows) <= max_inputs
        for raw in rows[:max_inputs]:
            item = dict(raw)
            old = db.one("SELECT fingerprint,active FROM kg_inputs WHERE input_key=?", (item["k"],))
            if old and old["active"] and old["fingerprint"] == item["fp"]:
                result["unchanged"] += 1
            else:
                try:
                    payload = load(db, item)
                    payload_bytes = len(encode(payload).encode())
                    if result["input_bytes"] + payload_bytes > max_bytes:
                        exhausted = False
                        break
                    output = build(settings, db, item, payload)
                    result["input_bytes"] += payload_bytes
                except (ValueError, TypeError, KeyError, OSError, RecursionError):
                    db.execute("INSERT INTO kg_inputs VALUES (?,?,?,?,?,?,0,?,'projection_input_rejected') ON CONFLICT(input_key) "
                               "DO UPDATE SET fingerprint=excluded.fingerprint,active=0,error_code=excluded.error_code,processed_at=excluded.processed_at",
                               (item["k"], item["fp"], item["family"], item["native"], item["origin"], item["pid"], iso_now()))
                    result["errors"] += 1
                else:
                    db.execute("INSERT INTO kg_inputs VALUES (?,?,?,?,?,?,1,?,NULL) ON CONFLICT(input_key) DO UPDATE SET "
                               "fingerprint=excluded.fingerprint,family=excluded.family,native_id=excluded.native_id,origin=excluded.origin,"
                               "project_id=excluded.project_id,active=1,processed_at=excluded.processed_at,error_code=NULL",
                               (item["k"], item["fp"], item["family"], item["native"], item["origin"], item["pid"], iso_now()))
                    db.execute("DELETE FROM kg_nodes WHERE input_key=?", (item["k"],))
                    db.execute("DELETE FROM kg_edges WHERE input_key=?", (item["k"],))
                    db.executemany("INSERT INTO kg_nodes VALUES (?,?,?,?,?,?,?,?,?,?,?)", [(item["k"], *n) for n in output.nodes.values()])
                    db.executemany("INSERT INTO kg_edges VALUES (?,?,?,?,?,?,?,?,?)", [(item["k"], *e) for e in output.edges.values()])
                    result["changed"] += 1
            result["examined"] += 1
            result["next_key"] = item["k"]
        if exhausted:
            prior = db.connection.total_changes
            db.execute(sql + "UPDATE kg_inputs SET active=0 WHERE active=1 AND input_key NOT IN (SELECT k FROM U)")
            result["retired"] = db.connection.total_changes - prior
            result["next_key"] = None
        gaps = db.one(sql + "SELECT count(*) FROM U LEFT JOIN kg_inputs g ON g.input_key=U.k "
                      "WHERE g.input_key IS NULL OR g.active=0 OR g.fingerprint<>U.fp")[0]
        result.update(status="ok" if exhausted and gaps == 0 else "partial", missing_or_stale_inputs=gaps)
        set_state(db, "next_key", result["next_key"] or "")
        set_state(db, "cycle_source_version", version)
        if result["status"] == "ok":
            set_state(db, "last_complete_at", iso_now())
            set_state(db, "last_complete_source_version", version)
        db.execute("INSERT INTO kg_runs(started_at,finished_at,status,examined,changed,unchanged,retired,errors,next_key,source_version) "
                   "VALUES (?,?,?,?,?,?,?,?,?,?)", (started, iso_now(), result["status"], result["examined"], result["changed"],
                    result["unchanged"], result["retired"], result["errors"], result["next_key"], version))
        return result
