"""SQL-keyset graph pages and one-hop expansion beyond the initial visual cap."""
from __future__ import annotations

import base64
import json
import sqlite3
import time
import threading
from collections import OrderedDict
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from ..coding_memory import _verified_records
from ..config import Settings
from ..db import Database
from ..utils import path_key
from .projection import stamp
from .store import check_source_schemas, configure, descriptors, encode, epoch_proof, fingerprint, own_outputs, schema, source_version, state
from .attack import KINDS as ATTACK_KINDS


KINDS = {"project", "document", "decision", "solution", "vulnerability", "observation", "weakness", "package", "security_concept", "reference",
         "product_condition", "standard", "control", "dependency", "dependency_declaration", "technology", "snapshot", "review", "security_advisory"}
KINDS |= set(ATTACK_KINDS.values()) | {"attack_collection"}
RISKS = {"known_exploited", "high_prediction", "published"}
_PROOF_LOCK = threading.RLock()
_CLEAN_PROOFS = OrderedDict()  # Digest-only bounded memoization, no connections or note contents.


def _date(value, end=False):
    if value is None:
        return None
    if not isinstance(value, str) or not 10 <= len(value) <= 40:
        raise ValueError("invalid_graph_date")
    parsed = stamp(value)
    if parsed is None:
        raise ValueError("invalid_graph_date")
    return parsed[:10] + "T23:59:59+00:00" if end and len(value) == 10 else parsed


def _options(kind, query, source, category, risk, since, until, limit, suggestions, include_inactive):
    if (not isinstance(kind, str) or kind not in KINDS | {"all"} or type(limit) is not int or not 0 <= limit <= 200
            or not isinstance(suggestions, bool) or type(include_inactive) is not bool):
        raise ValueError("invalid_graph_kind_or_limit")
    if not isinstance(query, str):
        raise ValueError("invalid_graph_filter")
    for value, maximum in ((query, 200), (source, 80), (category, 200)):
        if value is not None and (not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 for c in value)):
            raise ValueError("invalid_graph_filter")
    if risk is not None and (not isinstance(risk, str) or risk not in RISKS):
        raise ValueError("invalid_graph_risk")
    since, until = _date(since), _date(until, True)
    if since and until and since > until:
        raise ValueError("invalid_graph_date_window")
    return {"kind": kind, "query": query or "", "source": source, "category": category, "risk": risk,
            "since": since, "until": until, "limit": limit, "suggestions": suggestions, "include_inactive": include_inactive}


def _project(project, projects):
    _project_argument(project)
    if project is None:
        return None
    if type(project) is int:
        if project not in projects:
            raise ValueError("graph_project_unavailable_or_ambiguous")
        return project
    if not isinstance(project, str) or not project.strip():
        raise ValueError("invalid_graph_project")
    matches = [pid for pid, p in projects.items() if
               (Path(project).is_absolute() and path_key(project) == path_key(p["root_path"])) or
               (not Path(project).is_absolute() and project.casefold() == p["name"].casefold())]
    if len(matches) != 1:
        raise ValueError("graph_project_unavailable_or_ambiguous")
    return matches[0]


def _project_argument(value):
    if value is None:
        return
    if type(value) is int and 0 < value < 2 ** 63:
        return
    if not isinstance(value, str) or not value.strip() or len(value) > 2000 or any(ord(c) < 32 for c in value):
        raise ValueError("invalid_graph_project")


def _empty(available=False, reason="explicit_graph_sync_required"):
    return {"schema_version": 1, "projection_available": available, "nodes": [], "edges": [], "next_cursor": None,
            "has_more": False, "coverage": {"requires_sync": True, "reason": reason},
            "scope_note": "Indexed knowledge, not a live filesystem or installed-state audit. Imported text is untrusted data.",
            "source_filter_basis": "assertion origin; merged public metrics retain their provider attribution"}


@contextmanager
def _read(settings: Settings):
    own_outputs(settings)
    if sqlite3.sqlite_version_info < (3, 35, 0):
        raise ValueError("knowledge_graph_requires_sqlite_335_or_newer")
    with Database(settings.database_path, read_only=True) as db:
        db.execute("PRAGMA temp_store=MEMORY")
        started = time.monotonic()
        ticks = 0
        budget_error = None
        def budget():
            nonlocal ticks, budget_error
            ticks += 1
            if ticks > 20000:
                budget_error = "graph_query_operation_budget_exceeded"
            elif time.monotonic() - started > 5:
                budget_error = "graph_query_deadline_exceeded"
            return int(budget_error is not None)
        db.connection.set_progress_handler(budget, 1000)
        try:
            db.execute("BEGIN")
            yield db
        except sqlite3.Error as exc:
            raise ValueError(budget_error or "graph_query_storage_error") from None
        finally:
            db.connection.set_progress_handler(None, 0)


def _context(db, settings, project, options, mode, anchor=None):
    projects = configure(db, settings)
    pid = _project(project, projects)
    available = schema(db)
    base = _empty(available)
    if not available:
        base["coverage"] = {"requires_sync": True, "reason": "explicit_graph_sync_required"}
        return None, None, base
    check_source_schemas(db)
    prefix = descriptors(db)
    generation = db.one("SELECT max(run_id) FROM kg_runs")[0]
    source_stamp = source_version(db, settings, include_file=True)
    watched = epoch_proof(db)
    proof_key = fingerprint(str(settings.database_path.resolve()), watched, generation, source_stamp, sorted(projects))
    with _PROOF_LOCK:
        fast = watched is not None and proof_key in _CLEAN_PROOFS
    missing_sql = "SELECT count(*) FROM U LEFT JOIN kg_inputs g ON g.input_key=U.k WHERE g.input_key IS NULL OR g.active=0 OR g.fingerprint<>U.fp"
    # U keys are non-null. NOT IN builds an ephemeral membership index instead
    # of SQLite rescanning this UNION-derived table once per cached input.
    obsolete_sql = "SELECT count(*) FROM kg_inputs g WHERE g.active=1 AND g.input_key NOT IN (SELECT k FROM U)"
    missing, obsolete = (0, 0) if fast else db.one(prefix + "SELECT (" + missing_sql + "),(" + obsolete_sql + ")")
    if not fast and watched is not None and not missing and not obsolete:
        with _PROOF_LOCK:
            _CLEAN_PROOFS[proof_key] = True
            _CLEAN_PROOFS.move_to_end(proof_key)
            while len(_CLEAN_PROOFS) > 16:
                _CLEAN_PROOFS.popitem(last=False)
    base["coverage"] = {"requires_sync": bool(missing or obsolete or not state(db, "last_complete_at") or watched is None), "missing_or_stale_inputs": missing, "obsolete_inputs": obsolete,
                        "last_complete_at": state(db, "last_complete_at") or None,
                        "source_validation": "epoch_validated_fingerprints" if fast else "live_fingerprint_scan",
                        "watcher_coverage_complete": watched is not None,
                        "solution_checks": 0, "unverifiable_solutions_skipped": 0, "solution_budget_reached": False}
    signature = fingerprint(options, mode, anchor, pid, sorted(projects), generation, source_stamp)
    # Node canonicalization is performed AFTER current permissions and upstream
    # fingerprints, so an excluded project's contribution cannot poison a public node.
    scope = " AND (n.project_id IS NULL OR n.project_id=:pid)" if pid is not None else ""
    edge_scope = " AND (e.project_id IS NULL OR e.project_id=:pid)" if pid is not None else ""
    params = {"pid": pid, "include_inactive": int(options["include_inactive"])}
    cte = ("WITH L AS MATERIALIZED (SELECT g.* FROM kg_inputs g WHERE g.active=1), " if fast else
           prefix.rstrip() + ", L AS MATERIALIZED (SELECT g.* FROM kg_inputs g JOIN U ON U.k=g.input_key AND U.fp=g.fingerprint WHERE g.active=1), ")
    node_focus = ""
    if mode == "neighbors":
        params["anchor"] = anchor
        cte += "R AS MATERIALIZED (SELECT e.*,L.origin e_origin FROM kg_edges e JOIN L ON L.input_key=e.input_key "
        cte += "WHERE (e.source=:anchor OR e.target=:anchor)" + edge_scope + "), "
        node_focus = " AND n.node_id IN (SELECT :anchor UNION SELECT source FROM R UNION SELECT target FROM R)"
    elif pid is not None:
        suggestion_filter = " AND ep.validation<>'suggested'" if not options["suggestions"] else ""
        direct = "SELECT ep.source FROM kg_edges ep JOIN L lp ON lp.input_key=ep.input_key WHERE ep.project_id=:pid" + suggestion_filter
        direct += " UNION SELECT ep.target FROM kg_edges ep JOIN L lp ON lp.input_key=ep.input_key WHERE ep.project_id=:pid" + suggestion_filter
        node_focus = " AND (n.project_id=:pid OR n.node_id IN (" + direct + "))"
    else:
        selected_kind = options["kind"] if options["kind"] != "all" else "vulnerability" if options["risk"] else None
        if selected_kind:
            params["focused_kind"] = selected_kind
            node_focus = " AND n.kind=:focused_kind"
    active_nodes = (" AND (:include_inactive=1 OR n.origin<>'attack' OR "
                    "(coalesce(json_extract(n.data_json,'$.revoked'),0)=0 AND coalesce(json_extract(n.data_json,'$.deprecated'),0)=0))")
    cte += "C AS MATERIALIZED (SELECT n.*,row_number() OVER(PARTITION BY n.node_id ORDER BY n.rank,n.input_key) rn FROM kg_nodes n JOIN L ON L.input_key=n.input_key WHERE 1=1" + scope + node_focus + active_nodes + "), "
    cte += "N AS MATERIALIZED (SELECT * FROM C WHERE rn=1), EC AS ("
    if mode == "neighbors":
        cte += "SELECT e.*,row_number() OVER(PARTITION BY e.edge_id ORDER BY e.input_key) rn FROM R e"
    else:
        cte += "SELECT e.*,L.origin e_origin,row_number() OVER(PARTITION BY e.edge_id ORDER BY e.input_key) rn "
        cte += "FROM kg_edges e JOIN L ON L.input_key=e.input_key WHERE 1=1" + edge_scope
    cte += "), "
    cte += ("E AS (SELECT e.* FROM EC e JOIN N a ON a.node_id=e.source JOIN N b ON b.node_id=e.target WHERE e.rn=1 "
            "AND (:include_inactive=1 OR e.e_origin<>'attack' OR (coalesce(json_extract(e.data_json,'$.revoked'),0)=0 "
            "AND coalesce(json_extract(e.data_json,'$.deprecated'),0)=0))) ")
    return (cte, params, signature), pid, base


def _cursor(value, signature):
    if value is None:
        return ""
    if not isinstance(value, str) or not value or len(value) > 6000:
        raise ValueError("invalid_graph_cursor")
    try:
        raw = base64.b64decode(value.encode(), altchars=b"-_", validate=True)
        obj = json.loads(raw)
        if (not isinstance(obj, dict) or set(obj) != {"v", "scope", "after"} or obj["v"] != 1
                or not isinstance(obj["after"], str) or len(obj["after"]) > 2000):
            raise ValueError()
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("invalid_graph_cursor") from None
    if obj["scope"] != signature:
        raise ValueError("graph_changed_or_cursor_scope_mismatch_restart")
    return obj["after"]


def _next(signature, after):
    return base64.urlsafe_b64encode(encode({"v": 1, "scope": signature, "after": after}).encode()).decode()


def _rows(db, sql, params):
    # Database's legacy helpers intentionally bind positional tuples. Keep the
    # named bindings local to this SQL-only graph API.
    return db.connection.execute(sql, params).fetchall()


def _one(db, sql, params):
    return db.connection.execute(sql, params).fetchone()


def _filters(options, params, alias="n", *, neighborhood=False):
    clauses = []
    if options["kind"] != "all":
        clauses.append(alias + ".kind=:kind")
        params["kind"] = options["kind"]
    def literal(value):
        return value.casefold().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    if options["query"]:
        clauses.append(f"(kg_fold({alias}.title) LIKE :q ESCAPE '\\' OR kg_fold({alias}.citation) LIKE :q ESCAPE '\\' OR kg_fold({alias}.node_id) LIKE :q ESCAPE '\\')")
        params["q"] = "%" + literal(options["query"]) + "%"
    if options["category"]:
        clauses.append(f"kg_fold({alias}.category) LIKE :category ESCAPE '\\'")
        params["category"] = literal(options["category"]) + "%"
    if options["source"]:
        clauses.append(f"EXISTS(SELECT 1 FROM kg_nodes nx JOIN L lx ON lx.input_key=nx.input_key WHERE nx.node_id={alias}.node_id AND kg_fold(nx.origin)=:origin "
                       "AND (:pid IS NULL OR nx.project_id IS NULL OR nx.project_id=:pid))")
        params["origin"] = options["source"].casefold()
    for key, operator in (("since", ">="), ("until", "<=")):
        if options[key]:
            clauses.append(f"{alias}.updated{operator}:{key}")
            params[key] = options[key]
    if options["risk"]:
        risk = f"json_extract({alias}.data_json,'$.risk')=:risk"
        clauses.append(f"({alias}.kind<>'vulnerability' OR {risk})" if neighborhood else f"({alias}.kind='vulnerability' AND {risk})")
        params["risk"] = options["risk"]
    return " AND ".join(clauses) or "1=1"


def _emit(settings, rows, coverage):
    nodes, processed = [], 0
    for row in rows:
        if row["kind"] == "solution":
            if coverage["solution_checks"] >= 32:
                coverage["solution_budget_reached"] = True
                break
            coverage["solution_checks"] += 1
            data = json.loads(row["data_json"])
            verified, _ = _verified_records(settings, "", None, None, document_id=data["document_id"])
            if not verified:
                coverage["unverifiable_solutions_skipped"] += 1
                processed += 1
                continue
        data = json.loads(row["data_json"])
        if row["kind"] == "review":
            data["effective_state"] = "revoked" if data["revoked_at"] else "expired" if data["expires"] <= datetime.now(timezone.utc).date().isoformat() else "recorded_claim_not_revalidated"
        nodes.append({"id": row["node_id"], "kind": row["kind"], "title": row["title"], "source": row["origin"],
                      "category": row["category"], "updated": row["updated"], "citation": row["citation"],
                      "contributor_project_id": row["project_id"], "data": data})
        processed += 1
    return nodes, processed


def graph_page(settings: Settings, *, kind="all", project=None, query="", source=None, category=None,
               risk=None, since=None, until=None, limit=50, cursor=None, suggestions=False, include_inactive=False) -> dict:
    options = _options(kind, query, source, category, risk, since, until, limit, suggestions, include_inactive)
    _project_argument(project)
    if not settings.database_path.is_file():
        return _empty(reason="index_unavailable")
    with _read(settings) as db:
        ctx, pid, result = _context(db, settings, project, options, "page")
        if ctx is None or limit == 0:
            return result
        sql, params, signature = ctx
        after = _cursor(cursor, signature)
        where = _filters(options, params)
        if pid is not None:
            suggestion_filter = " AND e.validation<>'suggested'" if not suggestions else ""
            where += " AND (n.project_id=:pid OR EXISTS(SELECT 1 FROM E e WHERE e.project_id=:pid" + suggestion_filter + " AND (e.source=n.node_id OR e.target=n.node_id)))"
        params.update(after=after, page_limit=limit + 1)
        filtered = sql.rstrip() + ", F AS MATERIALIZED (SELECT n.* FROM N n WHERE " + where + ") "
        rows = _rows(db, filtered + "SELECT p.*,(SELECT count(*) FROM F) candidate_count FROM (SELECT 1) seed "
                     "LEFT JOIN (SELECT * FROM F WHERE node_id>:after ORDER BY node_id LIMIT :page_limit) p ON 1 ORDER BY p.node_id", params)
        result["total_candidates"] = rows[0]["candidate_count"]
        rows = [r for r in rows if r["node_id"] is not None]
        nodes, consumed = _emit(settings, rows[:limit], result["coverage"])
        result["nodes"] = nodes
        result["has_more"] = len(rows) > limit or consumed < len(rows[:limit])
        if result["has_more"] and consumed:
            result["next_cursor"] = _next(signature, rows[consumed - 1]["node_id"])
        result["count_basis"] = "candidate nodes before live solution verification; paginate to reach the full graph"
        return result


def graph_neighbors(settings: Settings, node_id: str, *, kind="all", query="", category=None, project=None, source=None, risk=None, since=None, until=None,
                    limit=50, cursor=None, suggestions=False, include_inactive=False) -> dict:
    if not isinstance(node_id, str) or not 1 <= len(node_id) <= 2000 or any(ord(c) < 32 for c in node_id):
        raise ValueError("invalid_graph_node_identifier")
    options = _options(kind, query, source, category, risk, since, until, limit, suggestions, include_inactive)
    _project_argument(project)
    if not settings.database_path.is_file():
        return {**_empty(reason="index_unavailable"), "anchor_visible": False, "hop_depth": 1}
    with _read(settings) as db:
        ctx, _, result = _context(db, settings, project, options, "neighbors", node_id)
        result.update(anchor_visible=False, hop_depth=1)
        if ctx is None or limit == 0:
            return result
        sql, params, signature = ctx
        after = _cursor(cursor, signature)
        params["anchor"] = node_id
        anchor = _one(db, sql + "SELECT * FROM N WHERE node_id=:anchor", params)
        if anchor is None:
            return result
        anchor_nodes, _ = _emit(settings, [anchor], result["coverage"])
        if not anchor_nodes:
            return result
        result["anchor_visible"] = True
        where = _filters(options, params, neighborhood=True)
        clauses = ["(e.source=:anchor OR e.target=:anchor)", "e.edge_id>:after", where]
        if not suggestions:
            clauses.append("e.validation<>'suggested'")
        if source:
            clauses.append("kg_fold(e.e_origin)=:origin")
        params.update(after=after, page_limit=limit + 1)
        opposite = "CASE WHEN e.source=:anchor THEN e.target ELSE e.source END"
        rows = _rows(db, sql + "SELECT e.* FROM E e JOIN N n ON n.node_id=" + opposite + " WHERE " + " AND ".join(clauses) +
                        " ORDER BY e.edge_id LIMIT :page_limit", params)
        selected = rows[:limit]
        identities = sorted({r["target"] if r["source"] == node_id else r["source"] for r in selected})
        neighbor_rows = []
        if identities:
            slots = ",".join(":n" + str(i) for i in range(len(identities)))
            params.update({"n" + str(i): value for i, value in enumerate(identities)})
            neighbor_rows = _rows(db, sql + f"SELECT * FROM N WHERE node_id IN ({slots}) ORDER BY node_id", params)
        others, _ = _emit(settings, neighbor_rows, result["coverage"])
        result["nodes"] = anchor_nodes + others
        visible = {n["id"] for n in result["nodes"]}
        for edge in selected:
            if edge["source"] in visible and edge["target"] in visible:
                validation = edge["validation"]
                classification = "suggested" if validation == "suggested" else "reviewed_claim" if validation == "reviewed_claim" else "inferred" if validation.startswith("inferred") else "explicit"
                result["edges"].append({"id": edge["edge_id"], "source": edge["source"], "target": edge["target"],
                                        "relation_type": edge["relation"], "kind": classification, "validation": validation,
                                        "citation": edge["citation"], "data": json.loads(edge["data_json"])})
        result["has_more"] = len(rows) > limit
        if result["has_more"] and selected:
            result["next_cursor"] = _next(signature, selected[-1]["edge_id"])
        result["scope_note"] += " One hop per paginated request; a client can expand returned neighbors for two hops with its own node/request budget."
        return result
