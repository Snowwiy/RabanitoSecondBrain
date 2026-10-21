from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .cadence import run_index_watch
from .capabilities import build_link_suggestions, collect_audit, level_up, write_audit
from .changes import recent_document_changes, resolve_active_project_root
from .config import default_config_path, load_settings, save_settings
from .cyber import cyber_status, get_vulnerability, search_vulnerabilities, sync_source
from .cyber.store import vulnerability_context
from .cyber.cadence import run_cyber_watch
from .db import Database, restore_database
from .decisions import add_memory_record, list_memory_records
from .documented_draft import preview_from_stream, read_draft_payload
from .documented_store import save_documented_experience
from .graph import graph_edges_for_nodes
from .indexer import _index_lock, discover_projects, project_inventory, index_all, prune_inactive_search_payload
from .interview import conduct_interview
from .onboard import approve_source, preview_source
from .search import (
    SCAN_SOURCE_SUMMARY_MAX_CHARS, get_document, project_scan_summary, related_documents,
    retrieve_context, search_documents, stats,
)
from .server import serve_dashboard
from .security import get_security_entry, index_security_catalog, search_security, security_context
from .public_graph import public_graph
from .dependencies import inspect_manifest, inspect_sbom
from .dependency_memory import export_openvex, review_inventory, reviewed_inventory, revoke_review, snapshot_inventory
from .coding_memory import recurring_patterns, similar_experiences
from .documented_memory import documented_experiences
from .knowledge_graph import graph_neighbors, graph_page, sync_graph
from .cyber.pending import discard_pending_window
from .cyber.history import vulnerability_history
from .cyber.providers import SOURCES
from .utils import iso_now, safe_relative, write_json_atomic
from .visibility import project_visibility_sql, register_project_visibility


def _json(value: Any) -> None:
    rendered = json.dumps(value, ensure_ascii=False, indent=2, default=str)
    encoding = getattr(sys.stdout, "encoding", None)
    if encoding:
        try:
            rendered.encode(encoding)
        except (LookupError, UnicodeEncodeError):
            # Keep JSON valid and readable on Windows consoles whose active
            # code page cannot represent every character in indexed notes.
            rendered = json.dumps(value, ensure_ascii=True, indent=2, default=str)
    sys.stdout.write(rendered + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rabanito", description="Rabanito Second Brain: local index, retrieval, graph and maintenance tools")
    parser.add_argument("--config", type=Path, default=None, help=f"settings JSON (default: {default_config_path()})")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    attack = sub.add_parser("attack", help="commit-pinned STIX capture, explicit indexing and offline cited retrieval")
    attack_actions = attack.add_subparsers(dest="attack_action", required=True)
    attack_capture = attack_actions.add_parser("capture", help="download one reviewed commit-pinned domain plus its license")
    attack_capture.add_argument("--domain", choices=["enterprise-attack", "mobile-attack", "ics-attack"], required=True)
    attack_capture.add_argument("--release", required=True)
    attack_capture.add_argument("--commit", required=True, help="reviewed official repository commit, 40 lowercase hex")
    attack_capture.add_argument("--blob", required=True, help="expected Git blob SHA from official file metadata")
    attack_capture.add_argument("--bytes", type=int, required=True, dest="capture_bytes")
    attack_inspect = attack_actions.add_parser("inspect", help="verify captured bytes and complete collection offline")
    attack_inspect.add_argument("--capture", required=True)
    attack_context = attack_actions.add_parser("context", help="bounded cited excerpts from one local capture; no network")
    attack_context.add_argument("query")
    attack_context.add_argument("--capture", help="optional quarantine scan instead of the published SQLite index")
    attack_context.add_argument("--domain", choices=["enterprise-attack", "mobile-attack", "ics-attack"])
    attack_context.add_argument("--release", help="published version or exact release ID; cannot combine with --capture")
    attack_context.add_argument("--kind")
    attack_context.add_argument("--include-inactive", action="store_true")
    attack_context.add_argument("--limit", type=int, default=5)
    attack_context.add_argument("--max-chars", type=int, default=6000)
    attack_index = attack_actions.add_parser("index", help="publish one verified local capture atomically; no network")
    attack_index.add_argument("--capture", required=True)
    for action in ("status", "search", "get", "relations", "history"):
        command = attack_actions.add_parser(action)
        command.add_argument("--domain", choices=["enterprise-attack", "mobile-attack", "ics-attack"], default="enterprise-attack")
        if action == "search":
            command.add_argument("query", nargs="?", default="")
        elif action in {"get", "relations", "history"}:
            command.add_argument("identifier")
        if action in {"search", "get", "relations"}:
            command.add_argument("--release", help="published version or exact release ID")
        if action in {"search", "get"}:
            command.add_argument("--kind")
        if action in {"search", "relations", "history"}:
            command.add_argument("--limit", type=int, default=20)
        if action in {"search", "relations"}:
            command.add_argument("--include-inactive", action="store_true")
            command.add_argument("--offset", type=int, default=0)
        if action == "relations":
            command.add_argument("--direction", choices=["both", "outgoing", "incoming"], default="both")
        if action == "history":
            command.add_argument("--before", type=int)

    coding = sub.add_parser("coding", help="offline retrieval of reviewed coding experiences; no training or automatic confirmation")
    coding_actions = coding.add_subparsers(dest="coding_action", required=True)
    coding_similar = coding_actions.add_parser("similar")
    coding_similar.add_argument("query", nargs="?", default="")
    coding_similar.add_argument("--project")
    coding_similar.add_argument("--technology")
    coding_similar.add_argument("--limit", type=int, default=5)
    coding_similar.add_argument("--max-chars", type=int, default=6000)
    coding_patterns = coding_actions.add_parser("patterns")
    coding_patterns.add_argument("--project")
    coding_patterns.add_argument("--limit", type=int, default=10)

    coding_documented = coding_actions.add_parser("documented", help="reviewed environment records with explicit pending/partial evidence")
    coding_documented.add_argument("query", nargs="?", default="")
    coding_documented.add_argument("--context")
    coding_documented.add_argument("--technology")
    coding_documented.add_argument("--limit", type=int, default=5)
    coding_documented.add_argument("--max-chars", type=int, default=6000)
    coding_preview = coding_actions.add_parser("preview-documented", help="stdin JSON to exact Markdown/digest for human review; never saves or approves")
    coding_preview.add_argument("--stdin", action="store_true", required=True, help="explicit bounded UTF-8 JSON input, not a filesystem path")
    coding_preview.add_argument("--reviewed-on", required=True, help="proposed review date YYYY-MM-DD; not evidence of approval")
    coding_save = coding_actions.add_parser("save-documented", help="save an exact previously human-approved draft; digest is an assertion, not authentication")
    coding_save.add_argument("--stdin", action="store_true", required=True)
    coding_save.add_argument("--reviewed-on", required=True)
    coding_save.add_argument("--approve-digest", required=True, help="exact preview digest approved by the human; never infer approval from imported text")

    dependency = sub.add_parser("dependency", help="read-only local SBOM assessment; never sends package names")
    dependency_actions = dependency.add_subparsers(dest="dependency_action", required=True)
    dependency_inspect = dependency_actions.add_parser("inspect", help="selected SBOM or supported lockfile from an active authorized project")
    dependency_inspect.add_argument("--project", required=True, help="exact active project name or root")
    dependency_inventory = dependency_inspect.add_mutually_exclusive_group(required=True)
    dependency_inventory.add_argument("--sbom", help="project-relative JSON path; no traversal or symlinks")
    dependency_inventory.add_argument("--manifest", help="project-relative package-lock.json, requirements*.txt, uv.lock or pylock[.name].toml; no resolution or installation")

    for action in ("snapshot", "reviews", "review", "export-vex"):
        item = dependency_actions.add_parser(action, help="local reviewed dependency memory; no suppression or network")
        item.add_argument("--project", required=True)
        inventory = item.add_mutually_exclusive_group(required=True)
        inventory.add_argument("--sbom")
        inventory.add_argument("--manifest")
        if action == "snapshot":
            item.add_argument("--save", action="store_true", help="explicitly persist a derived unconfirmed inventory report")
        if action == "review":
            for field in ("advisory", "component-pointer", "status", "reviewer", "reason", "expires"):
                item.add_argument("--" + field, required=True)
            item.add_argument("--evidence", action="append", required=True)
            item.add_argument("--justification", default="")
            item.add_argument("--impact", default="")
            item.add_argument("--action", default="")
            item.add_argument("--approve-digest", help="only after a human approved this exact preview digest")
    revoke = dependency_actions.add_parser("revoke", help="preview a review revocation; explicit digest required to write")
    for field in ("project", "review-id", "reviewer", "reason"):
        revoke.add_argument("--" + field, required=True)
    revoke.add_argument("--approve-digest")

    security = sub.add_parser("security", help="local cited standards, controls and Zero Trust knowledge")
    security_actions = security.add_subparsers(dest="security_action", required=True)
    security_index = security_actions.add_parser("index", help="index curated and registered local catalogs; no network")
    security_index.add_argument("--asvs-capture", help="explicitly register a verified ASVS5.0.0 capture")
    security_index.add_argument("--replace-asvs", action="store_true", help="explicitly replace a different snapshot of the same ASVS edition, with backup")
    security_actions.add_parser("imports", help="metadata of registered licensed catalogs, not their full content")
    asvs = sub.add_parser("asvs", help="explicit official ASVS5.0.0 capture and offline inspection")
    asvs_actions = asvs.add_subparsers(dest="asvs_action",required=True)
    asvs_capture = asvs_actions.add_parser("capture")
    for name in ('commit','blob','license-blob'):
        asvs_capture.add_argument('--'+name,required=True)
    for name in ('bytes','license-bytes'):
        asvs_capture.add_argument('--'+name,type=int,required=True)
    asvs_inspect = asvs_actions.add_parser('inspect')
    asvs_inspect.add_argument('--capture',required=True)
    security_get = security_actions.add_parser("get")
    security_get.add_argument("identifier")
    security_search = security_actions.add_parser("search")
    security_search.add_argument("query", nargs="?", default="")
    security_search.add_argument("--framework")
    security_search.add_argument("--release", help="exact reviewed release identifier, not a latest-version lookup")
    security_search.add_argument("--kind", choices=["framework", "control", "concept", "reference"])
    security_search.add_argument("--status", choices=["published", "historical", "draft", "rolling"])
    security_search.add_argument("--limit", type=int, default=20)
    security_search.add_argument("--offset", type=int, default=0)
    security_search.add_argument("--level",type=int,choices=[1,2,3],help="exact publisher ASVS level, not an assessment profile")
    security_context_parser = security_actions.add_parser("context")
    security_context_parser.add_argument("query")
    security_context_parser.add_argument("--max-chars", type=int, default=6000)
    security_context_parser.add_argument("--limit", type=int, default=8)
    security_context_parser.add_argument("--framework")
    security_context_parser.add_argument("--release")
    security_context_parser.add_argument("--kind", choices=["framework", "control", "concept", "reference"])
    security_context_parser.add_argument("--status", choices=["published", "historical", "draft", "rolling"])
    security_context_parser.add_argument("--level",type=int,choices=[1,2,3])

    cyber = sub.add_parser("cyber", help="public vulnerability knowledge; queries work offline")
    cyber_actions = cyber.add_subparsers(dest="cyber_action", required=True)
    cyber_pending = cyber_actions.add_parser("pending", help="inspect unpublished NVD staging; explicit backed-up discard for recovery")
    cyber_pending.add_argument("--discard", action="store_true")
    cyber_pending.add_argument("--approve", action="store_true")
    cyber_actions.add_parser("status", help="connector state, freshness and local counts")
    history = cyber_actions.add_parser("history", help="bounded observed revisions; never invents pre-activation history")
    history.add_argument("identifier")
    history.add_argument("--source", choices=SOURCES)
    history.add_argument("--limit", type=int, default=20)
    history.add_argument("--before", type=int)
    cyber_watch = cyber_actions.add_parser("watch", help="opt-in foreground public-source updates; disabled by default")
    cyber_watch.add_argument("--start", action="store_true", help="explicitly start foreground cadence without changing settings")
    cyber_watch.add_argument("--cycles", type=int)
    cyber_sync = cyber_actions.add_parser("sync", help="explicit bounded public GET requests; no local notes sent")
    cyber_sync.add_argument("--source", required=True, choices=SOURCES)
    cyber_sync.add_argument("--month", help="MSRC only: explicit public month, e.g. 2026-Oct")
    cyber_sync.add_argument("--capture", help="MSRC only: validated quarantine manifest basename")
    cyber_sync.add_argument("--id", action="append", default=None, help="public CVE/advisory identifier, repeatable")
    cyber_get = cyber_actions.add_parser("get", help="retrieve complete local observations with provenance")
    cyber_get.add_argument("identifier")
    cyber_search = cyber_actions.add_parser("search", help="local FTS, explicit evidence and compact results")
    cyber_search.add_argument("query", nargs="?", default="")
    cyber_search.add_argument("--source", choices=SOURCES)
    cyber_search.add_argument("--kev", action="store_true")
    cyber_search.add_argument("--limit", type=int, default=20)
    cyber_search.add_argument("--offset", type=int, default=0)
    cyber_search.add_argument("--since", help="ISO date: last modification at provider")
    cyber_search.add_argument("--min-epss", type=float)
    cyber_search.add_argument("--sort", choices=["risk", "modified", "published"], default="risk")
    cyber_context = cyber_actions.add_parser("context", help="bounded offline vulnerability fragments with official citations")
    cyber_context.add_argument("query")
    cyber_context.add_argument("--source", choices=SOURCES, help="return fragments only from this provider")
    cyber_context.add_argument("--max-chars", type=int, default=6000)
    cyber_context.add_argument("--limit", type=int, default=5)

    index = sub.add_parser("index", help="incrementally index configured sources")
    index.add_argument("--force", action="store_true", help="re-read unchanged files")

    prune_cache = sub.add_parser(
        "prune-search-cache", help="preview or explicitly purge text cache for deleted/skipped documents",
    )
    prune_cache.add_argument("--apply", action="store_true", help="create a verified backup, then purge inactive search text")
    prune_cache.add_argument("--yes", action="store_true", help="confirm the explicitly destructive --apply operation")

    watch = sub.add_parser("watch", help="opt-in foreground index loop; no service or scheduled task is installed")
    watch.add_argument("--interval-minutes", type=int, default=None, help="sync interval (5 to 10080 minutes; defaults to config)")
    watch.add_argument("--cycles", type=int, default=None, help="stop after this many scans; omit to run until Ctrl+C")

    search = sub.add_parser("search", help="search documents with SQLite FTS5")
    search.add_argument("query")
    search.add_argument("--limit", type=int)
    search.add_argument("--source")
    search.add_argument("--category")
    search.add_argument("--project")
    search.add_argument("--tag", help="exact indexed tag; accepts an optional leading #")

    context = sub.add_parser("context", help="retrieve bounded fragments with citations")
    context.add_argument("query")
    context.add_argument("--limit", type=int)
    context.add_argument("--max-chars", type=int)
    context.add_argument("--source")
    context.add_argument("--category")
    context.add_argument("--project")
    context.add_argument("--tag", help="exact indexed tag; accepts an optional leading #")

    sub.add_parser("stats", help="show index statistics")
    changes = sub.add_parser("changes", help="show recent indexed document changes")
    changes.add_argument("--limit", type=int, default=20)
    changes.add_argument("--project", help="active project name or exact root path")
    audit = sub.add_parser("audit", help="audit coverage, duplicates, links and stale content")
    audit.add_argument("--write", action="store_true", help="write a dated Markdown and JSON report")
    sub.add_parser("link", help="create explicit-link inventory and non-factual link suggestions")
    sub.add_parser("level-up", help="produce concrete recommendations from the latest audit")

    onboard = sub.add_parser("onboard", help="preview or approve a local knowledge source")
    onboard.add_argument("--path", type=Path, required=True)
    onboard.add_argument("--kind", default="local")
    onboard.add_argument("--name")
    onboard.add_argument("--approve", action="store_true")

    interview = sub.add_parser("interview", help="guided capture; writes only after explicit APROBAR")
    interview.add_argument("--topic", required=True)

    dashboard = sub.add_parser("dashboard", help="serve the local dashboard on loopback")
    dashboard.add_argument("--host", default=None)
    dashboard.add_argument("--port", type=int, default=None)

    doc = sub.add_parser("doc", help="show one indexed document and its relationships")
    doc.add_argument("document_id", type=int)
    related = sub.add_parser("related", help="show explicit and suggested relationships")
    related.add_argument("document_id", type=int)

    projects = sub.add_parser("projects", help="discover project metadata without indexing source code")
    projects.add_argument("--json", action="store_true")
    project_policy = projects.add_mutually_exclusive_group()
    project_policy.add_argument("--exclude", help="exclude a project name or path and synchronize the index")
    project_policy.add_argument("--include", help="remove a project exclusion and synchronize the index")

    decision = sub.add_parser("decision", help="create or list traceable project memory records")
    decision_actions = decision.add_subparsers(dest="decision_action", required=True)
    decision_add = decision_actions.add_parser("add", help="add a reviewed decision/fact/proposal/hypothesis")
    decision_add.add_argument("--project", required=True, help="exact project name or project root path")
    decision_add.add_argument("--problem", required=True)
    decision_add.add_argument("--statement", required=True, help="decision, fact, proposal, or hypothesis")
    decision_add.add_argument("--record-type", choices=["decision", "fact", "proposal", "hypothesis"], default="decision")
    decision_add.add_argument("--status", choices=["proposed", "confirmed", "rejected", "superseded"], default="proposed")
    decision_add.add_argument("--reason", default="")
    decision_add.add_argument("--alternative", action="append", default=[])
    decision_add.add_argument("--component", action="append", default=[])
    decision_add.add_argument("--technology", action="append", default=[])
    decision_add.add_argument("--test", action="append", default=[])
    decision_add.add_argument("--result", default="", help="observed outcome; do not infer it from a test command")
    decision_add.add_argument(
        "--evidence", action="append", default=[],
        help="local path or project:/projects:/obsidian:/internal: reference; projects: explicitly cites another project",
    )
    decision_add.add_argument("--validation", choices=["pending", "passed", "failed", "not_applicable"], default="pending")
    decision_add.add_argument("--date", help="record date YYYY-MM-DD; defaults to today")
    decision_list = decision_actions.add_parser("list", help="list indexed memory records")
    decision_list.add_argument("--project")
    decision_list.add_argument("--limit", type=int, default=50)
    decision_list.add_argument("--record-type", choices=["decision", "fact", "proposal", "hypothesis"])
    decision_list.add_argument("--status", choices=["proposed", "confirmed", "rejected", "superseded"])
    decision_list.add_argument("--query", default="", help="search indexed decision content with local FTS")

    graph = sub.add_parser("graph", help="export graph data from the real index")
    graph.add_argument("--limit", type=int, default=500)
    graph.add_argument("--suggestions", action="store_true")
    graph.add_argument("--domain", choices=["documents", "cyber", "security"], default="documents")
    graph.add_argument("--query", default="")

    graph_sync = sub.add_parser("graph-sync", help="explicitly update the incremental graph projection; never changes original sources")
    graph_sync.add_argument("--max-inputs", type=int, default=1000)
    graph_sync.add_argument("--max-bytes", type=int, default=32 * 1024 * 1024)
    knowledge = sub.add_parser("knowledge-graph", help="read-only typed graph with keyset pagination and cited neighbors")
    graph_actions = knowledge.add_subparsers(dest="graph_action", required=True)
    for action in ("page", "neighbors"):
        command = graph_actions.add_parser(action)
        if action == "neighbors":
            command.add_argument("node_id")
        command.add_argument("--suggestions", action="store_true")
        command.add_argument("--include-inactive", action="store_true", help="include historical revoked/deprecated ATT&CK objects and SROs")
        for field in ("kind", "query", "source", "category", "project", "risk", "since", "until", "cursor"):
            command.add_argument("--" + field, default="all" if field == "kind" else "" if field == "query" else None)
        command.add_argument("--limit", type=int, default=50)

    backup = sub.add_parser("backup", help="create a local SQLite backup")
    backup.add_argument("--path", type=Path, default=None)
    restore = sub.add_parser("restore", help="restore a local SQLite backup; explicit --yes required")
    restore.add_argument("path", type=Path)
    restore.add_argument("--yes", action="store_true")
    return parser


def _graph_export(settings, limit: int, suggestions: bool) -> dict[str, Any]:
    limit = min(max(int(limit), 0), 2000)
    with Database(settings.database_path, query_only=True, empty_if_missing=True) as db:
        register_project_visibility(db, settings)
        total_matches = int(db.one(
            "SELECT COUNT(*) AS total FROM documents d WHERE d.status='active' AND "
            + project_visibility_sql("d")
        )["total"])
        nodes = db.query(
            "SELECT d.document_id,d.title,d.source_kind,d.category,d.project_name,d.project_root_path,d.relative_path,d.mtime_iso "
            "FROM documents d WHERE d.status='active' AND " + project_visibility_sql("d") +
            " ORDER BY d.document_id LIMIT ?", (limit,),
        )
        node_ids = {int(row["document_id"]) for row in nodes}
        edges = graph_edges_for_nodes(db, node_ids, suggestions, include_suggestion_scores=False)
    return {
        "nodes": [dict(row) for row in nodes],
        "edges": edges,
        "node_limit": limit,
        "total_matches": total_matches,
        "truncated": total_matches > limit,
    }


def main(argv: list[str] | None = None) -> None:
    # The CLI contract is UTF-8 for agent/PowerShell pipes, independent of the
    # Windows ANSI code page. Respect caller-owned streams used by embedders.
    if sys.stdout is sys.__stdout__ and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    settings = load_settings(args.config)
    if args.command == "coding":
        try:
            if args.coding_action == "preview-documented":
                result = preview_from_stream(getattr(sys.stdin, "buffer", sys.stdin), reviewed_on=args.reviewed_on)
            elif args.coding_action == "save-documented":
                result = save_documented_experience(settings, read_draft_payload(getattr(sys.stdin, "buffer", sys.stdin)),
                    reviewed_on=args.reviewed_on, approve_digest=args.approve_digest, config_path=args.config)
            elif args.coding_action == "documented":
                result = documented_experiences(settings, args.query, context=args.context, technology=args.technology,
                                                limit=args.limit, max_chars=args.max_chars)
            else:
                result = (similar_experiences(settings, args.query, project=args.project, technology=args.technology,
                                          limit=args.limit, max_chars=args.max_chars) if args.coding_action == "similar" else
                      recurring_patterns(settings, project=args.project, limit=args.limit))
            _json(result)
            if args.coding_action == "save-documented" and not result['indexed']:
                raise SystemExit(2)
        except ValueError as exc:
            message = str(exc)
            if args.coding_action == "save-documented" and not re.fullmatch('[a-z_]{1,100}', message):
                message = 'invalid_documented_save_request'
            _json({"error": message})
            raise SystemExit(1) from None
        except (OSError, sqlite3.Error):
            if args.coding_action != "save-documented":
                raise
            _json({'error': 'documented_write_unavailable'})
            raise SystemExit(1) from None
    elif args.command == "dependency":
        try:
            if args.dependency_action == "revoke":
                result = revoke_review(settings, args.project, args.review_id, reviewer=args.reviewer,
                                       reason=args.reason, approve_digest=args.approve_digest)
            elif args.dependency_action == "inspect":
                result = inspect_sbom(settings, args.project, args.sbom) if args.sbom else inspect_manifest(settings, args.project, args.manifest)
            else:
                relative, kind = (args.sbom, "sbom") if args.sbom else (args.manifest, "manifest")
                if args.dependency_action == "snapshot":
                    result = snapshot_inventory(settings, args.project, relative, kind=kind, save=args.save)
                elif args.dependency_action == "reviews":
                    result = reviewed_inventory(settings, args.project, relative, kind=kind)
                elif args.dependency_action == "export-vex":
                    result = export_openvex(settings, args.project, relative, kind=kind)
                else:
                    result = review_inventory(settings, args.project, relative, kind=kind, advisory=args.advisory,
                        component_pointer=args.component_pointer, status=args.status, reviewer=args.reviewer,
                        reason=args.reason, expires=args.expires, evidence=args.evidence, justification=args.justification,
                        impact=args.impact, action=args.action, approve_digest=args.approve_digest)
            _json(result)
        except (ValueError, OSError, sqlite3.Error, TimeoutError) as exc:
            _json({"error": str(exc) if isinstance(exc, ValueError) else "dependency_operation_failed"})
            raise SystemExit(1) from None
    elif args.command == "attack":
        from .attack import capture_context, inspect_capture
        from .attack_capture import capture_release
        from .attack_store import index_capture
        from .attack_query import attack_context, search_attack, get_attack_object, attack_status, attack_relations, attack_history
        from .cyber.transport import FetchError
        try:
            if args.attack_action == "capture":
                _json(capture_release(settings, args.domain, args.release, args.commit, args.blob, args.capture_bytes))
            elif args.attack_action == "inspect":
                _json(inspect_capture(settings, args.capture))
            elif args.attack_action == "index":
                _json(index_capture(settings, args.capture))
            elif args.attack_action == "status":
                _json(attack_status(settings, domain=args.domain))
            elif args.attack_action == "get":
                _json(get_attack_object(settings, args.identifier, domain=args.domain, release=args.release, kind=args.kind))
            elif args.attack_action == "search":
                _json(search_attack(settings, args.query, domain=args.domain, release=args.release, kind=args.kind,
                                    include_inactive=args.include_inactive, limit=args.limit, offset=args.offset))
            elif args.attack_action == "relations":
                _json(attack_relations(settings, args.identifier, domain=args.domain, release=args.release,
                    direction=args.direction, include_inactive=args.include_inactive, limit=args.limit, offset=args.offset))
            elif args.attack_action == "history":
                _json(attack_history(settings, args.identifier, domain=args.domain, limit=args.limit, before=args.before))
            elif args.capture:
                if args.domain is not None or args.release is not None:
                    raise ValueError("attack_capture_context_cannot_select_published_release")
                _json(capture_context(settings, args.capture, args.query, kind=args.kind, include_inactive=args.include_inactive,
                                     limit=args.limit, max_chars=args.max_chars))
            else:
                _json(attack_context(settings, args.query, domain=args.domain or "enterprise-attack", release=args.release,
                    kind=args.kind, include_inactive=args.include_inactive, limit=args.limit, max_chars=args.max_chars))
        except (ValueError, OSError, FetchError, sqlite3.Error, TimeoutError) as exc:
            _json({"error": str(exc) if isinstance(exc, (ValueError, FetchError)) else "attack_operation_failed",
                   **({"status": exc.status, "retry_after": exc.retry_after} if isinstance(exc, FetchError) else {})})
            raise SystemExit(1) from None
    elif args.command == 'asvs':
        from .asvs_capture import capture,read_capture
        from .asvs import normalize
        from .cyber.transport import FetchError
        try:
            if args.asvs_action=='capture':
                _json(capture(settings,args.commit,args.blob,args.bytes,args.license_blob,args.license_bytes))
            else:
                raw,meta,_=read_capture(settings,args.capture)
                _json({'source_dataset':meta,'coverage':normalize(raw)['coverage'],'requests':0,'database_written':False})
        except (ValueError,OSError,FetchError) as exc:
            _json({'error':str(exc) if isinstance(exc,(ValueError,FetchError)) else 'asvs_operation_failed'})
            raise SystemExit(1) from None
    elif args.command == "security":
        if args.security_action == "index":
            try:
                _json(index_security_catalog(settings,asvs_capture=args.asvs_capture,replace_asvs=args.replace_asvs))
            except (ValueError,OSError,sqlite3.Error,TimeoutError) as exc:
                _json({'error':str(exc) if isinstance(exc,ValueError) else 'security_index_failed'})
                raise SystemExit(1) from None
        elif args.security_action == 'imports':
            from .security_imports import summaries
            try:
                if not settings.database_path.is_file():
                    _json({'imports':[]})
                else:
                    with Database(settings.database_path,read_only=True) as db:
                        _json({'imports':summaries(db)})
            except (ValueError,OSError,sqlite3.Error) as exc:
                _json({'error':str(exc) if isinstance(exc,ValueError) else 'security_import_status_failed'})
                raise SystemExit(1) from None
        elif args.security_action == "get":
            _json(get_security_entry(settings, args.identifier) or {"error": "not found locally"})
        elif args.security_action == "context":
            _json(security_context(settings, args.query, max_chars=args.max_chars, limit=args.limit, framework=args.framework,
                                   kind=args.kind, edition_status=args.status, release=args.release,level=args.level))
        else:
            _json(search_security(settings, args.query, framework=args.framework, kind=args.kind, edition_status=args.status,
                                  release=args.release, limit=args.limit, offset=args.offset,level=args.level))
    elif args.command == "cyber":
        if args.cyber_action == "pending":
            if args.approve and not args.discard:
                raise SystemExit("Use --discard --approve together; without them this command only previews.")
            _json(discard_pending_window(settings, approve=args.discard and args.approve))
        elif args.cyber_action == "status":
            _json(cyber_status(settings))
        elif args.cyber_action == "history":
            try:
                _json(vulnerability_history(settings, args.identifier, source=args.source, limit=args.limit, before=args.before))
            except (ValueError, OSError, sqlite3.Error) as exc:
                _json({"error": str(exc) if isinstance(exc, ValueError) else "cyber_history_unavailable"})
                raise SystemExit(1) from None
        elif args.cyber_action == "watch":
            result = run_cyber_watch(settings, start=args.start, cycles=args.cycles)
            _json(result)
            if result["status"] == "partial":
                raise SystemExit(1)
        elif args.cyber_action == "sync":
            result = sync_source(settings, args.source, args.id, month=args.month, capture_manifest=args.capture)
            _json(result)
            if result["status"] in {"error", "partial", "interrupted", "deferred"}:
                raise SystemExit(1)
        elif args.cyber_action == "get":
            _json(get_vulnerability(settings, args.identifier) or {"error": "not found locally"})
        elif args.cyber_action == "context":
            _json(vulnerability_context(settings, args.query, max_chars=args.max_chars, limit=args.limit, source=args.source))
        else:
            _json(search_vulnerabilities(settings, args.query, source=args.source, kev_only=args.kev,
                                         limit=args.limit, offset=args.offset, since=args.since, min_epss=args.min_epss, sort=args.sort))
    elif args.command == "index":
        _json(index_all(settings, force=args.force))
    elif args.command == "prune-search-cache":
        if args.apply and not args.yes:
            raise SystemExit("La purga modifica caché derivada y crea un respaldo; repite con --apply --yes tras revisar la vista previa.")
        if args.yes and not args.apply:
            raise SystemExit("--yes solo se admite junto con --apply.")
        _json(prune_inactive_search_payload(settings, apply=args.apply))
    elif args.command == "watch":
        try:
            run_index_watch(settings, args.interval_minutes, args.cycles)
        except ValueError as exc:
            raise SystemExit(str(exc)) from None
    elif args.command == "search":
        _json(search_documents(settings, args.query, args.limit, args.source, args.category, args.project, args.tag))
    elif args.command == "context":
        _json(retrieve_context(settings, args.query, args.limit, args.max_chars, args.source, args.category, args.project, args.tag))
    elif args.command == "stats":
        result = stats(settings, latest_scan_source_summary_limit=SCAN_SOURCE_SUMMARY_MAX_CHARS + 1)
        latest_scan = result.get("latest_scan")
        result["latest_scan"] = project_scan_summary(latest_scan) if isinstance(latest_scan, dict) else None
        _json(result)
    elif args.command == "changes":
        try:
            project_root = resolve_active_project_root(settings, args.project) if args.project else None
            _json({"changes": recent_document_changes(settings, args.limit, project_root)})
        except ValueError as exc:
            raise SystemExit(str(exc)) from None
    elif args.command == "audit":
        _json(write_audit(settings, config_path=args.config or default_config_path(settings.root)) if args.write else collect_audit(settings))
    elif args.command == "link":
        _json(build_link_suggestions(settings))
    elif args.command == "level-up":
        _json(level_up(settings, config_path=args.config or default_config_path(settings.root)))
    elif args.command == "onboard":
        result = approve_source(settings, args.path, args.kind, args.name) if args.approve else preview_source(settings, args.path, args.kind)
        _json(result)
    elif args.command == "interview":
        result = conduct_interview(settings, args.topic, config_path=args.config or default_config_path(settings.root))
        if result.get("approved"):
            _json({"interview": result, "index": index_all(settings)})
        else:
            _json({"interview": result})
    elif args.command == "dashboard":
        serve_dashboard(settings, args.host, args.port)
    elif args.command == "doc":
        result = get_document(settings, args.document_id)
        _json(result or {"error": "not found"})
    elif args.command == "related":
        _json(related_documents(settings, args.document_id))
    elif args.command == "projects":
        if args.exclude:
            value = args.exclude.strip()
            candidate = Path(value)
            if candidate.is_absolute():
                resolved = candidate.resolve(strict=False)
                if safe_relative(resolved, settings.projects_root) is None:
                    raise SystemExit("La ruta de exclusión debe estar bajo projects_root.")
                value = str(resolved)
            elif any(part in {".", ".."} for part in value.replace("\\", "/").split("/")):
                raise SystemExit("Usa un nombre de proyecto simple o una ruta absoluta dentro de projects_root.")
            excluded = settings.raw.setdefault("excluded_projects", [])
            if not any(str(item).casefold() == value.casefold() for item in excluded):
                excluded.append(value)
            save_settings(settings)
            _json({"excluded_projects": excluded, "index": index_all(settings)})
        elif args.include:
            value = args.include.strip()
            settings.raw["excluded_projects"] = [item for item in settings.raw.get("excluded_projects", []) if str(item).casefold() != value.casefold()]
            save_settings(settings)
            _json({"excluded_projects": settings.raw["excluded_projects"], "index": index_all(settings)})
        else:
            result = project_inventory(settings)
            _json(result)
    elif args.command == "decision" and args.decision_action == "add":
        # Reject unsafe owned roots/junctions before the legacy full refresh.
        from .decision_storage import validate_memory_storage
        validate_memory_storage(settings)
        index_all(settings)
        record = add_memory_record(
            settings, project=args.project, problem=args.problem, statement=args.statement,
            record_type=args.record_type, status=args.status, reason=args.reason,
            alternatives=args.alternative, components=args.component, technologies=args.technology,
            tests=args.test, evidence=args.evidence, result=args.result,
            validation=args.validation, recorded_date=args.date,
            config_path=args.config or default_config_path(settings.root),
        )
        record["index"] = index_all(settings)
        _json(record)
    elif args.command == "decision" and args.decision_action == "list":
        _json(list_memory_records(
            settings, project=args.project, limit=args.limit,
            record_type=args.record_type, status=args.status, query=args.query,
        ))
    elif args.command in {"graph-sync", "knowledge-graph"}:
        try:
            if args.command == "graph-sync":
                result = sync_graph(settings, max_inputs=args.max_inputs, max_bytes=args.max_bytes)
            else:
                options = {name: getattr(args, name) for name in ("kind", "query", "source", "category", "project", "risk", "since", "until", "cursor", "limit")}
                result = graph_page(settings, suggestions=args.suggestions, include_inactive=args.include_inactive, **options) if args.graph_action == "page" else graph_neighbors(settings, args.node_id, suggestions=args.suggestions, include_inactive=args.include_inactive, **options)
            _json(result)
            if result.get("status") == "partial":
                raise SystemExit(1)
        except (ValueError, OSError, sqlite3.Error, TimeoutError) as exc:
            _json({"error": str(exc) if isinstance(exc, ValueError) else "knowledge_graph_operation_failed"})
            raise SystemExit(1) from None
    elif args.command == "graph":
        _json(_graph_export(settings, args.limit, args.suggestions) if args.domain == "documents"
              else public_graph(settings, args.domain, limit=args.limit, query=args.query))
    elif args.command == "backup":
        target = args.path or (settings.data_dir / "backups" / f"rabanito-{iso_now().replace(':', '').replace('+00:00', 'Z').replace('-', '')}.db")
        with Database(settings.database_path, query_only=True) as db:
            db.backup(target)
        _json({"backup": str(target), "database": str(settings.database_path)})
    elif args.command == "restore":
        backup_path = args.path.resolve(strict=True)
        if not args.yes:
            raise SystemExit("Restaurar sobrescribe el índice local. Repite con --yes si estás seguro.")
        if backup_path.suffix.casefold() != ".db":
            raise SystemExit("El respaldo debe ser un archivo .db")
        settings.database_path.parent.mkdir(parents=True, exist_ok=True)
        with _index_lock(settings):
            sidecars = (Path(str(settings.database_path) + "-wal"), Path(str(settings.database_path) + "-shm"))
            if any(path.exists() for path in sidecars):
                raise SystemExit("La base está activa; cierra el dashboard/escritores antes de restaurar.")
            previous_backup = None
            if settings.database_path.exists():
                previous_backup = settings.data_dir / "backups" / f"pre-restore-{iso_now().replace(':', '').replace('+00:00', 'Z').replace('-', '')}.db"
                with Database(settings.database_path, query_only=True) as db:
                    db.backup(previous_backup)
            restore_database(backup_path, settings.database_path)
        _json({
            "restored": str(backup_path),
            "database": str(settings.database_path),
            "pre_restore_backup": str(previous_backup) if previous_backup else None,
        })


if __name__ == "__main__":
    main()
