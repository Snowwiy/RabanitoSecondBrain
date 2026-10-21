from __future__ import annotations

import json
import ipaddress
import os
import re
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse, urlsplit

from .capabilities import build_link_suggestions, dashboard_audit, dashboard_audit_view, write_audit
from .changes import recent_document_changes
from .config import SETTINGS_WRITE_LOCK, Settings, save_settings
from .cyber import cyber_status, get_vulnerability, search_vulnerabilities, sync_source
from .cyber.history import vulnerability_history
from .coding_memory import recurring_patterns, similar_experiences
from .documented_memory import documented_experiences
from .document_content import DocumentContentError, document_content
from .db import Database
from .decisions import list_memory_records
from .graph import graph_edges_for_nodes, graph_suggestion_edges
from .indexer import index_all, set_additional_source_enabled_and_sync
from .onboard import approve_source, preview_source
from .public_graph import public_graph
from .knowledge_graph import graph_neighbors, graph_page, sync_graph
from .security import get_security_entry, search_security
from .search import (
    SCAN_SOURCE_SUMMARY_MAX_CHARS, get_document, project_scan_summary, recent_documents, related_documents,
    retrieve_context, search_documents, stats,
)
from .utils import contains_reparse_component, path_key, safe_relative
from .visibility import project_visibility_sql, register_project_visibility


class RabanitoHandler(BaseHTTPRequestHandler):
    settings: Settings

    def log_message(self, format: str, *args) -> None:
        # Never log request paths or query strings: they can contain private search terms.
        request_parts = self.requestline.split()
        method = request_parts[0] if request_parts else "UNKNOWN"
        status = str(args[1]) if len(args) > 1 else "unknown"
        print(f"[dashboard] {self.address_string()} {method} status={status}")

    def _json(self, payload: object, status: int = 200) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _document_content_request(self, parsed) -> None:
        # Isolated parsing keeps the established API contracts unchanged.
        self.close_connection = True
        body_consumed = False
        def reject(code, status):
            # On Windows, closing with an unread small request body can reset the
            # connection before its structured error reaches the client. Drain
            # only unambiguous, bounded framing; never consume an oversized body.
            lengths = self.headers.get_all("Content-Length", [])
            if (not body_consumed and len(lengths) == 1 and re.fullmatch(r"[0-9]{1,10}", lengths[0])
                    and 0 < int(lengths[0]) <= 2048 and not self.headers.get_all("Transfer-Encoding", [])):
                previous_timeout = self.connection.gettimeout()
                try:
                    self.connection.settimeout(1)
                    self.rfile.read(int(lengths[0]))
                except OSError:
                    pass
                finally:
                    self.connection.settimeout(previous_timeout)
            self._json({"error": code}, status)
        try:
            if parsed.query or parsed.params or parsed.fragment:
                raise DocumentContentError(400, "json_body_required")
            if (len(self.headers.get_all("Host", [])) != 1
                    or len(self.headers.get_all("Origin", [])) != 1
                    or not _request_host_is_loopback(self.headers.get("Host", ""), self.server.server_address[1])):
                raise DocumentContentError(403, "same_origin_required")
            try:
                origin = urlsplit(self.headers["Origin"])
                host = urlsplit("http://" + self.headers["Host"])
                valid_origin = (origin.scheme == "http" and not origin.username and not origin.password
                    and not origin.path and not origin.query and not origin.fragment
                    and _is_loopback_host(origin.hostname or "") and origin.hostname == host.hostname
                    and origin.port == host.port == self.server.server_address[1])
            except ValueError:
                valid_origin = False
            if not valid_origin:
                raise DocumentContentError(403, "same_origin_required")
            if (len(self.headers.get_all("Content-Type", [])) != 1
                    or self.headers["Content-Type"].split(";", 1)[0].strip().casefold() != "application/json"):
                raise DocumentContentError(403, "json_content_type_required")
            lengths = self.headers.get_all("Content-Length", [])
            if (len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,10}", lengths[0])
                    or self.headers.get_all("Transfer-Encoding", [])):
                raise DocumentContentError(400, "invalid_request_framing")
            length = int(lengths[0])
            if length > 2048:
                raise DocumentContentError(413, "request_size_limit")
            if not length:
                raise DocumentContentError(400, "invalid_document_request")
            old_timeout = self.connection.gettimeout()
            try:
                self.connection.settimeout(3)
                body_consumed = True
                body = self.rfile.read(length)
            finally:
                self.connection.settimeout(old_timeout)
            if len(body) != length:
                raise DocumentContentError(400, "incomplete_request_body")
            def unique_fields(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate_key")
                    result[key] = value
                return result
            payload = json.loads(body.decode("utf-8"), object_pairs_hook=unique_fields)
            if not isinstance(payload, dict) or set(payload) != {"document_id", "max_bytes"}:
                raise DocumentContentError(400, "invalid_document_request")
            self._json(document_content(self.settings, payload["document_id"], payload["max_bytes"]))
        except DocumentContentError as exc:
            reject(exc.code, exc.status)
        except (UnicodeError, ValueError, TypeError, RecursionError):
            reject("invalid_document_request", 400)
        except OSError:
            reject("document_request_unavailable", 409)

    def _project_root_for_id(self, value: object) -> str | None:
        if value in (None, ""):
            return None
        if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,12}", str(value)):
            raise ValueError("A valid project identifier is required")
        with Database(self.settings.database_path, query_only=True, empty_if_missing=True) as db:
            row = db.one(
                "SELECT root_path,status FROM projects WHERE project_id=? AND status IN ('active','excluded')",
                (int(value),),
            )
        if not row:
            raise ValueError("Unknown project identifier")
        root = str(row["root_path"])
        if (row["status"] != "active" or safe_relative(Path(root), self.settings.projects_root) is None
                or self.settings.is_project_excluded(root)):
            raise ValueError("Project is not currently authorized")
        return root

    def _additional_source_by_id(self, value: object) -> dict[str, Any] | None:
        if not isinstance(value, str):
            return None
        match = re.fullmatch(r"additional-([0-9]{1,8})", value)
        if not match:
            return None
        sources = self.settings.additional_sources()
        index = int(match.group(1))
        if index >= len(sources) or not sources[index].get("path"):
            return None
        return sources[index]

    @staticmethod
    def _dashboard_scan_summary(scan: dict[str, Any]) -> dict[str, Any]:
        return project_scan_summary(scan)

    @staticmethod
    def _dashboard_document(document: dict[str, Any]) -> dict[str, Any]:
        private_fields = {
            "absolute_path", "project_root", "project_root_path", "source_root", "path_key", "source_url",
        }
        result = {key: value for key, value in document.items() if key not in private_fields}
        if isinstance(result.get("frontmatter"), dict):
            result["frontmatter"] = RabanitoHandler._dashboard_metadata(result["frontmatter"])
        if isinstance(result.get("links"), list):
            result["links"] = [RabanitoHandler._dashboard_metadata(row) for row in result["links"]]
        if isinstance(result.get("incoming_links"), list):
            result["incoming_links"] = [RabanitoHandler._dashboard_metadata(row) for row in result["incoming_links"]]
        return result

    @staticmethod
    def _dashboard_metadata(value: Any) -> Any:
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                normalized_key = str(key).casefold().replace("_", "").replace("-", "")
                if normalized_key in {"path", "absolutepath", "projectroot", "projectrootpath", "sourceroot", "vaultroot", "rootpath", "sourcepath", "targetpath"}:
                    continue
                result[key] = RabanitoHandler._dashboard_metadata(item)
            return result
        if isinstance(value, list):
            return [RabanitoHandler._dashboard_metadata(item) for item in value]
        if isinstance(value, str):
            normalized = value.replace("\\", "/")
            parsed = urlsplit(normalized)
            if parsed.scheme.casefold() == "file":
                basename = PurePosixPath(unquote(parsed.path).replace("\\", "/")).name
                return f"[URI de archivo omitida]{' · ' + basename if basename else ''}"
            if normalized.startswith("/") or normalized.startswith("//") or re.match(r"^[A-Za-z]:/", normalized):
                basename = PurePosixPath(normalized).name
                return f"[ruta absoluta omitida]{' · ' + basename if basename else ''}"
        return value

    @staticmethod
    def _dashboard_context(context: dict[str, Any]) -> dict[str, Any]:
        fragments = []
        for fragment in context.get("fragments", []):
            item = {key: value for key, value in fragment.items() if key not in {
                "absolute_path", "project_root", "project_root_path", "source_root", "source_url",
            }}
            item["citation"] = f"{item.get('source_kind', 'local')}:{item.get('relative_path', '')}:{item.get('line_start', '?')}-{item.get('line_end', '?')}"
            fragments.append(item)
        return {key: value for key, value in context.items() if key not in {"query", "fragments"}} | {"fragments": fragments}

    @staticmethod
    def _dashboard_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        blocked = {
            "project_root", "project_root_path", "absolute_path", "source_root", "path_key", "source_url",
            "frontmatter_json", "tags_json", "content_hash",
        }
        return [{key: value for key, value in record.items() if key not in blocked} for record in records]

    def _html(self, raw: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if not _request_host_is_loopback(self.headers.get("Host", ""), self.server.server_address[1]):
            self._json({"error": "loopback Host required"}, 403)
            return
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        try:
            if path == "/api/doc/content":
                self._json({"error": "post_json_required"}, 405)
                return
            if path == "/api/coding/documented":
                self._json({"error": "POST JSON required for private filters"}, 405)
                return
            if path.startswith("/api/attack/"):
                self._json({"error": "POST JSON required"}, 405)
                return
            if path in {"/api/search", "/api/context", "/api/decisions", "/api/graph", "/api/cyber/search", "/api/cyber/get", "/api/cyber/sync", "/api/cyber/history", "/api/security/search", "/api/security/get", "/api/coding/similar", "/api/coding/patterns", "/api/knowledge-graph", "/api/knowledge-graph/neighbors", "/api/knowledge-graph/sync"}:
                self._json({"error": "POST JSON required for private filters"}, 405)
                return
            if path in {"/", "/index.html"}:
                html_path = self.settings.root / "web" / "index.html"
                self._html(html_path.read_bytes())
                return
            if path in {"/assets/cyber.js", "/assets/knowledge.js"}:
                filename = "cyber.js" if path == "/assets/cyber.js" else "knowledge.js"
                raw = (self.settings.root / "web" / filename).read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/javascript; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(raw)
                return
            if path == "/api/cyber/status":
                self._json(cyber_status(self.settings))
                return
            if path == "/api/health":
                self._json({"ok": True, "host_policy": "loopback-only"})
                return
            if path == "/api/stats":
                result = stats(
                    self.settings,
                    latest_scan_source_summary_limit=SCAN_SOURCE_SUMMARY_MAX_CHARS + 1,
                )
                latest = result.get("latest_scan")
                result["latest_scan"] = self._dashboard_scan_summary(latest) if isinstance(latest, dict) else None
                self._json(result)
                return
            if path.startswith("/api/doc/"):
                document_id = int(path.rsplit("/", 1)[1])
                doc = get_document(self.settings, document_id)
                self._json(self._dashboard_document(doc) if doc else {"error": "not found"}, 200 if doc else 404)
                return
            if path.startswith("/api/related/"):
                related = related_documents(self.settings, int(path.rsplit("/", 1)[1]))
                self._json({"results": self._dashboard_records(related)})
                return
            if path == "/api/categories":
                with Database(self.settings.database_path, query_only=True, empty_if_missing=True) as db:
                    register_project_visibility(db, self.settings)
                    rows = db.query(
                        "SELECT DISTINCT d.category FROM documents d WHERE d.status='active' AND "
                        + project_visibility_sql("d") + " ORDER BY d.category"
                    )
                self._json({"categories": [row["category"] for row in rows]})
                return
            if path == "/api/tags":
                with Database(self.settings.database_path, query_only=True, empty_if_missing=True) as db:
                    register_project_visibility(db, self.settings)
                    rows = db.query(
                        """SELECT t.tag, COUNT(*) AS document_count FROM tags t
                           JOIN documents d ON d.document_id=t.document_id
                           WHERE d.status='active' AND """ + project_visibility_sql("d") +
                        " GROUP BY t.tag ORDER BY t.tag LIMIT 2000"
                    )
                self._json({"tags": [dict(row) for row in rows]})
                return
            if path == "/api/audit/latest":
                self._json(dashboard_audit(self.settings))
                return
            if path == "/api/scans":
                with Database(self.settings.database_path, query_only=True, empty_if_missing=True) as db:
                    scans = [dict(row) for row in db.query(
                        """SELECT scan_id,started_at,finished_at,status,files_seen,added,modified,unchanged,
                                  removed,skipped,errors,
                                  substr(source_summary_json,1,?) AS source_summary_json
                           FROM scan_runs ORDER BY scan_id DESC LIMIT 30""",
                        (SCAN_SOURCE_SUMMARY_MAX_CHARS + 1,),
                    )]
                self._json({"scans": [self._dashboard_scan_summary(scan) for scan in scans]})
                return
            if path == "/api/changes":
                raw_limit = query.get("limit", ["50"])[0]
                limit = min(max(int(raw_limit), 0), 100)
                if limit == 0:
                    self._json({"changes": []})
                    return
                raw_project_id = query.get("project_id", [""])[0]
                if raw_project_id and not re.fullmatch(r"[0-9]{1,12}", raw_project_id):
                    raise ValueError("invalid active project identifier")
                project_root_path = None
                if raw_project_id:
                    with Database(self.settings.database_path, query_only=True, empty_if_missing=True) as db:
                        project = db.one(
                            "SELECT root_path FROM projects WHERE project_id=? AND status='active'",
                            (int(raw_project_id),),
                        )
                    if not project or safe_relative(Path(str(project["root_path"])), self.settings.projects_root) is None:
                        raise ValueError("unknown or unauthorized active project")
                    project_root_path = str(project["root_path"])
                changes = recent_document_changes(self.settings, limit, project_root_path)
                self._json({"changes": changes})
                return
            if path == "/api/projects":
                include_excluded = query.get("all", ["0"])[0] in {"1", "true", "yes"}
                with Database(self.settings.database_path, query_only=True, empty_if_missing=True) as db:
                    condition = "status IN ('active','excluded')" if include_excluded else "status='active'"
                    rows = db.query(
                        "SELECT project_id, name, root_path, path_key, technology_json, dependencies_json, "
                        "dependencies_truncated, dependency_errors_json, status "
                        f"FROM projects WHERE {condition} ORDER BY name, root_path"
                    )
                    project_relative_paths: dict[int, str | None] = {}
                    project_effective_statuses: dict[int, str] = {}
                    visible_project_roots = []
                    for row in rows:
                        project_id = int(row["project_id"])
                        root_path = str(row["root_path"])
                        relative_root = safe_relative(Path(root_path), self.settings.projects_root)
                        config_excluded = self.settings.is_project_excluded(root_path)
                        effective_status = "excluded" if config_excluded else str(row["status"])
                        project_relative_paths[project_id] = relative_root
                        project_effective_statuses[project_id] = effective_status
                        if effective_status == "active" and relative_root not in (None, ".", ""):
                            visible_project_roots.append(root_path)

                    project_memory_candidates: dict[str, list[int]] = {}
                    if visible_project_roots:
                        register_project_visibility(db, self.settings)
                        for offset in range(0, len(visible_project_roots), 800):
                            batch = visible_project_roots[offset:offset + 800]
                            placeholders = ",".join("?" for _ in batch)
                            memory_rows = db.query(
                                "SELECT document_id, project_root_path, source_root, absolute_path, relative_path FROM documents d "
                                "WHERE d.source_kind='internal' AND d.status='active' "
                                "AND d.relative_path GLOB 'projects/*/PROJECT[_]MEMORY.md' "
                                f"AND d.project_root_path IN ({placeholders}) AND {project_visibility_sql('d')} "
                                "ORDER BY d.document_id",
                                batch,
                            )
                            visible_roots = {path_key(root) for root in batch}
                            for memory in memory_rows:
                                relative_parts = PurePosixPath(str(memory["relative_path"]).replace("\\", "/")).parts
                                root_key = path_key(str(memory["project_root_path"] or ""))
                                if (root_key in visible_roots and len(relative_parts) == 3
                                        and relative_parts[0] == "projects" and relative_parts[1] not in {"", ".", ".."}
                                        and relative_parts[2] == "PROJECT_MEMORY.md"):
                                    expected_path = self.settings.knowledge_root.joinpath(*relative_parts)
                                    if (path_key(str(memory["source_root"] or "")) == path_key(self.settings.knowledge_root)
                                            and path_key(str(memory["absolute_path"] or "")) == path_key(expected_path)):
                                        project_memory_candidates.setdefault(root_key, []).append(int(memory["document_id"]))
                    project_memory_ids = {
                        root_key: document_ids[0]
                        for root_key, document_ids in project_memory_candidates.items()
                        if len(document_ids) == 1
                    }
                projects = []
                for row in rows:
                    project_id = int(row["project_id"])
                    relative = project_relative_paths[project_id]
                    effective_status = project_effective_statuses[project_id]
                    if effective_status == "excluded" and not include_excluded:
                        continue
                    item = {
                        "project_id": project_id, "name": row["name"], "status": effective_status,
                        "relative_path": relative,
                    }
                    if effective_status == "active":
                        memory_document_id = project_memory_ids.get(path_key(str(row["root_path"])))
                        if memory_document_id is not None:
                            item["memory_document_id"] = memory_document_id
                        try:
                            technologies = json.loads(row["technology_json"] or "[]")
                        except (TypeError, json.JSONDecodeError):
                            technologies = []
                        if not isinstance(technologies, list):
                            technologies = []
                        item["technologies"] = [str(value)[:80] for value in technologies[:30] if isinstance(value, str)]
                        try:
                            dependencies = json.loads(row["dependencies_json"] or "[]")
                        except (TypeError, json.JSONDecodeError):
                            dependencies = []
                        if not isinstance(dependencies, list):
                            dependencies = []
                        safe_dependencies = []
                        for dependency in dependencies[:500]:
                            if not isinstance(dependency, dict) or not isinstance(dependency.get("name"), str):
                                continue
                            sources = []
                            raw_sources = dependency.get("sources", [])
                            if isinstance(raw_sources, list):
                                for raw_source in raw_sources[:20]:
                                    normalized = str(raw_source).replace("\\", "/")
                                    relative_source = PurePosixPath(normalized)
                                    if (normalized and len(normalized) <= 240 and not relative_source.is_absolute()
                                            and ".." not in relative_source.parts and ":" not in normalized):
                                        sources.append(normalized)
                            safe_dependencies.append({"name": dependency["name"][:160], "sources": sources})
                        item["dependencies"] = safe_dependencies[:100]
                        item["dependencies_count"] = len(safe_dependencies)
                        item["dependencies_display_truncated"] = len(safe_dependencies) > 100
                        item["dependencies_truncated"] = bool(row["dependencies_truncated"])
                        try:
                            dependency_errors = json.loads(row["dependency_errors_json"] or "[]")
                        except (TypeError, json.JSONDecodeError):
                            dependency_errors = []
                        safe_errors = []
                        if isinstance(dependency_errors, list):
                            for issue in dependency_errors[:500]:
                                if not isinstance(issue, dict):
                                    continue
                                normalized = str(issue.get("source", "")).replace("\\", "/")
                                relative_source = PurePosixPath(normalized)
                                error_type = str(issue.get("error_type", ""))
                                if (not normalized or len(normalized) > 240 or relative_source.is_absolute()
                                        or ".." in relative_source.parts or ":" in normalized
                                        or re.search(r"[\x00-\x1f\x7f]", normalized)
                                        or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", error_type)):
                                    continue
                                safe_errors.append({"source": normalized, "error_type": error_type})
                        item["dependency_errors"] = safe_errors[:20]
                        item["dependency_errors_count"] = len(safe_errors)
                        item["dependency_errors_display_truncated"] = len(safe_errors) > 20
                    projects.append(item)
                self._json({"projects": projects})
                return
            if path == "/api/sources":
                sources = []
                builtin_roots = self.settings.source_roots(include_disabled=False)[:3]
                for kind, root, name in builtin_roots:
                    sources.append({
                        "source_id": f"integrated-{kind}",
                        "kind": kind,
                        "name": name or root.name,
                        "managed": False,
                        "enabled": True,
                    })
                for index, item in enumerate(self.settings.additional_sources()):
                    if not item.get("path"):
                        continue
                    root = Path(item["path"])
                    sources.append({
                        "source_id": f"additional-{index}",
                        "kind": str(item.get("kind", "local")),
                        "name": item.get("name") or root.name,
                        "managed": True,
                        "enabled": bool(item.get("enabled", True)),
                    })
                self._json({"sources": sources})
                return
            self._json({"error": "not found"}, 404)
        except (ValueError, TypeError, RecursionError, OSError, sqlite3.Error, json.JSONDecodeError) as exc:
            self._json({"error": f"request failed: {type(exc).__name__}"}, 400)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/doc/content":
            self._document_content_request(parsed)
            return
        if not _request_host_is_loopback(self.headers.get("Host", ""), self.server.server_address[1]):
            self._json({"error": "loopback Host required"}, 403)
            return
        if parsed.path not in {
            "/api/index", "/api/audit", "/api/link", "/api/project-exclusion",
            "/api/source-preview", "/api/source-approve", "/api/source-impact", "/api/source-toggle",
            "/api/search", "/api/context", "/api/decisions", "/api/graph",
            "/api/cyber/search", "/api/cyber/get", "/api/cyber/sync", "/api/cyber/history",
            "/api/security/search", "/api/security/get",
            "/api/attack/status", "/api/attack/search", "/api/attack/get", "/api/attack/context",
            "/api/attack/relations", "/api/attack/history",
            "/api/coding/similar", "/api/coding/patterns",
            "/api/coding/documented",
            "/api/knowledge-graph", "/api/knowledge-graph/neighbors", "/api/knowledge-graph/sync",
        } and not parsed.path.startswith("/api/open/"):
            self._json({"error": "not found"}, 404)
            return
        origin = self.headers.get("Origin", "")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().casefold()
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = -1
        try:
            origin_url = urlparse(origin)
            same_loopback_origin = (
                origin_url.scheme == "http" and _is_loopback_host(origin_url.hostname or "")
                and origin_url.port == self.server.server_address[1]
            )
        except ValueError:
            same_loopback_origin = False
        max_body_length = 16_384 if parsed.path in {"/api/search", "/api/context", "/api/decisions", "/api/graph", "/api/knowledge-graph", "/api/knowledge-graph/neighbors"} else 2048
        if not same_loopback_origin or content_type != "application/json" or not 0 <= content_length <= max_body_length:
            self._json({"error": "same-origin JSON request required"}, 403)
            return
        try:
            def unique_graph_fields(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate_graph_json_key")
                    result[key] = value
                return result
            raw_payload = self.rfile.read(content_length) or b"{}"
            payload = json.loads(raw_payload, object_pairs_hook=unique_graph_fields) if parsed.path.startswith(("/api/knowledge-graph", "/api/attack/")) or parsed.path == "/api/coding/documented" else json.loads(raw_payload)
            if not isinstance(payload, dict):
                raise ValueError("JSON object required")
            if parsed.path.startswith("/api/knowledge-graph"):
                self._knowledge_graph(parsed.path, payload)
            elif parsed.path.startswith("/api/attack/"):
                self._attack_query(parsed.path, payload)
            elif parsed.path == "/api/index":
                self._json(self._dashboard_scan_summary(index_all(self.settings)))
            elif parsed.path == "/api/cyber/search":
                kev_only = payload.get("kev", False)
                if not isinstance(kev_only, bool):
                    raise ValueError("kev must be a boolean")
                self._json(search_vulnerabilities(self.settings, payload.get("q", ""), source=payload.get("source") or None,
                    kev_only=kev_only, limit=int(payload.get("limit", 20)), offset=int(payload.get("offset", 0)),
                    since=payload.get("since") or None, min_epss=payload.get("min_epss"), sort=payload.get("sort", "risk")))
            elif parsed.path == "/api/coding/documented":
                if set(payload) - {"q", "context", "technology", "limit", "max_chars"}:
                    raise ValueError("unknown_documented_memory_fields")
                self._json(documented_experiences(self.settings, payload.get("q", ""), context=payload.get("context"),
                    technology=payload.get("technology"), limit=payload.get("limit", 5), max_chars=payload.get("max_chars", 6000)))
            elif parsed.path == "/api/coding/similar":
                self._json(similar_experiences(self.settings, payload.get("q", ""), project=payload.get("project") or None,
                    technology=payload.get("technology") or None, limit=payload.get("limit", 5), max_chars=payload.get("max_chars", 6000)))
            elif parsed.path == "/api/coding/patterns":
                self._json(recurring_patterns(self.settings, project=payload.get("project") or None, limit=payload.get("limit", 10)))
            elif parsed.path == "/api/security/search":
                self._json(search_security(self.settings, payload.get("q", ""), framework=payload.get("framework") or None,
                    kind=payload.get("kind") or None, edition_status=payload.get("status") or None,
                    release=payload.get("release"),
                    limit=int(payload.get("limit", 20)), offset=int(payload.get("offset", 0)),level=payload.get('level')))
            elif parsed.path == "/api/security/get":
                result = get_security_entry(self.settings, payload.get("id", ""))
                self._json(result or {"error": "not found locally"}, 200 if result else 404)
            elif parsed.path == "/api/cyber/get":
                result = get_vulnerability(self.settings, payload.get("id", ""))
                self._json(result or {"error": "not found locally"}, 200 if result else 404)
            elif parsed.path == "/api/cyber/history":
                self._json(vulnerability_history(self.settings, payload.get("id", ""), source=payload.get("source"),
                                                limit=payload.get("limit", 20), before=payload.get("before")))
            elif parsed.path == "/api/cyber/sync":
                if payload.get("confirm_public_sync") is not True:
                    raise ValueError("Explicit public synchronization is required")
                values = payload.get("ids")
                if values is not None and (not isinstance(values, list) or len(values) > 1):
                    raise ValueError("Dashboard sync accepts one public identifier")
                if "capture" in payload or "capture_manifest" in payload:
                    raise ValueError("Capture replay is CLI-only")
                options = {"month": payload["month"]} if "month" in payload else {}
                self._json(sync_source(self.settings, payload.get("source", ""), values, **options))
            elif parsed.path == "/api/audit":
                self._json(dashboard_audit_view(write_audit(self.settings)))
            elif parsed.path == "/api/link":
                self._json(build_link_suggestions(self.settings))
            elif parsed.path in {"/api/source-preview", "/api/source-approve"}:
                raw_path = str(payload.get("path", "")).strip()
                kind = str(payload.get("kind", "local"))
                name = payload.get("name")
                if not raw_path or not Path(raw_path).is_absolute():
                    raise ValueError("An absolute local source path is required")
                if name is not None and not isinstance(name, str):
                    raise ValueError("Source name must be text")
                if parsed.path == "/api/source-preview":
                    preview = preview_source(self.settings, Path(raw_path), kind)
                else:
                    preview = approve_source(self.settings, Path(raw_path), kind, name)
                preview.pop("path", None)
                self._json(preview)
            elif parsed.path == "/api/source-impact":
                enabled = payload.get("enabled")
                source = self._additional_source_by_id(payload.get("source_id"))
                raw_path = str(payload.get("path", "")).strip()
                if source is None and raw_path and Path(raw_path).is_absolute():
                    source = next((item for item in self.settings.additional_sources() if item.get("path") and path_key(item["path"]) == path_key(raw_path)), None)
                if not isinstance(enabled, bool):
                    raise ValueError("A boolean enabled state is required")
                if source is None:
                    self._json({"error": "only registered additional sources can be toggled"}, 403)
                    return
                if enabled:
                    preview_source(self.settings, Path(source["path"]), str(source.get("kind", "local")))
                source_kind = str(source.get("kind", "local"))
                source_path = str(source["path"])
                with Database(self.settings.database_path, query_only=True, empty_if_missing=True) as db:
                    counts = {
                        str(row["status"]): int(row["count"])
                        for row in db.query(
                            "SELECT status, COUNT(*) AS count FROM documents WHERE source_kind=? AND source_root=? GROUP BY status",
                            (source_kind, source_path),
                        )
                    }
                    outgoing_links = int(db.one(
                        """SELECT COUNT(*) AS count FROM links l JOIN documents d ON d.document_id=l.source_document_id
                           WHERE d.source_kind=? AND d.source_root=? AND d.status IN ('active','skipped')""",
                        (source_kind, source_path),
                    )["count"])
                self._json({
                    "enabled_currently": bool(source.get("enabled", True)),
                    "enabled_requested": enabled,
                    "would_change": bool(source.get("enabled", True)) != enabled,
                    "active_documents": counts.get("active", 0),
                    "skipped_documents": counts.get("skipped", 0),
                    "previously_deleted_records": counts.get("deleted", 0),
                    "outgoing_link_records": outgoing_links,
                })
            elif parsed.path == "/api/source-toggle":
                enabled = payload.get("enabled")
                source = self._additional_source_by_id(payload.get("source_id"))
                raw_path = str(payload.get("path", "")).strip()
                if source is None and raw_path and Path(raw_path).is_absolute():
                    source = next((item for item in self.settings.additional_sources() if item.get("path") and path_key(item["path"]) == path_key(raw_path)), None)
                if not isinstance(enabled, bool):
                    raise ValueError("A boolean enabled state is required")
                if source is None:
                    self._json({"error": "only registered additional sources can be toggled"}, 403)
                    return
                source_path = Path(source["path"])
                if enabled:
                    preview_source(self.settings, source_path, str(source.get("kind", "local")))
                result = set_additional_source_enabled_and_sync(self.settings, source_path, enabled)
                self._json({"enabled": enabled, "index": self._dashboard_scan_summary(result["index"])})
            elif parsed.path == "/api/project-exclusion":
                exclude = payload.get("exclude")
                if not isinstance(exclude, bool):
                    raise ValueError("A boolean exclude state is required")
                project_id = payload.get("project_id")
                if project_id not in (None, ""):
                    if isinstance(project_id, bool) or not re.fullmatch(r"[0-9]{1,12}", str(project_id)):
                        raise ValueError("A valid project identifier is required")
                    with Database(self.settings.database_path, query_only=True, empty_if_missing=True) as db:
                        project = db.one("SELECT project_id, root_path, name FROM projects WHERE project_id=? AND status IN ('active','excluded')", (int(project_id),))
                else:
                    project_path = str(payload.get("project", ""))
                    with Database(self.settings.database_path, query_only=True, empty_if_missing=True) as db:
                        project = db.one("SELECT project_id, root_path, name FROM projects WHERE root_path=? AND status IN ('active','excluded')", (project_path,))
                project_root = Path(project["root_path"]) if project else None
                if not project_root or safe_relative(project_root, self.settings.projects_root) is None:
                    self._json({"error": "unknown or unauthorized project"}, 403)
                    return
                with SETTINGS_WRITE_LOCK:
                    excluded = list(self.settings.raw.get("excluded_projects", []))
                    excluded = [item for item in excluded if str(item).casefold() != str(project_root).casefold() and str(item).casefold() != project["name"].casefold()]
                    if exclude:
                        excluded.append(str(project_root))
                    self.settings.raw["excluded_projects"] = excluded
                    save_settings(self.settings)
                scan = index_all(self.settings)
                self._json({"project": project["name"], "excluded": exclude, "index": self._dashboard_scan_summary(scan)})
            elif parsed.path == "/api/search":
                term = str(payload.get("q", ""))
                project = self._project_root_for_id(payload.get("project_id"))
                source = payload.get("source")
                category = payload.get("category")
                tag = payload.get("tag")
                limit = int(payload.get("limit", 20))
                results = (recent_documents if not term.strip() else search_documents)(
                    self.settings, *(() if not term.strip() else (term,)), limit,
                    str(source) if source else None, str(category) if category else None, project,
                    str(tag) if tag else None,
                )
                self._json({"results": self._dashboard_records(results)})
            elif parsed.path == "/api/context":
                project = self._project_root_for_id(payload.get("project_id"))
                context = retrieve_context(
                    self.settings, str(payload.get("q", "")), int(payload.get("limit", 8)),
                    int(payload.get("max_chars", self.settings.max_context_chars)),
                    str(payload["source"]) if payload.get("source") else None,
                    str(payload["category"]) if payload.get("category") else None,
                    project, str(payload["tag"]) if payload.get("tag") else None,
                )
                self._json(self._dashboard_context(context))
            elif parsed.path == "/api/decisions":
                project = self._project_root_for_id(payload.get("project_id"))
                records = list_memory_records(
                    self.settings, project=project, limit=int(payload.get("limit", 50)),
                    record_type=str(payload["type"]) if payload.get("type") else None,
                    status=str(payload["status"]) if payload.get("status") else None,
                    query=str(payload["q"]) if payload.get("q") else None,
                )
                self._json({"records": self._dashboard_records(records)})
            elif parsed.path == "/api/graph":
                normalized = {str(key): [str(value)] for key, value in payload.items() if value is not None}
                self._graph(normalized)
            else:
                self._open_document(int(parsed.path.rsplit("/", 1)[1]))
        except TimeoutError as exc:
            self._json({"error": str(exc)}, 409)
        except (ValueError, TypeError, RecursionError, OSError, sqlite3.Error, json.JSONDecodeError) as exc:
            message = str(exc) if parsed.path.startswith("/api/knowledge-graph") and re.fullmatch(r"[a-z_]{1,100}", str(exc)) else f"request failed: {type(exc).__name__}"
            self._json({"error": message}, 400)

    def _attack_query(self, path: str, payload: dict) -> None:
        from .attack_query import attack_status, search_attack, get_attack_object, attack_context, attack_relations, attack_history
        action = path.removeprefix("/api/attack/")
        allowed = {
            "status": {"domain"},
            "search": {"q", "domain", "release", "kind", "include_inactive", "limit", "offset"},
            "get": {"id", "domain", "release", "kind"},
            "context": {"q", "domain", "release", "kind", "include_inactive", "limit", "max_chars"},
            "relations": {"id", "domain", "release", "direction", "include_inactive", "limit", "offset"},
            "history": {"id", "domain", "limit", "before"},
        }
        if action not in allowed or set(payload) - allowed[action]:
            raise ValueError("unsupported_attack_query_fields")
        options = {k: v for k, v in payload.items() if k not in {"q", "id"}}
        if action == "status":
            result = attack_status(self.settings, **options)
        elif action == "search":
            result = search_attack(self.settings, payload.get("q", ""), **options)
        elif action == "get":
            result = get_attack_object(self.settings, payload.get("id"), **options)
        elif action == "context":
            result = attack_context(self.settings, payload.get("q"), **options)
        elif action == "relations":
            result = attack_relations(self.settings, payload.get("id"), **options)
        else:
            result = attack_history(self.settings, payload.get("id"), **options)
        self._json(result, 404 if action == "get" and not result["matches"] else 200)

    def _knowledge_graph(self, path: str, payload: dict) -> None:
        if path.endswith("/sync"):
            if set(payload) - {"confirm_graph_sync", "max_inputs", "max_bytes"} or payload.get("confirm_graph_sync") is not True:
                raise ValueError("explicit_graph_sync_required")
            self._json(sync_graph(self.settings, max_inputs=payload.get("max_inputs", 1000), max_bytes=payload.get("max_bytes", 32 * 1024 * 1024)))
            return
        allowed = {"kind", "q", "category", "project", "project_id", "source", "risk", "since", "until", "limit", "cursor", "suggestions", "include_inactive"}
        neighbors = path.endswith("/neighbors")
        if neighbors:
            allowed |= {"id", "suggestions"}
        if set(payload) - allowed or "project" in payload and "project_id" in payload:
            raise ValueError("invalid_graph_request_fields")
        options = {key: value for key, value in payload.items() if key not in {"q", "project_id", "id", "suggestions"}}
        if "q" in payload:
            options["query"] = payload["q"]
        if "project_id" in payload:
            if type(payload["project_id"]) is not int:
                raise ValueError("invalid_graph_project")
            options["project"] = payload["project_id"]
        self._json(graph_neighbors(self.settings, payload.get("id"), suggestions=payload.get("suggestions", False), **options)
                   if neighbors else graph_page(self.settings, suggestions=payload.get("suggestions", False), **options))

    def _graph(self, query: dict[str, list[str]]) -> None:
        domain = query.get("domain", ["documents"])[0]
        if domain in {"cyber", "security"}:
            if query.get("project_id", [""])[0] or query.get("project", [""])[0]:
                raise ValueError("Public graphs do not establish project applicability")
            self._json(public_graph(self.settings, domain, limit=int(query.get("limit", [250])[0]),
                query=query.get("q", [""])[0], source=query.get("provider", [""])[0] or None,
                min_degree=int(query.get("min_degree", [0])[0])))
            return
        if domain != "documents":
            raise ValueError("Unknown graph domain")
        limit = min(max(int(query.get("limit", [250])[0]), 0), 1000)
        include_suggestions = query.get("suggestions", ["0"])[0] in {"1", "true", "yes"}
        source = query.get("source", [""])[0].strip()
        project = query.get("project", [""])[0].strip()
        project_id = query.get("project_id", [""])[0].strip()
        if project_id:
            project = self._project_root_for_id(project_id) or ""
        category = query.get("category", [""])[0].strip()
        text_filter = query.get("q", [""])[0].strip().casefold()
        min_degree = min(max(int(query.get("min_degree", ["0"])[0]), 0), 100)
        where = ["status='active'", project_visibility_sql("documents")]
        params: list[object] = []
        if source:
            where.append("source_kind=?")
            params.append(source)
        if project:
            if Path(project).is_absolute():
                where.append("(source_root=? OR project_root_path=?)")
                params.extend([project, project])
            else:
                where.append("project_name=?")
                params.append(project)
        if category:
            where.append("category LIKE ?")
            params.append(category + "%")
        if text_filter:
            where.append("(lower(title) LIKE ? OR lower(relative_path) LIKE ?)")
            pattern = f"%{text_filter}%"
            params.extend([pattern, pattern])
        with Database(self.settings.database_path, query_only=True, empty_if_missing=True) as db:
            register_project_visibility(db, self.settings)
            total_matches = int(db.one(
                f"SELECT COUNT(*) AS total FROM documents WHERE {' AND '.join(where)}", params
            )["total"])
            truncated = total_matches > limit
            nodes = db.query(
                f"SELECT document_id, title, source_kind, category, project_name, project_root_path, source_root, relative_path, mtime_iso "
                f"FROM documents WHERE {' AND '.join(where)} ORDER BY document_id LIMIT ?", (*params, limit)
            )
            node_ids = {int(row["document_id"]) for row in nodes}
            related_node_ids: set[int] = set()
            if include_suggestions and node_ids:
                # A project-scoped graph can optionally show related Obsidian notes,
                # but only via explicitly enabled, visibly non-factual suggestions.
                # Other projects and internal records never leak into this expansion.
                if Path(project).is_absolute() and node_ids and source in {"", "obsidian"}:
                    candidate_scores: dict[int, float] = {}
                    for edge in graph_suggestion_edges(db, node_ids):
                        left, right = int(edge["source"]), int(edge["target"])
                        if left in node_ids and right not in node_ids:
                            candidate = right
                        elif right in node_ids and left not in node_ids:
                            candidate = left
                        else:
                            continue
                        candidate_scores[candidate] = max(candidate_scores.get(candidate, 0.0), float(edge["score"]))

                    eligible_ids: set[int] = set()
                    candidate_ids = sorted(candidate_scores)
                    candidate_filters = ["status='active'", "source_kind='obsidian'", project_visibility_sql("documents")]
                    candidate_params: list[object] = []
                    if category:
                        candidate_filters.append("category LIKE ?")
                        candidate_params.append(category + "%")
                    if text_filter:
                        candidate_filters.append("(lower(title) LIKE ? OR lower(relative_path) LIKE ?)")
                        pattern = f"%{text_filter}%"
                        candidate_params.extend([pattern, pattern])
                    for offset in range(0, len(candidate_ids), 900):
                        batch = candidate_ids[offset:offset + 900]
                        placeholders = ",".join("?" for _ in batch)
                        found = db.query(
                            f"SELECT document_id FROM documents WHERE document_id IN ({placeholders}) AND {' AND '.join(candidate_filters)}",
                            (*batch, *candidate_params),
                        )
                        eligible_ids.update(int(row["document_id"]) for row in found)

                    remaining = max(0, limit - len(nodes))
                    if len(eligible_ids) > remaining:
                        truncated = True
                    related_node_ids = {
                        document_id
                        for _, document_id in sorted(
                            ((-score, document_id) for document_id, score in candidate_scores.items() if document_id in eligible_ids)
                        )[:remaining]
                    }
                    for offset in range(0, len(related_node_ids), 900):
                        batch = sorted(related_node_ids)[offset:offset + 900]
                        placeholders = ",".join("?" for _ in batch)
                        related_nodes = db.query(
                            f"SELECT document_id, title, source_kind, category, project_name, project_root_path, source_root, relative_path, mtime_iso "
                            f"FROM documents WHERE document_id IN ({placeholders}) AND {' AND '.join(candidate_filters)} ORDER BY document_id",
                            (*batch, *candidate_params),
                        )
                        nodes.extend(related_nodes)
                    node_ids.update(related_node_ids)
            selected_edges = graph_edges_for_nodes(db, node_ids, include_suggestions)
        degree: dict[int, int] = {}
        for edge in selected_edges:
            degree[int(edge["source"])] = degree.get(int(edge["source"]), 0) + 1
            degree[int(edge["target"])] = degree.get(int(edge["target"]), 0) + 1
        if min_degree:
            nodes = [row for row in nodes if degree.get(int(row["document_id"]), 0) >= min_degree]
            node_ids = {int(row["document_id"]) for row in nodes}
        public_nodes = []
        for row in nodes:
            node = dict(row)
            for key in ("source_root", "project_root_path", "absolute_path", "path_key"):
                node.pop(key, None)
            node["degree"] = degree.get(int(row["document_id"]), 0)
            node["related_via_suggestion"] = int(row["document_id"]) in related_node_ids
            public_nodes.append(node)
        self._json({
            "nodes": public_nodes,
            "edges": [edge for edge in selected_edges if int(edge["source"]) in node_ids and int(edge["target"]) in node_ids],
            "node_limit": limit,
            "total_matches": total_matches,
            "truncated": truncated,
        })

    def _open_document(self, document_id: int) -> None:
        with Database(self.settings.database_path, query_only=True, empty_if_missing=True) as db:
            register_project_visibility(db, self.settings)
            row = db.one(
                "SELECT absolute_path, source_kind, source_root, project_root_path, status "
                "FROM documents d WHERE document_id=? AND "
                + project_visibility_sql("d"),
                (document_id,),
            )
        if not row or row["status"] != "active":
            self._json({"error": "document not active"}, 404)
            return
        path = Path(row["absolute_path"])
        source_root = Path(row["source_root"])
        source_kind = str(row["source_kind"] or "")
        if source_kind == "projects":
            project_root = str(row["project_root_path"] or "")
            source_root_authorized = bool(
                project_root
                and path_key(source_root) == path_key(project_root)
                and safe_relative(source_root, self.settings.projects_root) not in {None, "."}
                and not self.settings.is_project_excluded(source_root)
            )
        else:
            source_root_authorized = any(
                kind == source_kind and path_key(root) == path_key(source_root)
                for kind, root, _name in self.settings.source_roots()
            )
        try:
            unsafe_path = (
                not source_root_authorized
                or contains_reparse_component(source_root)
                or contains_reparse_component(path)
            )
            resolved_path = path.resolve(strict=True) if not unsafe_path else path
            safe_path = (
                not unsafe_path
                and path.is_file()
                and safe_relative(resolved_path, source_root) is not None
            )
        except (OSError, RuntimeError, ValueError):
            safe_path = False
        if not safe_path:
            self._json({"error": "path is outside configured roots"}, 403)
            return
        if not hasattr(os, "startfile"):
            self._json({"error": "opening local files is only supported on Windows"}, 501)
            return
        os.startfile(str(resolved_path))
        self._json({"opened": True})


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().strip("[]").casefold()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _request_host_is_loopback(host_header: str, expected_port: int) -> bool:
    """Reject DNS-rebinding Host values even when the socket is loopback-bound."""
    try:
        parsed = urlparse("//" + host_header.strip())
        if parsed.username is not None or parsed.password is not None:
            return False
        if parsed.path or parsed.query or parsed.fragment:
            return False
        host = parsed.hostname
        port = parsed.port if parsed.port is not None else 80
    except ValueError:
        return False
    return bool(host and _is_loopback_host(host) and port == int(expected_port))


def serve_dashboard(settings: Settings, host: str | None = None, port: int | None = None) -> None:
    host = host or str(settings.raw.get("dashboard_host", "127.0.0.1"))
    port = int(settings.raw.get("dashboard_port", 8765) if port is None else port)
    if not _is_loopback_host(host):
        raise ValueError("Dashboard host must be a loopback address (localhost, 127.0.0.1 or ::1).")
    if host.casefold() == "localhost":
        # Bind a literal loopback IP rather than trusting local name resolution.
        host = "127.0.0.1"
    if not 1 <= port <= 65535:
        raise ValueError("Dashboard port must be between 1 and 65535.")
    handler = type("ConfiguredRabanitoHandler", (RabanitoHandler,), {"settings": settings})
    server = ThreadingHTTPServer((host, port), handler)
    print(f"Rabanito dashboard: http://{host}:{port}/")
    print("Press Ctrl+C to stop. The server is local and does not send vault content externally.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping dashboard")
    finally:
        server.server_close()
