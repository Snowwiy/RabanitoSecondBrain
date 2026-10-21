from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from html.parser import HTMLParser
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from unittest.mock import patch

from rabanito.capabilities import (
    _collect_audit_raw, _write_report_pair, audit_report_view, build_link_suggestions, collect_audit, dashboard_audit, dashboard_audit_view,
    level_up, write_audit,
)
from rabanito.cli import _json as cli_json, main as cli_main
from rabanito.config import Settings, set_additional_source_enabled
from rabanito.db import Database, restore_database
from rabanito.decisions import _safe_evidence_refs, add_memory_record, list_memory_records
from rabanito.graph import graph_edges_for_nodes, graph_suggestion_edges
from rabanito.indexer import (
    PARSER_VERSION, _existing_source_file, _index_lock, _is_reparse_entry, _normalize_project_excerpt_markdown,
    _project_document_priority,
    _purge_inactive_search_payload, index_all, prune_inactive_search_payload, set_additional_source_enabled_and_sync,
)
from rabanito.interview import QUESTIONS, conduct_interview
from rabanito.onboard import approve_source, preview_source
from rabanito.parsing import ParsedDocument, parse_markdown
from rabanito.search import get_document, recent_documents, related_documents, retrieve_context, search_documents, stats
from rabanito.server import RabanitoHandler, _is_loopback_host, _request_host_is_loopback, serve_dashboard
from rabanito.utils import (
    contains_reparse_component, path_key, redact_sensitive_lines, unclosed_private_key_lines,
    write_json_atomic, write_text_atomic,
)
from rabanito.visibility import register_project_visibility
from http.server import ThreadingHTTPServer


class RabanitoCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Keep every test-created file inside the authorized project directory.
        cls.test_temp_root = Path(__file__).resolve().parent / ".test-temp"
        cls.test_temp_root.mkdir(parents=True, exist_ok=True)

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls.test_temp_root.rmdir()
        except OSError:
            # Preserve any failed-test artifacts for diagnosis instead of deleting broadly.
            pass

    def temporary_directory(self) -> tempfile.TemporaryDirectory[str]:
        return tempfile.TemporaryDirectory(dir=self.test_temp_root)

    def make_settings(self, root: Path) -> Settings:
        vault = root / "Bóveda Unicode"
        projects = root / "Proyectos"
        knowledge = root / "knowledge"
        vault.mkdir()
        projects.mkdir()
        knowledge.mkdir()
        raw = {
            "project_root": str(root), "vault_root": str(vault), "projects_root": str(projects),
            "database_path": str(root / "data" / "brain.db"), "data_dir": str(root / "data"), "knowledge_dir": str(knowledge),
            "max_search_results": 20, "max_context_chars": 5000, "stale_days": 180,
            "source_policy": {
                "obsidian": {"extensions": [".md"], "exclude_dirs": [".obsidian"], "exclude_names": []},
                "projects": {"extensions": [".md"], "metadata_names": ["README.md"], "exclude_dirs": [".git"], "exclude_names": []},
                "internal": {"extensions": [".md"], "exclude_dirs": [], "exclude_names": []},
            }, "additional_sources": [],
        }
        return Settings(root, raw)

    def test_stats_expose_persisted_parser_version_and_tolerate_missing_metadata(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            self.assertIsNone(stats(settings)["parser_version"])
            (settings.vault_root / "Parser.md").write_text("# Parser status\n", encoding="utf-8")
            index_all(settings)
            self.assertEqual(stats(settings)["parser_version"], PARSER_VERSION)

    def test_cli_stats_sanitizes_and_bounds_persisted_scan_summary(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            raw_summary = '{"obsidian":{"seen":1},"filler":"' + ("x" * 300_000) + 'SECRET_STATS_TAIL_SENTINEL"}'
            error_message = "PRIVATE_STATS_ERROR_SENTINEL"
            with Database(settings.database_path) as db:
                db.execute(
                    "INSERT INTO scan_runs(started_at,status,source_summary_json,error_message) VALUES(?,?,?,?)",
                    ("2026-10-13T00:00:00Z", "error", raw_summary, error_message),
                )
                db.commit()
            config_path = settings.root / "config" / "settings.example.json"
            write_json_atomic(config_path, settings.raw)

            programmatic_latest = stats(settings)["latest_scan"]
            self.assertEqual(programmatic_latest["source_summary"], {})
            self.assertTrue(programmatic_latest["source_summary_truncated"])
            self.assertNotIn("source_summary_json", programmatic_latest)
            self.assertNotIn("error_message", programmatic_latest)

            output = StringIO()
            with redirect_stdout(output):
                cli_main(["--config", str(config_path), "stats"])
            payload = json.loads(output.getvalue())
            latest = payload["latest_scan"]
            self.assertEqual(latest["source_summary"], {})
            self.assertTrue(latest["source_summary_truncated"])
            encoded = json.dumps(payload, ensure_ascii=False)
            self.assertNotIn("SECRET_STATS_TAIL_SENTINEL", encoded)
            self.assertNotIn(error_message, encoded)
            self.assertNotIn("error_message", latest)
            self.assertNotIn("source_summary_json", latest)

    def test_audit_scan_query_does_not_read_unneeded_private_columns(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            with Database(settings.database_path) as db:
                db.execute(
                    "INSERT INTO scan_runs(started_at,status,source_summary_json,error_message) VALUES(?,?,?,?)",
                    (
                        "2026-10-13T00:00:00Z", "error",
                        '{"private-kind":{"errors":1},"filler":"' + ("x" * 300_000) + '"}',
                        "PRIVATE_AUDIT_SCAN_ERROR_SENTINEL",
                    ),
                )
                db.commit()

            scan_queries = []

            class CapturingAuditDatabase(Database):
                def one(self, sql, params=()):
                    if "FROM scan_runs" in sql:
                        scan_queries.append(sql)
                    return super().one(sql, params)

            with patch("rabanito.capabilities.Database", CapturingAuditDatabase):
                report = collect_audit(settings)
            self.assertEqual(len(scan_queries), 1)
            self.assertNotIn("SELECT *", scan_queries[0].upper())
            self.assertIn("scan_id", scan_queries[0])
            self.assertNotIn("source_summary_json", scan_queries[0])
            self.assertNotIn("error_message", scan_queries[0])
            encoded = json.dumps(report, ensure_ascii=False)
            self.assertNotIn("PRIVATE_AUDIT_SCAN_ERROR_SENTINEL", encoded)
            self.assertNotIn("source_summary_json", encoded)

    def test_unicode_incremental_index_links_and_retrieval(self) -> None:
        with self.temporary_directory() as temp:
            root = Path(temp)
            settings = self.make_settings(root)
            vault = settings.vault_root
            (vault / "Inicio.md").write_text("---\ntags: [inicio, seguridad]\naliases: [Comienzo]\n---\n# Inicio\n\nConsulta [[Destino]] y [[No Existe]].\n", encoding="utf-8")
            (vault / "Destino.md").write_text("# Destino\n\nContenido verificable de ciberseguridad y arquitectura.\n", encoding="utf-8")
            project = settings.projects_root / "Proyecto Ñ"
            project.mkdir()
            (project / "README.md").write_text("# Proyecto Ñ\n\nArquitectura local con Python.\n", encoding="utf-8")

            first = index_all(settings)
            self.assertGreaterEqual(first["added"], 3)
            self.assertEqual(stats(settings)["documents_active"], 4)  # includes generated project memory
            results = search_documents(settings, "ciberseguridad")
            self.assertTrue(any(item["title"] == "Destino" for item in results))
            context = retrieve_context(settings, "arquitectura", max_chars=2000)
            self.assertTrue(context["fragments"])
            self.assertIn(":", context["fragments"][0]["citation"])
            with Database(settings.database_path) as db:
                links = db.query("SELECT status, target_raw FROM links ORDER BY target_raw")
                destination = db.one("SELECT document_id FROM documents WHERE relative_path='Destino.md' AND status='active'")
                inicio = db.one("SELECT document_id FROM documents WHERE relative_path='Inicio.md' AND status='active'")
            self.assertIn({"status": "resolved", "target_raw": "Destino"}, [dict(row) for row in links])
            self.assertIn({"status": "broken", "target_raw": "No Existe"}, [dict(row) for row in links])
            incoming_related = related_documents(settings, int(destination["document_id"]))
            self.assertTrue(any(
                item["relative_path"] == "Inicio.md" and item["relation_kind"] == "explicit"
                for item in incoming_related
            ))
            with Database(settings.database_path) as db:
                db.execute(
                    "INSERT INTO links(source_document_id,target_raw,target_document_id,relation_type,status,line_number) VALUES(?,?,?,?,?,?)",
                    (int(destination["document_id"]), "Inicio", int(inicio["document_id"]), "wikilink", "resolved", 99),
                )
                db.commit()
            reciprocal = related_documents(settings, int(inicio["document_id"]))
            self.assertEqual(
                sum(item["relative_path"] == "Destino.md" and item["relation_kind"] == "explicit" for item in reciprocal),
                1,
            )

            second = index_all(settings)
            self.assertEqual(second["added"], 0)
            self.assertEqual(second["modified"], 0)
            (vault / "Destino.md").write_text("# Destino\n\nContenido actualizado de arquitectura.\n", encoding="utf-8")
            third = index_all(settings)
            self.assertGreaterEqual(third["modified"], 1)
            with Database(settings.database_path) as db:
                count = db.one("SELECT COUNT(*) AS c FROM documents WHERE absolute_path=?", (str(vault / "Destino.md"),))["c"]
            self.assertEqual(count, 1)
            (vault / "Destino.md").unlink()
            removed = index_all(settings)
            self.assertGreaterEqual(removed["removed"], 1)
            audit = collect_audit(settings)
            self.assertGreaterEqual(audit["counts"]["documents_deleted"], 1)

    def test_index_scan_status_reports_unavailable_sources_without_tombstoning(self) -> None:
        with self.temporary_directory() as temp:
            root = Path(temp)
            settings = self.make_settings(root)
            note = settings.vault_root / "Keep on partial scan.md"
            note.write_text("# Keep on partial scan\n\nRecovery evidence remains indexed.\n", encoding="utf-8")
            index_all(settings)

            settings.raw["vault_root"] = str(root / "Unavailable vault")
            partial = index_all(settings)
            self.assertEqual(partial["status"], "partial")
            self.assertEqual(partial["errors"], 1)
            self.assertEqual(partial["source_summary"]["obsidian"]["errors"], 1)
            with Database(settings.database_path) as db:
                note_status = db.one(
                    "SELECT status FROM documents WHERE relative_path=?", (note.name,),
                )["status"]
                scan = db.one("SELECT * FROM scan_runs ORDER BY scan_id DESC LIMIT 1")
            self.assertEqual(note_status, "active", "a failed source enumeration must never tombstone unseen documents")
            self.assertEqual((scan["status"], scan["errors"], scan["error_message"]), ("partial", 1, None))
            projected = RabanitoHandler._dashboard_scan_summary(dict(scan))
            self.assertEqual(projected["source_summary"], {
                "obsidian": {"seen": 0, "added": 0, "modified": 0, "unchanged": 0, "skipped": 0, "errors": 1},
            })

            settings.raw["vault_root"] = str(root / "Unavailable vault 2")
            settings.raw["projects_root"] = str(root / "Unavailable projects")
            settings.raw["knowledge_dir"] = str(root / "Unavailable knowledge")
            failed = index_all(settings)
            self.assertEqual(failed["status"], "error")
            self.assertEqual(failed["errors"], 3)
            with Database(settings.database_path) as db:
                note_status = db.one(
                    "SELECT status FROM documents WHERE relative_path=?", (note.name,),
                )["status"]
                scan = dict(db.one("SELECT * FROM scan_runs ORDER BY scan_id DESC LIMIT 1"))
            self.assertEqual(note_status, "active")
            self.assertEqual((scan["status"], scan["errors"]), ("error", 3))
            projected = RabanitoHandler._dashboard_scan_summary(scan)
            self.assertEqual(
                {kind: counts["errors"] for kind, counts in projected["source_summary"].items()},
                {"internal": 1, "obsidian": 1, "projects": 1},
            )

    def test_direct_document_and_relation_reads_hide_tombstones(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            retired_note = settings.vault_root / "Retired.md"
            retired_note.write_text(
                "---\nprivate_marker: stale-frontmatter\n---\n# Retired\n\n[[Current]]\n", encoding="utf-8",
            )
            (settings.vault_root / "Current.md").write_text("# Current\n\nActive note.\n", encoding="utf-8")
            index_all(settings)
            with Database(settings.database_path) as db:
                identifiers = {
                    str(row["relative_path"]): int(row["document_id"])
                    for row in db.query("SELECT relative_path,document_id FROM documents WHERE status='active'")
                }
            retired_id = identifiers["Retired.md"]
            current_id = identifiers["Current.md"]

            retired_note.unlink()
            index_all(settings)
            with Database(settings.database_path) as db:
                self.assertEqual(db.one("SELECT status FROM documents WHERE document_id=?", (retired_id,))["status"], "deleted")
                self.assertEqual(db.one("SELECT status FROM links WHERE source_document_id=?", (retired_id,))["status"], "resolved")
            self.assertIsNone(get_document(settings, retired_id))
            self.assertEqual(related_documents(settings, retired_id), [])
            current = get_document(settings, current_id)
            self.assertIsNotNone(current)
            self.assertFalse(any(link["source_title"] == "Retired" for link in current["incoming_links"]))

            handler = type("TestRabanitoHandler", (RabanitoHandler,), {"settings": settings})
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with self.assertRaises(HTTPError) as hidden_tombstone:
                    urlopen(f"http://127.0.0.1:{server.server_address[1]}/api/doc/{retired_id}")
                self.assertEqual(hidden_tombstone.exception.code, 404)
                hidden_tombstone.exception.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_document_change_journal_tracks_transitions_without_idempotent_noise(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            note = settings.vault_root / "Memoria Ñ.md"
            note.write_text("# Primera versión\n\nContenido inicial verificable.\n", encoding="utf-8")

            first = index_all(settings)
            self.assertEqual(first["added"], 1)
            document_id: int
            with Database(settings.database_path) as db:
                document_id = int(db.one(
                    "SELECT document_id FROM documents WHERE relative_path=? AND source_kind='obsidian'",
                    (note.name,),
                )["document_id"])
                events = db.query(
                    "SELECT change_type,reason FROM document_changes WHERE document_id=? ORDER BY change_id",
                    (document_id,),
                )
            self.assertEqual([tuple(row) for row in events], [("added", "new_document")])

            second = index_all(settings)
            self.assertEqual(second["unchanged"], 1)
            note.write_text("# Segunda versión\n\nContenido actualizado con una prueba.\n", encoding="utf-8")
            modified = index_all(settings)
            self.assertEqual(modified["modified"], 1)
            note.unlink()
            removed = index_all(settings)
            self.assertEqual(removed["removed"], 1)
            note.write_text("# Segunda versión\n\nContenido actualizado con una prueba.\n", encoding="utf-8")
            restored = index_all(settings)
            self.assertEqual(restored["modified"], 1)
            settings.raw["source_policy"]["obsidian"]["max_file_bytes"] = 1
            skipped = index_all(settings)
            self.assertEqual(skipped["skipped"], 1)
            with Database(settings.database_path) as db:
                skipped_fts = int(db.one(
                    "SELECT COUNT(*) AS c FROM documents_fts WHERE document_id=?", (str(document_id),)
                )["c"])
                skipped_chunks = int(db.one(
                    "SELECT COUNT(*) AS c FROM document_chunks WHERE document_id=?", (document_id,)
                )["c"])
                skipped_chunk_fts = int(db.one(
                    "SELECT COUNT(*) AS c FROM chunks_fts WHERE document_id=?", (str(document_id),)
                )["c"])
            self.assertEqual((skipped_fts, skipped_chunks, skipped_chunk_fts), (1, 1, 1))
            repeated_skip = index_all(settings)
            self.assertEqual(repeated_skip["skipped"], 1)
            settings.raw["source_policy"]["obsidian"].pop("max_file_bytes")
            restored_again = index_all(settings)
            self.assertEqual(restored_again["modified"], 1)
            with Database(settings.database_path) as db:
                self.assertEqual(db.one(
                    "SELECT COUNT(*) AS c FROM documents_fts WHERE document_id=?", (str(document_id),)
                )["c"], 1)
                self.assertGreater(db.one(
                    "SELECT COUNT(*) AS c FROM chunks_fts WHERE document_id=?", (str(document_id),)
                )["c"], 0)

            with Database(settings.database_path) as db:
                events = db.query(
                    "SELECT change_type,reason FROM document_changes WHERE document_id=? ORDER BY change_id",
                    (document_id,),
                )
                scans_without_events = db.query(
                    """SELECT s.scan_id FROM scan_runs s LEFT JOIN document_changes c ON c.scan_id=s.scan_id
                       WHERE s.unchanged=1 GROUP BY s.scan_id HAVING COUNT(c.change_id)=0"""
                )
                self.assertEqual(db.one("PRAGMA integrity_check")[0], "ok")
                self.assertEqual(db.query("PRAGMA foreign_key_check"), [])
            self.assertEqual(
                [tuple(row) for row in events],
                [("added", "new_document"), ("modified", "content_changed"),
                 ("removed", "not_seen_in_complete_scan"), ("restored", "source_reappeared"),
                 ("skipped", "file_size_limit"), ("restored", "source_reappeared")],
            )
            self.assertTrue(scans_without_events, "idempotent scans must not synthesize document events")

    def test_document_changes_cli_is_bounded_and_project_scoped(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project_a = settings.projects_root / "CLI Proyecto A"
            project_a.mkdir()
            (project_a / "README.md").write_text("# CLI Proyecto A\nArquitectura documentada.\n", encoding="utf-8")
            project_b = settings.projects_root / "CLI Proyecto B"
            project_b.mkdir()
            (project_b / "README.md").write_text("# CLI Proyecto B\nOtra arquitectura.\n", encoding="utf-8")
            (settings.vault_root / "Nota general.md").write_text("# Nota general\nContexto compartido.\n", encoding="utf-8")
            index_all(settings)
            config_path = settings.root / "config" / "settings.example.json"
            write_json_atomic(config_path, settings.raw)

            output = StringIO()
            with redirect_stdout(output):
                cli_main(["--config", str(config_path), "changes", "--project", "cli proyecto a", "--limit", "10"])
            payload = json.loads(output.getvalue())
            self.assertTrue(payload["changes"])
            self.assertTrue(all(change.get("project") == "CLI Proyecto A" for change in payload["changes"]))
            self.assertFalse(any(change.get("project") == "CLI Proyecto B" for change in payload["changes"]))
            self.assertTrue(all("relative_path" in change and "absolute_path" not in change for change in payload["changes"]))
            self.assertNotIn(str(settings.projects_root), json.dumps(payload, ensure_ascii=False))

            empty_output = StringIO()
            with redirect_stdout(empty_output):
                cli_main(["--config", str(config_path), "changes", "--limit", "0"])
            self.assertEqual(json.loads(empty_output.getvalue()), {"changes": []})
            with self.assertRaises(SystemExit) as missing_project:
                with redirect_stdout(StringIO()):
                    cli_main(["--config", str(config_path), "changes", "--project", "No existe"])
            self.assertEqual(str(missing_project.exception), "active project not found")

            # Config exclusion is authoritative immediately, before a future scan
            # updates the cached database status.
            settings.raw["excluded_projects"] = [str(project_a)]
            write_json_atomic(config_path, settings.raw)
            with self.assertRaises(SystemExit) as excluded_project:
                with redirect_stdout(StringIO()):
                    cli_main(["--config", str(config_path), "changes", "--project", "CLI Proyecto A"])
            self.assertEqual(str(excluded_project.exception), "active project not found")

    def test_live_project_exclusion_hides_stale_index_from_all_core_retrieval(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "SensitiveProject"
            project.mkdir()
            (project / "README.md").write_text(
                "---\ntags: [project-private-tag]\n---\n# SensitiveProject\n\nproject-private sentinel architecture note\n",
                encoding="utf-8",
            )
            index_all(settings)
            add_memory_record(
                settings, project=project.name, problem="Need a documented choice", statement="Use local SQLite",
                record_type="decision", status="proposed",
            )
            index_all(settings)
            with Database(settings.database_path) as db:
                project_documents = db.query(
                    "SELECT document_id FROM documents WHERE project_root_path=? AND status='active'",
                    (str(project),),
                )
            self.assertTrue(project_documents)
            document_id = int(project_documents[0]["document_id"])
            self.assertTrue(search_documents(settings, "project-private sentinel", source_kind="projects"))
            self.assertTrue(retrieve_context(settings, "project-private sentinel", source_kind="projects")["fragments"])
            self.assertIsNotNone(get_document(settings, document_id))
            self.assertTrue(list_memory_records(settings, project=project.name))
            before = stats(settings)
            self.assertEqual(before["projects"], 1)

            # Config is authoritative immediately; SQLite deliberately remains stale.
            settings.raw["excluded_projects"] = [str(project)]
            with Database(settings.database_path) as db:
                self.assertEqual(
                    db.one("SELECT status FROM projects WHERE root_path=?", (str(project),))["status"],
                    "active",
                )
                project_document_count = db.one(
                    "SELECT COUNT(*) AS c FROM documents WHERE project_root_path=? AND status='active'",
                    (str(project),),
                )["c"]
                decision = db.one(
                    "SELECT document_id,frontmatter_json FROM documents "
                    "WHERE source_kind='internal' AND project_name=? AND relative_path LIKE 'decisions/%' AND status='active'",
                    (project.name,),
                )
                self.assertIsNotNone(decision)
                decision_frontmatter = json.loads(decision["frontmatter_json"] or "{}")
                decision_frontmatter.pop("project_root", None)
                db.execute(
                    "UPDATE documents SET project_root_path=NULL,frontmatter_json=? WHERE document_id=?",
                    (json.dumps(decision_frontmatter), int(decision["document_id"])),
                )
                # Simulate a legacy/corrupt project row without an authorized root.
                db.execute("UPDATE documents SET project_root_path=NULL WHERE document_id=?", (document_id,))
                db.commit()
            self.assertFalse(search_documents(settings, "project-private sentinel", source_kind="projects"))
            self.assertFalse(recent_documents(settings, source_kind="projects"))
            self.assertFalse(retrieve_context(settings, "project-private sentinel", source_kind="projects")["fragments"])
            self.assertIsNone(get_document(settings, document_id))
            self.assertFalse(related_documents(settings, document_id))
            self.assertFalse(list_memory_records(settings, project=project.name))
            settings.raw["excluded_projects"] = [project.name]
            self.assertFalse(search_documents(settings, "project-private sentinel", source_kind="projects"))
            settings.raw["excluded_projects"] = [str(project)]
            with self.assertRaisesRegex(ValueError, "Proyecto no encontrado"):
                add_memory_record(
                    settings, project=project.name, problem="Should be blocked", statement="New hidden record",
                    record_type="decision", status="proposed",
                )
            after = stats(settings)
            self.assertEqual(after["documents_active"], before["documents_active"] - project_document_count)
            self.assertEqual(after["projects"], 0)
            self.assertEqual(after["unique_tags"], before["unique_tags"] - 1)
            audit = collect_audit(settings)
            self.assertEqual(audit["counts"]["documents_active"], after["documents_active"])
            self.assertNotIn("project-private sentinel", json.dumps(audit, ensure_ascii=False))
            self.assertNotIn("SensitiveProject", json.dumps(audit, ensure_ascii=False))
            build_link_suggestions(settings)
            project_ids = {int(row["document_id"]) for row in project_documents}
            with Database(settings.database_path) as db:
                suggestions = db.query("SELECT source_document_id,target_document_id FROM link_suggestions WHERE status='suggested'")
            self.assertFalse(any(
                int(row["source_document_id"]) in project_ids or int(row["target_document_id"]) in project_ids
                for row in suggestions
            ))

            handler = type("TestRabanitoHandler", (RabanitoHandler,), {"settings": settings})
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                with urlopen(origin + "/api/projects") as response:
                    self.assertFalse(json.loads(response.read())["projects"])
                with urlopen(origin + "/api/projects?all=1") as response:
                    visible_excluded = json.loads(response.read())["projects"]
                self.assertEqual(visible_excluded[0]["status"], "excluded")
                self.assertNotIn("technologies", visible_excluded[0])
                with urlopen(origin + "/api/categories") as response:
                    self.assertNotIn("projects/SensitiveProject", json.loads(response.read())["categories"])
                with urlopen(origin + "/api/tags") as response:
                    tags = json.loads(response.read())["tags"]
                self.assertNotIn("project-private-tag", [item["tag"] for item in tags])
                with self.assertRaises(HTTPError) as hidden_document:
                    urlopen(origin + f"/api/doc/{document_id}")
                self.assertEqual(hidden_document.exception.code, 404)
                hidden_document.exception.close()
                open_request = Request(
                    origin + f"/api/open/{document_id}", data=b"{}", method="POST",
                    headers={"Content-Type": "application/json", "Origin": origin},
                )
                with self.assertRaises(HTTPError) as hidden_open:
                    urlopen(open_request)
                self.assertEqual(hidden_open.exception.code, 404)
                hidden_open.exception.close()

                def post(endpoint: str, payload: dict[str, object]) -> dict[str, object]:
                    request = Request(
                        origin + endpoint, data=json.dumps(payload).encode(), method="POST",
                        headers={"Content-Type": "application/json", "Origin": origin},
                    )
                    with urlopen(request) as response:
                        return json.loads(response.read())

                self.assertFalse(post("/api/search", {"q": "project-private sentinel"})["results"])
                self.assertFalse(post("/api/context", {"q": "project-private sentinel"})["fragments"])
                graph = post("/api/graph", {"limit": 100})
                self.assertFalse(any(node["title"] == "SensitiveProject" for node in graph["nodes"]))
                self.assertFalse(post("/api/decisions", {})["records"])
                config_path = settings.root / "config" / "settings.example.json"
                write_json_atomic(config_path, settings.raw)
                cli_graph = StringIO()
                with redirect_stdout(cli_graph):
                    cli_main(["--config", str(config_path), "graph", "--limit", "100"])
                cli_graph_payload = json.loads(cli_graph.getvalue())
                self.assertFalse(any(node["title"] == "SensitiveProject" for node in cli_graph_payload["nodes"]))
                with self.assertRaises(HTTPError) as excluded_scope:
                    post("/api/search", {"q": "project-private sentinel", "project_id": 1})
                self.assertEqual(excluded_scope.exception.code, 400)
                excluded_scope.exception.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_unrooted_project_visibility_fails_closed_and_path_exclusions_match_legacy_names(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            hidden_root = settings.projects_root / "HiddenLegacyProject"
            settings.raw["excluded_projects"] = [str(hidden_root)]
            with Database(settings.database_path) as db:
                register_project_visibility(db, settings)
                result = db.one(
                    "SELECT "
                    "rabanito_project_visible('projects','UnknownProject',NULL) AS unrooted_project, "
                    "rabanito_project_visible('internal','HiddenLegacyProject',NULL) AS named_legacy_memory, "
                    "rabanito_project_visible('projects','HiddenLegacyProject',?) AS same_name_other_root, "
                    "rabanito_project_visible('projects','ProjectsContainer',?) AS projects_container, "
                    "rabanito_project_visible('internal','GeneralMemory',NULL) AS general_memory"
                    , (
                        str(settings.projects_root / "AnotherParent" / "HiddenLegacyProject"),
                        str(settings.projects_root),
                    )
                )
            self.assertEqual(int(result["unrooted_project"]), 0)
            self.assertEqual(int(result["named_legacy_memory"]), 0)
            self.assertEqual(int(result["same_name_other_root"]), 1)
            self.assertEqual(int(result["projects_container"]), 0)
            self.assertEqual(int(result["general_memory"]), 1)

    def test_change_journal_rolls_back_with_failed_scan_transaction(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            note = settings.vault_root / "Atomicidad.md"
            original = "# Atomicidad\nEste archivo permanece intacto en origen.\n"
            note.write_text(original, encoding="utf-8")
            with patch("rabanito.indexer._resolve_links", side_effect=RuntimeError("simulated post-index failure")):
                with self.assertRaisesRegex(RuntimeError, "simulated post-index failure"):
                    index_all(settings)

            with Database(settings.database_path) as db:
                active_documents = int(db.one("SELECT COUNT(*) AS c FROM documents WHERE status='active'")["c"])
                scan_runs = int(db.one("SELECT COUNT(*) AS c FROM scan_runs")["c"])
                changes = int(db.one("SELECT COUNT(*) AS c FROM document_changes")["c"])
                integrity = db.one("PRAGMA integrity_check")[0]
                foreign_keys = db.query("PRAGMA foreign_key_check")
            self.assertEqual((active_documents, scan_runs, changes), (0, 0, 0))
            self.assertEqual(integrity, "ok")
            self.assertEqual(foreign_keys, [])
            self.assertEqual(note.read_text(encoding="utf-8"), original)

    def test_explicit_inactive_search_payload_purge_is_backup_gated_and_atomic(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            note = settings.vault_root / "Purge atómico.md"
            note.write_text("# Purge atómico\n\nrollbackneedle contenido preservado.\n", encoding="utf-8")
            index_all(settings)
            note.unlink()
            index_all(settings)
            with Database(settings.database_path) as db:
                document_id = int(db.one(
                    "SELECT document_id FROM documents WHERE relative_path=?", (note.name,)
                )["document_id"])
                original_scan_count = int(db.one("SELECT COUNT(*) AS c FROM scan_runs")["c"])
                original_change_count = int(db.one("SELECT COUNT(*) AS c FROM document_changes")["c"])

            def purge_then_fail(db, inactive_ids):
                _purge_inactive_search_payload(db, inactive_ids)
                raise RuntimeError("injected failure after purge")

            with patch("rabanito.indexer._purge_inactive_search_payload", side_effect=purge_then_fail):
                with self.assertRaisesRegex(RuntimeError, "injected failure after purge"):
                    prune_inactive_search_payload(settings, apply=True)

            with Database(settings.database_path) as db:
                row = db.one("SELECT status FROM documents WHERE document_id=?", (document_id,))
                document_fts_count = int(db.one(
                    "SELECT COUNT(*) AS c FROM documents_fts WHERE document_id=?", (str(document_id),)
                )["c"])
                chunk_count = int(db.one(
                    "SELECT COUNT(*) AS c FROM document_chunks WHERE document_id=?", (document_id,)
                )["c"])
                scan_count = int(db.one("SELECT COUNT(*) AS c FROM scan_runs")["c"])
                change_count = int(db.one("SELECT COUNT(*) AS c FROM document_changes")["c"])
                integrity = db.one("PRAGMA integrity_check")[0]
            self.assertEqual(row["status"], "deleted")
            self.assertEqual(document_fts_count, 1)
            self.assertGreater(chunk_count, 0)
            self.assertEqual((scan_count, change_count), (original_scan_count, original_change_count))
            self.assertEqual(integrity, "ok")
            backups = list((settings.data_dir / "backups").glob("pre-inactive-search-purge-*.db"))
            self.assertEqual(len(backups), 1, "the verified pre-purge backup is retained after rollback")
            backup_db = sqlite3.connect(backups[0].resolve().as_uri() + "?mode=ro", uri=True)
            try:
                self.assertGreater(backup_db.execute(
                    "SELECT COUNT(*) FROM documents_fts WHERE document_id=?", (str(document_id),)
                ).fetchone()[0], 0)
            finally:
                backup_db.close()

            applied = prune_inactive_search_payload(settings, apply=True)
            self.assertEqual(applied["status"], "applied")
            with Database(settings.database_path) as db:
                self.assertEqual(db.one(
                    "SELECT COUNT(*) AS c FROM documents_fts WHERE document_id=?", (str(document_id),)
                )["c"], 0)
                self.assertEqual(db.one(
                    "SELECT COUNT(*) AS c FROM document_chunks WHERE document_id=?", (document_id,)
                )["c"], 0)

    def test_explicit_search_payload_purge_batches_more_than_four_hundred_tombstones(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            notes = [settings.vault_root / f"Batch-{number:03d}.md" for number in range(405)]
            for number, note in enumerate(notes):
                note.write_text(
                    f"# Batch {number:03d}\n\nBatch-boundary recovery fact {number}.\n",
                    encoding="utf-8",
                )
            indexed = index_all(settings)
            self.assertEqual(indexed["added"], 405)
            for note in notes:
                note.unlink()
            removed = index_all(settings)
            self.assertEqual(removed["removed"], 405)

            preview = prune_inactive_search_payload(settings)
            self.assertEqual(preview["inactive_documents"], 405)
            self.assertEqual(preview["documents_with_payload"], 405)
            self.assertEqual(preview["documents_fts_rows"], 405)
            self.assertEqual(preview["document_chunks_rows"], 405)
            self.assertEqual(preview["chunks_fts_rows"], 405)

            applied = prune_inactive_search_payload(settings, apply=True)
            self.assertEqual(applied["status"], "applied")
            self.assertEqual(applied["documents_with_payload"], 405)
            self.assertEqual(applied["integrity_check"], "ok")
            backup_path = settings.root / applied["backup"]
            backup_db = sqlite3.connect(backup_path.resolve().as_uri() + "?mode=ro", uri=True)
            try:
                self.assertEqual(backup_db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertEqual(backup_db.execute("SELECT COUNT(*) FROM documents_fts").fetchone()[0], 405)
            finally:
                backup_db.close()
            with Database(settings.database_path) as db:
                self.assertEqual(db.one("SELECT COUNT(*) AS c FROM documents WHERE status='deleted'")["c"], 405)
                self.assertEqual(db.one("SELECT COUNT(*) AS c FROM documents_fts")["c"], 0)
                self.assertEqual(db.one("SELECT COUNT(*) AS c FROM document_chunks")["c"], 0)
                self.assertEqual(db.one("SELECT COUNT(*) AS c FROM chunks_fts")["c"], 0)
                self.assertEqual(db.one("PRAGMA integrity_check")[0], "ok")

    def test_context_respects_small_and_zero_character_budgets(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "Budget.md").write_text(
                "# Budget\n\n" + ("budgetneedle context fragment. " * 100), encoding="utf-8",
            )
            index_all(settings)

            bounded = retrieve_context(settings, "budgetneedle", limit=5, max_chars=37)
            self.assertEqual(bounded["max_chars"], 37)
            self.assertEqual(bounded["characters"], 37)
            self.assertEqual(sum(len(fragment["text"]) for fragment in bounded["fragments"]), 37)
            self.assertTrue(bounded["fragments"])

            config_path = settings.root / "config" / "settings.example.json"
            write_json_atomic(config_path, settings.raw)
            cli_output = StringIO()
            with redirect_stdout(cli_output):
                cli_main(["--config", str(config_path), "context", "budgetneedle", "--max-chars", "37"])
            cli_context = json.loads(cli_output.getvalue())
            self.assertEqual(cli_context["characters"], 37)
            self.assertLessEqual(sum(len(fragment["text"]) for fragment in cli_context["fragments"]), 37)

            empty = retrieve_context(settings, "budgetneedle", max_chars=0)
            self.assertEqual(empty["max_chars"], 0)
            self.assertEqual(empty["characters"], 0)
            self.assertEqual(empty["fragments"], [])

    def test_cli_json_output_escapes_unicode_for_legacy_windows_code_pages(self) -> None:
        class Cp1252Capture(StringIO):
            @property
            def encoding(self) -> str:
                return "cp1252"

            def write(self, value: str) -> int:
                value.encode(self.encoding)
                return super().write(value)

        output = Cp1252Capture()
        payload = {"fragment": "café ≤ 5 min 😀"}
        with patch("rabanito.cli.sys.stdout", output):
            cli_json(payload)

        rendered = output.getvalue()
        self.assertIn(r"\u2264", rendered)
        self.assertIn(r"\ud83d\ude00", rendered)
        self.assertEqual(json.loads(rendered), payload)

    def test_cli_json_output_preserves_unicode_for_utf8_streams(self) -> None:
        class Utf8Capture(StringIO):
            @property
            def encoding(self) -> str:
                return "utf-8"

        output = Utf8Capture()
        with patch("rabanito.cli.sys.stdout", output):
            cli_json({"fragment": "café ≤ 5 min 😀"})
        self.assertIn("café ≤ 5 min 😀", output.getvalue())

    def test_zero_result_limits_are_honored_across_search_context_relations_and_cli(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "Limit A.md").write_text(
                "# Limit A\n\nlimitneedle links to [[Limit B]].\n", encoding="utf-8",
            )
            (settings.vault_root / "Limit B.md").write_text(
                "# Limit B\n\nlimitneedle has a context fragment.\n", encoding="utf-8",
            )
            index_all(settings)

            self.assertTrue(search_documents(settings, "limitneedle", limit=1))
            self.assertEqual(search_documents(settings, "limitneedle", limit=0), [])
            self.assertEqual(recent_documents(settings, limit=0), [])
            context = retrieve_context(settings, "limitneedle", limit=0, max_chars=2000)
            self.assertEqual(context["limit"], 0)
            self.assertEqual(context["max_chars"], 2000)
            self.assertEqual(context["characters"], 0)
            self.assertEqual(context["fragments"], [])
            with Database(settings.database_path) as db:
                row = db.one("SELECT document_id FROM documents WHERE relative_path='Limit A.md' AND status='active'")
            self.assertTrue(related_documents(settings, int(row["document_id"]), limit=1))
            self.assertEqual(related_documents(settings, int(row["document_id"]), limit=0), [])

            config_path = settings.root / "config" / "settings.example.json"
            write_json_atomic(config_path, settings.raw)
            for args in (
                ["search", "limitneedle", "--limit", "0"],
                ["context", "limitneedle", "--limit", "0", "--max-chars", "2000"],
                ["graph", "--limit", "0"],
            ):
                cli_output = StringIO()
                with redirect_stdout(cli_output):
                    cli_main(["--config", str(config_path), *args])
                payload = json.loads(cli_output.getvalue())
                if args[0] in {"search", "graph"}:
                    if args[0] == "search":
                        self.assertEqual(payload, [])
                    else:
                        self.assertEqual(payload["nodes"], [])
                        self.assertEqual(payload["edges"], [])
                        self.assertEqual(payload["node_limit"], 0)
                        self.assertEqual(payload["total_matches"], 2)
                        self.assertTrue(payload["truncated"])
                else:
                    self.assertEqual(payload["limit"], 0)
                    self.assertEqual(payload["fragments"], [])

    def test_graph_queries_load_only_selected_nodes_and_incident_suggestions(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "Alpha.md").write_text("# Alpha\n\n[[Beta]]\n", encoding="utf-8")
            (settings.vault_root / "Beta.md").write_text("# Beta\n", encoding="utf-8")
            (settings.vault_root / "Gamma.md").write_text("# Gamma\n", encoding="utf-8")
            (settings.vault_root / "Delta.md").write_text("# Delta\n\n[[Gamma]]\n", encoding="utf-8")
            index_all(settings)

            with Database(settings.database_path) as db:
                suggestion_indexes = {
                    row["name"] for row in db.query("PRAGMA index_list(link_suggestions)")
                }
                self.assertIn("idx_suggestions_status_source", suggestion_indexes)
                self.assertIn("idx_suggestions_status_target", suggestion_indexes)
                ids = {
                    row["relative_path"]: int(row["document_id"])
                    for row in db.query("SELECT document_id, relative_path FROM documents WHERE status='active'")
                }
                alpha_id, beta_id = ids["Alpha.md"], ids["Beta.md"]
                gamma_id, delta_id = ids["Gamma.md"], ids["Delta.md"]
                db.execute(
                    "INSERT INTO link_suggestions(source_document_id,target_document_id,score,reason,created_at) VALUES(?,?,?,?,?)",
                    (alpha_id, gamma_id, 0.8, "fixture", "2026-10-13T00:00:00+00:00"),
                )
                db.execute(
                    "INSERT INTO link_suggestions(source_document_id,target_document_id,score,reason,created_at) VALUES(?,?,?,?,?)",
                    (delta_id, gamma_id, 0.7, "unrelated fixture", "2026-10-13T00:00:00+00:00"),
                )
                db.execute(
                    "INSERT INTO link_suggestions(source_document_id,target_document_id,score,reason,created_at) VALUES(?,?,?,?,?)",
                    (gamma_id, alpha_id, 0.6, "incoming fixture", "2026-10-13T00:00:00+00:00"),
                )
                db.commit()

                statements: list[str] = []
                original_query = db.query

                def capture_query(sql, params=()):
                    statements.append(sql.casefold())
                    return original_query(sql, params)

                with patch.object(db, "query", side_effect=capture_query):
                    edges = graph_edges_for_nodes(db, {alpha_id, beta_id}, include_suggestions=True)
                    incident = graph_suggestion_edges(db, {alpha_id, beta_id})

            self.assertEqual([(edge["source"], edge["target"], edge["kind"]) for edge in edges], [(alpha_id, beta_id, "explicit")])
            self.assertEqual(
                [(int(edge["source"]), int(edge["target"])) for edge in incident],
                [(alpha_id, gamma_id), (gamma_id, alpha_id)],
            )
            edge_queries = [sql for sql in statements if " from links " in sql or " from link_suggestions " in sql]
            self.assertTrue(edge_queries)
            self.assertTrue(all("source_document_id in (" in sql or "target_document_id in (" in sql for sql in edge_queries))

    def test_graph_edge_queries_chunk_large_node_sets_without_duplicates(self) -> None:
        class FakeDatabase:
            def __init__(self):
                self.calls: list[tuple[str, tuple[int, ...]]] = []

            def query(self, sql, params=()):
                normalized = sql.casefold()
                bound = tuple(int(value) for value in params)
                self.calls.append((normalized, bound))
                if " from links " in normalized and "source_document_id in (" in normalized and 450 in bound:
                    return [{"source": 450, "target": 451, "kind": "explicit", "status": "resolved"}]
                if " from link_suggestions " in normalized and (
                    ("source_document_id in (" in normalized and 450 in bound)
                    or ("target_document_id in (" in normalized and 451 in bound)
                ):
                    return [{"source": 450, "target": 451, "kind": "suggested", "status": "suggested", "score": 0.8}]
                return []

        db = FakeDatabase()
        edges = graph_edges_for_nodes(db, range(1, 452), include_suggestions=True)
        self.assertEqual([(edge["source"], edge["target"], edge["kind"]) for edge in edges], [
            (450, 451, "explicit"), (450, 451, "suggested"),
        ])
        self.assertTrue(db.calls)
        self.assertTrue(all(len(params) <= 450 for _, params in db.calls))

    def test_existing_database_recreates_missing_graph_suggestion_indexes(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            with Database(settings.database_path) as db:
                db.execute("DROP INDEX idx_suggestions_status_source")
                db.execute("DROP INDEX idx_suggestions_status_target")
            with Database(settings.database_path) as db:
                indexes = {row["name"] for row in db.query("PRAGMA index_list(link_suggestions)")}
            self.assertIn("idx_suggestions_status_source", indexes)
            self.assertIn("idx_suggestions_status_target", indexes)

    def test_yaml_block_lists_do_not_keep_empty_initial_scalar(self) -> None:
        parsed = parse_markdown(
            Path("Note.md"),
            raw_text="---\nevidence:\n  - 'project:README.md'\ntags:\n  - memoria\n---\n# Note\n",
        )
        self.assertEqual(parsed.frontmatter["evidence"], ["project:README.md"])
        self.assertEqual(parsed.frontmatter["tags"], ["memoria"])

    def test_yaml_literal_and_folded_block_scalars_preserve_indentation_and_chomping(self) -> None:
        parsed = parse_markdown(
            Path("Blocks.md"),
            raw_text=(
                "---\n"
                "literal: |\n  first line\n  second line\n\n  paragraph\n"
                "folded: >- # folded description\n  first line\n  second line\n\n  paragraph\n"
                "more_indented: >\n  ordinary\n   preserve line break\n  ordinary again\n"
                "indented: >2-\n  first line\n  second line\n"
                "keep: |+\n  trailing\n\n\n"
                "separator: done\n"
                "quoted_marker: |\n  text\n  ---\n  still text\n"
                "---\n# Blocks\n"
            ),
        )
        self.assertEqual(parsed.frontmatter["literal"], "first line\nsecond line\n\nparagraph\n")
        self.assertEqual(parsed.frontmatter["folded"], "first line second line\nparagraph")
        self.assertEqual(parsed.frontmatter["more_indented"], "ordinary\n preserve line break\nordinary again\n")
        self.assertEqual(parsed.frontmatter["indented"], "first line second line")
        self.assertEqual(parsed.frontmatter["keep"], "trailing\n\n\n")
        self.assertEqual(parsed.frontmatter["quoted_marker"], "text\n---\nstill text\n")
        self.assertEqual(parsed.frontmatter["separator"], "done")
        self.assertTrue(parsed.text.startswith("# Blocks"))

    def test_parser_version_migration_rebuilds_legacy_block_scalar_metadata(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            note = settings.vault_root / "BlockScalar.md"
            note.write_text(
                "---\ndescription: >-\n  first line\n  second line\n---\n# Block scalar\n",
                encoding="utf-8",
            )
            index_all(settings)
            with Database(settings.database_path) as db:
                db.execute(
                    "UPDATE documents SET frontmatter_json=? WHERE relative_path=?",
                    (json.dumps({"description": ">-"}), note.name),
                )
                db.execute("UPDATE meta SET value='8' WHERE key='parser_version'")
                db.commit()
            migration = index_all(settings)
            self.assertEqual(migration["modified"], 1)
            with Database(settings.database_path) as db:
                row = db.one("SELECT frontmatter_json FROM documents WHERE relative_path=?", (note.name,))
                parser_version = db.one("SELECT value FROM meta WHERE key='parser_version'")["value"]
            self.assertEqual(json.loads(row["frontmatter_json"]), {"description": "first line second line"})
            self.assertEqual(parser_version, str(PARSER_VERSION))

    def test_yaml_flow_sequences_preserve_quoted_commas_and_nesting(self) -> None:
        quoted = parse_markdown(
            Path("Quoted.md"),
            raw_text=(
                "---\nproject: 'O''Brien'\naliases: [\"Alpha, Beta\", \"Gamma\"]\n"
                "authors: ['O''Brien, PhD', 'Ada, Lovelace']\n"
                "groups: [[\"A, B\"], [\"C\", \"D\"]]\n---\n# Quoted\n"
            ),
        )
        self.assertEqual(quoted.frontmatter["project"], "O'Brien")
        self.assertEqual(quoted.frontmatter["aliases"], ["Alpha, Beta", "Gamma"])
        self.assertEqual(quoted.frontmatter["authors"], ["O'Brien, PhD", "Ada, Lovelace"])
        self.assertEqual(quoted.frontmatter["groups"], [["A, B"], ["C", "D"]])

    def test_yaml_inline_comments_respect_quotes_and_embedded_hashes(self) -> None:
        parsed = parse_markdown(
            Path("Comments.md"),
            raw_text=(
                "---\nname: \"Hash # stays\" # annotation\n"
                "tags: [alpha, beta] # annotation\n"
                "description: plain value # annotation\n"
                "url: https://example.invalid/path#fragment\n---\n# Comments\n"
            ),
        )
        self.assertEqual(parsed.frontmatter["name"], "Hash # stays")
        self.assertEqual(parsed.frontmatter["tags"], ["alpha", "beta"])
        self.assertEqual(parsed.frontmatter["description"], "plain value")
        self.assertEqual(parsed.frontmatter["url"], "https://example.invalid/path#fragment")

    def test_yaml_double_quoted_escapes_decode_and_preserve_invalid_sequences(self) -> None:
        parsed = parse_markdown(
            Path("Escapes.md"),
            raw_text=r'''---
description: "line\nnext"
quote: "say \"hello\""
path: "C:\\Temp\\notes"
unicode: "\u03A9 \U0001F600"
nested: ["tab\tvalue", "backslash: \\"]
invalid: "keep\q and \x4G"
---
# Escapes
''',
        )
        self.assertEqual(parsed.frontmatter["description"], "line\nnext")
        self.assertEqual(parsed.frontmatter["quote"], 'say "hello"')
        self.assertEqual(parsed.frontmatter["path"], "C:\\Temp\\notes")
        self.assertEqual(parsed.frontmatter["unicode"], "Ω 😀")
        self.assertEqual(parsed.frontmatter["nested"], ["tab\tvalue", "backslash: \\"])
        self.assertEqual(parsed.frontmatter["invalid"], r"keep\q and \x4G")

    def test_parser_version_migration_rebuilds_legacy_double_quoted_metadata(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            note = settings.vault_root / "Escapes.md"
            note.write_text(
                r'''---
aliases: ["Line\nBreak", "Quoted: \"Name\""]
---
# Escapes
''',
                encoding="utf-8",
            )
            index_all(settings)
            with Database(settings.database_path) as db:
                db.execute(
                    "UPDATE documents SET frontmatter_json=? WHERE relative_path=?",
                    (json.dumps({"aliases": [r"Line\nBreak", r"Quoted: \"Name\""]}), note.name),
                )
                db.execute(
                    "UPDATE meta SET value=? WHERE key='parser_version'",
                    (str(PARSER_VERSION - 1),),
                )
                db.commit()

            migrated = index_all(settings)
            self.assertEqual(migrated["modified"], 1)
            with Database(settings.database_path) as db:
                row = db.one("SELECT frontmatter_json FROM documents WHERE relative_path=?", (note.name,))
                version = db.one("SELECT value FROM meta WHERE key='parser_version'")["value"]
            self.assertEqual(json.loads(row["frontmatter_json"]), {"aliases": ["Line\nBreak", 'Quoted: "Name"']})
            self.assertEqual(version, str(PARSER_VERSION))

    def test_double_quoted_yaml_alias_resolves_real_wikilink(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            target = settings.vault_root / "Target.md"
            source = settings.vault_root / "Source.md"
            target.write_text(
                '---\naliases: ["Quoted \\"Alias\\""]\n---\n# Canonical target\n',
                encoding="utf-8",
            )
            source.write_text('# Source\n\n[[Quoted "Alias"]]\n', encoding="utf-8")
            result = index_all(settings)
            self.assertEqual(result["errors"], 0)
            with Database(settings.database_path) as db:
                source_row = db.one("SELECT document_id FROM documents WHERE relative_path='Source.md'")
                target_row = db.one("SELECT document_id FROM documents WHERE relative_path='Target.md'")
                link = db.one(
                    "SELECT target_document_id,status FROM links WHERE source_document_id=?",
                    (source_row["document_id"],),
                )
            self.assertEqual(link["target_document_id"], target_row["document_id"])
            self.assertEqual(link["status"], "resolved")

    def test_parser_version_migration_cleans_legacy_block_list_metadata(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            note = settings.vault_root / "Lista.md"
            note.write_text(
                "---\ntags:\n  - memoria\naliases:\n  - Segundo nombre\n---\n# Lista\n",
                encoding="utf-8",
            )
            index_all(settings)
            with Database(settings.database_path) as db:
                db.execute(
                    "UPDATE documents SET frontmatter_json=? WHERE relative_path=?",
                    (json.dumps({"tags": ["", "memoria"], "aliases": ["", "Segundo nombre"]}), note.name),
                )
                db.execute("UPDATE meta SET value=? WHERE key='parser_version'", (str(PARSER_VERSION - 1),))
                db.commit()

            migrated = index_all(settings)
            self.assertEqual(migrated["modified"], 1)
            with Database(settings.database_path) as db:
                row = db.one("SELECT frontmatter_json FROM documents WHERE relative_path=?", (note.name,))
                version = db.one("SELECT value FROM meta WHERE key='parser_version'")["value"]
            self.assertEqual(json.loads(row["frontmatter_json"]), {"aliases": ["Segundo nombre"], "tags": ["memoria"]})
            self.assertEqual(version, str(PARSER_VERSION))

    def test_parser_version_migration_rebuilds_legacy_flow_sequence_metadata(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            note = settings.vault_root / "Aliases.md"
            note.write_text(
                '---\naliases: ["Alpha, Beta", "Gamma"]\n---\n# Aliases\n',
                encoding="utf-8",
            )
            index_all(settings)
            with Database(settings.database_path) as db:
                db.execute(
                    "UPDATE documents SET frontmatter_json=? WHERE relative_path=?",
                    (json.dumps({"aliases": ['"Alpha', 'Beta"', "Gamma"]}), note.name),
                )
                db.execute(
                    "UPDATE meta SET value=? WHERE key='parser_version'",
                    (str(PARSER_VERSION - 1),),
                )
                db.commit()

            migrated = index_all(settings)
            self.assertEqual(migrated["modified"], 1)
            with Database(settings.database_path) as db:
                row = db.one(
                    "SELECT frontmatter_json FROM documents WHERE relative_path=?", (note.name,),
                )
                version = db.one("SELECT value FROM meta WHERE key='parser_version'")["value"]
            self.assertEqual(json.loads(row["frontmatter_json"]), {"aliases": ["Alpha, Beta", "Gamma"]})
            self.assertEqual(version, str(PARSER_VERSION))

    def test_parser_version_migration_strips_legacy_inline_yaml_comments(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            note = settings.vault_root / "Comentarios.md"
            note.write_text(
                '---\nname: "Hash # stays" # annotation\ntags: [alpha, beta] # annotation\n---\n# Comments\n',
                encoding="utf-8",
            )
            index_all(settings)
            with Database(settings.database_path) as db:
                db.execute(
                    "UPDATE documents SET frontmatter_json=? WHERE relative_path=?",
                    (json.dumps({"name": '"Hash # stays" # annotation', "tags": ["[alpha", "beta] # annotation"]}), note.name),
                )
                db.execute(
                    "UPDATE meta SET value=? WHERE key='parser_version'",
                    (str(PARSER_VERSION - 1),),
                )
                db.commit()

            migrated = index_all(settings)
            self.assertEqual(migrated["modified"], 1)
            with Database(settings.database_path) as db:
                row = db.one(
                    "SELECT frontmatter_json FROM documents WHERE relative_path=?", (note.name,),
                )
                version = db.one("SELECT value FROM meta WHERE key='parser_version'")["value"]
            self.assertEqual(
                json.loads(row["frontmatter_json"]),
                {"name": "Hash # stays", "tags": ["alpha", "beta"]},
            )
            self.assertEqual(version, str(PARSER_VERSION))

    def test_exact_unicode_tag_filter_works_for_search_context_api_and_cli(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            tagged = settings.vault_root / "Nota con etiqueta.md"
            tagged.write_text(
                "---\ntags: [seguridad, memoria/rápida]\n---\n# Nota etiquetada\n\nNeedle marker en documento etiquetado.\n",
                encoding="utf-8",
            )
            untagged = settings.vault_root / "Nota sin etiqueta.md"
            untagged.write_text("# Sin etiqueta\n\nNeedle marker en documento distinto.\n", encoding="utf-8")
            index_all(settings)

            found = search_documents(settings, "Needle marker", source_kind="obsidian", tag="#seguridad")
            self.assertEqual([row["relative_path"] for row in found], [tagged.name])
            self.assertEqual(found[0]["tags"], ["memoria/rápida", "seguridad"])
            self.assertEqual([row["relative_path"] for row in recent_documents(settings, tag="memoria/rápida")], [tagged.name])

            context = retrieve_context(settings, "Needle marker", tag="#memoria/rápida", max_chars=2000)
            self.assertEqual(len(context["fragments"]), 1)
            self.assertIn(f"{tagged}:4-6", context["fragments"][0]["citation"])

            config_path = settings.root / "config" / "settings.example.json"
            write_json_atomic(config_path, settings.raw)
            cli_output = StringIO()
            with redirect_stdout(cli_output):
                cli_main(["--config", str(config_path), "search", "Needle", "--tag", "#seguridad"])
            cli_results = json.loads(cli_output.getvalue())
            self.assertEqual([row["relative_path"] for row in cli_results], [tagged.name])
            self.assertEqual(cli_results[0]["query_match"], {
                "matched_terms": 1, "total_terms": 1, "complete": True,
            })

            web_root = settings.root / "web"
            web_root.mkdir()
            (web_root / "index.html").write_text("<html>test</html>", encoding="utf-8")
            handler = type("TestRabanitoHandler", (RabanitoHandler,), {"settings": settings})
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                search_request = Request(
                    origin + "/api/search", data=json.dumps({"q": "Needle", "tag": "#seguridad"}).encode(),
                    method="POST", headers={"Content-Type": "application/json", "Origin": origin},
                )
                with urlopen(search_request) as response:
                    payload = json.loads(response.read())
                self.assertEqual([row["relative_path"] for row in payload["results"]], [tagged.name])
                self.assertNotIn(str(tagged), json.dumps(payload, ensure_ascii=False))
                partial_search_request = Request(
                    origin + "/api/search",
                    data=json.dumps({"q": "Needle marker absentneedle", "tag": "seguridad"}).encode(),
                    method="POST", headers={"Content-Type": "application/json", "Origin": origin},
                )
                with urlopen(partial_search_request) as response:
                    partial_payload = json.loads(response.read())
                self.assertEqual([row["relative_path"] for row in partial_payload["results"]], [tagged.name])
                self.assertEqual(partial_payload["results"][0]["query_match"], {
                    "matched_terms": 2, "total_terms": 3, "complete": False,
                })
                self.assertNotIn(str(tagged), json.dumps(partial_payload, ensure_ascii=False))
                zero_search_request = Request(
                    origin + "/api/search", data=json.dumps({"q": "Needle", "tag": "seguridad", "limit": 0}).encode(),
                    method="POST", headers={"Content-Type": "application/json", "Origin": origin},
                )
                with urlopen(zero_search_request) as response:
                    self.assertEqual(json.loads(response.read())["results"], [])
                with urlopen(origin + "/api/tags") as response:
                    payload = json.loads(response.read())
                tags_by_name = {item["tag"]: item["document_count"] for item in payload["tags"]}
                self.assertEqual(tags_by_name["memoria/rápida"], 1)
                context_request = Request(
                    origin + "/api/context", data=json.dumps({"q": "Needle", "tag": "memoria/rápida", "max_chars": 1200}).encode(),
                    method="POST", headers={"Content-Type": "application/json", "Origin": origin},
                )
                with urlopen(context_request) as response:
                    payload = json.loads(response.read())
                self.assertEqual(len(payload["fragments"]), 1)
                self.assertEqual(payload["fragments"][0]["citation"], f"obsidian:{tagged.name}:4-6")
                self.assertNotIn(str(tagged), json.dumps(payload, ensure_ascii=False))
                zero_context_request = Request(
                    origin + "/api/context", data=json.dumps({"q": "Needle", "tag": "memoria/rápida", "max_chars": 0}).encode(),
                    method="POST", headers={"Content-Type": "application/json", "Origin": origin},
                )
                with urlopen(zero_context_request) as response:
                    zero_payload = json.loads(response.read())
                self.assertEqual(zero_payload["max_chars"], 0)
                self.assertEqual(zero_payload["characters"], 0)
                self.assertEqual(zero_payload["fragments"], [])
                zero_limit_context_request = Request(
                    origin + "/api/context", data=json.dumps({"q": "Needle", "tag": "memoria/rápida", "limit": 0, "max_chars": 1200}).encode(),
                    method="POST", headers={"Content-Type": "application/json", "Origin": origin},
                )
                with urlopen(zero_limit_context_request) as response:
                    zero_limit_payload = json.loads(response.read())
                self.assertEqual(zero_limit_payload["limit"], 0)
                self.assertEqual(zero_limit_payload["max_chars"], 1200)
                self.assertEqual(zero_limit_payload["characters"], 0)
                self.assertEqual(zero_limit_payload["fragments"], [])
                zero_graph_request = Request(
                    origin + "/api/graph", data=json.dumps({"limit": 0}).encode(),
                    method="POST", headers={"Content-Type": "application/json", "Origin": origin},
                )
                with urlopen(zero_graph_request) as response:
                    zero_graph = json.loads(response.read())
                self.assertEqual(zero_graph["nodes"], [])
                self.assertEqual(zero_graph["edges"], [])
                self.assertEqual(zero_graph["node_limit"], 0)
                self.assertGreater(zero_graph["total_matches"], 0)
                self.assertTrue(zero_graph["truncated"])
                with self.assertRaises(HTTPError) as private_query_get:
                    urlopen(origin + "/api/search?" + urlencode({"q": "Needle", "tag": "#seguridad"}))
                self.assertEqual(private_query_get.exception.code, 405)
                private_query_get.exception.close()
                for route in ("/api/context", "/api/graph"):
                    with self.assertRaises(HTTPError) as private_filter_get:
                        urlopen(origin + route + "?" + urlencode({"q": "Needle", "project": "Sensitive Project Root"}))
                    self.assertEqual(private_filter_get.exception.code, 405)
                    private_filter_get.exception.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_search_ranking_prefers_title_and_heading_matches_over_repeated_body_terms(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "Title match.md").write_text(
                "# Quasar Operations\n\nA short operational note.\n", encoding="utf-8",
            )
            (settings.vault_root / "Body match.md").write_text(
                "# General Notes\n\n" + "quasar " * 30 + "\n", encoding="utf-8",
            )
            (settings.vault_root / "Tag match.md").write_text(
                "---\ntags: [quasar]\n---\n# Metadata Note\n\nA short note without the query in its body.\n", encoding="utf-8",
            )
            index_all(settings)

            results = search_documents(settings, "quasar")
            context = retrieve_context(settings, "quasar", limit=10)
            self.assertEqual(results[0]["title"], "Quasar Operations")
            titles = [item["title"] for item in results]
            self.assertLess(titles.index("Metadata Note"), titles.index("General Notes"))
            self.assertEqual(context["fragments"][0]["title"], "Quasar Operations")

    def test_fts_query_quotes_operators_and_accepts_adversarial_unicode(self) -> None:
        import random

        from rabanito.search import fts_query

        connection = sqlite3.connect(":memory:")
        try:
            connection.execute("CREATE VIRTUAL TABLE probe USING fts5(body)")
            connection.executemany(
                "INSERT INTO probe(body) VALUES (?)",
                [("alpha beta",), ("alpha or beta",), ("alpha beta gamma",)],
            )
            all_terms = fts_query("alpha OR beta", require_all=True)
            matching_rows = connection.execute(
                "SELECT rowid FROM probe WHERE probe MATCH ? ORDER BY rowid", (all_terms,),
            ).fetchall()
            self.assertEqual([int(row[0]) for row in matching_rows], [2])
            any_terms = fts_query("alpha OR beta", require_all=False)
            matching_rows = connection.execute(
                "SELECT rowid FROM probe WHERE probe MATCH ? ORDER BY rowid", (any_terms,),
            ).fetchall()
            self.assertEqual([int(row[0]) for row in matching_rows], [1, 2, 3])

            rng = random.Random(0x5EC0D)
            alphabet = "abcXYZ019 _-.:/\\\"'(){}[]*^~&|!?,;#@+%=<>\t\n\x00éñ中🧠"
            queries = [
                '" OR *: NEAR', "Café", "Cafe\u0301", "__proto__", "a:b/c.d",
                "AND OR NOT NEAR",
            ] + [
                "".join(rng.choice(alphabet) for _ in range(rng.randrange(100)))
                for _ in range(256)
            ]
            for query in queries:
                for require_all in (False, True):
                    with self.subTest(query=repr(query), require_all=require_all):
                        expression = fts_query(query, require_all=require_all)
                        connection.execute(
                            "SELECT rowid FROM probe WHERE probe MATCH ?", (expression,),
                        ).fetchall()
        finally:
            connection.close()

    def test_project_retrieval_filters_accept_windows_case_variants_without_cross_project_leaks(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            target = settings.projects_root / "Proyecto Ñ"
            other = settings.projects_root / "Otra Raíz"
            target.mkdir()
            other.mkdir()
            (target / "README.md").write_text(
                "# Proyecto Ñ\n\nsharedneedle arquitectura local del proyecto objetivo.\n", encoding="utf-8",
            )
            (other / "README.md").write_text(
                "# Otra Raíz\n\nsharedneedle arquitectura del otro proyecto.\n", encoding="utf-8",
            )
            index_all(settings)

            path_variant = str(target).swapcase()
            name_variant = target.name.swapcase()
            search = search_documents(settings, "sharedneedle", project=path_variant)
            recent = recent_documents(settings, project=path_variant)
            context = retrieve_context(settings, "sharedneedle", project=path_variant)
            name_search = search_documents(settings, "sharedneedle", project=name_variant)

            self.assertTrue(search)
            self.assertTrue(recent)
            self.assertTrue(context["fragments"])
            self.assertTrue(name_search)
            self.assertTrue(all(item["project_root"] == str(target) for item in search))
            self.assertTrue(all(item["project_root"] == str(target) for item in recent))
            self.assertTrue(all(item["project_root"] == str(target) for item in context["fragments"]))
            self.assertTrue(all(item["project_root"] == str(target) for item in name_search))

            with Database(settings.database_path) as db:
                readmes = db.query(
                    "SELECT document_id FROM documents WHERE status='active' AND source_kind='projects' "
                    "AND relative_path='README.md' AND project_root_path IN (?,?) ORDER BY project_root_path",
                    (str(target), str(other)),
                )
                self.assertEqual(len(readmes), 2)
                db.execute("UPDATE documents SET project_name='Alpha' WHERE document_id=?", (readmes[0]["document_id"],))
                db.execute("UPDATE documents SET project_name='ALPHA' WHERE document_id=?", (readmes[1]["document_id"],))
                db.commit()
            self.assertEqual(search_documents(settings, "sharedneedle", project="alpha"), [])
            self.assertEqual(len(search_documents(settings, "sharedneedle", project="Alpha")), 1)

    def test_atomic_writers_propagate_failures_and_preserve_existing_files(self) -> None:
        with self.temporary_directory() as temp:
            root = Path(temp)
            json_path = root / "settings.json"
            json_path.write_text("original-json\n", encoding="utf-8")
            with self.assertRaises(TypeError):
                write_json_atomic(json_path, {"unsupported": object()})
            self.assertEqual(json_path.read_text(encoding="utf-8"), "original-json\n")
            self.assertEqual(list(root.glob("settings.json.*.tmp")), [])

            with patch("rabanito.utils.os.replace", side_effect=OSError("simulated replace failure")):
                with self.assertRaisesRegex(OSError, "simulated replace failure"):
                    write_json_atomic(json_path, {"new": "value"})
            self.assertEqual(json_path.read_text(encoding="utf-8"), "original-json\n")
            self.assertEqual(list(root.glob("settings.json.*.tmp")), [])

            text_path = root / "report.md"
            text_path.write_text("original-report\n", encoding="utf-8")
            with patch("rabanito.utils.os.replace", side_effect=OSError("simulated replace failure")):
                with self.assertRaisesRegex(OSError, "simulated replace failure"):
                    write_text_atomic(text_path, "replacement")
            self.assertEqual(text_path.read_text(encoding="utf-8"), "original-report\n")
            self.assertEqual(list(root.glob("report.md.*.tmp")), [])

    def test_security_terms_in_markdown_titles_do_not_hide_notes(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "credential-sniffing.md").write_text(
                "# Credential Sniffing\n\nDocumented defensive testing notes.\n", encoding="utf-8"
            )
            (settings.vault_root / "oauth-token-pentest.md").write_text(
                "# OAuth Token Pentest\n\nDocumented authorization testing notes.\n", encoding="utf-8"
            )

            index_all(settings)
            results = search_documents(settings, "pentest", source_kind="obsidian")
            credential_note = search_documents(settings, "sniffing", source_kind="obsidian")

            self.assertEqual([item["relative_path"] for item in results], ["oauth-token-pentest.md"])
            self.assertEqual([item["relative_path"] for item in credential_note], ["credential-sniffing.md"])

    def test_suggestions_are_separate_from_explicit_relations(self) -> None:
        with self.temporary_directory() as temp:
            root = Path(temp)
            settings = self.make_settings(root)
            (settings.vault_root / "Uno.md").write_text("---\ntags: [python, arquitectura]\n---\n# Uno\n", encoding="utf-8")
            (settings.vault_root / "Dos.md").write_text("---\ntags: [python, arquitectura]\n---\n# Dos\n", encoding="utf-8")
            index_all(settings)
            result = build_link_suggestions(settings)
            self.assertGreaterEqual(result["created"], 1)
            with Database(settings.database_path) as db:
                explicit = db.one("SELECT COUNT(*) AS c FROM links WHERE status='resolved'")["c"]
                suggested = db.one("SELECT COUNT(*) AS c FROM link_suggestions WHERE status='suggested'")["c"]
            self.assertEqual(explicit, 0)
            self.assertGreaterEqual(suggested, 1)
            self.assertEqual(stats(settings)["relations_suggested"], suggested)

            (settings.vault_root / "Dos.md").unlink()
            index_all(settings)
            self.assertEqual(stats(settings)["relations_suggested"], 0)
            with Database(settings.database_path) as db:
                stale_suggestions = db.one(
                    "SELECT COUNT(*) AS c FROM link_suggestions WHERE status='suggested'"
                )["c"]
            self.assertGreater(stale_suggestions, 0)

    def test_link_suggestion_write_shares_the_index_writer_lock(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            settings.raw["index_lock_timeout_seconds"] = 0.01
            with _index_lock(settings):
                with self.assertRaises(TimeoutError):
                    build_link_suggestions(settings)

    def test_index_lock_serializes_separate_windows_processes(self) -> None:
        with self.temporary_directory() as temp:
            root = Path(temp)
            data_dir = root / "data"
            ready = root / "lock-held"
            project_root = Path(__file__).resolve().parents[1]
            holder_script = (
                "import sys,time\n"
                "from pathlib import Path\n"
                "from types import SimpleNamespace\n"
                "from rabanito.indexer import _index_lock\n"
                "settings=SimpleNamespace(raw={'index_lock_timeout_seconds':3},data_dir=Path(sys.argv[1]))\n"
                "with _index_lock(settings):\n"
                " Path(sys.argv[2]).write_text('ready',encoding='utf-8')\n"
                " time.sleep(1.5)\n"
            )
            holder = subprocess.Popen(
                [sys.executable, "-c", holder_script, str(data_dir), str(ready)],
                cwd=project_root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8",
            )
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and holder.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                if not ready.exists():
                    stdout, stderr = holder.communicate(timeout=2)
                    self.fail(f"lock holder exited before acquiring the lock: {stdout!r} {stderr!r}")

                contender_script = (
                    "import sys\n"
                    "from pathlib import Path\n"
                    "from types import SimpleNamespace\n"
                    "from rabanito.indexer import _index_lock\n"
                    "settings=SimpleNamespace(raw={'index_lock_timeout_seconds':0.15},data_dir=Path(sys.argv[1]))\n"
                    "try:\n"
                    " with _index_lock(settings): print('unexpectedly-acquired')\n"
                    "except TimeoutError: print('busy')\n"
                )
                contender = subprocess.run(
                    [sys.executable, "-c", contender_script, str(data_dir)],
                    cwd=project_root, capture_output=True, text=True, encoding="utf-8", timeout=5,
                    check=False,
                )
                self.assertEqual(contender.returncode, 0, contender.stderr)
                self.assertEqual(contender.stdout.strip(), "busy")
                stdout, stderr = holder.communicate(timeout=5)
                self.assertEqual(holder.returncode, 0, stderr or stdout)

                released_script = (
                    "import sys\n"
                    "from pathlib import Path\n"
                    "from types import SimpleNamespace\n"
                    "from rabanito.indexer import _index_lock\n"
                    "settings=SimpleNamespace(raw={'index_lock_timeout_seconds':1},data_dir=Path(sys.argv[1]))\n"
                    "with _index_lock(settings): print('acquired')\n"
                )
                released = subprocess.run(
                    [sys.executable, "-c", released_script, str(data_dir)],
                    cwd=project_root, capture_output=True, text=True, encoding="utf-8", timeout=5,
                    check=False,
                )
                self.assertEqual(released.returncode, 0, released.stderr)
                self.assertEqual(released.stdout.strip(), "acquired")
            finally:
                if holder.poll() is None:
                    holder.terminate()
                    try:
                        holder.communicate(timeout=2)
                    except subprocess.TimeoutExpired:
                        holder.kill()
                        holder.communicate(timeout=2)

    def test_simultaneous_index_processes_preserve_sqlite_integrity(self) -> None:
        with self.temporary_directory() as temp:
            root = Path(temp)
            settings = self.make_settings(root)
            for number in range(24):
                previous = f"\nSee [[Nota {number - 1:02d}]].\n" if number else ""
                (settings.vault_root / f"Nota {number:02d}.md").write_text(
                    f"# Nota {number:02d}\n\nConcurrent index fixture.{previous}", encoding="utf-8",
                )
            project = settings.projects_root / "Proyecto Concurrente"
            project.mkdir()
            (project / "README.md").write_text("# Proyecto Concurrente\n", encoding="utf-8")

            gate = root / "start-indexing"
            worker_script = (
                "import json,sys,time\n"
                "from pathlib import Path\n"
                "from rabanito.config import Settings\n"
                "from rabanito.indexer import index_all\n"
                "raw=json.loads(sys.argv[1])\n"
                "settings=Settings(Path(raw['project_root']),raw)\n"
                "Path(sys.argv[2]).write_text('ready',encoding='utf-8')\n"
                "while not Path(sys.argv[3]).exists(): time.sleep(0.01)\n"
                "result=index_all(settings)\n"
                "print(json.dumps({key:result[key] for key in ('status','files_seen','added','modified','unchanged','removed','errors')},ensure_ascii=False))\n"
            )
            project_root = Path(__file__).resolve().parents[1]
            processes: list[subprocess.Popen[str]] = []
            try:
                for number in range(2):
                    ready = root / f"ready-{number}"
                    processes.append(subprocess.Popen(
                        [sys.executable, "-c", worker_script, json.dumps(settings.raw, ensure_ascii=False), str(ready), str(gate)],
                        cwd=project_root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, encoding="utf-8",
                    ))
                ready_paths = [root / "ready-0", root / "ready-1"]
                deadline = time.monotonic() + 10
                while not all(path.exists() for path in ready_paths) and time.monotonic() < deadline:
                    if any(process.poll() is not None for process in processes):
                        break
                    time.sleep(0.02)
                self.assertTrue(all(path.exists() for path in ready_paths), "index workers did not reach the start barrier")
                gate.write_text("go", encoding="utf-8")
                summaries = []
                for process in processes:
                    stdout, stderr = process.communicate(timeout=20)
                    self.assertEqual(process.returncode, 0, stderr or stdout)
                    summaries.append(json.loads(stdout.strip().splitlines()[-1]))
                self.assertTrue(all(item["status"] == "ok" and item["errors"] == 0 for item in summaries))
                self.assertEqual(sorted(item["added"] for item in summaries), [0, 26])
                self.assertEqual(sorted(item["unchanged"] for item in summaries), [0, 26])

                database_uri = f"{settings.database_path.resolve().as_uri()}?mode=ro"
                connection = sqlite3.connect(database_uri, uri=True)
                try:
                    self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                    self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
                    document_counts = connection.execute(
                        "SELECT COUNT(*), COUNT(DISTINCT path_key) FROM documents WHERE status='active'"
                    ).fetchone()
                    self.assertEqual(document_counts, (26, 26))
                    self.assertEqual(connection.execute(
                        "SELECT COUNT(*) FROM links WHERE status='resolved'"
                    ).fetchone()[0], 23)
                    scan_counts = connection.execute(
                        "SELECT COUNT(*), SUM(CASE WHEN status='ok' THEN 1 ELSE 0 END) FROM scan_runs"
                    ).fetchone()
                    self.assertEqual(scan_counts, (2, 2))
                finally:
                    connection.close()
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.communicate(timeout=2)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.communicate(timeout=2)

    def test_suggestions_are_undirected_deduplicated_and_exclude_explicit_edges(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "Uno.md").write_text(
                "---\ntags: [python, arquitectura, local]\n---\n# Uno\n\nVéase [[Dos]].\n", encoding="utf-8"
            )
            (settings.vault_root / "Dos.md").write_text(
                "---\ntags: [python, arquitectura, local]\n---\n# Dos\n", encoding="utf-8"
            )
            (settings.vault_root / "Tres.md").write_text(
                "---\ntags: [python, arquitectura, local]\n---\n# Tres\n", encoding="utf-8"
            )
            index_all(settings)
            result = build_link_suggestions(settings)
            self.assertGreaterEqual(result["created"], 1)

            with Database(settings.database_path) as db:
                suggestions = db.query(
                    "SELECT source_document_id,target_document_id FROM link_suggestions WHERE status='suggested'"
                )
                explicit = db.query(
                    "SELECT source_document_id,target_document_id FROM links WHERE status='resolved'"
                )
                ids = {row["title"]: int(row["document_id"]) for row in db.query(
                    "SELECT title,document_id FROM documents WHERE status='active'"
                )}
            pairs = [(int(row["source_document_id"]), int(row["target_document_id"])) for row in suggestions]
            self.assertTrue(all(source < target for source, target in pairs))
            self.assertEqual(len(pairs), len(set(pairs)))
            self.assertFalse(any((target, source) in set(pairs) for source, target in pairs))
            explicit_pairs = {
                tuple(sorted((int(row["source_document_id"]), int(row["target_document_id"]))))
                for row in explicit
            }
            self.assertFalse(any(tuple(sorted(pair)) in explicit_pairs for pair in pairs))

            for source_id, target_id in pairs:
                for document_id, neighbor_id in ((source_id, target_id), (target_id, source_id)):
                    neighbors = related_documents(settings, document_id)
                    self.assertTrue(any(
                        item["document_id"] == neighbor_id and item["relation_kind"] == "suggested"
                        for item in neighbors
                    ))
            self.assertIn("Uno", ids)
            self.assertIn("Dos", ids)
            self.assertEqual(stats(settings)["relations_suggested"], len(pairs))

    def test_related_documents_prioritize_explicit_then_highest_scoring_suggestions(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            for name in ("Anchor", "Explicit", "Alpha", "Beta", "Zulu"):
                (settings.vault_root / f"{name}.md").write_text(f"# {name}\n", encoding="utf-8")
            index_all(settings)

            with Database(settings.database_path) as db:
                identifiers = {
                    str(row["title"]): int(row["document_id"])
                    for row in db.query("SELECT title,document_id FROM documents WHERE status='active'")
                }
                anchor_id = identifiers["Anchor"]
                db.execute(
                    "INSERT INTO links(source_document_id,target_raw,target_document_id,relation_type,status,line_number) "
                    "VALUES(?,?,?,?,?,?)",
                    (anchor_id, "Explicit", identifiers["Explicit"], "wikilink", "resolved", 1),
                )
                for title, score in (("Alpha", 0.2), ("Beta", 0.6), ("Zulu", 0.95)):
                    db.execute(
                        "INSERT INTO link_suggestions(source_document_id,target_document_id,score,reason,created_at) "
                        "VALUES(?,?,?,?,?)",
                        (anchor_id, identifiers[title], score, f"fixture ranking {title}", "2026-10-13T00:00:00Z"),
                    )
                db.commit()

            related = related_documents(settings, anchor_id, limit=4)
            self.assertEqual(
                [item["relative_path"] for item in related],
                ["Explicit.md", "Zulu.md", "Beta.md", "Alpha.md"],
            )
            self.assertEqual(
                [item["relation_kind"] for item in related],
                ["explicit", "suggested", "suggested", "suggested"],
            )
            self.assertTrue(all("relation_score" not in item for item in related))

    def test_related_documents_ignore_broken_outgoing_link_with_stale_target_id(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "Source.md").write_text("# Source\n", encoding="utf-8")
            (settings.vault_root / "Former target.md").write_text("# Former target\n", encoding="utf-8")
            index_all(settings)
            with Database(settings.database_path) as db:
                identifiers = {
                    str(row["title"]): int(row["document_id"])
                    for row in db.query("SELECT title,document_id FROM documents WHERE status='active'")
                }
                source_id = identifiers["Source"]
                db.execute(
                    "INSERT INTO links(source_document_id,target_raw,target_document_id,relation_type,status,line_number) "
                    "VALUES(?,?,?,?,?,?)",
                    (source_id, "Former target", identifiers["Former target"], "wikilink", "broken", 3),
                )
                db.commit()

            self.assertEqual(related_documents(settings, source_id), [])

    def test_interview_requires_explicit_approval_before_writing(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            answers = iter(["respuesta de prueba"] * len(QUESTIONS) + ["NO"])
            rejected = conduct_interview(settings, "Tema de prueba", input_fn=lambda _prompt: next(answers), output_fn=lambda _text: None)
            self.assertFalse(rejected["approved"])
            self.assertEqual(list((settings.knowledge_root / "personal").rglob("*.md")), [])
            answers = iter(["respuesta aprobada"] * len(QUESTIONS) + ["APROBAR"])
            approved = conduct_interview(settings, "Tema aprobado", input_fn=lambda _prompt: next(answers), output_fn=lambda _text: None)
            self.assertTrue(approved["approved"])
            self.assertTrue(Path(str(approved["path"])).exists())

    def test_interview_topic_is_single_line_and_yaml_quoted(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            for invalid_topic in ("", "\nstatus: approved\nx", "tema\tinyectado", "tema\x7fcontrol"):
                with self.subTest(topic=invalid_topic), self.assertRaises(ValueError):
                    conduct_interview(settings, invalid_topic, input_fn=lambda _prompt: self.fail("invalid topics must fail before prompting"), output_fn=lambda _text: None)

            topic = 'Tema status: draft: "YAML" # notas — O\'Brien'
            answers = iter(["status: draft — respuesta sin confirmar"] + ["respuesta revisada"] * (len(QUESTIONS) - 1) + ["APROBAR"])
            with patch("rabanito.interview.datetime") as clock:
                clock.now.return_value.strftime.return_value = "20261013-210000"
                result = conduct_interview(settings, topic, input_fn=lambda _prompt: next(answers), output_fn=lambda _text: None)
            saved_path = Path(str(result["path"]))
            document = parse_markdown(saved_path, raw_text=saved_path.read_text(encoding="utf-8"))
            self.assertEqual(document.frontmatter["topic"], topic)
            self.assertEqual(document.frontmatter["status"], "approved")
            self.assertIn("status: draft — respuesta sin confirmar", saved_path.read_text(encoding="utf-8"))

    def test_approved_interviews_with_same_timestamp_never_overwrite(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))

            def approve(marker: str) -> dict[str, object]:
                answers = iter([f"{marker}-{index}" for index in range(len(QUESTIONS))] + ["APROBAR"])
                with patch("rabanito.interview.datetime") as clock:
                    clock.now.return_value.strftime.return_value = "20261013-210001"
                    return conduct_interview(settings, "Mismo tema", input_fn=lambda _prompt: next(answers), output_fn=lambda _text: None)

            first = approve("primera")
            second = approve("segunda")
            first_path = Path(str(first["path"]))
            second_path = Path(str(second["path"]))
            self.assertNotEqual(first_path, second_path)
            self.assertIn("primera-0", first_path.read_text(encoding="utf-8"))
            self.assertIn("segunda-0", second_path.read_text(encoding="utf-8"))

    def test_frontmatter_citations_use_physical_line_numbers(self) -> None:
        with self.temporary_directory() as temp:
            path = Path(temp) / "Cita.md"
            path.write_text("---\ntitle: Cita\ntags: [x]\n---\n# Sección\n\nfragmento verificable\n", encoding="utf-8")
            parsed = parse_markdown(path)
            self.assertEqual((parsed.chunks[0]["line_start"], parsed.chunks[0]["line_end"]), (5, 7))

    def test_sensitive_redaction_covers_frontmatter_multiline_values_and_private_keys(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            source = settings.vault_root / "Privacidad.md"
            original = (
                "---\n"
                "title: Privacidad\n"
                "api_key: rabanito_frontmatter_marker\n"
                "CI_GITHUB_TOKEN: rabanito_prefixed_token_marker\n"
                "DATABASE_PASSWORD:\n"
                "  primary: rabanito_nested_password_marker\n"
                "  backup: rabanito_nested_backup_marker\n"
                "client_secret: |\n"
                "  rabanito_yaml_block_marker\n"
                "tags: [seguridad]\n"
                "---\n"
                "# Nota\n\n"
                "password: \"rabanito_quoted secret marker\"\n"
                "AWS_SECRET_ACCESS_KEY=rabanito_aws_key_marker\n"
                "OPENAI_API_KEY: rabanito_openai_key_marker\n"
                "DATABASE_URL=https://rabanito-user:rabanito-url-password@local.example/db\n"
                "Authorization: Bearer rabanito_auth_marker\n"
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "rabanito_private_key_marker\n"
                "-----END OPENSSH PRIVATE KEY-----\n"
                "Contenido público verificable.\n"
            )
            source.write_text(original, encoding="utf-8")
            parsed = parse_markdown(source)
            parsed_values = json.dumps(parsed.frontmatter, ensure_ascii=False) + parsed.text + json.dumps(parsed.chunks)
            for marker in (
                "rabanito_frontmatter_marker", "rabanito_yaml_block_marker", "rabanito_quoted secret marker",
                "rabanito_prefixed_token_marker", "rabanito_nested_password_marker", "rabanito_nested_backup_marker",
                "rabanito_aws_key_marker", "rabanito_openai_key_marker", "rabanito-url-password",
                "rabanito_auth_marker", "rabanito_private_key_marker",
            ):
                self.assertNotIn(marker, parsed_values)
            self.assertIn("Contenido público verificable.", parsed.text)
            self.assertIn("[REDACTED]@local.example/db", parsed.text)
            self.assertEqual(source.read_text(encoding="utf-8"), original)

            # Also cover ordinary body-only notes, which do not enter the frontmatter branch.
            body_only = "password=body_only_secret_marker\nContenido local.\n"
            self.assertNotIn("body_only_secret_marker", parse_markdown(source, raw_text=body_only).text)

            index_all(settings)
            with Database(settings.database_path) as db:
                document = db.one("SELECT document_id,frontmatter_json FROM documents WHERE relative_path='Privacidad.md'")
                document_id = int(document["document_id"])
                db.execute("UPDATE documents SET frontmatter_json=? WHERE document_id=?", ('{"api_key":"old_index_secret_marker"}', document_id))
                db.execute("UPDATE documents_fts SET body=? WHERE document_id=?", ("old_index_secret_marker", str(document_id)))
                chunk = db.one("SELECT chunk_id FROM document_chunks WHERE document_id=? LIMIT 1", (document_id,))
                if chunk:
                    db.execute("UPDATE document_chunks SET text=? WHERE chunk_id=?", ("old_index_secret_marker", chunk["chunk_id"]))
                    db.execute("UPDATE chunks_fts SET text=? WHERE chunk_id=?", ("old_index_secret_marker", str(chunk["chunk_id"])))
                db.execute("UPDATE meta SET value='2' WHERE key='parser_version'")
                db.commit()

            reparsed = index_all(settings)
            self.assertGreaterEqual(reparsed["modified"], 1)
            self.assertEqual(index_all(settings)["unchanged"], 1)
            with Database(settings.database_path) as db:
                self.assertEqual(db.one("SELECT value FROM meta WHERE key='parser_version'")["value"], str(PARSER_VERSION))
                indexed_values = " ".join(str(row[0]) for row in db.query(
                    "SELECT frontmatter_json FROM documents WHERE relative_path='Privacidad.md' UNION ALL "
                    "SELECT body FROM documents_fts WHERE document_id=? UNION ALL "
                    "SELECT text FROM document_chunks WHERE document_id=? UNION ALL "
                    "SELECT text FROM chunks_fts WHERE document_id=?",
                    (str(document_id), document_id, str(document_id)),
                ))
            self.assertNotIn("old_index_secret_marker", indexed_values)

    def test_redaction_keeps_line_numbers_and_fails_closed_on_unclosed_private_key(self) -> None:
        raw = "# Inicio\n-----BEGIN PRIVATE KEY-----\nsecret line\nlast secret line"
        redacted = redact_sensitive_lines(raw)
        self.assertEqual(len(redacted.splitlines()), len(raw.splitlines()))
        self.assertNotIn("secret line", redacted)
        self.assertNotIn("last secret line", redacted)
        parsed = parse_markdown(Path("unclosed-key-fixture.md"), raw_text=raw + "\n[[Do Not Index]]\n")
        self.assertNotIn("Do Not Index", parsed.text)
        self.assertEqual(parsed.links, [])

    def test_hash_detects_same_size_edit_with_preserved_mtime(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            note = settings.vault_root / "Cambio.md"
            note.write_text("# Nota\n\nold fact one.\n", encoding="utf-8")
            index_all(settings)
            original_stat = note.stat()
            note.write_text("# Nota\n\nnew fact one.\n", encoding="utf-8")
            self.assertEqual(note.stat().st_size, original_stat.st_size)
            os.utime(note, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            changed = index_all(settings)
            self.assertGreaterEqual(changed["modified"], 1)
            self.assertTrue(search_documents(settings, "new fact", source_kind="obsidian"))

    def test_empty_source_scan_marks_last_document_deleted(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            note = settings.vault_root / "Única.md"
            note.write_text("# Única\ncontenido privado de indexación [[Destino]]\n", encoding="utf-8")
            destination = settings.vault_root / "Destino.md"
            destination.write_text("# Destino\nnota vinculada\n", encoding="utf-8")
            index_all(settings)
            with Database(settings.database_path) as db:
                original = db.one(
                    "SELECT document_id FROM documents WHERE relative_path=? AND status='active'", (note.name,)
                )
                original_id = int(original["document_id"])
                self.assertEqual(db.one(
                    "SELECT COUNT(*) AS c FROM documents_fts WHERE document_id=?", (str(original_id),)
                )["c"], 1)
            note.unlink()
            result = index_all(settings)
            self.assertGreaterEqual(result["removed"], 1)
            with Database(settings.database_path) as db:
                row = db.one("SELECT status,document_id FROM documents WHERE relative_path='Única.md'")
                fts_rows = int(db.one(
                    "SELECT COUNT(*) AS c FROM documents_fts WHERE document_id=?", (str(original_id),)
                )["c"])
                chunk_rows = int(db.one(
                    "SELECT COUNT(*) AS c FROM document_chunks WHERE document_id=?", (original_id,)
                )["c"])
                chunk_fts_rows = int(db.one(
                    "SELECT COUNT(*) AS c FROM chunks_fts WHERE document_id=?", (str(original_id),)
                )["c"])
                retained_links = int(db.one(
                    "SELECT COUNT(*) AS c FROM links WHERE source_document_id=?", (original_id,)
                )["c"])
            self.assertEqual((row["status"], int(row["document_id"])), ("deleted", original_id))
            self.assertEqual(fts_rows, 1)
            self.assertGreater(chunk_rows, 0)
            self.assertGreater(chunk_fts_rows, 0)
            self.assertEqual(retained_links, 1, "tombstone relationship metadata remains reversible")
            residue_audit = collect_audit(settings)
            self.assertEqual(residue_audit["counts"]["documents_with_inactive_search_payload"], 1)
            self.assertEqual(
                dashboard_audit_view(residue_audit)["counts"]["documents_with_inactive_search_payload"], 1
            )
            level_up_actions = level_up(settings)["recommendations"]
            prune_action = next(
                item for item in level_up_actions
                if item["action"] == "Revisar caché de texto de documentos inactivos"
            )
            self.assertEqual(prune_action["command"], "python -m rabanito prune-search-cache")
            preview = prune_inactive_search_payload(settings)
            self.assertEqual(preview["status"], "preview")
            self.assertEqual(preview["documents_with_payload"], 1)
            self.assertIsNone(preview["backup"])
            config_path = settings.root / "config" / "settings.example.json"
            write_json_atomic(config_path, settings.raw)
            cli_output = StringIO()
            with redirect_stdout(cli_output):
                cli_main(["--config", str(config_path), "prune-search-cache"])
            self.assertEqual(json.loads(cli_output.getvalue())["status"], "preview")
            with self.assertRaisesRegex(SystemExit, "--yes"):
                cli_main(["--config", str(config_path), "prune-search-cache", "--apply"])
            apply_output = StringIO()
            with redirect_stdout(apply_output):
                cli_main([
                    "--config", str(config_path), "prune-search-cache", "--apply", "--yes",
                ])
            pruned = json.loads(apply_output.getvalue())
            self.assertEqual(pruned["status"], "applied")
            self.assertEqual(pruned["integrity_check"], "ok")
            backup_path = settings.root / pruned["backup"]
            self.assertTrue(backup_path.is_file())
            backup_uri = backup_path.resolve().as_uri() + "?mode=ro"
            backup_db = sqlite3.connect(backup_uri, uri=True)
            try:
                self.assertEqual(backup_db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertGreater(backup_db.execute(
                    "SELECT COUNT(*) FROM documents_fts WHERE document_id=?", (str(original_id),)
                ).fetchone()[0], 0)
            finally:
                backup_db.close()
            with Database(settings.database_path) as db:
                self.assertEqual(db.one(
                    "SELECT COUNT(*) AS c FROM documents_fts WHERE document_id=?", (str(original_id),)
                )["c"], 0)
                self.assertEqual(db.one(
                    "SELECT COUNT(*) AS c FROM document_chunks WHERE document_id=?", (original_id,)
                )["c"], 0)
                self.assertEqual(db.one(
                    "SELECT COUNT(*) AS c FROM chunks_fts WHERE document_id=?", (str(original_id),)
                )["c"], 0)
                self.assertEqual(db.one(
                    "SELECT COUNT(*) AS c FROM links WHERE source_document_id=?", (original_id,)
                )["c"], 1)
            self.assertEqual(collect_audit(settings)["counts"]["documents_with_inactive_search_payload"], 0)
            note.write_text("# Única\ncontenido privado de indexación [[Destino]]\n", encoding="utf-8")
            restored = index_all(settings)
            self.assertGreaterEqual(restored["modified"], 1)
            with Database(settings.database_path) as db:
                restored_row = db.one(
                    "SELECT status,document_id FROM documents WHERE relative_path=?", (note.name,)
                )
            self.assertEqual((restored_row["status"], int(restored_row["document_id"])), ("active", original_id))
            self.assertTrue(search_documents(settings, "contenido privado indexación", source_kind="obsidian"))

    def test_project_root_enumeration_error_does_not_retire_indexed_project(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "Resistente"
            project.mkdir()
            (project / "README.md").write_text("# Resistente\nknown project fact\n", encoding="utf-8")
            index_all(settings)
            original_scandir = os.scandir
            first_call = True

            def fail_once(path):
                nonlocal first_call
                if Path(path) == settings.projects_root and first_call:
                    first_call = False
                    raise PermissionError("simulated root enumeration denial")
                return original_scandir(path)

            with patch("rabanito.indexer.os.scandir", side_effect=fail_once):
                result = index_all(settings)
            self.assertEqual(result["removed"], 0)
            self.assertTrue(search_documents(settings, "known project fact", source_kind="projects"))
            with Database(settings.database_path) as db:
                row = db.one("SELECT status FROM documents WHERE relative_path='README.md' AND source_kind='projects'")
                removed_events = db.one(
                    """SELECT COUNT(*) AS c FROM document_changes c JOIN documents d ON d.document_id=c.document_id
                       WHERE d.source_kind='projects' AND c.change_type='removed'"""
                )["c"]
            self.assertEqual(row["status"], "active")
            self.assertEqual(removed_events, 0, "an unenumerated project root must not produce false removal events")

    def test_nested_project_markers_remain_components_of_immediate_project_root(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "Monorepo"
            component = project / "apps" / "Widget"
            component.mkdir(parents=True)
            (project / "README.md").write_text("# Monorepo\nWorkspace overview.\n", encoding="utf-8")
            (component / "README.md").write_text("# Widget\nNested component documentation.\n", encoding="utf-8")
            (component / "pyproject.toml").write_text('[project]\nname = "widget"\n', encoding="utf-8")

            result = index_all(settings)

            self.assertEqual(result["errors"], 0)
            with Database(settings.database_path) as db:
                projects = db.query("SELECT name, root_path FROM projects WHERE status='active'")
                nested_doc = db.one(
                    "SELECT project_name, project_root_path FROM documents "
                    "WHERE source_kind='projects' AND relative_path='apps/Widget/README.md' AND status='active'"
                )
            self.assertEqual(len(projects), 1)
            self.assertEqual(projects[0]["name"], "Monorepo")
            self.assertIsNotNone(nested_doc)
            self.assertEqual(nested_doc["project_name"], "Monorepo")
            self.assertEqual(Path(nested_doc["project_root_path"]), project)

    def test_nested_vcs_roots_are_projects_and_are_not_double_indexed(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            workspace = settings.projects_root / "Workspace"
            widget = workspace / "apps" / "Widget"
            worker = workspace / "tools" / "Worker"
            mercurial = workspace / "libs" / "Mercurial"
            subversion = workspace / "legacy" / "Subversion"
            widget_git = widget / ".git"
            widget_git.mkdir(parents=True)
            worker.mkdir(parents=True)
            (worker / ".git").write_text("gitdir: ../metadata/worktree\n", encoding="utf-8")
            (mercurial / ".hg").mkdir(parents=True)
            (subversion / ".svn").mkdir(parents=True)
            (workspace / "README.md").write_text("# Workspace\nParent documentation.\n", encoding="utf-8")
            (widget / "README.md").write_text("# Widget\nNested repository docs.\n", encoding="utf-8")
            (worker / "README.md").write_text("# Worker\nWorktree repository docs.\n", encoding="utf-8")
            (mercurial / "README.md").write_text("# Mercurial\nNested repository docs.\n", encoding="utf-8")
            (subversion / "README.md").write_text("# Subversion\nNested repository docs.\n", encoding="utf-8")

            first = index_all(settings)
            self.assertEqual(first["errors"], 0)
            with Database(settings.database_path) as db:
                projects = db.query(
                    "SELECT name, root_path, project_id FROM projects WHERE status='active' ORDER BY root_path"
                )
                docs = db.query(
                    "SELECT absolute_path, project_name, project_root_path FROM documents "
                    "WHERE source_kind='projects' AND status='active' AND absolute_path LIKE ?",
                    (str(workspace) + "%",),
                )
                marker_files = db.query(
                    "SELECT project_id, relative_path FROM project_files "
                    "WHERE relative_path IN ('.git','.hg','.svn')"
                )
            self.assertEqual(
                {row["name"] for row in projects},
                {"Workspace", "Widget", "Worker", "Mercurial", "Subversion"},
            )
            by_absolute_path = {Path(row["absolute_path"]): row for row in docs}
            self.assertEqual(len(docs), 5)
            self.assertEqual(by_absolute_path[workspace / "README.md"]["project_name"], "Workspace")
            self.assertEqual(by_absolute_path[widget / "README.md"]["project_name"], "Widget")
            self.assertEqual(by_absolute_path[worker / "README.md"]["project_name"], "Worker")
            self.assertEqual(by_absolute_path[mercurial / "README.md"]["project_name"], "Mercurial")
            self.assertEqual(by_absolute_path[subversion / "README.md"]["project_name"], "Subversion")
            self.assertFalse(marker_files)
            second = index_all(settings)
            self.assertEqual(second["added"], 0)
            self.assertEqual(second["modified"], 0)
            self.assertEqual(second["removed"], 0)

    def test_same_named_nested_projects_require_root_filter_for_retrieval(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            parent = settings.projects_root / "SameName"
            nested = parent / "apps" / "SameName"
            (nested / ".git").mkdir(parents=True)
            parent.mkdir(exist_ok=True)
            (parent / "README.md").write_text("# Parent\nsharedrootmarker parent scope.\n", encoding="utf-8")
            (nested / "README.md").write_text("# Nested\nsharedrootmarker nested scope.\n", encoding="utf-8")
            index_all(settings)

            self.assertEqual(search_documents(settings, "sharedrootmarker", project="SameName"), [])
            parent_results = search_documents(
                settings, "sharedrootmarker", project=str(parent), source_kind="projects",
            )
            nested_results = search_documents(
                settings, "sharedrootmarker", project=str(nested), source_kind="projects",
            )
            self.assertEqual(len(parent_results), 1)
            self.assertEqual(len(nested_results), 1)
            self.assertEqual(Path(parent_results[0]["project_root"]), parent)
            self.assertEqual(Path(nested_results[0]["project_root"]), nested)
            nested_context = retrieve_context(
                settings, "sharedrootmarker", project=str(nested), max_chars=2000,
            )
            self.assertTrue(nested_context["fragments"])
            self.assertTrue(all(item["project_root"] == str(nested) for item in nested_context["fragments"]))

            settings.raw["excluded_projects"] = [str(nested)]
            index_all(settings)
            self.assertTrue(search_documents(
                settings, "sharedrootmarker", project=str(parent), source_kind="projects",
            ))
            self.assertFalse(search_documents(
                settings, "sharedrootmarker", project=str(nested),
            ))
            with Database(settings.database_path) as db:
                parent_status = db.one(
                    "SELECT status FROM projects WHERE root_path=?", (str(parent),),
                )["status"]
                nested_status = db.one(
                    "SELECT status FROM projects WHERE root_path=?", (str(nested),),
                )["status"]
                nested_source_status = db.one(
                    "SELECT status FROM documents WHERE absolute_path=?", (str(nested / "README.md"),),
                )["status"]
            self.assertEqual(parent_status, "active")
            self.assertEqual(nested_status, "excluded")
            self.assertEqual(nested_source_status, "deleted")

    def test_project_metadata_for_deleted_files_is_removed_after_complete_scan(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "Incremental"
            source = project / "src" / "module.py"
            source.parent.mkdir(parents=True)
            (project / "README.md").write_text("# Incremental\n", encoding="utf-8")
            source.write_text("# Source code is not read or indexed\n", encoding="utf-8")
            index_all(settings)
            with Database(settings.database_path) as db:
                project_id = db.one("SELECT project_id FROM projects WHERE root_path=?", (str(project),))["project_id"]
                before = db.one("SELECT COUNT(*) AS c FROM project_files WHERE project_id=?", (project_id,))["c"]
                technologies = db.one("SELECT technology_json FROM projects WHERE project_id=?", (project_id,))["technology_json"]
            self.assertEqual(before, 2)
            self.assertIn("Python", technologies)

            source.unlink()
            index_all(settings)
            with Database(settings.database_path) as db:
                after = db.one("SELECT COUNT(*) AS c FROM project_files WHERE project_id=?", (project_id,))["c"]
                technologies = db.one("SELECT technology_json FROM projects WHERE project_id=?", (project_id,))["technology_json"]
            self.assertEqual(after, 1)
            self.assertNotIn("Python", technologies)

    def test_project_inventory_excludes_sensitive_extensions_and_large_files(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            policy = settings.raw["source_policy"]["projects"]
            policy["exclude_extensions"] = [".sqlite", ".pem", ".key"]
            policy["max_metadata_file_bytes"] = 128
            project = settings.projects_root / "Secure"
            project.mkdir()
            (project / "README.md").write_text("# Secure\n", encoding="utf-8")
            (project / "sentra.env").write_text("rabanito_secret_marker_value", encoding="utf-8")
            (project / "api_token.txt").write_text("rabanito_token_marker_value", encoding="utf-8")
            (project / "private.pem").write_text("rabanito_key_marker_value", encoding="utf-8")
            (project / "storage.sqlite").write_text("rabanito_database_marker_value", encoding="utf-8")
            (project / "large.md").write_text("rabanito_large_marker_value" + "x" * 256, encoding="utf-8")
            generated_metadata = project / "backend.egg-info"
            generated_metadata.mkdir()
            (generated_metadata / "requires.txt").write_text("private build metadata", encoding="utf-8")

            index_all(settings)
            with Database(settings.database_path) as db:
                project_id = db.one("SELECT project_id FROM projects WHERE name='Secure'")["project_id"]
                inventoried = {row["relative_path"] for row in db.query(
                    "SELECT relative_path FROM project_files WHERE project_id=?", (project_id,)
                )}
                indexed = {row["relative_path"] for row in db.query(
                    "SELECT relative_path FROM documents WHERE source_kind='projects' AND project_name='Secure' AND status='active'"
                )}
                profile_association = db.one(
                    "SELECT project_root_path FROM documents WHERE relative_path='projects/secure/PROJECT_MEMORY.md' AND status='active'"
                )
            profile = (settings.knowledge_root / "projects" / "secure" / "PROJECT_MEMORY.md").read_text(encoding="utf-8")

            self.assertEqual(inventoried, {"README.md"})
            self.assertEqual(indexed, {"README.md"})
            self.assertEqual(profile_association["project_root_path"], str(project))
            for name in ("sentra.env", "api_token.txt", "private.pem", "storage.sqlite", "large.md", "backend.egg-info"):
                self.assertNotIn(name, profile)
            for marker in (
                "rabanito_secret_marker_value", "rabanito_token_marker_value", "rabanito_key_marker_value",
                "rabanito_database_marker_value", "rabanito_large_marker_value",
            ):
                self.assertFalse(search_documents(settings, marker, source_kind="projects"))

    def test_project_policy_excludes_conversation_exports_but_keeps_technical_docs(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project_config = Path(__file__).resolve().parents[1] / "config" / "settings.example.json"
            project_policy = json.loads(project_config.read_text(encoding="utf-8"))["source_policy"]["projects"]
            settings.raw["source_policy"]["projects"] = project_policy
            project = settings.projects_root / "ConversationSafe"
            (project / "docs").mkdir(parents=True)
            (project / "README.md").write_text("# ConversationSafe\nLocal architecture project.\n", encoding="utf-8")
            (project / "docs" / "conversation-architecture.md").write_text(
                "# Conversation lifecycle architecture\nTechnical design for state transitions.\n", encoding="utf-8",
            )
            marker = "rabanito_private_conversation_export_marker"
            excluded_sources = {
                "conversations/2026-10.md": marker + " user/assistant transcript",
                "Chat-History/export.md": marker + " exported chat history",
                "transcripts/session.txt": marker + " agent transcript",
                "session-exports/run.md": marker + " session export",
                "chatgpt-export.md": marker + " generated chat export",
                "session-transcript.md": marker + " generated session transcript",
            }
            for relative, contents in excluded_sources.items():
                path = project / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents, encoding="utf-8")

            first = index_all(settings)
            with Database(settings.database_path) as db:
                project_id = db.one("SELECT project_id FROM projects WHERE root_path=?", (str(project),))["project_id"]
                inventoried = {row["relative_path"] for row in db.query(
                    "SELECT relative_path FROM project_files WHERE project_id=?", (project_id,),
                )}
                indexed = {row["relative_path"] for row in db.query(
                    "SELECT relative_path FROM documents WHERE source_kind='projects' AND project_root_path=? AND status='active'",
                    (str(project),),
                )}
            self.assertEqual(first["errors"], 0)
            self.assertEqual(inventoried, {"README.md", "docs/conversation-architecture.md"})
            self.assertEqual(indexed, inventoried)
            self.assertTrue(search_documents(settings, "conversation lifecycle architecture", source_kind="projects"))
            self.assertFalse(search_documents(settings, marker, source_kind="projects"))

            new_export = project / "conversations" / "next-session.md"
            new_export.write_text(marker + " another transcript", encoding="utf-8")
            second = index_all(settings)
            self.assertEqual(second["added"], 0)
            self.assertEqual(second["modified"], 0)
            self.assertEqual(second["removed"], 0)
            self.assertFalse(search_documents(settings, marker, source_kind="projects"))

    def test_project_policy_change_tombstones_previously_indexed_conversation_export(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "PolicyTransition"
            export = project / "conversations" / "previous-session.md"
            export.parent.mkdir(parents=True)
            marker = "rabanito_previously_indexed_conversation_marker"
            export.write_text("# Prior conversation export\n\n" + marker, encoding="utf-8")
            (project / "README.md").write_text("# PolicyTransition\nTechnical project documentation.\n", encoding="utf-8")

            first = index_all(settings)
            self.assertEqual(first["errors"], 0)
            self.assertTrue(search_documents(settings, marker, source_kind="projects"))
            with Database(settings.database_path) as db:
                indexed = db.one(
                    "SELECT document_id,status FROM documents WHERE absolute_path=?", (str(export),),
                )
                self.assertIsNotNone(indexed)
                document_id = int(indexed["document_id"])

            project_config = Path(__file__).resolve().parents[1] / "config" / "settings.example.json"
            settings.raw["source_policy"]["projects"] = json.loads(
                project_config.read_text(encoding="utf-8"),
            )["source_policy"]["projects"]
            second = index_all(settings)

            self.assertEqual(second["errors"], 0)
            self.assertEqual(second["removed"], 1)
            self.assertFalse(search_documents(settings, marker, source_kind="projects"))
            self.assertTrue(export.is_file(), "source files remain untouched by the policy transition")
            with Database(settings.database_path) as db:
                retired = db.one(
                    "SELECT status FROM documents WHERE document_id=?", (document_id,),
                )
                inventoried = db.one(
                    "SELECT COUNT(*) AS c FROM project_files WHERE relative_path=?",
                    ("conversations/previous-session.md",),
                )["c"]
            self.assertEqual(retired["status"], "deleted", "excluded history is tombstoned, not purged")
            self.assertEqual(inventoried, 0)

    def test_project_dependency_inventory_is_static_bounded_and_incremental(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "Motor Ñ"
            (project / "web").mkdir(parents=True)
            (project / "src").mkdir()
            (project / "README.md").write_text("# Motor Ñ\n", encoding="utf-8")
            (project / "pyproject.toml").write_text(
                "[build-system]\nrequires = ['setuptools>=70']\nbuild-backend = 'setuptools.build_meta'\n"
                "[project]\ndependencies = ['httpx>=0.27', 'rich[markdown]>=13']\n"
                "[project.optional-dependencies]\ntest = ['pytest>=8']\n"
                "[tool.poetry.dependencies]\npython = '^3.11'\nruff = '^0.8'\n",
                encoding="utf-8",
            )
            package_manifest = project / "web" / "package.json"
            package_manifest.write_text(
                json.dumps({"dependencies": {"@noble/hashes": "^1", "react": "^19"},
                            "devDependencies": {"vite": "^6"}}),
                encoding="utf-8",
            )
            (project / "Cargo.toml").write_text(
                "[dependencies]\nserde = '1'\n\n[build-dependencies]\ncc = '1'\n", encoding="utf-8",
            )
            (project / "requirements-dev.txt").write_text(
                "urllib3>=2\n-r requirements.txt\n# comments are not packages\n", encoding="utf-8",
            )
            (project / "go.mod").write_text(
                "module example.invalid/app\n\nrequire (\n github.com/acme/tool v1.2.3 // indirect\n)\n", encoding="utf-8",
            )
            (project / "Desktop.csproj").write_text(
                "<Project><ItemGroup><PackageReference Include=\"Newtonsoft.Json\" Version=\"13\" />"
                "</ItemGroup></Project>", encoding="utf-8",
            )
            (project / "composer.json").write_text(
                json.dumps({"require": {"symfony/console": "^7", "php": ">=8"}}), encoding="utf-8",
            )
            secret_marker = "rabanito_unindexed_source_secret_marker"
            (project / "src" / "app.py").write_text(f"API_TOKEN = '{secret_marker}'\n", encoding="utf-8")

            index_all(settings)
            with Database(settings.database_path) as db:
                row = db.one("SELECT project_id, dependencies_json, dependencies_truncated FROM projects WHERE name=?", (project.name,))
                project_id = int(row["project_id"])
            dependencies = json.loads(row["dependencies_json"])
            names = {item["name"] for item in dependencies}
            expected = {
                "setuptools", "httpx", "rich", "pytest", "ruff", "@noble/hashes", "react", "vite", "serde", "cc",
                "urllib3", "github.com/acme/tool", "Newtonsoft.Json", "symfony/console",
            }
            self.assertTrue(expected.issubset(names), names)
            self.assertEqual(row["dependencies_truncated"], 0)
            self.assertEqual(next(item for item in dependencies if item["name"] == "httpx")["sources"], ["pyproject.toml"])
            profile_path = settings.knowledge_root / "projects" / "motor-ñ" / "PROJECT_MEMORY.md"
            profile_before = profile_path.read_text(encoding="utf-8")
            self.assertIn("## Dependencias declaradas", profile_before)
            self.assertIn("`@noble/hashes`", profile_before)
            self.assertIn("`web/package.json`", profile_before)
            self.assertIn("no prueba instalación ni uso en ejecución", profile_before)
            self.assertNotIn("0.27", profile_before)
            self.assertNotIn(secret_marker, profile_before)
            self.assertFalse(search_documents(settings, secret_marker, source_kind="projects"))
            dependency_results = search_documents(settings, "httpx", source_kind="internal", project=str(project))
            self.assertTrue(any(item["relative_path"].endswith("PROJECT_MEMORY.md") for item in dependency_results))
            dependency_context = retrieve_context(
                settings, "httpx", source_kind="internal", project=str(project), max_chars=2000,
            )
            self.assertTrue(dependency_context["fragments"])
            self.assertIn("PROJECT_MEMORY.md:", dependency_context["fragments"][0]["citation"])

            second = index_all(settings)
            self.assertEqual(second["modified"], 0)
            self.assertEqual(profile_path.read_text(encoding="utf-8"), profile_before)

            package_manifest.write_text(
                json.dumps({"dependencies": {"@noble/hashes": "^1", "react": "^19", "zod": "^4"},
                            "devDependencies": {"vite": "^6"}}),
                encoding="utf-8",
            )
            changed = index_all(settings)
            self.assertGreaterEqual(changed["modified"], 1)
            with Database(settings.database_path) as db:
                refreshed = json.loads(db.one("SELECT dependencies_json FROM projects WHERE project_id=?", (project_id,))["dependencies_json"])
            self.assertIn("zod", {item["name"] for item in refreshed})

            package_manifest.unlink()
            index_all(settings)
            with Database(settings.database_path) as db:
                after_delete = json.loads(db.one("SELECT dependencies_json FROM projects WHERE project_id=?", (project_id,))["dependencies_json"])
                files = {item["relative_path"] for item in db.query("SELECT relative_path FROM project_files WHERE project_id=?", (project_id,))}
            self.assertNotIn("zod", {item["name"] for item in after_delete})
            self.assertNotIn("vite", {item["name"] for item in after_delete})
            self.assertNotIn("web/package.json", files)
            self.assertNotIn("web/package.json", profile_path.read_text(encoding="utf-8"))

    def test_malformed_dependency_manifests_are_skipped_without_failure_or_expansion(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            settings.raw["source_policy"]["projects"]["max_metadata_file_bytes"] = 180
            project = settings.projects_root / "MalformedManifests"
            project.mkdir()
            (project / "README.md").write_text("# MalformedManifests\n", encoding="utf-8")
            private_marker = "rabanito_manifest_private_payload_marker"
            (project / "package.json").write_text('{"private": "' + private_marker + '", "dependencies": [broken}', encoding="utf-8")
            (project / "Unsafe.csproj").write_text(
                '<!DOCTYPE Project [<!ENTITY injected "rabanito_manifest_entity_marker">]>'
                '<Project><ItemGroup><PackageReference Include="&injected;" /></ItemGroup></Project>',
                encoding="utf-8",
            )
            (project / "requirements-prod.txt").write_text(
                "# " + private_marker + "\n" + "x" * 240 + "\n", encoding="utf-8",
            )
            invalid_utf8_marker = "rabanito_invalid_utf8_private_marker"
            (project / "Cargo.toml").write_bytes(b"\xff" + invalid_utf8_marker.encode("ascii"))
            result = index_all(settings)
            with Database(settings.database_path) as db:
                row = db.one("SELECT project_id, dependencies_json, dependency_errors_json FROM projects WHERE name='MalformedManifests'")
                project_id = int(row["project_id"])
                indexed_files = {item["relative_path"] for item in db.query(
                    "SELECT relative_path FROM project_files WHERE project_id=?", (project_id,),
                )}
            profile = (settings.knowledge_root / "projects" / "malformedmanifests" / "PROJECT_MEMORY.md").read_text(encoding="utf-8")
            issues = json.loads(row["dependency_errors_json"])
            self.assertEqual(result["errors"], 0)
            self.assertEqual(json.loads(row["dependencies_json"]), [])
            self.assertNotIn("rabanito_manifest_entity_marker", profile)
            self.assertNotIn(private_marker, profile)
            self.assertNotIn("requirements-prod.txt", indexed_files, "oversized manifest contents remain outside project_files")
            self.assertEqual(
                {(item["source"], item["error_type"]) for item in issues},
                {("package.json", "JSONDecodeError"), ("Unsafe.csproj", "ValueError"),
                 ("requirements-prod.txt", "FileTooLarge"), ("Cargo.toml", "UnicodeDecodeError")},
            )
            self.assertIn("## Manifiestos por revisar", profile)
            self.assertIn("requirements-prod.txt", profile)
            self.assertIn("Cargo.toml", profile)
            self.assertNotIn(invalid_utf8_marker, profile)
            audit = collect_audit(settings)
            self.assertEqual(audit["counts"]["project_dependency_manifest_errors"], 4)
            self.assertEqual(len(audit["project_manifest_warnings"]), 4)
            self.assertTrue(all(item["review_only"] is True for item in audit["project_manifest_warnings"]))
            encoded_audit = json.dumps(dashboard_audit(settings), ensure_ascii=False)
            self.assertNotIn(private_marker, encoded_audit)
            self.assertNotIn(invalid_utf8_marker, encoded_audit)
            self.assertNotIn(str(project), encoded_audit)
            self.assertIn("requirements-prod.txt", encoded_audit)
            written_audit = write_audit(settings)
            report_text = (settings.knowledge_root / written_audit["markdown_path"]).read_text(encoding="utf-8")
            self.assertIn("requirements-prod.txt", report_text)
            self.assertNotIn(private_marker, report_text)
            self.assertNotIn(invalid_utf8_marker, report_text)
            recommendations = level_up(settings)["recommendations"]
            self.assertTrue(any(item["action"] == "Revisar manifiestos de dependencias" for item in recommendations))

            for manifest_name in ("package.json", "Unsafe.csproj", "requirements-prod.txt", "Cargo.toml"):
                (project / manifest_name).unlink()
            index_all(settings)
            with Database(settings.database_path) as db:
                cleared = db.one("SELECT dependency_errors_json FROM projects WHERE project_id=?", (project_id,))
            self.assertEqual(json.loads(cleared["dependency_errors_json"]), [])
            self.assertEqual(collect_audit(settings)["counts"]["project_dependency_manifest_errors"], 0)

    def test_project_dependency_inventory_enforces_manifest_and_entry_limits(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            policy = settings.raw["source_policy"]["projects"]
            policy["max_project_dependency_manifests"] = 1
            policy["max_project_dependencies"] = 1
            project = settings.projects_root / "Capped"
            (project / "nested").mkdir(parents=True)
            (project / "README.md").write_text("# Capped\n", encoding="utf-8")
            (project / "Cargo.toml").write_text(
                "[dependencies]\nalpha = '1'\nbeta = '1'\n", encoding="utf-8",
            )
            (project / "nested" / "package.json").write_text(
                json.dumps({"dependencies": {"later": "1"}}), encoding="utf-8",
            )
            index_all(settings)
            with Database(settings.database_path) as db:
                row = db.one("SELECT dependencies_json, dependencies_truncated FROM projects WHERE name='Capped'")
            self.assertEqual([item["name"] for item in json.loads(row["dependencies_json"])], ["alpha"])
            self.assertEqual(row["dependencies_truncated"], 1)
            profile = (settings.knowledge_root / "projects" / "capped" / "PROJECT_MEMORY.md").read_text(encoding="utf-8")
            self.assertIn("truncado por el límite local configurado", profile)
            self.assertNotIn("later", profile)

    def test_legacy_generated_project_profile_is_refreshed_without_touching_custom_profiles(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "Proyecto Perfil"
            project.mkdir()
            (project / "README.md").write_text("# Proyecto Perfil\nDocumentación actual verificable.\n", encoding="utf-8")
            (project / "app.py").write_text("# metadata-only fixture\n", encoding="utf-8")
            build_metadata = project / "backend.egg-info"
            build_metadata.mkdir()
            (build_metadata / "requires.txt").write_text("old build artifact", encoding="utf-8")
            profile_path = settings.knowledge_root / "projects" / "proyecto-perfil" / "PROJECT_MEMORY.md"
            profile_path.parent.mkdir(parents=True)
            profile_path.write_text(
                "---\nkind: project-memory\nstatus: observed\nproject: Proyecto Perfil\n"
                "observed_at: 2026-01-01T00:00:00+00:00\nsource_type: derived-metadata\n---\n\n"
                "# Proyecto Perfil — memoria observada\n\n"
                "> Esta memoria se genera a partir de nombres, estructura y documentación seleccionada. "
                "No copia código fuente ni afirma decisiones que no estén documentadas.\n\n"
                f"## Fuente\n\n- Ruta: `{project}`\n- Observado: `2026-01-01T00:00:00+00:00`\n\n"
                "## Tecnologías detectadas\n\n- Python\n\n"
                "## Estructura observada\n\n- `.env`\n- `backend.egg-info`\n\n"
                "## Documentación indexable\n\n- `README.md`\n- `backend.egg-info/requires.txt`\n\n"
                "## Pendiente de revisión humana\n\n- Confirmar estado funcional y decisiones técnicas.\n"
                "- Añadir problemas, soluciones y tareas pendientes cuando estén documentados.\n",
                encoding="utf-8",
            )

            index_all(settings)
            refreshed = profile_path.read_text(encoding="utf-8")
            self.assertIn("generated_version: 21", refreshed)
            self.assertIn("README.md", refreshed)
            self.assertIn("Descripción documentada (extracto literal)", refreshed)
            self.assertIn("README.md:2-2", refreshed)
            self.assertNotIn("2026-01-01", refreshed)
            self.assertNotIn(".env", refreshed)
            self.assertNotIn("egg-info", refreshed)
            self.assertNotIn("- No concluyente", refreshed)
            self.assertNotIn("- Sin elementos documentados", refreshed)
            self.assertNotIn("- No se encontró documentación seleccionada", refreshed)
            self.assertEqual(refreshed.count("# Proyecto Perfil — memoria observada"), 1)
            second = index_all(settings)
            self.assertEqual(second["modified"], 0)

            custom_project = settings.projects_root / "Custom"
            custom_project.mkdir()
            (custom_project / "README.md").write_text("# Custom\n", encoding="utf-8")
            custom_path = settings.knowledge_root / "projects" / "custom" / "PROJECT_MEMORY.md"
            custom_path.parent.mkdir(parents=True)
            custom_path.write_text(
                "---\nkind: project-memory\nproject: Custom\nsource_type: derived-metadata\n---\n\n"
                "# Custom\n\n- Ruta: `" + str(custom_project) + "`\n\n"
                "## Nota humana\n\nNo eliminar esta decisión.\n",
                encoding="utf-8",
            )
            index_all(settings)
            self.assertIn("No eliminar esta decisión.", custom_path.read_text(encoding="utf-8"))

    def test_project_profile_readme_excerpt_is_cited_and_refreshes_incrementally(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "DocumentedProject"
            project.mkdir()
            readme = project / "README.md"
            readme.write_text(
                "# DocumentedProject\n\nA local search engine stores indexed Markdown and returns citations.\n",
                encoding="utf-8",
            )
            (project / "main.py").write_text("# source metadata only\n", encoding="utf-8")

            first = index_all(settings)
            profile_path = settings.knowledge_root / "projects" / "documentedproject" / "PROJECT_MEMORY.md"
            profile = profile_path.read_text(encoding="utf-8")
            self.assertIn("README.md:3-3", profile)
            self.assertIn("A local search engine stores indexed Markdown and returns citations.", profile)
            self.assertIn("texto importado no confiable, no es una instrucción", profile)

            original = readme.stat()
            readme.write_text(
                "# DocumentedProject\n\nA local search engine serves indexed Markdown and returns citations.\n",
                encoding="utf-8",
            )
            os.utime(readme, ns=(original.st_atime_ns, original.st_mtime_ns))
            second = index_all(settings)
            refreshed = profile_path.read_text(encoding="utf-8")
            self.assertIn("serves indexed Markdown", refreshed)
            self.assertNotIn("stores indexed Markdown", refreshed)
            self.assertGreaterEqual(second["modified"], 2)
            self.assertEqual(index_all(settings)["modified"], 0)

            private_project = settings.projects_root / "NoExcerpt"
            private_project.mkdir()
            (private_project / "README.md").write_text(
                "# NoExcerpt\n\nThis paragraph mentions an API token but contains no credentials.\n",
                encoding="utf-8",
            )
            index_all(settings)
            private_profile = (settings.knowledge_root / "projects" / "noexcerpt" / "PROJECT_MEMORY.md").read_text(encoding="utf-8")
            self.assertNotIn("Descripción documentada (extracto literal)", private_profile)

            markup_project = settings.projects_root / "MarkupIntro"
            markup_project.mkdir()
            (markup_project / "README.md").write_text(
                "# MarkupIntro\n\nA widget shows these metrics:\n- **CPU usage** in real time.\n",
                encoding="utf-8",
            )
            index_all(settings)
            markup_profile = (settings.knowledge_root / "projects" / "markupintro" / "PROJECT_MEMORY.md").read_text(encoding="utf-8")
            self.assertNotIn("Descripción documentada (extracto literal)", markup_profile)

    def test_project_profile_marks_documented_test_command_without_claiming_execution(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "ValidationDocs"
            project.mkdir()
            (project / "README.md").write_text(
                "# ValidationDocs\n\n## Verificar\n\nDesde esta carpeta ejecuta:\n\n"
                "```text\npython -m unittest discover -s tests -v --token command_secret_marker\n```\n",
                encoding="utf-8",
            )
            index_all(settings)
            profile = (settings.knowledge_root / "projects" / "validationdocs" / "PROJECT_MEMORY.md").read_text(encoding="utf-8")

            self.assertIn("generated_version: 21", profile)
            self.assertIn("## Procedimientos de prueba documentados (sin resultado en el fragmento)", profile)
            self.assertIn("`README.md:8-8` · Verificar", profile)
            self.assertIn("no registra su ejecución ni resultado", profile)
            self.assertNotIn("python -m unittest", profile)
            self.assertNotIn("command_secret_marker", profile)
            self.assertNotIn("pruebas aprobadas", profile.casefold())

            ordinary_project = settings.projects_root / "OrdinaryLaunch"
            ordinary_project.mkdir()
            (ordinary_project / "README.md").write_text(
                "# OrdinaryLaunch\n\n## Abrir\n\n```text\npython main.py\n```\n",
                encoding="utf-8",
            )
            index_all(settings)
            ordinary_profile = (settings.knowledge_root / "projects" / "ordinarylaunch" / "PROJECT_MEMORY.md").read_text(encoding="utf-8")
            self.assertNotIn("Procedimientos de prueba documentados", ordinary_profile)
            self.assertEqual(index_all(settings)["modified"], 0)

    def test_project_profile_outlines_document_headings_with_lines_without_claiming_status(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "OutlineProject"
            (project / "docs").mkdir(parents=True)
            (project / "README.md").write_text(
                "# OutlineProject\n\n## What exists\n\nDocumented but not interpreted by the profile.\n",
                encoding="utf-8",
            )
            architecture = project / "docs" / "ARCHITECTURE.md"
            architecture.write_text(
                "---\ntitle: Architecture\n---\n# Architecture\n\n## Components\n\nThe architecture routes search requests through a local SQLite index.\n"
                "## API_TOKEN\n\nNever include sensitive headings.\n\n```md\n## Fake heading\n```\n\n## Data flow\n",
                encoding="utf-8",
            )
            (project / "docs" / "TESTING.md").write_text(
                "# Testing\n\n## Tests\n\nThe suite checks path resolution and quote handling.\n\n"
                "## Pending tasks\n\n- [ ] Verify behavior on Windows junctions.\n\n"
                "## Status\n\nAPI_TOKEN = EVIDENCE_SECRET_SENTINEL\n\n"
                "## Known issues\n\nThe project graph can omit one explicit edge under a narrow filter.\n\n"
                "## Solutions\n\nCheck the source citation before accepting a suggested graph connection.\n",
                encoding="utf-8",
            )
            (project / "docs" / "DECISIONS.md").write_text(
                "# Decision log\n\n## Technical decisions\n\n"
                "Proposal: retain SQLite as the local index; validation is still pending.\n\n"
                "## Alternatives considered\n\nA network database was discussed but not adopted.\n",
                encoding="utf-8",
            )

            index_all(settings)
            profile_path = settings.knowledge_root / "projects" / "outlineproject" / "PROJECT_MEMORY.md"
            profile = profile_path.read_text(encoding="utf-8")
            self.assertIn("generated_version: 21", profile)
            self.assertIn("## Índice de secciones documentales", profile)
            self.assertIn("No confirma que una función esté implementada", profile)
            self.assertIn("`README.md`", profile)
            self.assertIn("`What exists` · línea 3", profile)
            self.assertIn("`docs/ARCHITECTURE.md`", profile)
            self.assertIn("`Components` · línea 6", profile)
            self.assertIn("`Data flow` · línea 17", profile)
            self.assertIn("## Pasajes documentales seleccionados", profile)
            self.assertIn("docs/DECISIONS.md:5-5", profile)
            self.assertIn("decisions / Technical decisions", profile)
            self.assertIn("Proposal: retain SQLite as the local index; validation is still pending.", profile)
            self.assertIn("docs/ARCHITECTURE.md:8-8", profile)
            self.assertIn("The architecture routes search requests through a local SQLite index.", profile)
            self.assertIn("docs/TESTING.md:5-5", profile)
            self.assertIn("docs/TESTING.md:9-9", profile)
            self.assertIn("The suite checks path resolution and quote handling.", profile)
            self.assertIn("[ ] Verify behavior on Windows junctions.", profile)
            self.assertIn("issues / Known issues", profile)
            self.assertIn("docs/TESTING.md:17-17", profile)
            self.assertIn("The project graph can omit one explicit edge under a narrow filter.", profile)
            self.assertIn("solutions / Solutions", profile)
            self.assertIn("docs/TESTING.md:21-21", profile)
            self.assertIn("Check the source citation before accepting a suggested graph connection.", profile)
            self.assertNotIn("EVIDENCE_SECRET_SENTINEL", profile)
            self.assertIn("no confirman implementación ni convierten propuestas en decisiones", profile)
            self.assertNotIn("API_TOKEN", profile)
            self.assertNotIn("Fake heading", profile)
            self.assertFalse((settings.knowledge_root / "decisions").exists())

            decision_context = retrieve_context(
                settings, "retain SQLite local index", source_kind="internal", max_chars=3000,
            )
            self.assertTrue(any(
                "docs/DECISIONS.md:5-5" in fragment["text"]
                and fragment["relative_path"].endswith("PROJECT_MEMORY.md")
                for fragment in decision_context["fragments"]
            ))

            original = architecture.stat()
            architecture.write_text(
                architecture.read_text(encoding="utf-8").replace("Data flow", "Test flow"), encoding="utf-8",
            )
            os.utime(architecture, ns=(original.st_atime_ns, original.st_mtime_ns))
            refreshed = index_all(settings)
            profile_after = profile_path.read_text(encoding="utf-8")
            self.assertIn("`Test flow` · línea 17", profile_after)
            self.assertNotIn("`Data flow` · línea 17", profile_after)
            self.assertGreaterEqual(refreshed["modified"], 1)
            self.assertEqual(index_all(settings)["modified"], 0)

    def test_project_verification_command_is_retrievable_without_claiming_it_ran(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "Widget Verify"
            project.mkdir()
            command = "python -m unittest discover -s tests -v"
            (project / "README.md").write_text(
                "# Widget Verify\n\n## Verificar\n\nDesde esta carpeta ejecuta:\n\n"
                f"```text\n{command}\n```\n",
                encoding="utf-8",
            )

            index_all(settings)
            context = retrieve_context(
                settings, "unittest discover", limit=3, max_chars=1000,
                source_kind="projects", project=str(project),
            )
            cited = next(
                (fragment for fragment in context["fragments"] if command in fragment["text"]),
                None,
            )
            profile = (settings.knowledge_root / "projects" / "widget-verify" / "PROJECT_MEMORY.md").read_text(
                encoding="utf-8",
            )

            self.assertIsNotNone(cited)
            self.assertEqual(cited["relative_path"], "README.md")
            self.assertIn("README.md:", cited["citation"])
            self.assertIn("`Verificar` · línea 3", profile)
            self.assertNotIn(command, profile, "a documented command is not proof that tests ran")

    def test_project_evidence_maps_realistic_headings_without_promoting_pending_work(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "EvidenceMap"
            status_doc = project / "docs" / "DEVELOPMENT_STATUS.md"
            status_doc.parent.mkdir(parents=True)
            (project / "README.md").write_text("# EvidenceMap\n", encoding="utf-8")
            status_doc.write_text(
                "# Project status\n\n"
                "## Current state\nThe documented project state is under human review.\n\n"
                "## Data model\nThe data model defines stable local records and their references.\n\n"
                "## Endpoints\n- API.\n- The documented API exposes local status and search endpoints.\n"
                "- [ ] Add an admin endpoint in a future release.\n\n"
                "## Implementation and validation pending\nWindows junction validation remains a documented pending task.\n\n"
                "## Verification results\nThe documented test suite checks Unicode paths and index recovery.\n\n"
                "## Known issues\nThe current index may contain stale link targets after file moves.\n",
                encoding="utf-8",
            )

            index_all(settings)

            profile = (settings.knowledge_root / "projects" / "evidencemap" / "PROJECT_MEMORY.md").read_text(encoding="utf-8")
            self.assertIn("generated_version: 21", profile)
            self.assertIn("status / Current state", profile)
            self.assertIn("architecture / Data model", profile)
            self.assertIn("features / Endpoints", profile)
            self.assertIn("docs/DEVELOPMENT_STATUS.md:10-11", profile)
            self.assertNotIn("Add an admin endpoint in a future release", profile)
            self.assertIn("pending / Implementation and validation pending", profile)
            self.assertIn("tests / Verification results", profile)
            self.assertIn("issues / Known issues", profile)
            self.assertNotIn("status / Implementation and validation pending", profile)
            self.assertNotIn("tests / Implementation and validation pending", profile)
            self.assertIn("no confirman implementación ni convierten propuestas en decisiones", profile)
            context = retrieve_context(
                settings, "documented API exposes local status search endpoints",
                source_kind="internal", max_chars=2000,
            )
            self.assertTrue(any(
                "docs/DEVELOPMENT_STATUS.md:10-11" in fragment["text"]
                and "documented API exposes local status and search endpoints" in fragment["text"]
                for fragment in context["fragments"]
            ))
            self.assertEqual(index_all(settings)["modified"], 0)

    def test_project_profile_prioritizes_standard_knowledge_docs_with_many_markdown_files(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "StandardKnowledgeDocs"
            project.mkdir()
            sources = {
                "README.md": "# StandardKnowledgeDocs\n\n## Features\n\nThe local service indexes Markdown and returns source citations.\n",
                "ARCHITECTURE.md": "# Architecture\n\n## Architecture\n\nThe service stores metadata in SQLite and derives links from documents.\n",
                "ARCHITECTURE_DECISIONS.md": "# Decisions\n\n## Decisions\n\nThe documented choice keeps the index local and incrementally updated.\n",
                "DEVELOPMENT_PROGRESS.md": "# Progress\n\n## Current status\n\nIncremental discovery is implemented; Windows scan validation remains pending.\n",
                "TEST_RESULTS.md": "# Test results\n\n## Test results\n\nThe regression suite passed Unicode path and incremental recovery fixtures.\n",
                "TASK_BACKLOG.md": "# Backlog\n\n## Pending tasks\n\n- [ ] Verify junction handling on the supported Windows filesystem.\n",
            }
            for name, content in sources.items():
                (project / name).write_text(content, encoding="utf-8")
            for index in range(61):
                (project / f"B-{index:02d}.md").write_text(
                    f"# Supporting note {index}\n\nNo classified evidence in this document.\n",
                    encoding="utf-8",
                )

            index_all(settings)
            profile_path = settings.knowledge_root / "projects" / "standardknowledgedocs" / "PROJECT_MEMORY.md"
            profile = profile_path.read_text(encoding="utf-8")
            self.assertIn("ARCHITECTURE.md:5-5` · architecture / Architecture", profile)
            self.assertIn("ARCHITECTURE_DECISIONS.md:5-5` · decisions / Decisions", profile)
            self.assertIn("DEVELOPMENT_PROGRESS.md:5-5` · status / Current status", profile)
            self.assertIn("TEST_RESULTS.md:5-5` · tests / Test results", profile)
            self.assertIn("TASK_BACKLOG.md:5-5` · pending / Pending tasks", profile)
            self.assertIn("[ ] Verify junction handling on the supported Windows filesystem.", profile)
            self.assertIn("generated_version: 21", profile)
            self.assertEqual(index_all(settings)["modified"], 0)

    def test_project_profile_prioritizes_individual_adrs_with_many_markdown_files(self) -> None:
        self.assertEqual(_project_document_priority("ADR-0002-local-index.md"), 12)
        self.assertEqual(_project_document_priority("docs/adr/0001-local-index.md"), 12)
        self.assertEqual(_project_document_priority("decisions/0003-local-index.md"), 12)
        self.assertIsNone(_project_document_priority("B-00.md"))
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "IndividualAdrDocs"
            project.mkdir()
            (project / "README.md").write_text(
                "# IndividualAdrDocs\n\n## Features\n\nThe service keeps project metadata local.\n",
                encoding="utf-8",
            )
            adr_dir = project / "docs" / "adr"
            adr_dir.mkdir(parents=True)
            (adr_dir / "0001-local-index.md").write_text(
                "# ADR 0001\n\n## Decision\n\nThe project stores searchable metadata in its local SQLite index.\n",
                encoding="utf-8",
            )
            for index in range(61):
                (project / f"B-{index:02d}.md").write_text(
                    f"# Supporting note {index}\n\nNo classified evidence in this document.\n",
                    encoding="utf-8",
                )

            index_all(settings)

            profile_path = settings.knowledge_root / "projects" / "individualadrdocs" / "PROJECT_MEMORY.md"
            profile = profile_path.read_text(encoding="utf-8")
            self.assertIn("docs/adr/0001-local-index.md:5-5` · decisions / Decision", profile)
            self.assertIn("local SQLite index", profile)
            self.assertIn("generated_version: 21", profile)
            self.assertEqual(index_all(settings)["modified"], 0)

    def test_project_profile_captures_multiple_feature_sections_with_citations(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "RicherProject"
            project.mkdir()
            (project / "README.md").write_text(
                "# RicherProject\n\n"
                "## Widget\n"
                "The floating widget exposes these functions:\n"
                "- Live resource metrics\n"
                "  - CPU and memory update once per second.\n"
                "  - Temperature reads ACPI zones when available.\n"
                "- Controls\n"
                "  - Pinning keeps the window on top.\n\n"
                "## Data sources\n"
                "The monitor reads local configuration and updates each second.\n\n"
                "## Monitor en consola / reportes\n"
                "The console monitor emits a periodic usage report for local sessions.\n\n"
                "## Architecture\n"
                "The UI reads metrics from a local provider that isolates platform-specific calls.\n\n"
                "## Tests\n"
                "The unit suite checks metric parsing and settings persistence.\n",
                encoding="utf-8",
            )

            index_all(settings)

            profile_path = next((settings.knowledge_root / "projects").rglob("PROJECT_MEMORY.md"))
            profile = profile_path.read_text(encoding="utf-8")
            self.assertEqual(profile.count(" · features / "), 3)
            self.assertIn(
                "README.md:5-9` · features / Widget: “Live resource metrics CPU and memory update once per second. Temperature reads ACPI zones when available. Controls Pinning keeps the window on top.”",
                profile,
            )
            self.assertIn(
                "README.md:12-12` · features / Data sources: “The monitor reads local configuration and updates each second.”",
                profile,
            )
            self.assertIn(
                "README.md:15-15` · features / Monitor en consola / reportes: “The console monitor emits a periodic usage report for local sessions.”",
                profile,
            )
            self.assertIn("README.md:18-18` · architecture / Architecture", profile)
            self.assertIn("README.md:21-21` · tests / Tests", profile)
            context = retrieve_context(
                settings, "periodic usage report local sessions",
                source_kind="internal", max_chars=2000,
            )
            self.assertTrue(any(
                "README.md:15-15" in fragment["text"]
                and "periodic usage report for local sessions" in fragment["text"]
                for fragment in context["fragments"]
            ))
            self.assertEqual(index_all(settings)["modified"], 0)

    def test_archived_project_docs_remain_searchable_but_not_current_evidence(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "HistoricalDocs"
            archive = project / "anterior" / "README_v1.md"
            archive.parent.mkdir(parents=True)
            (project / "README.md").write_text(
                "# HistoricalDocs\n\n## Features\n\nThe current release displays live CPU metrics in its local window.\n",
                encoding="utf-8",
            )
            archive_marker = "retired_legacy_feature_evidence_marker"
            archive.write_text(
                "# HistoricalDocs v1\n\n## Features\n\n"
                f"The retired release included {archive_marker} and an earlier layout.\n",
                encoding="utf-8",
            )

            index_all(settings)
            profile_path = settings.knowledge_root / "projects" / "historicaldocs" / "PROJECT_MEMORY.md"
            profile = profile_path.read_text(encoding="utf-8")
            self.assertIn("generated_version: 21", profile)
            self.assertIn("README.md:5-5` · features / Features", profile)
            self.assertNotIn(archive_marker, profile)
            self.assertIn(
                "`anterior/README_v1.md` — ruta histórica; se conserva indexada, pero no se usa como evidencia vigente.",
                profile,
            )
            self.assertTrue(search_documents(settings, archive_marker, source_kind="projects", project=str(project)))
            self.assertEqual(index_all(settings)["modified"], 0)

    def test_context_prefers_complete_query_matches_then_falls_back_to_partial(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "Relevant.md").write_text(
                "# Relevant\n\nPeriodic usage report for local sessions.\n", encoding="utf-8",
            )
            (settings.vault_root / "Noise.md").write_text(
                "# Noise\n\nPeriodic maintenance notes for the index.\n", encoding="utf-8",
            )
            (settings.vault_root / "Quartz.md").write_text(
                "# Quartz\n\nQuartz reference token.\n", encoding="utf-8",
            )
            (settings.vault_root / "Marzipan.md").write_text(
                "# Marzipan\n\nMarzipan reference token.\n", encoding="utf-8",
            )
            (settings.vault_root / "Strong evidence.md").write_text(
                "# Strong evidence\n\nHarbor lantern are documented together.\n", encoding="utf-8",
            )
            (settings.vault_root / "Weak evidence.md").write_text(
                "# Weak evidence\n\nHarbor appears without its related term.\n", encoding="utf-8",
            )
            (settings.vault_root / "Compass only.md").write_text(
                "# Compass only\n\nCompass is documented separately.\n", encoding="utf-8",
            )
            (settings.vault_root / "Identifier.md").write_text(
                "# Identifier\n\nIncremental sync preserves Unicode información técnica.\n",
                encoding="utf-8",
            )
            index_all(settings)

            complete = retrieve_context(settings, "periodic usage report local sessions", max_chars=2000)
            self.assertTrue(complete["fragments"])
            self.assertEqual({item["title"] for item in complete["fragments"]}, {"Relevant"})
            self.assertIn("Relevant.md:", complete["fragments"][0]["citation"])

            partial = retrieve_context(settings, "quartz marzipan", max_chars=2000)
            self.assertEqual(
                {item["title"] for item in partial["fragments"]}, {"Quartz", "Marzipan"},
            )
            best_partial = retrieve_context(
                settings, "harbor lantern compass", max_chars=2000,
            )
            self.assertEqual(
                {item["title"] for item in best_partial["fragments"]}, {"Strong evidence"},
            )
            identifier = retrieve_context(settings, "incremental_sync informacion tecnica", max_chars=2000)
            self.assertEqual({item["title"] for item in identifier["fragments"]}, {"Identifier"})

    def test_document_search_falls_back_to_best_partial_match_with_coverage(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "Relevant.md").write_text(
                "# Relevant\n\nPeriodic usage report for local sessions.\n", encoding="utf-8",
            )
            (settings.vault_root / "Noise.md").write_text(
                "# Noise\n\nPeriodic maintenance notes for the index.\n", encoding="utf-8",
            )
            (settings.vault_root / "Weak.md").write_text(
                "# Weak\n\nUsage report is mentioned without the other requested terms.\n", encoding="utf-8",
            )
            index_all(settings)

            exact = search_documents(settings, "periodic usage report sessions")
            self.assertEqual([item["title"] for item in exact], ["Relevant"])
            self.assertEqual(exact[0]["query_match"], {
                "matched_terms": 4, "total_terms": 4, "complete": True,
            })

            partial = search_documents(settings, "periodic usage report sessions absentneedle")
            self.assertEqual([item["title"] for item in partial], ["Relevant"])
            self.assertEqual(partial[0]["query_match"], {
                "matched_terms": 4, "total_terms": 5, "complete": False,
            })
            self.assertEqual(partial[0]["relative_path"], "Relevant.md")
            self.assertEqual(search_documents(
                settings, "periodic absentneedle missingword",
            ), [], "one shared token must not produce a noisy partial result")
            self.assertEqual(search_documents(
                settings, "periodic usage report sessions absentneedle", source_kind="projects",
            ), [])

    def test_project_memory_normalizes_safe_markdown_and_never_promotes_unchecked_features(self) -> None:
        self.assertIsNone(_normalize_project_excerpt_markdown(
            "A nested destination [label](https://example.invalid/a_(b)) remains unsupported."
        ))
        self.assertIsNone(_normalize_project_excerpt_markdown("Untrusted inline <script>markup</script> is unsupported."))
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "MarkdownEvidence"
            project.mkdir()
            (project / "README.md").write_text(
                "# MarkdownEvidence\n\n"
                "## Features\n"
                "- [ ] Add a future export control before the next release.\n"
                "The **local widget** reads [daily metrics](https://example.invalid/metrics) "
                "from \x60settings.json\x60 and *shows recent activity*.\n\n"
                "## Architecture\n"
                "password: fixture-secret-marker\n\n"
                "## Pending\n"
                "- [x] Completed an old task that should not be listed as pending.\n"
                "- [ ] Review the documented import behavior before enabling synchronization.\n",
                encoding="utf-8",
            )

            index_all(settings)

            profile = (settings.knowledge_root / "projects" / "markdownevidence" / "PROJECT_MEMORY.md").read_text(encoding="utf-8")
            self.assertIn("generated_version: 21", profile)
            self.assertIn("README.md:5-5", profile)
            self.assertIn(
                "features / Features: “The local widget reads daily metrics from settings.json and shows recent activity.”",
                profile,
            )
            self.assertNotIn("example.invalid", profile)
            self.assertNotIn("Add a future export control", profile)
            self.assertNotIn("fixture-secret-marker", profile)
            self.assertNotIn("Completed an old task", profile)
            self.assertIn(
                "pending / Pending: “[ ] Review the documented import behavior before enabling synchronization.”",
                profile,
            )
            self.assertEqual(index_all(settings)["modified"], 0)

    def test_project_memory_slug_collision_uses_stable_path_identity(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project_one = settings.projects_root / "A B"
            project_two = settings.projects_root / "A_B"
            project_one.mkdir()
            project_two.mkdir()
            (project_one / "README.md").write_text("# Project one\nFirst profile evidence.\n", encoding="utf-8")
            (project_two / "README.md").write_text("# Project two\nSecond profile evidence.\n", encoding="utf-8")
            legacy_profile = settings.knowledge_root / "projects" / "a-b" / "PROJECT_MEMORY.md"
            legacy_profile.parent.mkdir(parents=True)
            legacy_profile.write_text(
                f"# Legacy notes for A B\n\nPreserve this human-authored line.\n- Ruta: `{project_one}`\n",
                encoding="utf-8",
            )

            index_all(settings)
            profiles = list((settings.knowledge_root / "projects").glob("*/PROJECT_MEMORY.md"))
            self.assertEqual(len(profiles), 2)
            profile_texts = {path.read_text(encoding="utf-8") for path in profiles}
            self.assertTrue(any(f"- Ruta: `{project_one}`" in text for text in profile_texts))
            self.assertTrue(any(f"- Ruta: `{project_two}`" in text for text in profile_texts))
            self.assertIn("Preserve this human-authored line.", legacy_profile.read_text(encoding="utf-8"))
            before_paths = {str(path.resolve()) for path in profiles}

            index_all(settings)
            after_paths = {str(path.resolve()) for path in (settings.knowledge_root / "projects").glob("*/PROJECT_MEMORY.md")}
            self.assertEqual(after_paths, before_paths)
            with Database(settings.database_path) as db:
                count = db.one(
                    "SELECT COUNT(*) AS c FROM documents WHERE status='active' AND source_kind='internal' AND relative_path LIKE 'projects/%/PROJECT_MEMORY.md'"
                )["c"]
            self.assertEqual(count, 2)

    def test_onboard_unicode_source_preview_approval_and_incremental_index(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            source = Path(temp) / "Fuentes autorizadas" / "Guía Ñ"
            source.mkdir(parents=True)
            (source / "README.md").write_text("# Guía Ñ\nConocimiento local incorporado.\n", encoding="utf-8")

            preview = preview_source(settings, source, "local")
            self.assertFalse(preview["already_configured"])
            self.assertTrue(preview["approval_required"])
            self.assertIn("README.md", preview["sample_entries"])
            self.assertEqual(settings.additional_sources(), [])

            with patch.object(Path, "iterdir", side_effect=PermissionError("simulated permission denial")):
                with self.assertRaises(PermissionError):
                    preview_source(settings, source, "local")
            self.assertEqual(settings.additional_sources(), [])

            approved = approve_source(settings, source, "local", "Guía local")
            self.assertTrue(approved["approved"])
            self.assertEqual(len(settings.additional_sources()), 1)
            approve_source(settings, source, "local", "Guía local")
            self.assertEqual(len(settings.additional_sources()), 1)

            scan = index_all(settings)
            self.assertEqual(scan["errors"], 0)
            self.assertTrue(search_documents(settings, "Conocimiento local incorporado", source_kind="local"))

    def test_onboard_rejects_symlink_and_reparse_paths_before_resolving(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            source = Path(temp) / "Fuente segura"
            source.mkdir()
            with self.assertRaises(FileNotFoundError):
                preview_source(settings, Path(temp) / "No existe", "local")
            traversal = Path(temp) / ".." / "Fuente segura"
            self.assertTrue(contains_reparse_component(traversal))
            with self.assertRaisesRegex(ValueError, "reparse point"):
                preview_source(settings, traversal, "local")
            nested_source = source / "Notas"
            nested_source.mkdir()
            alias = Path(temp) / "Alias fuente"
            parent_alias = Path(temp) / "Alias padre"
            try:
                alias.symlink_to(source, target_is_directory=True)
                parent_alias.symlink_to(source, target_is_directory=True)
            except (OSError, NotImplementedError):
                alias = source
                parent_alias = Path(temp)
                simulated_reparse = True
            else:
                simulated_reparse = False

            if not simulated_reparse:
                self.assertTrue(contains_reparse_component(alias))
                with self.assertRaisesRegex(ValueError, "reparse point"):
                    preview_source(settings, alias, "local")
                self.assertTrue(contains_reparse_component(parent_alias / "Notas"))
                with self.assertRaisesRegex(ValueError, "reparse point"):
                    preview_source(settings, parent_alias / "Notas", "local")
            with patch("rabanito.onboard.contains_reparse_component", return_value=True):
                with self.assertRaisesRegex(ValueError, "reparse point"):
                    preview_source(settings, source, "local")

    def test_onboard_preview_enumerates_at_most_twenty_entries(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            source = Path(temp) / "Large source"
            source.mkdir()
            original_iterdir = Path.iterdir
            inspected: list[int] = []

            def counted_iterdir(path: Path):
                if path == source.resolve():
                    for index in range(1000):
                        inspected.append(index)
                        yield source / f"entry-{index:04}.md"
                    return
                yield from original_iterdir(path)

            with patch.object(Path, "iterdir", counted_iterdir):
                preview = preview_source(settings, source, "local")
            self.assertEqual(len(inspected), 20)
            self.assertEqual(len(preview["sample_entries"]), 20)

    def test_removed_project_is_marked_missing_and_reappears_without_deleting_memory_file(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "Lifecycle"
            project.mkdir()
            readme = project / "README.md"
            readme.write_text("# Lifecycle\ntraceable project description\n", encoding="utf-8")
            index_all(settings)
            memory_file = settings.knowledge_root / "projects" / "lifecycle" / "PROJECT_MEMORY.md"
            self.assertTrue(memory_file.is_file())

            readme.unlink()
            project.rmdir()
            result = index_all(settings)
            self.assertEqual(result["removed"], 2)
            with Database(settings.database_path) as db:
                row = db.one("SELECT status FROM projects WHERE name='Lifecycle'")
                memory_status = db.one("SELECT status FROM documents WHERE relative_path LIKE 'projects/lifecycle/PROJECT_MEMORY.md'")
            self.assertEqual(row["status"], "missing")
            self.assertEqual(memory_status["status"], "deleted")
            self.assertTrue(memory_file.is_file())
            self.assertFalse(search_documents(settings, "traceable project description", source_kind="projects"))

            project.mkdir()
            readme.write_text("# Lifecycle\ntraceable project description\n", encoding="utf-8")
            index_all(settings)
            with Database(settings.database_path) as db:
                row = db.one("SELECT status FROM projects WHERE name='Lifecycle'")
                memory_status = db.one("SELECT status FROM documents WHERE relative_path LIKE 'projects/lifecycle/PROJECT_MEMORY.md'")
            self.assertEqual(row["status"], "active")
            self.assertEqual(memory_status["status"], "active")
            self.assertTrue(search_documents(settings, "traceable project description", source_kind="projects"))

    def test_unreadable_replacement_preserves_previous_indexed_document(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            note = settings.vault_root / "Resistente.md"
            note.write_text("# Resistente\ncontenido bueno y verificable\n", encoding="utf-8")
            index_all(settings)
            note.write_text("# Resistente\ncontenido nuevo\n", encoding="utf-8")
            failed_parse = ParsedDocument("Resistente", {}, [], [], "", [], "", "OSError: simulated")
            with patch("rabanito.indexer.parse_markdown", return_value=failed_parse):
                result = index_all(settings)
            self.assertEqual(result["errors"], 1)
            self.assertTrue(search_documents(settings, "verificable", source_kind="obsidian"))

    def test_link_parser_ignores_code_and_classifies_reference_types(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "Destino.md").write_text("# Destino\n", encoding="utf-8")
            source = settings.vault_root / "Sub" / "Nota.md"
            source.parent.mkdir()
            source.write_text(
                "```md\n[[No Indexar]] #falso\n```\n`[[Inline]] #oculto`\n"
                "[[../Destino]] [destino](../Destino.md) [[https://example.test/a]] [[imagen.png]]\n",
                encoding="utf-8",
            )
            parsed = parse_markdown(source)
            self.assertEqual({link["target_raw"] for link in parsed.links}, {"../Destino", "../Destino.md", "https://example.test/a", "imagen.png"})
            self.assertNotIn("falso", parsed.tags)
            self.assertNotIn("oculto", parsed.tags)
            index_all(settings)
            with Database(settings.database_path) as db:
                links = [dict(row) for row in db.query("SELECT target_raw, relation_type, status FROM links")]
            self.assertIn({"target_raw": "../Destino", "relation_type": "wikilink", "status": "resolved"}, links)
            self.assertIn({"target_raw": "../Destino.md", "relation_type": "markdown", "status": "resolved"}, links)
            self.assertIn({"target_raw": "https://example.test/a", "relation_type": "wikilink", "status": "external"}, links)
            self.assertIn({"target_raw": "imagen.png", "relation_type": "wikilink", "status": "attachment"}, links)

    def test_path_suffix_resolves_only_unique_same_root_candidates(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            course = settings.vault_root / "Curso"
            labs = course / "02 Labs"
            target = labs / "Lab 02 - IDS.md"
            target.parent.mkdir(parents=True)
            target.write_text("# IDS\n", encoding="utf-8")
            (course / "11 Detection").mkdir()
            (course / "11 Detection" / "Amazon GuardDuty.md").write_text("# GuardDuty\n", encoding="utf-8")
            source = labs / "Lab 01 - Nmap.md"
            source.write_text(
                "# Nmap\n\n[[02 Labs/Lab 02 - IDS]]\n[[15 Cloud Security/Amazon GuardDuty]]\n",
                encoding="utf-8",
            )

            index_all(settings)
            with Database(settings.database_path) as db:
                rows = {row["target_raw"]: dict(row) for row in db.query(
                    "SELECT target_raw,status,resolution_reason,target_path_guess FROM links"
                )}
            self.assertEqual(rows["02 Labs/Lab 02 - IDS"]["status"], "resolved")
            self.assertEqual(rows["02 Labs/Lab 02 - IDS"]["resolution_reason"], "suffix_path_match")
            self.assertEqual(rows["02 Labs/Lab 02 - IDS"]["target_path_guess"], "Curso/02 Labs/Lab 02 - IDS.md")
            self.assertEqual(rows["15 Cloud Security/Amazon GuardDuty"]["status"], "broken")

            decoy = settings.vault_root / "Otro Curso" / "02 Labs" / "Lab 02 - IDS.md"
            decoy.parent.mkdir(parents=True)
            decoy.write_text("# IDS otro\n", encoding="utf-8")
            index_all(settings)
            with Database(settings.database_path) as db:
                row = dict(db.one(
                    "SELECT status,resolution_reason FROM links WHERE target_raw='02 Labs/Lab 02 - IDS'"
                ))
            self.assertEqual(row, {"status": "ambiguous", "resolution_reason": "multiple_suffix_path_matches"})

    def test_markdown_links_with_unicode_spaces_titles_and_parentheses_resolve(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            target = settings.vault_root / "Carpeta (Guía)" / "Nota Ñ.md"
            target.parent.mkdir()
            target.write_text("# Nota Ñ\nContenido destino.\n", encoding="utf-8")
            source = settings.vault_root / "Origen.md"
            source.write_text(
                '# Origen\n\n'
                '[nota](Carpeta (Guía)/Nota Ñ.md "título de enlace")\n'
                '[otra forma](<Carpeta (Guía)/Nota Ñ.md>)\n'
                '![diagrama](assets/Mapa final.svg)\n',
                encoding="utf-8",
            )
            parsed = parse_markdown(source)
            self.assertEqual(
                [(link["target_raw"], link["relation_type"]) for link in parsed.links],
                [
                    ("Carpeta (Guía)/Nota Ñ.md", "markdown"),
                    ("Carpeta (Guía)/Nota Ñ.md", "markdown"),
                    ("assets/Mapa final.svg", "embed"),
                ],
            )
            index_all(settings)
            with Database(settings.database_path) as db:
                links = [dict(row) for row in db.query(
                    "SELECT target_raw, relation_type, status FROM links ORDER BY line_number"
                )]
            self.assertEqual(links, [
                {"target_raw": "Carpeta (Guía)/Nota Ñ.md", "relation_type": "markdown", "status": "resolved"},
                {"target_raw": "Carpeta (Guía)/Nota Ñ.md", "relation_type": "markdown", "status": "resolved"},
                {"target_raw": "assets/Mapa final.svg", "relation_type": "embed", "status": "attachment"},
            ])

    def test_existing_directory_link_is_classified_separately_from_missing_notes(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "wiki" / "vulnerabilities").mkdir(parents=True)
            (settings.vault_root / "Raven.md").write_text(
                "# Raven\n\n[[wiki/vulnerabilities/]]\n[[wiki/missing-note/]]\n", encoding="utf-8"
            )
            index_all(settings)
            with Database(settings.database_path) as db:
                rows = [dict(row) for row in db.query(
                    "SELECT target_raw,status,resolution_reason FROM links ORDER BY target_raw"
                )]
            self.assertEqual(rows, [
                {"target_raw": "wiki/missing-note/", "status": "broken", "resolution_reason": "missing_path"},
                {"target_raw": "wiki/vulnerabilities/", "status": "directory", "resolution_reason": "existing_directory_not_document"},
            ])
            self.assertEqual(stats(settings)["links_directories"], 1)
            self.assertEqual(collect_audit(settings)["counts"]["links_directories"], 1)

    def test_audit_detects_source_drift_without_mutating_the_index(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            changed_metadata = settings.vault_root / "Changed metadata.md"
            same_metadata = settings.vault_root / "Same metadata.md"
            missing = settings.vault_root / "Missing after scan.md"
            stable = settings.vault_root / "Stable.md"
            changed_metadata.write_text("# Changed metadata\nold content\n", encoding="utf-8")
            same_metadata.write_text("# Same metadata\nold text\n", encoding="utf-8")
            missing.write_text("# Missing after scan\nstill indexed\n", encoding="utf-8")
            stable.write_text("# Stable\nunchanged content\n", encoding="utf-8")
            index_all(settings)

            changed_metadata.write_text("# Changed metadata\nnew content with a different size\n", encoding="utf-8")
            original = same_metadata.stat()
            same_metadata.write_text("# Same metadata\nnew text\n", encoding="utf-8")
            self.assertEqual(same_metadata.stat().st_size, original.st_size)
            os.utime(same_metadata, ns=(original.st_atime_ns, original.st_mtime_ns))
            missing.unlink()
            with Database(settings.database_path) as db:
                scan_before = int(db.one("SELECT MAX(scan_id) AS scan_id FROM scan_runs")["scan_id"])

            report = collect_audit(settings)
            findings = {item["relative_path"]: item["status"] for item in report["index_drift_findings"]}
            self.assertEqual(findings["Changed metadata.md"], "metadata_changed")
            self.assertEqual(findings["Same metadata.md"], "content_changed_same_metadata")
            self.assertEqual(findings["Missing after scan.md"], "path_unavailable_or_unsafe")
            self.assertEqual(report["counts"]["documents_index_drift"], 3, f"findings={findings!r}, summary={report['index_drift_summary']!r}")
            self.assertEqual(report["index_drift_summary"]["by_status"]["unchanged"], 1)
            self.assertGreater(report["index_drift_summary"]["bytes_hashed"], 0)
            self.assertTrue(report["index_drift_summary"]["coverage_complete"])
            written = write_audit(settings)
            rendered = (settings.knowledge_root / written["markdown_path"]).read_text(encoding="utf-8")
            self.assertIn("Read-only source/index consistency", rendered)
            self.assertIn("content_changed_same_metadata", rendered)
            with Database(settings.database_path) as db:
                scan_after = int(db.one("SELECT MAX(scan_id) AS scan_id FROM scan_runs")["scan_id"])
                missing_status = db.one(
                    "SELECT status FROM documents WHERE relative_path='Missing after scan.md'"
                )["status"]
            self.assertEqual(scan_after, scan_before)
            self.assertEqual(missing_status, "active", "Audit must report drift, not silently synchronize the index")
            self.assertTrue(search_documents(settings, "old text", source_kind="obsidian"))

    def test_audit_index_drift_budget_is_visible_and_dashboard_redacts_paths_and_content(self) -> None:
        with self.temporary_directory() as temp:
            root = Path(temp)
            settings = self.make_settings(root)
            source = settings.vault_root / "Ruta Privada.md"
            source.write_text("# Ruta Privada\ncontenido-privado-centinela\n", encoding="utf-8")
            index_all(settings)
            settings.raw["audit_index_check_max_bytes"] = 1
            report = collect_audit(settings)
            self.assertFalse(report["index_drift_summary"]["coverage_complete"])
            self.assertEqual(report["counts"]["documents_index_check_skipped"], 1)
            self.assertEqual(report["counts"]["documents_index_drift"], 0)

            settings.raw["audit_index_check_max_bytes"] = 1024 * 1024
            original = source.stat()
            source.write_text("# Ruta Privada\ncontenido-privado-observado\n", encoding="utf-8")
            self.assertEqual(source.stat().st_size, original.st_size)
            os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
            projected = dashboard_audit(settings)
            encoded = json.dumps(projected, ensure_ascii=False)
            self.assertEqual(projected["counts"]["documents_index_drift"], 1)
            self.assertEqual(projected["index_drift_findings"][0]["status"], "content_changed_same_metadata")
            self.assertEqual(projected["index_drift_findings"][0]["relative_path"], "Ruta Privada.md")
            self.assertNotIn(str(root), encoded)
            self.assertNotIn("contenido-privado-centinela", encoded)
            self.assertNotIn("contenido-privado-observado", encoded)
            self.assertNotIn("content_hash", encoded)
            synthetic = collect_audit(settings)
            synthetic["index_drift_summary"]["findings_truncated"] = False
            synthetic["index_drift_findings"] = [
                {
                    "document_id": index + 1, "title": f"Note {index}",
                    "source_kind": "obsidian", "relative_path": f"Notes/{index}.md",
                    "status": "metadata_changed", "review_only": True,
                }
                for index in range(101)
            ]
            limited_projection = dashboard_audit_view(synthetic)
            self.assertEqual(len(limited_projection["index_drift_findings"]), 100)
            self.assertTrue(limited_projection["index_drift_summary"]["findings_truncated"])
            leveled = level_up(settings)
            self.assertIn(
                "Sincronizar cambios locales del índice",
                [item["action"] for item in leveled["recommendations"]],
            )

    def test_audit_index_document_budget_reports_partial_coverage(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "One.md").write_text("# One\ncontent one\n", encoding="utf-8")
            (settings.vault_root / "Two.md").write_text("# Two\ncontent two\n", encoding="utf-8")
            index_all(settings)
            settings.raw["audit_index_check_max_documents"] = 1

            report = collect_audit(settings)
            self.assertEqual(report["index_drift_summary"]["active_documents"], 2)
            self.assertEqual(report["index_drift_summary"]["checked_documents"], 1)
            self.assertEqual(report["index_drift_summary"]["documents_skipped_by_budget"], 1)
            self.assertFalse(report["index_drift_summary"]["coverage_complete"])
            self.assertEqual(report["counts"]["documents_index_check_skipped"], 1)

    def test_dashboard_audit_projection_is_redacted_minimal_and_read_only(self) -> None:
        with self.temporary_directory() as temp:
            root = Path(temp)
            settings = self.make_settings(root)
            source = settings.vault_root / "Source.md"
            source.write_text("# Source\n\nDocumento de auditoría.\n", encoding="utf-8")
            index_all(settings)
            with Database(settings.database_path) as db:
                source_id = db.one("SELECT document_id FROM documents WHERE relative_path='Source.md'")["document_id"]
                db.execute(
                    "INSERT INTO links(source_document_id,target_raw,status,resolution_reason,line_number) VALUES(?,?,?,?,?)",
                    (source_id, "api_key=dashboard-secret-fixture", "broken", "missing_path", 3),
                )
                db.execute(
                    "INSERT INTO links(source_document_id,target_raw,status,resolution_reason,line_number) VALUES(?,?,?,?,?)",
                    (source_id, r"C:\Users\fixture-user\private\confidential.md", "broken", "invalid_absolute_path", 4),
                )
                db.execute(
                    "INSERT INTO links(source_document_id,target_raw,status,resolution_reason,line_number) VALUES(?,?,?,?,?)",
                    (source_id, "file:///C:/Users/fixture-user/private/nota%20privada.md", "broken", "invalid_file_reference", 5),
                )
                db.commit()

            report = dashboard_audit(settings)
            encoded = json.dumps(report, ensure_ascii=False)
            self.assertNotIn("dashboard-secret-fixture", encoded)
            self.assertNotIn(r"C:\Users\fixture-user\private", encoded)
            self.assertNotIn("file:///C:/Users/fixture-user/private", encoded)
            self.assertNotIn(str(root), encoded)
            self.assertNotIn('"absolute_path"', encoded)
            self.assertNotIn("potential_contradictions", encoded)
            self.assertTrue(report["review_only"])
            self.assertEqual(report["counts"]["links_broken"], 3)
            finding = report["missing_link_review"][0]
            self.assertEqual(finding["source_document_id"], source_id)
            self.assertEqual(finding["source_relative_path"], "Source.md")
            self.assertIn("[REDACTED]", finding["target_raw"])
            absolute_finding = report["other_broken_findings"][0]
            self.assertEqual(absolute_finding["resolution_reason"], "invalid_absolute_path")
            self.assertIn("[ruta absoluta omitida]", absolute_finding["target_raw"])
            file_uri_finding = next(item for item in report["other_broken_findings"] if item["resolution_reason"] == "invalid_file_reference")
            self.assertEqual(file_uri_finding["target_raw"], "[URI de archivo omitida] · nota privada.md")

            handler = type("TestRabanitoHandler", (RabanitoHandler,), {"settings": settings})
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                with urlopen(origin + "/api/audit/latest") as response:
                    get_report = json.loads(response.read())
                self.assertEqual(get_report["counts"]["links_broken"], 3)
                self.assertNotIn("dashboard-secret-fixture", json.dumps(get_report, ensure_ascii=False))
                self.assertNotIn(r"C:\Users\fixture-user\private", json.dumps(get_report, ensure_ascii=False))
                self.assertNotIn("file:///C:/Users/fixture-user/private", json.dumps(get_report, ensure_ascii=False))
                request = Request(
                    origin + "/api/audit", data=b"{}", method="POST",
                    headers={"Content-Type": "application/json", "Origin": origin},
                )
                with urlopen(request) as response:
                    written_report = json.loads(response.read())
                self.assertNotIn("dashboard-secret-fixture", json.dumps(written_report, ensure_ascii=False))
                self.assertNotIn("json_path", written_report)
                with Database(settings.database_path) as db:
                    status = db.one("SELECT status FROM links WHERE source_document_id=?", (source_id,))["status"]
                self.assertEqual(status, "broken", "dashboard audit must not resolve links")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_report_pairs_are_exclusive_under_existing_names_and_concurrency(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            directory = settings.knowledge_root / "quality-reports"
            directory.mkdir(parents=True)
            reserved = directory / "20261013-210500-audit.json"
            reserved.write_text("existing report sentinel", encoding="utf-8")

            def write_report(number: int) -> tuple[Path, Path]:
                return _write_report_pair(settings, "audit", {"run": number}, f"# report {number}\n")

            with patch("rabanito.capabilities.datetime") as clock:
                clock.now.return_value.strftime.return_value = "20261013-210500"
                with ThreadPoolExecutor(max_workers=8) as pool:
                    paths = list(pool.map(write_report, range(8)))

            json_paths = [item[0] for item in paths]
            markdown_paths = [item[1] for item in paths]
            self.assertEqual(len(set(json_paths)), 8)
            self.assertEqual(len(set(markdown_paths)), 8)
            self.assertEqual(reserved.read_text(encoding="utf-8"), "existing report sentinel")
            self.assertTrue(all(path.exists() for path in json_paths + markdown_paths))
            self.assertEqual({json.loads(path.read_text(encoding="utf-8"))["run"] for path in json_paths}, set(range(8)))

    def test_report_writer_rejects_reparse_destination_before_creating_it(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            report_directory = settings.knowledge_root / "quality-reports"
            with patch("rabanito.capabilities.contains_reparse_component", return_value=True):
                with self.assertRaisesRegex(ValueError, "reparse-point"):
                    _write_report_pair(settings, "audit", {"safe": True}, "# safe\n")
            self.assertFalse(report_directory.exists())

    def test_cli_and_persisted_audit_reports_use_safe_relative_references(self) -> None:
        with self.temporary_directory() as temp:
            root = Path(temp) / "PRIVATE_AUDIT_ROOT_SENTINEL"
            root.mkdir()
            settings = self.make_settings(root)
            (settings.vault_root / "Source.md").write_text(
                "# Source\n\n[[Missing Target]]\n", encoding="utf-8",
            )
            (settings.vault_root / "Positive.md").write_text(
                "# Positive\n\nDeployment mode is CLAIM_SENTINEL_6d21.\n", encoding="utf-8",
            )
            (settings.vault_root / "Negative.md").write_text(
                "# Negative\n\nDeployment mode is not CLAIM_SENTINEL_6d21.\n", encoding="utf-8",
            )
            duplicate_text = "# Duplicate\n\nSame content for the duplicate detector.\n"
            (settings.vault_root / "Duplicate A.md").write_text(duplicate_text, encoding="utf-8")
            (settings.vault_root / "Duplicate B.md").write_text(duplicate_text, encoding="utf-8")
            index_all(settings)
            with Database(settings.database_path) as db:
                db.execute(
                    "UPDATE documents SET mtime_iso=? WHERE relative_path=?",
                    ("2000-01-01T00:00:00+00:00", "Positive.md"),
                )
                db.commit()

            raw = collect_audit(settings)
            self.assertTrue(raw["potential_contradictions"], "fixture must exercise claim redaction")
            safe = audit_report_view(raw)
            encoded_safe = json.dumps(safe, ensure_ascii=False)
            self.assertNotIn(str(root), encoded_safe)
            self.assertNotIn("CLAIM_SENTINEL_6d21", encoded_safe)
            self.assertNotIn('"absolute_path"', encoded_safe)
            self.assertNotIn('"content_hash"', encoded_safe)
            self.assertTrue(safe["stale_documents"])
            self.assertTrue(safe["duplicate_hashes"])
            self.assertTrue(safe["potential_contradictions"][0]["review_only"])

            written = write_audit(settings)
            self.assertFalse(Path(written["json_path"]).is_absolute())
            self.assertFalse(Path(written["markdown_path"]).is_absolute())
            json_report = settings.knowledge_root / written["json_path"]
            markdown_report = settings.knowledge_root / written["markdown_path"]
            persisted = json_report.read_text(encoding="utf-8")
            rendered = markdown_report.read_text(encoding="utf-8")
            for content in (persisted, rendered):
                self.assertNotIn(str(root), content)
                self.assertNotIn("CLAIM_SENTINEL_6d21", content)
            self.assertIn("obsidian:Source.md:3", rendered)

            level = level_up(settings)
            level_json = settings.knowledge_root / level["json_path"]
            level_text = level_json.read_text(encoding="utf-8")
            self.assertNotIn(str(root), level_text)
            self.assertNotIn("CLAIM_SENTINEL_6d21", level_text)

            config_path = root / "config" / "settings.example.json"
            write_json_atomic(config_path, settings.raw)
            output = StringIO()
            with redirect_stdout(output):
                cli_main(["--config", str(config_path), "audit"])
            self.assertNotIn(str(root), output.getvalue())
            self.assertNotIn("CLAIM_SENTINEL_6d21", output.getvalue())
            output = StringIO()
            with redirect_stdout(output):
                cli_main(["--config", str(config_path), "audit", "--write"])
            written_cli_report = json.loads(output.getvalue())
            self.assertFalse(Path(written_cli_report["json_path"]).is_absolute())
            self.assertNotIn(str(root), output.getvalue())
            self.assertNotIn("CLAIM_SENTINEL_6d21", output.getvalue())

    def test_audit_lists_exact_alternate_path_candidates_without_resolving_them(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            for folder in ("Actual One", "Actual Two"):
                target = settings.vault_root / folder / "Moved Note.md"
                target.parent.mkdir()
                target.write_text("# Moved Note\n", encoding="utf-8")
            source = settings.vault_root / "Source.md"
            source.write_text("# Source\n\n[[Wrong Folder/Moved Note]]\n", encoding="utf-8")
            index_all(settings)

            report = collect_audit(settings)
            review = report["missing_link_review"]
            self.assertEqual(len(review), 1)
            self.assertEqual(review[0]["review_classification"], "multiple_same_root_candidates")
            self.assertEqual(review[0]["candidate_count"], 2)
            self.assertTrue(review[0]["review_only"])
            with Database(settings.database_path) as db:
                row = dict(db.one("SELECT status,target_document_id FROM links"))
            self.assertEqual(row, {"status": "broken", "target_document_id": None})

    def test_audit_detects_live_markdown_created_after_scan_without_mutating_link(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            source = settings.vault_root / "Origen.md"
            source.write_text("# Origen\n\n[[Nueva Carpeta/Nota Ñ]]\n", encoding="utf-8")
            index_all(settings)

            target = settings.vault_root / "Nueva Carpeta" / "Nota Ñ.md"
            target.parent.mkdir()
            target.write_text("# Nota Ñ\n\nContenido nuevo para indexar.\n", encoding="utf-8")
            report = collect_audit(settings)
            finding = report["missing_link_review"][0]
            self.assertEqual(finding["live_path_classification"], "live_markdown_not_indexed")
            self.assertEqual(finding["live_path_candidates"], ["Nueva Carpeta/Nota Ñ.md"])
            self.assertEqual(report["missing_link_path_state_counts"], {"live_markdown_not_indexed": 1})
            written = write_audit(settings)
            rendered = (settings.knowledge_root / written["markdown_path"]).read_text(encoding="utf-8")
            self.assertIn("live_markdown_not_indexed: 1", rendered)
            self.assertIn("Nueva Carpeta/Nota Ñ.md", rendered)
            with Database(settings.database_path) as db:
                row = dict(db.one("SELECT status,target_document_id FROM links"))
                active_target_count = db.one(
                    "SELECT COUNT(*) AS c FROM documents WHERE relative_path=? AND status='active'",
                    ("Nueva Carpeta/Nota Ñ.md",),
                )["c"]
            self.assertEqual(row, {"status": "broken", "target_document_id": None})
            self.assertEqual(active_target_count, 0)

            result = index_all(settings)
            self.assertGreaterEqual(result["added"], 1)
            with Database(settings.database_path) as db:
                row = dict(db.one("SELECT status,target_document_id FROM links"))
            self.assertEqual(row["status"], "resolved")
            self.assertIsNotNone(row["target_document_id"])

    def test_audit_checks_extensionful_non_markdown_target_without_duplicating_suffix(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            target = settings.vault_root / "assets" / "reference.pdf"
            target.parent.mkdir()
            target.write_bytes(b"fixture attachment")
            (settings.vault_root / "Source.md").write_text(
                "# Source\n\n[[assets/reference.pdf]]\n", encoding="utf-8",
            )
            index_all(settings)
            with Database(settings.database_path) as db:
                db.execute(
                    "UPDATE links SET status='broken',resolution_reason='missing_path' WHERE target_raw='assets/reference.pdf'"
                )
                db.commit()

            report = collect_audit(settings)
            finding = report["missing_link_review"][0]
            self.assertEqual(finding["live_path_classification"], "live_non_markdown_not_indexed")
            self.assertEqual(finding["live_path_candidates"], ["assets/reference.pdf"])
            with Database(settings.database_path) as db:
                row = dict(db.one("SELECT status,resolution_reason FROM links"))
            self.assertEqual(row, {"status": "broken", "resolution_reason": "missing_path"})

    def test_audit_contradictions_require_same_subject_and_same_base_value(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "Positive.md").write_text(
                "# Positive\n\nService is available.\n", encoding="utf-8"
            )
            (settings.vault_root / "Negated.md").write_text(
                "# Negated\n\nService is not available.\nService is not configured.\n", encoding="utf-8"
            )
            (settings.vault_root / "Sensitive.md").write_text(
                "# Sensitive\n\nAPI key is TEST-ONLY-NOT-A-CREDENTIAL.\nAPI key is not TEST-ONLY-NOT-A-CREDENTIAL.\n",
                encoding="utf-8",
            )
            index_all(settings)

            candidates = _collect_audit_raw(settings)["potential_contradictions"]
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0]["subject"], "service")
            self.assertEqual({candidates[0]["left"]["value"].rstrip("."), candidates[0]["right"]["value"].rstrip(".")}, {"available"})
            self.assertTrue(any(
                item["operator"].casefold() == "is not"
                for item in (candidates[0]["left"], candidates[0]["right"])
            ))

    def test_audit_contradictions_detects_spanish_negated_claims(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "Disponible.md").write_text(
                "# Estado\n\n"
                "El servicio está disponible.\n"
                "La interfaz es estable.\n"
                "Los componentes son locales.\n"
                "El proceso se encuentra activo.\n"
                "El backend funciona en Windows.\n",
                encoding="utf-8",
            )
            (settings.vault_root / "NoDisponible.md").write_text(
                "# Estado\n\n"
                "El servicio no está disponible.\n"
                "La interfaz no es estable.\n"
                "Los componentes no son locales.\n"
                "El proceso no se encuentra activo.\n"
                "El backend no funciona en Windows.\n",
                encoding="utf-8",
            )
            index_all(settings)

            report = _collect_audit_raw(settings)
            candidates = report["potential_contradictions"]
            self.assertEqual(len(candidates), 5)
            self.assertEqual(
                {item["subject"] for item in candidates},
                {"servicio", "interfaz", "componentes", "proceso", "backend"},
            )
            self.assertEqual({
                item["subject"]: item["left"]["value"].rstrip(".")
                for item in candidates
            }, {
                "servicio": "disponible", "interfaz": "estable",
                "componentes": "locales", "proceso": "activo", "backend": "en Windows",
            })
            for item in candidates:
                self.assertTrue(any("no" in claim["operator"].casefold() for claim in (item["left"], item["right"])))
            safe = audit_report_view(report)
            self.assertTrue(safe["potential_contradictions"][0]["review_only"])

    def test_audit_contradictions_deduplicate_repeated_claims_per_document(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            repeated_positive = "El servicio está disponible.\n" * 120
            repeated_negative = "El servicio no está disponible.\n" * 120
            (settings.vault_root / "Disponible.md").write_text(repeated_positive, encoding="utf-8")
            (settings.vault_root / "NoDisponible.md").write_text(repeated_negative, encoding="utf-8")
            index_all(settings)

            report = _collect_audit_raw(settings)
            self.assertEqual(len(report["potential_contradictions"]), 1)
            summary = report["contradiction_scan_summary"]
            self.assertEqual(summary["claims_indexed"], 2)
            finding = report["potential_contradictions"][0]
            self.assertNotEqual(finding["left"]["document_id"], finding["right"]["document_id"])

    def test_audit_contradiction_claim_budget_marks_coverage_partial(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            settings.raw["audit_contradiction_max_claims"] = 1
            (settings.vault_root / "Positive.md").write_text(
                "El servicio está disponible.\n", encoding="utf-8",
            )
            (settings.vault_root / "Negative.md").write_text(
                "El servicio no está disponible.\n", encoding="utf-8",
            )
            index_all(settings)

            report = _collect_audit_raw(settings)
            summary = report["contradiction_scan_summary"]
            self.assertEqual(summary["claims_indexed"], 1)
            self.assertTrue(summary["claim_budget_exhausted"])
            self.assertFalse(summary["coverage_complete"])
            self.assertEqual(report["potential_contradictions"], [])

            projected = dashboard_audit_view(report)["contradiction_scan_summary"]
            self.assertTrue(projected["claim_budget_exhausted"])
            self.assertEqual(projected["claim_limit"], 1)
            self.assertFalse(projected["coverage_complete"])
            recommendations = level_up(settings)["recommendations"]
            review = next(item for item in recommendations if item["action"] == "Completar revisión de contradicciones")
            self.assertIn("límite de 1 afirmaciones únicas", review["why"])
            written = write_audit(settings)
            markdown = (settings.knowledge_root / written["markdown_path"]).read_text(encoding="utf-8")
            self.assertIn("claim budget exhausted: True", markdown)

    def test_audit_contradictions_include_authorized_project_roots(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "Proyecto Verificable"
            project.mkdir()
            (settings.vault_root / "Architecture.md").write_text(
                "# Architecture\n\nService is available.\n", encoding="utf-8",
            )
            (project / "README.md").write_text(
                "# Proyecto Verificable\n\nService is not available.\n", encoding="utf-8",
            )
            index_all(settings)

            candidates = _collect_audit_raw(settings)["potential_contradictions"]
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0]["subject"], "service")
            self.assertIn(str(project / "README.md"), {
                candidates[0]["left"]["path"], candidates[0]["right"]["path"],
            })

    def test_audit_contradiction_scan_exposes_global_byte_budget(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            first = settings.vault_root / "A.md"
            second = settings.vault_root / "B.md"
            first.write_text("# A\n\nService is available.\n", encoding="utf-8")
            second.write_text("# B\n\nService is not available.\n", encoding="utf-8")
            index_all(settings)
            budget = max(first.stat().st_size, second.stat().st_size)
            settings.raw["audit_contradiction_max_bytes"] = budget

            report = collect_audit(settings)
            summary = report["contradiction_scan_summary"]
            self.assertFalse(summary["coverage_complete"])
            self.assertEqual(summary["documents_read"], 1)
            self.assertGreater(summary["documents_skipped_by_byte_budget"], 0)
            self.assertLessEqual(summary["bytes_read"], budget + 1)
            self.assertEqual(report["potential_contradictions"], [])

            projected = dashboard_audit_view(report)
            self.assertFalse(projected["contradiction_scan_summary"]["coverage_complete"])
            self.assertNotIn(str(settings.vault_root), json.dumps(projected, ensure_ascii=False))
            written = write_audit(settings)
            persisted = json.loads((settings.knowledge_root / written["json_path"]).read_text(encoding="utf-8"))
            self.assertFalse(persisted["contradiction_scan_summary"]["coverage_complete"])
            markdown = (settings.knowledge_root / written["markdown_path"]).read_text(encoding="utf-8")
            self.assertIn("Contradiction review:", markdown)

    def test_audit_contradiction_scan_exposes_document_budget(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            for name in ("Uno.md", "Dos.md", "Tres.md"):
                (settings.vault_root / name).write_text(f"# {name}\n", encoding="utf-8")
            index_all(settings)
            settings.raw["audit_contradiction_max_documents"] = 1

            summary = collect_audit(settings)["contradiction_scan_summary"]
            self.assertEqual(summary["active_documents"], 3)
            self.assertEqual(summary["documents_read"], 1)
            self.assertEqual(summary["documents_skipped_by_document_budget"], 2)
            self.assertFalse(summary["coverage_complete"])
            recommendations = level_up(settings)["recommendations"]
            self.assertTrue(any(
                item["action"] == "Completar revisión de contradicciones"
                for item in recommendations
            ))

    def test_audit_skips_project_sources_excluded_after_last_index(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "Proyecto Excluido"
            project.mkdir()
            project_file = project / "README.md"
            project_file.write_text(
                "# Proyecto Excluido\n-----BEGIN PRIVATE KEY-----\n"
                "Service is not available.\n", encoding="utf-8",
            )
            (settings.vault_root / "Architecture.md").write_text(
                "# Architecture\n\nService is available.\n", encoding="utf-8",
            )
            index_all(settings)
            # Exercise a configuration change before the next sync; Audit must honor it now.
            settings.raw["excluded_projects"] = [str(project)]

            with patch("rabanito.capabilities._existing_source_file", wraps=_existing_source_file) as safe_file:
                report = collect_audit(settings)

            self.assertEqual(report["potential_contradictions"], [])
            self.assertEqual(report["counts"]["documents_with_unclosed_sensitive_blocks"], 0)
            self.assertFalse(any(
                call.args[0] == project for call in safe_file.call_args_list
            ))

    def test_audit_contradictions_skip_paths_rejected_as_reparse_or_nonregular(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "One.md").write_text("# One\n\nService is available.\n", encoding="utf-8")
            (settings.vault_root / "Two.md").write_text("# Two\n\nService is not available.\n", encoding="utf-8")
            index_all(settings)

            with patch("rabanito.capabilities._existing_source_file", return_value=None) as safe_file:
                report = collect_audit(settings)
            self.assertEqual(report["potential_contradictions"], [])
            self.assertGreaterEqual(safe_file.call_count, 4)

    def test_audit_reports_unclosed_private_key_marker_without_copying_source_content(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            open_block = settings.vault_root / "Bloque abierto.md"
            original = (
                "# Bloque abierto\n"
                "-----BEGIN PRIVATE KEY-----\n"
                "PRIVATE_MATERIAL_SENTINEL\n"
                "[[Not Imported]]\n"
                "still censored\n"
            )
            open_block.write_text(original, encoding="utf-8")
            (settings.vault_root / "Bloque cerrado.md").write_text(
                "# Bloque cerrado\n-----BEGIN PRIVATE KEY-----\nmaterial\n-----END PRIVATE KEY-----\n",
                encoding="utf-8",
            )
            self.assertEqual(unclosed_private_key_lines(original), [2])
            index_all(settings)

            report = collect_audit(settings)
            self.assertEqual(report["counts"]["documents_with_unclosed_sensitive_blocks"], 1)
            finding = report["sensitive_redaction_review"][0]
            self.assertEqual(finding["relative_path"], "Bloque abierto.md")
            self.assertEqual(finding["marker_lines"], [2])
            self.assertEqual(finding["suppressed_line_count"], 4)
            self.assertNotIn("PRIVATE_MATERIAL_SENTINEL", json.dumps(report, ensure_ascii=False))
            self.assertEqual(open_block.read_text(encoding="utf-8"), original)

            written = write_audit(settings)
            rendered = (settings.knowledge_root / written["markdown_path"]).read_text(encoding="utf-8")
            self.assertIn("Bloque abierto.md:2", rendered)
            self.assertNotIn("PRIVATE_MATERIAL_SENTINEL", rendered)

    def test_audit_redaction_review_accepts_project_roots_only_under_authorized_projects_root(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "Proyecto Local"
            project.mkdir()
            (project / "README.md").write_text(
                "# Proyecto Local\n-----BEGIN PRIVATE KEY-----\nsecreto de fixture\n",
                encoding="utf-8",
            )
            index_all(settings)
            report = collect_audit(settings)
            project_findings = [item for item in report["sensitive_redaction_review"] if item["source_kind"] == "projects"]
            self.assertEqual(len(project_findings), 1)
            self.assertEqual(project_findings[0]["relative_path"], "README.md")
            self.assertEqual(project_findings[0]["marker_lines"], [2])

    def test_audit_contradictions_do_not_read_documents_from_unconfigured_roots(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "Allowed.md").write_text("# Allowed\n\nService is available.\n", encoding="utf-8")
            index_all(settings)
            external_root = settings.root / "Unconfigured source"
            external_root.mkdir()
            external_file = external_root / "Outside.md"
            external_file.write_text(
                "# Outside\n-----BEGIN PRIVATE KEY-----\nService is not available.\n",
                encoding="utf-8",
            )
            external_target = external_root / "Private Target.md"
            external_target.write_text("# Private Target\nnot read by audit\n", encoding="utf-8")
            invalid_root = str(settings.projects_root / "Invalid\x00Root")
            with Database(settings.database_path) as db:
                external_document = db.execute(
                    """INSERT INTO documents(source_kind,source_root,relative_path,absolute_path,path_key,title,category,indexed_at,last_seen_scan)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    ("local", str(external_root), external_file.name, str(external_file), "unauthorized-source-test-key",
                     "Outside", "local", "2026-10-13T00:00:00+00:00", "2026-10-13T00:00:00+00:00"),
                )
                db.execute(
                    "INSERT INTO links(source_document_id,target_raw,status,resolution_reason,line_number) VALUES(?,?,?,?,?)",
                    (external_document.lastrowid, "Private Target", "broken", "missing_path", 9),
                )
                db.execute(
                    """INSERT INTO documents(source_kind,source_root,relative_path,absolute_path,path_key,title,category,indexed_at,last_seen_scan)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    ("projects", invalid_root, "README.md", invalid_root + "\\README.md", "invalid-project-root-test-key",
                     "Invalid path", "projects/Invalid", "2026-10-13T00:00:00+00:00", "2026-10-13T00:00:00+00:00"),
                )
                db.commit()

            with patch("rabanito.capabilities._existing_source_file", wraps=_existing_source_file) as safe_file:
                report = collect_audit(settings)
            self.assertEqual(report["potential_contradictions"], [])
            self.assertEqual(report["counts"]["documents_with_unclosed_sensitive_blocks"], 0)
            self.assertGreaterEqual(safe_file.call_count, 2)
            self.assertTrue(all(Path(call.args[0]) == settings.vault_root for call in safe_file.call_args_list))
            # Unconfigured origins are now excluded before metadata projection,
            # not merely prevented from opening files during link review.
            self.assertFalse(any(item["source_title"] == "Outside" for item in report["missing_link_review"]))
            self.assertEqual(report["counts"]["documents_active"], 1)
            self.assertNotIn("Private Target", json.dumps(report, ensure_ascii=False))
            self.assertNotIn("not read by audit", json.dumps(report, ensure_ascii=False))

    def test_level_up_returns_bounded_summary_and_preserves_full_audit_report(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "Source.md").write_text("# Source\n\nSee [[Missing Target]].\n", encoding="utf-8")
            index_all(settings)
            result = level_up(settings)
            self.assertEqual(result["based_on"]["counts"]["links_broken"], 1)
            self.assertNotIn("link_findings", result["based_on"])
            self.assertEqual(result["recommendations"][0]["priority"], "high")
            full_report = json.loads((settings.knowledge_root / result["json_path"]).read_text(encoding="utf-8"))
            self.assertEqual(full_report["based_on"]["counts"]["links_broken"], 1)
            self.assertEqual(len(full_report["based_on"]["link_findings"]), 1)
            self.assertTrue((settings.knowledge_root / result["markdown_path"]).is_file())

    def test_extensionless_existing_non_markdown_wikilink_is_an_attachment(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            attachment = settings.vault_root / "wiki" / ".gitignore-security-template"
            attachment.parent.mkdir(parents=True)
            attachment.write_text("local template", encoding="utf-8")
            (settings.vault_root / "Raven.md").write_text(
                "# Raven\n\n[[wiki/.gitignore-security-template]]\n", encoding="utf-8"
            )

            index_all(settings)
            with Database(settings.database_path) as db:
                row = dict(db.one("SELECT status,resolution_reason,target_path_guess FROM links"))

            self.assertEqual(row, {
                "status": "attachment",
                "resolution_reason": "existing_non_markdown_file_not_indexed",
                "target_path_guess": "wiki/.gitignore-security-template",
            })
            self.assertEqual(stats(settings)["links_broken"], 0)
            self.assertEqual(stats(settings)["links_attachments"], 1)

    def test_reparse_directory_entries_are_skipped(self) -> None:
        class FakeEntry:
            def is_symlink(self) -> bool:
                return False

            def stat(self, *, follow_symlinks: bool) -> SimpleNamespace:
                return SimpleNamespace(st_file_attributes=0x400)

        self.assertTrue(_is_reparse_entry(FakeEntry()))
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            link_like = settings.vault_root / "Junction"
            link_like.mkdir()
            (link_like / "not-indexed.md").write_text("# Not indexed\n", encoding="utf-8")
            with patch("rabanito.indexer._is_reparse_entry", side_effect=lambda entry: entry.name == "Junction"):
                index_all(settings)
            self.assertFalse(search_documents(settings, "not indexed", source_kind="obsidian"))

    def test_excluded_projects_are_not_discovered_or_indexed(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project_name = "Proyecto Ñ Privado"
            settings.raw["excluded_projects"] = [project_name]
            private = settings.projects_root / project_name
            private.mkdir()
            (private / "README.md").write_text(f"# {project_name}\nsecret project description\n", encoding="utf-8")
            result = index_all(settings)
            self.assertEqual(result["source_summary"].get("projects", {}).get("seen", 0), 0)
            self.assertFalse(search_documents(settings, "secret project", source_kind="projects"))

    def test_excluding_an_indexed_project_retires_source_and_generated_profile(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "Privado"
            project.mkdir()
            readme = project / "README.md"
            readme.write_text("# Privado\nunique private architecture fact\n", encoding="utf-8")
            index_all(settings)
            add_memory_record(
                settings, project="Privado", problem="Isolation test", statement="private decision marker",
                evidence=["project:README.md"], status="confirmed", validation="passed",
            )
            index_all(settings)
            self.assertTrue(search_documents(settings, "private architecture", source_kind="projects"))
            self.assertTrue(search_documents(settings, "private decision marker", source_kind="internal"))
            settings.raw["excluded_projects"] = [str(project)]
            result = index_all(settings)
            self.assertGreaterEqual(result["removed"], 3)
            self.assertFalse(search_documents(settings, "private architecture", source_kind="projects"))
            self.assertFalse(search_documents(settings, "Privado", source_kind="internal"))
            self.assertFalse(search_documents(settings, "private decision marker", source_kind="internal"))

            settings.raw["excluded_projects"] = []
            index_all(settings)
            self.assertTrue(search_documents(settings, "private decision marker", source_kind="internal"))

    def test_index_jobs_serialize_and_do_not_duplicate_documents(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "Concurrente.md").write_text("# Concurrente\núnico documento\n", encoding="utf-8")
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _n: index_all(settings), range(2)))
            self.assertEqual(sum(item["added"] for item in results), 1)
            with Database(settings.database_path) as db:
                count = db.one("SELECT COUNT(*) AS c FROM documents WHERE relative_path='Concurrente.md'")["c"]
            self.assertEqual(count, 1)

    def test_dashboard_only_accepts_loopback_hosts(self) -> None:
        self.assertTrue(_is_loopback_host("127.0.0.1"))
        self.assertTrue(_is_loopback_host("::1"))
        self.assertTrue(_is_loopback_host("localhost"))
        self.assertFalse(_is_loopback_host("0.0.0.0"))
        self.assertTrue(_request_host_is_loopback("127.0.0.1:8765", 8765))
        self.assertTrue(_request_host_is_loopback("localhost:8765", 8765))
        self.assertTrue(_request_host_is_loopback("[::1]:8765", 8765))
        self.assertFalse(_request_host_is_loopback("attacker.example:8765", 8765))
        self.assertFalse(_request_host_is_loopback("127.0.0.1:8764", 8765))
        self.assertFalse(_request_host_is_loopback("user@127.0.0.1:8765", 8765))
        self.assertFalse(_request_host_is_loopback("127.0.0.1", 8765))
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            with self.assertRaises(ValueError):
                serve_dashboard(settings, host="0.0.0.0")
            with patch("rabanito.server.ThreadingHTTPServer") as server_factory:
                server_factory.return_value.serve_forever.side_effect = KeyboardInterrupt
                with patch("builtins.print"):
                    serve_dashboard(settings, host="localhost", port=8765)
                self.assertEqual(server_factory.call_args.args[0], ("127.0.0.1", 8765))
                server_factory.return_value.server_close.assert_called_once_with()

    def test_dashboard_rejects_dns_rebinding_host_on_all_routes(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            handler = type("TestRabanitoHandler", (RabanitoHandler,), {"settings": settings})
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f"http://127.0.0.1:{server.server_address[1]}"
            malicious_host = f"rebind.attacker.example:{server.server_address[1]}"
            try:
                for path in ("/", "/api/stats", "/api/scans", "/api/changes", "/api/search?q=private", "/api/audit/latest"):
                    request = Request(origin + path, headers={"Host": malicious_host})
                    with self.assertRaises(HTTPError) as denied:
                        urlopen(request)
                    self.assertEqual(denied.exception.code, 403)
                    denied.exception.close()
                request = Request(
                    origin + "/api/source-preview", data=json.dumps({"path": str(settings.vault_root), "kind": "local"}).encode(),
                    method="POST", headers={"Host": malicious_host, "Origin": origin, "Content-Type": "application/json"},
                )
                with self.assertRaises(HTTPError) as denied_post:
                    urlopen(request)
                self.assertEqual(denied_post.exception.code, 403)
                denied_post.exception.close()
                self.assertEqual(settings.additional_sources(), [])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_dashboard_controls_have_accessible_names_and_graph_keyboard_navigation(self) -> None:
        html = (Path(__file__).resolve().parents[1] / "web" / "index.html").read_text(encoding="utf-8")

        class LabelAudit(HTMLParser):
            def __init__(self) -> None:
                super().__init__()
                self.label_stack: list[str | None] = []
                self.labelled: set[str] = set()
                self.controls: set[str] = set()
                self.unlabelled: set[str] = set()

            def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
                attributes = dict(attrs)
                if tag == "label":
                    target = attributes.get("for")
                    self.label_stack.append(target)
                    if target:
                        self.labelled.add(target)
                elif tag in {"input", "select", "textarea"}:
                    control_id = attributes.get("id")
                    if control_id:
                        self.controls.add(control_id)
                        has_aria_name = bool(attributes.get("aria-label") or attributes.get("aria-labelledby"))
                        if not has_aria_name and control_id not in self.labelled and not self.label_stack:
                            self.unlabelled.add(control_id)
                        elif self.label_stack:
                            self.labelled.add(control_id)

            def handle_endtag(self, tag: str) -> None:
                if tag == "label" and self.label_stack:
                    self.label_stack.pop()

        audit = LabelAudit()
        audit.feed(html)
        self.assertTrue(audit.controls)
        self.assertEqual(audit.unlabelled, set())
        self.assertIn('aria-describedby="graphStatus"', html)
        self.assertIn("$('graph').focus()", html)
        self.assertIn("e.key==='Escape'", html)
        self.assertIn("e.key==='ArrowLeft'", html)
        self.assertIn("e.key===' '", html)
        self.assertIn('id="projectInventory"', html)
        self.assertIn('id="auditIndexDrift" class="results" aria-live="polite"', html)
        self.assertIn("function renderIndexDrift(report)", html)
        self.assertIn("project.status!=='active'", html)
        self.assertIn("list.append(entry)", html)

    def test_confirmed_memory_requires_local_evidence_and_is_searchable(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "Proyecto Memoria"
            project.mkdir()
            (project / "README.md").write_text("# Proyecto Memoria\nEl servicio usa SQLite local.\n", encoding="utf-8")
            other_project = settings.projects_root / "Otra Raíz"
            other_project.mkdir()
            (other_project / "README.md").write_text("# Otra Raíz\nSQLite local unrelated marker Otra Raíz.\n", encoding="utf-8")
            index_all(settings)
            with self.assertRaises(ValueError):
                add_memory_record(settings, project="Proyecto Memoria", problem="Persistencia", statement="SQLite", status="confirmed")
            for prefix in ("project", "obsidian", "internal"):
                with self.subTest(evidence_prefix=prefix):
                    with self.assertRaisesRegex(ValueError, "sale de la raíz local"):
                        add_memory_record(
                            settings, project="Proyecto Memoria", problem="Aislamiento de evidencia",
                            statement=f"No cruzar desde {prefix}", status="confirmed",
                            evidence=[f"{prefix}:{other_project / 'README.md'}"],
                        )
            self.assertEqual(
                _safe_evidence_refs(settings, project, [str(other_project / "README.md")]),
                ["projects:Otra Raíz/README.md"],
            )
            self.assertEqual(
                _safe_evidence_refs(settings, project, [f"projects:{project / 'README.md'}"]),
                ["project:README.md"],
            )
            self.assertFalse((settings.knowledge_root / "decisions").exists())
            record = add_memory_record(
                settings, project="Proyecto Memoria", problem="Conservar estado sin servicio remoto",
                statement="Usar SQLite local para el índice persistente", status="confirmed",
                reason="La documentación del proyecto especifica almacenamiento local.",
                components=["índice"], technologies=["Python", "SQLite"],
                tests=["integridad SQLite: correcta"], result="151/151 pruebas pasaron",
                evidence=["project:README.md"], validation="passed",
            )
            self.assertTrue(Path(record["path"]).is_file())
            self.assertEqual(record["technologies"], ["Python", "SQLite"])
            record_source = Path(record["path"]).read_text(encoding="utf-8")
            record_body = record_source.split("---", 2)[2]
            self.assertIn("project:README.md", record_body)
            self.assertNotIn(str(project / "README.md"), record_body)
            self.assertIn("## Tecnologías", record_source)
            self.assertIn("151/151 pruebas pasaron", record_source)
            index_all(settings)
            listed = list_memory_records(settings, project="Proyecto Memoria")
            self.assertEqual(len(listed), 1)
            self.assertEqual(listed[0]["status"], "confirmed")
            self.assertEqual(listed[0]["record_type"], "decision")
            self.assertEqual(listed[0]["evidence"], ["project:README.md"])
            self.assertEqual(listed[0]["technologies"], ["Python", "SQLite"])
            path_filtered_records = list_memory_records(settings, project=str(project))
            self.assertEqual(len(path_filtered_records), 1)
            self.assertEqual(path_filtered_records[0]["project_root"], str(project))
            found = search_documents(settings, "índice persistente", source_kind="internal")
            self.assertTrue(any(item["title"].startswith("Decisión técnica") for item in found))
            project_context = retrieve_context(
                settings, "SQLite local", project=str(project), limit=20, max_chars=5000,
            )
            self.assertTrue(project_context["fragments"])
            self.assertTrue(all(item["project_root"] == str(project) for item in project_context["fragments"]))
            self.assertTrue(any(item["relative_path"].endswith("PROJECT_MEMORY.md") for item in project_context["fragments"]))
            self.assertTrue(any(item["relative_path"].startswith("decisions/") for item in project_context["fragments"]))
            self.assertFalse(any("Otra Raíz" in item["text"] for item in project_context["fragments"]))
            project_search = search_documents(settings, "SQLite local", project=str(project))
            self.assertTrue(any(item["relative_path"].endswith("PROJECT_MEMORY.md") for item in project_search))
            self.assertTrue(all(item["project_root"] == str(project) for item in project_search))
            dashboard_html = (Path(__file__).resolve().parents[1] / "web" / "index.html").read_text(encoding="utf-8")
            for control in ('id="decisionQuery"', 'id="decisionProject"', 'id="decisionType"', 'id="decisionStatus"'):
                self.assertIn(control, dashboard_html)
            self.assertIn("Evidencias:", dashboard_html)

            handler = type("TestRabanitoHandler", (RabanitoHandler,), {"settings": settings})
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with Database(settings.database_path) as db:
                    project_id = db.one("SELECT project_id FROM projects WHERE root_path=?", (str(project),))["project_id"]
                decision_request = Request(
                    f"http://127.0.0.1:{server.server_address[1]}/api/decisions",
                    data=json.dumps({"project_id": project_id, "type": "decision", "status": "confirmed", "q": "SQLite"}).encode(),
                    method="POST", headers={"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{server.server_address[1]}"},
                )
                with urlopen(decision_request) as response:
                    records = json.loads(response.read().decode("utf-8"))["records"]
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["project"], "Proyecto Memoria")
                self.assertEqual(records[0]["validation"], "passed")
                self.assertEqual(records[0]["evidence"], ["project:README.md"])
                self.assertNotIn("absolute_path", records[0])
                self.assertNotIn("project_root", records[0])
                self.assertNotIn(str(project), json.dumps(records[0], ensure_ascii=False))
                document_request = Request(
                    f"http://127.0.0.1:{server.server_address[1]}/api/doc/{records[0]['document_id']}",
                )
                with urlopen(document_request) as response:
                    document_payload = json.loads(response.read())
                self.assertEqual(document_payload["frontmatter"]["evidence"], ["project:README.md"])
                self.assertNotIn(str(project), json.dumps(document_payload, ensure_ascii=False))
                context_request = Request(
                    f"http://127.0.0.1:{server.server_address[1]}/api/context",
                    data=json.dumps({"project_id": project_id, "q": "README evidence", "limit": 20}).encode(),
                    method="POST", headers={"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{server.server_address[1]}"},
                )
                with urlopen(context_request) as response:
                    context_payload = json.loads(response.read())
                self.assertTrue(context_payload["fragments"])
                self.assertTrue(any("project:README.md" in item["text"] for item in context_payload["fragments"]))
                self.assertNotIn(str(project), json.dumps(context_payload, ensure_ascii=False))
                search_request = Request(
                    f"http://127.0.0.1:{server.server_address[1]}/api/search",
                    data=json.dumps({"project_id": project_id, "q": "SQLite local"}).encode(),
                    method="POST", headers={"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{server.server_address[1]}"},
                )
                with urlopen(search_request) as response:
                    search_payload = json.loads(response.read())
                self.assertTrue(search_payload["results"])
                self.assertTrue(all("absolute_path" not in item and "project_root" not in item for item in search_payload["results"]))
                self.assertNotIn(str(project), json.dumps(search_payload, ensure_ascii=False))
                with self.assertRaises(HTTPError) as query_get:
                    urlopen(f"http://127.0.0.1:{server.server_address[1]}/api/decisions?{urlencode({'project': str(project)})}")
                self.assertEqual(query_get.exception.code, 405)
                query_get.exception.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_explicit_cross_project_evidence_preserves_query_isolation(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            target = settings.projects_root / "Proyecto A"
            other = settings.projects_root / "Proyecto B"
            target.mkdir()
            other.mkdir()
            (target / "README.md").write_text("# Proyecto A\nA mantiene su propio contexto.\n", encoding="utf-8")
            (other / "README.md").write_text(
                "# Proyecto B\nsharedcrossmarker documenta su API pública.\n", encoding="utf-8",
            )
            index_all(settings)

            record = add_memory_record(
                settings, project=target.name,
                problem="sharedcrossmarker fue revisado como dependencia compartida",
                statement="Referenciar explícitamente la API documentada del otro proyecto",
                status="confirmed", evidence=["projects:Proyecto B/README.md"],
            )
            self.assertEqual(record["evidence"], ["projects:Proyecto B/README.md"])
            index_all(settings)

            memories = list_memory_records(settings, project=str(target), limit=10)
            self.assertEqual(len(memories), 1)
            self.assertEqual(memories[0]["evidence"], ["projects:Proyecto B/README.md"])
            search = search_documents(settings, "sharedcrossmarker", project=str(target), limit=20)
            context = retrieve_context(settings, "sharedcrossmarker", project=str(target), limit=20, max_chars=3000)
            self.assertTrue(search)
            self.assertTrue(context["fragments"])
            self.assertTrue(all(item["project_root"] == str(target) for item in search))
            self.assertTrue(all(item["project_root"] == str(target) for item in context["fragments"]))
            self.assertTrue(any(item["relative_path"].startswith("decisions/") for item in context["fragments"]))
            self.assertFalse(any(item["project_root"] == str(other) for item in search))
            self.assertFalse(any(item["project_root"] == str(other) for item in context["fragments"]))

    def test_decision_search_filters_before_applying_result_limit(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            target = settings.projects_root / "Proyecto Objetivo"
            distractor = settings.projects_root / "Proyecto Reciente"
            target.mkdir()
            distractor.mkdir()
            (target / "README.md").write_text("# Objetivo\n", encoding="utf-8")
            (distractor / "README.md").write_text("# Reciente\n", encoding="utf-8")
            index_all(settings)

            add_memory_record(
                settings, project=target.name, problem="Cache provider selection for local lookup",
                statement="Cache provider is selected for lookup", status="confirmed",
                reason="contexto " * 500,
                evidence=["project:README.md"], validation="passed",
            )
            for number in range(11):
                add_memory_record(
                    settings, project=distractor.name,
                    problem=f"Cache provider selection for local lookup, note {number}",
                    statement="Cache provider is selected for lookup", record_type="proposal",
                    status="proposed",
                )
            index_all(settings)

            from rabanito.search import DOCUMENT_BM25, fts_query
            with Database(settings.database_path) as db:
                unfiltered_top_ten = db.query(
                    "SELECT d.project_name FROM documents_fts JOIN documents d "
                    "ON d.document_id=CAST(documents_fts.document_id AS INTEGER) "
                    "WHERE d.source_kind='internal' AND d.relative_path LIKE 'decisions/%' "
                    f"AND documents_fts MATCH ? ORDER BY {DOCUMENT_BM25}, d.mtime_ns DESC LIMIT 10",
                    (fts_query("cache provider"),),
                )
            self.assertTrue(unfiltered_top_ten)
            self.assertTrue(all(row["project_name"] == distractor.name for row in unfiltered_top_ten))

            records = list_memory_records(
                settings, project=target.name, limit=1, record_type="decision",
                status="confirmed", query="cache provider",
            )
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["project"], target.name)
            self.assertEqual(records[0]["status"], "confirmed")
            self.assertEqual(records[0]["record_type"], "decision")
            self.assertEqual(list_memory_records(settings, project=target.name, limit=0), [])
            recent = list_memory_records(
                settings, project=target.name, limit=1, record_type="decision", status="confirmed",
            )
            self.assertEqual(len(recent), 1)
            self.assertEqual(recent[0]["project"], target.name)
            path_filtered = list_memory_records(
                settings, project=str(target), limit=1, record_type="decision",
                status="confirmed", query="cache provider",
            )
            self.assertEqual(len(path_filtered), 1)
            self.assertEqual(path_filtered[0]["project"], target.name)
            config_path = settings.root / "config" / "settings.example.json"
            config_path.parent.mkdir(parents=True, exist_ok=True)
            write_json_atomic(config_path, settings.raw)
            cli_output = StringIO()
            with redirect_stdout(cli_output):
                cli_main([
                    "--config", str(config_path), "decision", "list", "--project", str(target),
                    "--record-type", "decision", "--status", "confirmed", "--query", "cache provider",
                    "--limit", "1",
                ])
            cli_records = json.loads(cli_output.getvalue())
            self.assertEqual(len(cli_records), 1)
            self.assertEqual(cli_records[0]["project"], target.name)
            self.assertEqual(cli_records[0]["status"], "confirmed")
            cli_empty = StringIO()
            with redirect_stdout(cli_empty):
                cli_main([
                    "--config", str(config_path), "decision", "list", "--project", str(target), "--limit", "0",
                ])
            self.assertEqual(json.loads(cli_empty.getvalue()), [])

    def test_decision_list_orders_by_recorded_date_not_file_mtime(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "Chronology"
            project.mkdir()
            (project / "README.md").write_text("# Chronology\n", encoding="utf-8")
            index_all(settings)

            recorded_later = add_memory_record(
                settings, project=project.name, problem="Recent historical event",
                statement="Recorded date newer", record_type="fact", status="proposed",
                recorded_date="2026-10-10",
            )
            recorded_earlier = add_memory_record(
                settings, project=project.name, problem="Earlier historical event",
                statement="Recorded date older", record_type="fact", status="proposed",
                recorded_date="2026-10-01",
            )
            # Make the older event's file modification time unambiguously newer.
            os.utime(recorded_later["path"], ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000))
            os.utime(recorded_earlier["path"], ns=(1_750_000_000_000_000_000, 1_750_000_000_000_000_000))
            index_all(settings)

            listed = list_memory_records(settings, project=project.name, limit=2)
            self.assertEqual(
                [item["recorded_date"] for item in listed], ["2026-10-10", "2026-10-01"],
            )
            self.assertIn("Recorded date newer", listed[0]["title"])

            relevant_title = add_memory_record(
                settings, project=project.name, problem="A local search preference",
                statement="Quartz cache selects the local search index", record_type="decision",
                status="proposed", recorded_date="2026-10-01",
            )
            add_memory_record(
                settings, project=project.name, problem="Quartz cache " * 30,
                statement="Alternative storage approach documented", record_type="proposal",
                status="proposed", recorded_date="2026-10-10",
            )
            index_all(settings)
            search_order = list_memory_records(settings, project=project.name, query="quartz cache", limit=2)
            self.assertEqual(len(search_order), 2)
            self.assertIn("Quartz cache selects", search_order[0]["title"])

    def test_decision_search_tolerates_invalid_legacy_frontmatter_json(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "Legacy Project"
            project.mkdir()
            (project / "README.md").write_text("# Legacy Project\n", encoding="utf-8")
            index_all(settings)
            add_memory_record(
                settings, project=project.name, problem="Legacy decision lookup",
                statement="Keep local search available", status="confirmed",
                evidence=["project:README.md"], validation="passed",
            )
            index_all(settings)
            with Database(settings.database_path) as db:
                db.execute(
                    "UPDATE documents SET frontmatter_json=? WHERE source_kind='internal' AND relative_path LIKE 'decisions/%'",
                    ("{malformed legacy metadata",),
                )
                db.commit()

            unfiltered = list_memory_records(settings, query="local search")
            self.assertEqual(len(unfiltered), 1)
            self.assertIsNone(unfiltered[0]["status"])
            self.assertEqual(
                list_memory_records(settings, query="local search", status="confirmed"), [],
            )

    def test_decision_evidence_rejects_unverifiable_reparse_paths_before_resolve(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "EvidenceProject"
            project.mkdir()
            (project / "README.md").write_text("# EvidenceProject\n", encoding="utf-8")
            index_all(settings)
            with patch("rabanito.decisions.contains_reparse_component", return_value=True):
                with self.assertRaisesRegex(ValueError, "symlink/reparse"):
                    add_memory_record(
                        settings, project="EvidenceProject", problem="Path safety", statement="Reject reparse evidence",
                        evidence=["project:README.md"], status="confirmed",
                    )

    def test_decision_capture_rejects_sensitive_looking_values_before_creating_file(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "SensitiveMemory"
            project.mkdir()
            (project / "README.md").write_text("# SensitiveMemory\nDocumented local project.\n", encoding="utf-8")
            index_all(settings)

            with self.assertRaisesRegex(ValueError, "material sensible") as caught:
                add_memory_record(
                    settings, project="SensitiveMemory", problem="Credential handling",
                    statement="Record the operational finding", reason="AWS_SECRET_ACCESS_KEY=TEST_ONLY_SENTINEL",
                )
            self.assertNotIn("TEST_ONLY_SENTINEL", str(caught.exception))
            decision_root = settings.knowledge_root / "decisions"
            self.assertFalse(decision_root.exists())

    def test_concurrent_decision_records_are_serialized_and_never_overwrite(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project = settings.projects_root / "ConcurrentProject"
            project.mkdir()
            (project / "README.md").write_text("# ConcurrentProject\n", encoding="utf-8")
            index_all(settings)

            def record(number: int) -> dict[str, object]:
                return add_memory_record(
                    settings, project="ConcurrentProject", problem=f"Problem {number}",
                    statement="Concurrent decision record", evidence=["project:README.md"],
                )

            with ThreadPoolExecutor(max_workers=8) as pool:
                records = list(pool.map(record, range(8)))
            paths = [str(item["path"]) for item in records]
            self.assertEqual(len(paths), len(set(paths)))
            self.assertTrue(all(Path(path).is_file() for path in paths))
            self.assertEqual(len(list((settings.knowledge_root / "decisions").rglob("*.md"))), 8)

    def test_existing_database_schema_gets_link_reason_migration(self) -> None:
        with self.temporary_directory() as temp:
            database = Path(temp) / "legacy.db"
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE links (link_id INTEGER PRIMARY KEY, source_document_id INTEGER NOT NULL, "
                "target_raw TEXT NOT NULL, target_document_id INTEGER, relation_type TEXT NOT NULL DEFAULT 'wikilink', "
                "status TEXT NOT NULL DEFAULT 'unresolved', label TEXT, line_number INTEGER, target_path_guess TEXT, "
                "UNIQUE(source_document_id,target_raw,line_number))"
            )
            connection.execute(
                "CREATE TABLE documents (document_id INTEGER PRIMARY KEY, source_kind TEXT NOT NULL, "
                "source_root TEXT NOT NULL, project_name TEXT, relative_path TEXT NOT NULL, absolute_path TEXT NOT NULL, "
                "path_key TEXT NOT NULL, title TEXT NOT NULL, category TEXT NOT NULL, content_hash TEXT NOT NULL DEFAULT '', "
                "status TEXT NOT NULL DEFAULT 'active')"
            )
            connection.execute(
                "CREATE TABLE projects (project_id INTEGER PRIMARY KEY, name TEXT NOT NULL, root_path TEXT NOT NULL UNIQUE, "
                "path_key TEXT NOT NULL UNIQUE, technology_json TEXT NOT NULL DEFAULT '[]', structure_json TEXT NOT NULL DEFAULT '[]', "
                "documentation_json TEXT NOT NULL DEFAULT '[]', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, "
                "status TEXT NOT NULL DEFAULT 'active')"
            )
            connection.execute(
                "INSERT INTO projects(name,root_path,path_key,technology_json,structure_json,documentation_json,first_seen,last_seen) "
                "VALUES('Legacy','C:\\Projects\\Legacy','legacy','[\"Python\"]','[\"src\"]','[\"README.md\"]','2026-01-01','2026-01-02')"
            )
            connection.execute(
                "INSERT INTO documents(source_kind,source_root,project_name,relative_path,absolute_path,path_key,title,category) "
                "VALUES('projects','C:\\Projects\\Legacy','Legacy','README.md','C:\\Projects\\Legacy\\README.md','legacy','Legacy','projects/Legacy')"
            )
            connection.commit()
            connection.close()
            with Database(database) as db:
                columns = {row["name"] for row in db.query("PRAGMA table_info(links)")}
                document_columns = {row["name"] for row in db.query("PRAGMA table_info(documents)")}
                change_columns = {row["name"] for row in db.query("PRAGMA table_info(document_changes)")}
                project_columns = {row["name"] for row in db.query("PRAGMA table_info(projects)")}
                migrated = db.one("SELECT project_root_path FROM documents WHERE project_name='Legacy'")
                project = db.one("SELECT technology_json, structure_json, documentation_json, dependencies_json, dependencies_truncated, dependency_errors_json FROM projects WHERE name='Legacy'")
            self.assertIn("resolution_reason", columns)
            self.assertIn("project_root_path", document_columns)
            self.assertTrue({"scan_id", "document_id", "change_type", "reason", "occurred_at"}.issubset(change_columns))
            self.assertIn("dependencies_json", project_columns)
            self.assertIn("dependencies_truncated", project_columns)
            self.assertIn("dependency_errors_json", project_columns)
            self.assertEqual(migrated["project_root_path"], "C:\\Projects\\Legacy")
            self.assertEqual(project["technology_json"], '["Python"]')
            self.assertEqual(project["structure_json"], '["src"]')
            self.assertEqual(project["documentation_json"], '["README.md"]')
            self.assertEqual(project["dependencies_json"], "[]")
            self.assertEqual(project["dependencies_truncated"], 0)
            self.assertEqual(project["dependency_errors_json"], "[]")

    def test_database_backup_remains_integral_and_recovers_prior_search_state(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            note = settings.vault_root / "Snapshot.md"
            note.write_text("# Snapshot\noriginal recovery marker\n", encoding="utf-8")
            index_all(settings)
            backup_path = settings.data_dir / "backups" / "snapshot.db"
            with Database(settings.database_path) as db:
                db.backup(backup_path)
                original_event_count = int(db.one("SELECT COUNT(*) AS c FROM document_changes")["c"])
            self.assertEqual(original_event_count, 1)

            check = sqlite3.connect(backup_path)
            try:
                self.assertEqual(check.execute("PRAGMA journal_mode").fetchone()[0].casefold(), "delete")
                self.assertEqual(check.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertEqual(check.execute("PRAGMA foreign_key_check").fetchall(), [])
                self.assertEqual(check.execute("SELECT COUNT(*) FROM documents WHERE status='active'").fetchone()[0], 1)
            finally:
                check.close()
            self.assertFalse(Path(str(backup_path) + "-wal").exists())
            self.assertFalse(Path(str(backup_path) + "-shm").exists())

            original_backup = backup_path.read_bytes()
            with Database(settings.database_path) as db:
                with self.assertRaises(FileExistsError):
                    db.backup(backup_path)
            self.assertEqual(backup_path.read_bytes(), original_backup)

            detached_copy = settings.data_dir / "backups" / "detached-copy.db"
            detached_copy.write_bytes(original_backup)
            detached_check = sqlite3.connect(detached_copy)
            try:
                self.assertEqual(detached_check.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertEqual(
                    detached_check.execute("SELECT COUNT(*) FROM documents WHERE status='active'").fetchone()[0], 1
                )
            finally:
                detached_check.close()

            note.write_text("# Snapshot\nchanged live source marker\n", encoding="utf-8")
            index_all(settings)
            with Database(settings.database_path) as db:
                self.assertEqual(db.one("SELECT COUNT(*) AS c FROM document_changes")["c"], 2)
            backup_settings = Settings(settings.root, {**settings.raw, "database_path": str(backup_path)})
            self.assertTrue(search_documents(backup_settings, "original recovery marker", source_kind="obsidian"))
            self.assertFalse(search_documents(backup_settings, "changed live source marker", source_kind="obsidian"))
            with Database(backup_path) as db:
                backup_events = db.query("SELECT change_type,reason FROM document_changes ORDER BY change_id")
            self.assertEqual([tuple(row) for row in backup_events], [("added", "new_document")])

    def test_restore_is_validated_atomic_and_refuses_active_sidecars(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            note = settings.vault_root / "Restore.md"
            note.write_text("# Restore\nsnapshot recovery marker\n", encoding="utf-8")
            index_all(settings)
            backup_path = settings.data_dir / "backups" / "restore-source.db"
            with Database(settings.database_path) as db:
                db.backup(backup_path)

            note.write_text("# Restore\nnewer live marker\n", encoding="utf-8")
            index_all(settings)
            with Database(settings.database_path) as db:
                self.assertEqual(db.one("SELECT COUNT(*) AS c FROM document_changes")["c"], 2)
            restore_database(backup_path, settings.database_path)
            check = sqlite3.connect(settings.database_path)
            try:
                self.assertEqual(check.execute("PRAGMA journal_mode").fetchone()[0].casefold(), "delete")
                self.assertEqual(check.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertEqual(check.execute("PRAGMA foreign_key_check").fetchall(), [])
            finally:
                check.close()
            self.assertTrue(search_documents(settings, "snapshot recovery marker", source_kind="obsidian"))
            self.assertFalse(search_documents(settings, "newer live marker", source_kind="obsidian"))
            with Database(settings.database_path) as db:
                restored_events = db.query("SELECT change_type,reason FROM document_changes ORDER BY change_id")
            self.assertEqual([tuple(row) for row in restored_events], [("added", "new_document")])

            corrupt = settings.data_dir / "backups" / "not-a-rabanito-db.db"
            invalid = sqlite3.connect(corrupt)
            try:
                invalid.execute("CREATE TABLE unrelated (value TEXT)")
            finally:
                invalid.close()
            with self.assertRaises(sqlite3.DatabaseError):
                restore_database(corrupt, settings.database_path)
            self.assertTrue(search_documents(settings, "snapshot recovery marker", source_kind="obsidian"))
            self.assertEqual(list(settings.database_path.parent.glob("rabanito.db.*.restore.tmp")), [])

            wal_sidecar = Path(str(settings.database_path) + "-wal")
            wal_sidecar.write_bytes(b"test-only active marker")
            try:
                with self.assertRaisesRegex(sqlite3.OperationalError, "active SQLite sidecars"):
                    restore_database(backup_path, settings.database_path)
                self.assertTrue(search_documents(settings, "snapshot recovery marker", source_kind="obsidian"))
            finally:
                wal_sidecar.unlink(missing_ok=True)

    def test_restore_cli_requires_confirmation_and_saves_pre_restore_backup(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            note = settings.vault_root / "CliRestore.md"
            note.write_text("# Restore\nbackup marker before change\n", encoding="utf-8")
            index_all(settings)
            backup_path = settings.data_dir / "backups" / "cli-restore-source.db"
            with Database(settings.database_path) as db:
                db.backup(backup_path)

            note.write_text("# Restore\ncurrent live marker\n", encoding="utf-8")
            index_all(settings)
            config_path = settings.root / "config" / "settings.example.json"
            write_json_atomic(config_path, settings.raw)

            with self.assertRaises(SystemExit), redirect_stdout(StringIO()):
                cli_main(["--config", str(config_path), "restore", str(backup_path)])
            self.assertTrue(search_documents(settings, "current live marker", source_kind="obsidian"))

            output = StringIO()
            with redirect_stdout(output):
                cli_main(["--config", str(config_path), "restore", str(backup_path), "--yes"])
            result = json.loads(output.getvalue())
            self.assertTrue(result["pre_restore_backup"])
            pre_restore_path = Path(result["pre_restore_backup"])
            self.assertTrue(pre_restore_path.is_file())
            restored_settings = Settings(settings.root, {**settings.raw, "database_path": str(pre_restore_path)})
            self.assertTrue(search_documents(settings, "backup marker before change", source_kind="obsidian"))
            self.assertFalse(search_documents(settings, "current live marker", source_kind="obsidian"))
            self.assertTrue(search_documents(restored_settings, "current live marker", source_kind="obsidian"))

    def test_document_open_is_post_only_and_same_origin(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            note = settings.vault_root / "Local.md"
            note.write_text("# Local\n", encoding="utf-8")
            index_all(settings)
            handler = type("TestRabanitoHandler", (RabanitoHandler,), {"settings": settings})
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                with patch("rabanito.server.os.startfile") as open_file:
                    try:
                        urlopen(origin + "/api/open/1")
                    except HTTPError as exc:
                        self.assertEqual(exc.code, 404)
                        exc.close()
                    self.assertFalse(open_file.called)
                    request = Request(origin + "/api/open/1", data=b"{}", method="POST", headers={"Content-Type": "application/json", "Origin": "http://attacker.example"})
                    with self.assertRaises(HTTPError) as forbidden:
                        urlopen(request)
                    self.assertEqual(forbidden.exception.code, 403)
                    forbidden.exception.close()
                    self.assertFalse(open_file.called)
                    request = Request(origin + "/api/open/1", data=b"{}", method="POST", headers={"Content-Type": "application/json", "Origin": origin})
                    with urlopen(request) as response:
                        self.assertEqual(response.status, 200)
                    open_file.assert_called_once_with(str(note))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_document_open_rejects_path_from_another_authorized_source_root(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            note = settings.vault_root / "Original.md"
            note.write_text("# Original\n", encoding="utf-8")
            unrelated_root = settings.projects_root / "OtherAuthorizedRoot"
            unrelated_root.mkdir()
            unrelated_file = unrelated_root / "not-indexed.txt"
            unrelated_file.write_text("Not the indexed document.\n", encoding="utf-8")
            project_readme = unrelated_root / "README.md"
            project_readme.write_text("# Other authorized project\n", encoding="utf-8")
            index_all(settings)
            with Database(settings.database_path) as db:
                document = db.one(
                    "SELECT document_id FROM documents WHERE absolute_path=? AND status='active'",
                    (str(note),),
                )
                project_document = db.one(
                    "SELECT document_id FROM documents WHERE absolute_path=? AND status='active'",
                    (str(project_readme),),
                )
                self.assertIsNotNone(document)
                self.assertIsNotNone(project_document)
                # Simulate a stale/corrupt path mapping without changing either source file.
                db.execute(
                    "UPDATE documents SET absolute_path=? WHERE document_id=?",
                    (str(unrelated_file), int(document["document_id"])),
                )
                db.commit()

            handler = type("TestRabanitoHandler", (RabanitoHandler,), {"settings": settings})
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                request = Request(
                    origin + f"/api/open/{int(document['document_id'])}",
                    data=b"{}", method="POST",
                    headers={"Content-Type": "application/json", "Origin": origin},
                )
                with patch("rabanito.server.os.startfile") as open_file:
                    with self.assertRaises(HTTPError) as forbidden:
                        urlopen(request)
                    self.assertEqual(forbidden.exception.code, 403)
                    forbidden.exception.close()
                    open_file.assert_not_called()
                    valid_project_request = Request(
                        origin + f"/api/open/{int(project_document['document_id'])}",
                        data=b"{}", method="POST",
                        headers={"Content-Type": "application/json", "Origin": origin},
                    )
                    with urlopen(valid_project_request) as response:
                        self.assertEqual(response.status, 200)
                    open_file.assert_called_once_with(str(project_readme.resolve()))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_document_open_rejects_reparse_path_inside_its_source_root(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            note = settings.vault_root / "Reparse.md"
            note.write_text("# Reparse\n", encoding="utf-8")
            index_all(settings)
            with Database(settings.database_path) as db:
                document = db.one(
                    "SELECT document_id FROM documents WHERE absolute_path=? AND status='active'",
                    (str(note),),
                )
            self.assertIsNotNone(document)

            handler = type("TestRabanitoHandler", (RabanitoHandler,), {"settings": settings})
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f"http://127.0.0.1:{server.server_address[1]}"
            request = Request(
                origin + f"/api/open/{int(document['document_id'])}",
                data=b"{}", method="POST",
                headers={"Content-Type": "application/json", "Origin": origin},
            )
            try:
                with patch(
                    "rabanito.server.contains_reparse_component",
                    side_effect=lambda candidate: Path(candidate) == note,
                ), patch("rabanito.server.os.startfile") as open_file:
                    with self.assertRaises(HTTPError) as forbidden:
                        urlopen(request)
                    self.assertEqual(forbidden.exception.code, 403)
                    forbidden.exception.close()
                    open_file.assert_not_called()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_dashboard_project_exclusion_updates_local_config_and_index(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project_root = settings.projects_root / "DashboardProject"
            project_root.mkdir()
            (project_root / "README.md").write_text("# DashboardProject\nvisible project memory term\n", encoding="utf-8")
            declared = ", ".join(f"'project-package-{number:03}'" for number in range(105))
            (project_root / "pyproject.toml").write_text(
                f"[project]\ndependencies = ['httpx>=0.27', {declared}]\n", encoding="utf-8",
            )
            (project_root / "malformed").mkdir()
            (project_root / "malformed" / "package.json").write_text(
                '{"dependencies": [broken}', encoding="utf-8",
            )
            index_all(settings)
            handler = type("TestRabanitoHandler", (RabanitoHandler,), {"settings": settings})
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                with urlopen(origin + "/api/projects") as response:
                    projects = json.loads(response.read())["projects"]
                project_record = next(item for item in projects if item["name"] == "DashboardProject")
                self.assertNotIn("root_path", project_record)
                self.assertIsInstance(project_record.get("memory_document_id"), int)
                self.assertEqual(project_record["technologies"], ["Node.js", "Python"])
                self.assertEqual(project_record["dependencies"][0], {"name": "httpx", "sources": ["pyproject.toml"]})
                self.assertEqual(project_record["dependencies_count"], 106)
                self.assertEqual(len(project_record["dependencies"]), 100)
                self.assertTrue(project_record["dependencies_display_truncated"])
                self.assertEqual(project_record["dependency_errors_count"], 1)
                self.assertEqual(project_record["dependency_errors"], [
                    {"source": "malformed/package.json", "error_type": "JSONDecodeError"},
                ])
                self.assertNotIn(str(project_root), json.dumps(project_record, ensure_ascii=False))
                with urlopen(origin + f"/api/doc/{project_record['memory_document_id']}") as response:
                    memory_document = json.loads(response.read())
                self.assertEqual(memory_document["source_kind"], "internal")
                self.assertEqual(memory_document["relative_path"], "projects/dashboardproject/PROJECT_MEMORY.md")
                self.assertNotIn(str(settings.knowledge_root), json.dumps(memory_document, ensure_ascii=False))
                with Database(settings.database_path) as db:
                    db.execute("UPDATE documents SET status='removed' WHERE document_id=?", (project_record["memory_document_id"],))
                    db.commit()
                with urlopen(origin + "/api/projects") as response:
                    without_profile = next(item for item in json.loads(response.read())["projects"] if item["name"] == "DashboardProject")
                self.assertNotIn("memory_document_id", without_profile)
                with Database(settings.database_path) as db:
                    db.execute("UPDATE documents SET status='active' WHERE document_id=?", (project_record["memory_document_id"],))
                    profile_row = db.one(
                        "SELECT absolute_path FROM documents WHERE document_id=?",
                        (project_record["memory_document_id"],),
                    )
                    db.execute(
                        "UPDATE documents SET absolute_path=? WHERE document_id=?",
                        (str(settings.knowledge_root / "wrong-profile.md"), project_record["memory_document_id"]),
                    )
                    db.commit()
                with urlopen(origin + "/api/projects") as response:
                    mismapped_profile = next(item for item in json.loads(response.read())["projects"] if item["name"] == "DashboardProject")
                self.assertNotIn("memory_document_id", mismapped_profile)
                with Database(settings.database_path) as db:
                    db.execute(
                        "UPDATE documents SET absolute_path=? WHERE document_id=?",
                        (profile_row["absolute_path"], project_record["memory_document_id"]),
                    )
                    ambiguous_path = settings.knowledge_root / "projects" / "duplicate-profile" / "PROJECT_MEMORY.md"
                    db.execute(
                        """INSERT INTO documents (
                            source_kind, source_root, project_name, project_root_path, relative_path,
                            absolute_path, path_key, title, category, indexed_at, last_seen_scan, status
                        ) SELECT source_kind, source_root, project_name, project_root_path, ?, ?, ?, title,
                            category, indexed_at, last_seen_scan, 'active'
                            FROM documents WHERE document_id=?""",
                        (
                            "projects/duplicate-profile/PROJECT_MEMORY.md", str(ambiguous_path), path_key(ambiguous_path),
                            project_record["memory_document_id"],
                        ),
                    )
                    db.commit()
                with urlopen(origin + "/api/projects") as response:
                    ambiguous_profile = next(item for item in json.loads(response.read())["projects"] if item["name"] == "DashboardProject")
                self.assertNotIn("memory_document_id", ambiguous_profile)
                with Database(settings.database_path) as db:
                    db.execute("DELETE FROM documents WHERE absolute_path=?", (str(ambiguous_path),))
                    db.commit()
                with urlopen(origin + "/api/audit/latest") as response:
                    audit_payload = json.loads(response.read())
                self.assertEqual(audit_payload["counts"]["project_dependency_manifest_errors"], 1)
                self.assertEqual(audit_payload["project_manifest_warnings"][0]["source"], "malformed/package.json")
                self.assertNotIn(str(project_root), json.dumps(audit_payload, ensure_ascii=False))
                payload = json.dumps({"project_id": project_record["project_id"], "exclude": True}).encode()
                request = Request(origin + "/api/project-exclusion", data=payload, method="POST", headers={"Content-Type": "application/json", "Origin": origin})
                with urlopen(request) as response:
                    result = json.loads(response.read())
                self.assertTrue(result["excluded"])
                self.assertGreaterEqual(result["index"]["removed"], 2)
                with Database(settings.database_path) as db:
                    active = db.one("SELECT COUNT(*) AS c FROM documents WHERE source_kind='projects' AND status='active'")["c"]
                self.assertEqual(active, 0)
                with urlopen(origin + "/api/audit/latest") as response:
                    excluded_audit = json.loads(response.read())
                self.assertEqual(excluded_audit["counts"]["project_dependency_manifest_errors"], 0)
                with urlopen(origin + "/api/projects?all=1") as response:
                    excluded_project = next(item for item in json.loads(response.read())["projects"] if item["name"] == "DashboardProject")
                self.assertNotIn("dependencies", excluded_project)
                self.assertNotIn("dependency_errors", excluded_project)
                self.assertNotIn("memory_document_id", excluded_project)
                with self.assertRaises(HTTPError) as hidden_memory:
                    urlopen(origin + f"/api/doc/{project_record['memory_document_id']}")
                self.assertEqual(hidden_memory.exception.code, 404)
                hidden_memory.exception.close()
                payload = json.dumps({"project_id": project_record["project_id"], "exclude": False}).encode()
                request = Request(origin + "/api/project-exclusion", data=payload, method="POST", headers={"Content-Type": "application/json", "Origin": origin})
                with urlopen(request) as response:
                    result = json.loads(response.read())
                self.assertFalse(result["excluded"])
                self.assertTrue(search_documents(settings, "visible project", source_kind="projects"))
                with urlopen(origin + "/api/projects") as response:
                    reactivated = next(item for item in json.loads(response.read())["projects"] if item["name"] == "DashboardProject")
                self.assertEqual(reactivated["dependencies"][0]["name"], "httpx")
                self.assertEqual(reactivated["dependency_errors_count"], 1)
                self.assertEqual(reactivated["memory_document_id"], project_record["memory_document_id"])
                with urlopen(origin + "/api/audit/latest") as response:
                    restored_audit = json.loads(response.read())
                self.assertEqual(restored_audit["counts"]["project_dependency_manifest_errors"], 1)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_dashboard_source_onboarding_requires_preview_approval_then_separate_sync(self) -> None:
        with self.temporary_directory() as temp:
            root = Path(temp)
            settings = self.make_settings(root)
            source = root / "Fuentes autorizadas" / "Notas Ñ"
            source.mkdir(parents=True)
            (source / "README.md").write_text(
                "# Muestra privada\neste texto no debe entrar al índice durante onboarding\n", encoding="utf-8"
            )
            handler = type("TestRabanitoHandler", (RabanitoHandler,), {"settings": settings})
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f"http://127.0.0.1:{server.server_address[1]}"

            def post(path: str, payload: dict[str, object], request_origin: str = origin) -> dict[str, object]:
                request = Request(
                    origin + path, data=json.dumps(payload).encode("utf-8"), method="POST",
                    headers={"Content-Type": "application/json", "Origin": request_origin},
                )
                with urlopen(request) as response:
                    return json.loads(response.read())

            try:
                with urlopen(origin + "/api/sources") as response:
                    initial_sources = json.loads(response.read())["sources"]
                self.assertEqual({item["kind"] for item in initial_sources}, {"obsidian", "projects", "internal"})
                payload = {"path": str(source), "kind": "research", "name": "Investigación Ñ"}
                preview = post("/api/source-preview", payload)
                self.assertTrue(preview["approval_required"])
                self.assertIn("README.md", preview["sample_entries"])
                self.assertNotIn("path", preview)
                self.assertNotIn(str(source), json.dumps(preview, ensure_ascii=False))
                self.assertNotIn("no debe entrar al índice", json.dumps(preview, ensure_ascii=False))
                self.assertEqual(settings.additional_sources(), [])
                self.assertEqual(stats(settings)["documents_active"], 0)

                with self.assertRaises(HTTPError) as forbidden:
                    post("/api/source-approve", payload, "http://attacker.example")
                self.assertEqual(forbidden.exception.code, 403)
                forbidden.exception.close()
                with self.assertRaises(HTTPError) as relative_path:
                    post("/api/source-preview", {"path": "relative\\notes", "kind": "research"})
                self.assertEqual(relative_path.exception.code, 400)
                relative_path.exception.close()
                with self.assertRaises(HTTPError) as reserved_kind:
                    post("/api/source-preview", {"path": str(source), "kind": "projects"})
                self.assertEqual(reserved_kind.exception.code, 400)
                reserved_kind.exception.close()

                approved = post("/api/source-approve", payload)
                self.assertTrue(approved["approved"])
                self.assertNotIn("path", approved)
                self.assertNotIn(str(source), json.dumps(approved, ensure_ascii=False))
                self.assertEqual(len(settings.additional_sources()), 1)
                self.assertEqual(settings.additional_sources()[0]["name"], "Investigación Ñ")
                self.assertEqual(stats(settings)["documents_active"], 0, "approval must not start indexing")
                post("/api/source-approve", payload)
                with ThreadPoolExecutor(max_workers=6) as pool:
                    list(pool.map(lambda _item: post("/api/source-approve", payload), range(12)))
                self.assertEqual(len(settings.additional_sources()), 1, "repeated approval must be idempotent")
                with urlopen(origin + "/api/sources") as response:
                    sources = json.loads(response.read())["sources"]
                managed_source = next(item for item in sources if item["kind"] == "research" and item["managed"])
                self.assertNotIn("path", managed_source)
                self.assertNotIn(str(source), json.dumps(sources, ensure_ascii=False))
                self.assertTrue(managed_source["source_id"].startswith("additional-"))

                html = (Path(__file__).resolve().parents[1] / "web" / "index.html").read_text(encoding="utf-8")
                self.assertIn('id="sourcePath"', html)
                self.assertIn('id="previewSourceBtn"', html)
                self.assertIn("Aprobar esta fuente", html)
                self.assertIn("no la indexará", html)
                self.assertIn("renderSourceFilters", html)
                self.assertIn("Revisar exclusión", html)
                self.assertIn("Revisar reactivación", html)
                self.assertIn("Confirmar exclusión y sincronizar", html)
                self.assertIn("/api/source-impact", html)
                self.assertIn("source_id:source.source_id", html)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_disabled_additional_source_is_hidden_before_index_reconciliation(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            source = Path(temp) / "Authorized Research"
            source.mkdir()
            note = source / "Private research.md"
            note.write_text("# Private research\n\nRevocation window sentinel phrase.\n", encoding="utf-8")
            approve_source(settings, source, "research", "Research")
            index_all(settings)
            with Database(settings.database_path) as db:
                document = db.one(
                    "SELECT document_id,status FROM documents WHERE source_kind='research' AND relative_path=?",
                    (note.name,),
                )
            self.assertIsNotNone(document)
            self.assertEqual(document["status"], "active")
            self.assertTrue(search_documents(settings, "revocation window sentinel", source_kind="research"))

            # This is the interval between the authorization update and the scan.
            set_additional_source_enabled(settings, source, False)
            self.assertFalse(settings.is_configured_root(note))
            with Database(settings.database_path) as db:
                self.assertEqual(db.one(
                    "SELECT status FROM documents WHERE document_id=?", (int(document["document_id"]),)
                )["status"], "active")
            self.assertFalse(search_documents(settings, "revocation window sentinel", source_kind="research"))
            self.assertFalse(recent_documents(settings, source_kind="research"))
            self.assertFalse(retrieve_context(settings, "revocation window sentinel", source_kind="research")["fragments"])
            self.assertIsNone(get_document(settings, int(document["document_id"])))
            self.assertEqual(stats(settings)["documents_active"], 0)
            self.assertNotIn("Revocation window sentinel", json.dumps(collect_audit(settings), ensure_ascii=False))

            handler = type("TestRabanitoHandler", (RabanitoHandler,), {"settings": settings})
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                request = Request(
                    origin + "/api/search",
                    data=json.dumps({"q": "revocation window sentinel", "source": "research"}).encode(),
                    method="POST", headers={"Content-Type": "application/json", "Origin": origin},
                )
                with urlopen(request) as response:
                    self.assertFalse(json.loads(response.read())["results"])
                with urlopen(origin + "/api/stats") as response:
                    self.assertEqual(json.loads(response.read())["documents_active"], 0)
                with self.assertRaises(HTTPError) as hidden_document:
                    urlopen(origin + f"/api/doc/{int(document['document_id'])}")
                self.assertEqual(hidden_document.exception.code, 404)
                hidden_document.exception.close()
                open_request = Request(
                    origin + f"/api/open/{int(document['document_id'])}", data=b"{}", method="POST",
                    headers={"Content-Type": "application/json", "Origin": origin},
                )
                with patch("rabanito.server.os.startfile") as open_file:
                    with self.assertRaises(HTTPError) as hidden_open:
                        urlopen(open_request)
                    self.assertEqual(hidden_open.exception.code, 404)
                    hidden_open.exception.close()
                    open_file.assert_not_called()
                graph_request = Request(
                    origin + "/api/graph",
                    data=json.dumps({"source": "research"}).encode(), method="POST",
                    headers={"Content-Type": "application/json", "Origin": origin},
                )
                with urlopen(graph_request) as response:
                    self.assertFalse(json.loads(response.read())["nodes"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

            set_additional_source_enabled(settings, source, True)
            self.assertTrue(search_documents(settings, "revocation window sentinel", source_kind="research"))

    def test_dashboard_additional_source_revocation_is_reversible_and_preserves_files(self) -> None:
        with self.temporary_directory() as temp:
            root = Path(temp)
            settings = self.make_settings(root)
            source = root / "Fuentes autorizadas" / "Relaciones Ñ"
            source.mkdir(parents=True)
            first_note = source / "Alpha.md"
            second_note = source / "Beta.md"
            first_note.write_text("# Alpha\n\nVínculo local [[Beta]], referencia [[Missing Research]] y frase única de prueba.\n", encoding="utf-8")
            second_note.write_text("# Beta\n\nDestino de la relación explícita.\n", encoding="utf-8")
            originals = {path: path.read_bytes() for path in (first_note, second_note)}
            approve_source(settings, source, "research", "Investigación Ñ")
            index_all(settings)
            with Database(settings.database_path) as db:
                before = db.query(
                    "SELECT document_id, path_key, status FROM documents WHERE source_root=? ORDER BY relative_path",
                    (str(source),),
                )
                link_before = db.one(
                    "SELECT status, target_document_id FROM links WHERE source_document_id=?",
                    (before[0]["document_id"],),
                )
            self.assertEqual(len(before), 2)
            self.assertEqual({row["status"] for row in before}, {"active"})
            self.assertEqual(link_before["status"], "resolved")
            self.assertEqual(stats(settings)["relations_resolved"], 1)
            self.assertEqual(stats(settings)["links_broken"], 1)
            self.assertTrue(settings.is_configured_root(source))

            handler = type("TestRabanitoHandler", (RabanitoHandler,), {"settings": settings})
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f"http://127.0.0.1:{server.server_address[1]}"

            def post(path: str, payload: dict[str, object], request_origin: str = origin) -> dict[str, object]:
                request = Request(
                    origin + path, data=json.dumps(payload).encode("utf-8"), method="POST",
                    headers={"Content-Type": "application/json", "Origin": request_origin},
                )
                with urlopen(request) as response:
                    return json.loads(response.read())

            try:
                authorized_open = Request(
                    origin + f"/api/open/{int(before[0]['document_id'])}",
                    data=b"{}", method="POST",
                    headers={"Content-Type": "application/json", "Origin": origin},
                )
                with patch("rabanito.server.os.startfile") as open_file:
                    with urlopen(authorized_open) as response:
                        self.assertEqual(response.status, 200)
                    open_file.assert_called_once_with(str(first_note.resolve()))
                with urlopen(origin + "/api/sources") as response:
                    sources = json.loads(response.read())["sources"]
                managed = next(item for item in sources if item["name"] == "Investigación Ñ" and item["managed"])
                self.assertNotIn("path", managed)
                self.assertTrue(managed["enabled"])
                payload = {"source_id": managed["source_id"], "enabled": False}
                with self.assertRaises(HTTPError) as cross_origin:
                    post("/api/source-toggle", payload, "http://attacker.example")
                self.assertEqual(cross_origin.exception.code, 403)
                cross_origin.exception.close()

                impact = post("/api/source-impact", payload)
                self.assertTrue(impact["would_change"])
                self.assertEqual(impact["active_documents"], 2)
                self.assertEqual(impact["outgoing_link_records"], 2)
                self.assertTrue(settings.is_configured_root(source), "impact preview must not mutate authorization")
                self.assertEqual(stats(settings)["documents_active"], 2)

                disabled = post("/api/source-toggle", payload)
                self.assertFalse(disabled["enabled"])
                self.assertEqual(disabled["index"]["removed"], 2)
                self.assertFalse(settings.is_configured_root(source))
                self.assertFalse(search_documents(settings, "frase única de prueba", source_kind="research"))
                self.assertEqual(stats(settings)["relations_resolved"], 0)
                self.assertEqual(stats(settings)["links_broken"], 0)
                self.assertEqual(collect_audit(settings)["counts"]["links_broken"], 0)
                with Database(settings.database_path) as db:
                    tombstones = db.query(
                        "SELECT document_id, path_key, status FROM documents WHERE source_root=? ORDER BY relative_path",
                        (str(source),),
                    )
                self.assertEqual([row["document_id"] for row in tombstones], [row["document_id"] for row in before])
                self.assertEqual({row["status"] for row in tombstones}, {"deleted"})
                self.assertEqual({path: path.read_bytes() for path in originals}, originals)
                with urlopen(origin + "/api/sources") as response:
                    current_sources = json.loads(response.read())["sources"]
                managed = next(item for item in current_sources if item["source_id"] == managed["source_id"])
                self.assertFalse(managed["enabled"])

                reactivation_impact = post("/api/source-impact", {"source_id": managed["source_id"], "enabled": True})
                self.assertEqual(reactivation_impact["previously_deleted_records"], 2)
                self.assertFalse(settings.is_configured_root(source), "reactivation preview must not mutate authorization")
                with Database(settings.database_path) as db:
                    self.assertEqual(db.one("SELECT COUNT(*) AS count FROM documents WHERE source_root=? AND status='deleted'", (str(source),))["count"], 2)

                with patch("rabanito.indexer.contains_reparse_component", return_value=True):
                    with self.assertRaisesRegex(ValueError, "reparse point"):
                        set_additional_source_enabled_and_sync(settings, source, True)
                self.assertFalse(settings.is_configured_root(source), "unsafe reactivation must leave authorization disabled")

                enabled = post("/api/source-toggle", {"source_id": managed["source_id"], "enabled": True})
                self.assertTrue(enabled["enabled"])
                self.assertTrue(settings.is_configured_root(source))
                with Database(settings.database_path) as db:
                    restored = db.query(
                        "SELECT document_id, path_key, status FROM documents WHERE source_root=? ORDER BY relative_path",
                        (str(source),),
                    )
                    link_after = db.one(
                        "SELECT status, target_document_id FROM links WHERE source_document_id=?",
                        (restored[0]["document_id"],),
                    )
                    duplicates = db.one("SELECT COUNT(*) AS count FROM documents WHERE path_key=?", (restored[0]["path_key"],))
                self.assertEqual([row["document_id"] for row in restored], [row["document_id"] for row in before])
                self.assertEqual({row["status"] for row in restored}, {"active"})
                self.assertEqual(link_after["status"], "resolved")
                self.assertEqual(duplicates["count"], 1)
                self.assertTrue(search_documents(settings, "frase única de prueba", source_kind="research"))
                self.assertEqual(stats(settings)["relations_resolved"], 1)
                self.assertEqual(stats(settings)["links_broken"], 1)
                self.assertEqual({path: path.read_bytes() for path in originals}, originals)

                with self.assertRaises(HTTPError) as unregistered:
                    post("/api/source-toggle", {"path": str(root / "unregistered"), "enabled": False})
                self.assertEqual(unregistered.exception.code, 403)
                unregistered.exception.close()

                html = (Path(__file__).resolve().parents[1] / "web" / "index.html").read_text(encoding="utf-8")
                self.assertIn("Revisar exclusión", html)
                self.assertIn("Revisar reactivación", html)
                self.assertIn("Confirmar exclusión y sincronizar", html)
                self.assertIn("/api/source-impact", html)
                self.assertIn("/api/source-toggle", html)
                self.assertIn("los archivos originales no se modifican", html)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_dashboard_graph_filters_real_edges_and_local_actions(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            project_root = settings.projects_root / "Proyecto Ñ & Local"
            (project_root / "docs").mkdir(parents=True)
            (project_root / "README.md").write_text(
                "# Proyecto Ñ\n\n[Decisión](docs/ADR.md)\n", encoding="utf-8"
            )
            (project_root / "docs" / "ADR.md").write_text(
                "# ADR local\n\nSQLite mantiene el índice verificable.\n", encoding="utf-8"
            )
            other_project = settings.projects_root / "Proyecto similar aislado"
            other_project.mkdir()
            (other_project / "README.md").write_text(
                "# Otro proyecto\n\nNo debe filtrarse a la vista del proyecto seleccionado.\n", encoding="utf-8"
            )
            (settings.vault_root / "Nota aparte.md").write_text(
                "# Nota aparte\n\nEsta fuente no pertenece al proyecto.\n", encoding="utf-8"
            )
            web_root = settings.root / "web"
            web_root.mkdir()
            dashboard_source = Path(__file__).resolve().parents[1] / "web" / "index.html"
            (web_root / "index.html").write_text(dashboard_source.read_text(encoding="utf-8"), encoding="utf-8")
            index_all(settings)

            handler = type("TestRabanitoHandler", (RabanitoHandler,), {"settings": settings})
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                with Database(settings.database_path) as db:
                    project_id = db.one("SELECT project_id FROM projects WHERE root_path=?", (str(project_root),))["project_id"]
                graph_request = Request(
                    origin + "/api/graph",
                    data=json.dumps({"project_id": project_id, "min_degree": 1}).encode(),
                    method="POST", headers={"Content-Type": "application/json", "Origin": origin},
                )
                with urlopen(graph_request) as response:
                    graph = json.loads(response.read())
                limited_graph_request = Request(
                    origin + "/api/graph",
                    data=json.dumps({"project_id": project_id, "limit": 1}).encode(),
                    method="POST", headers={"Content-Type": "application/json", "Origin": origin},
                )
                with urlopen(limited_graph_request) as response:
                    limited_graph = json.loads(response.read())
                self.assertEqual(len(limited_graph["nodes"]), 1)
                self.assertEqual(limited_graph["node_limit"], 1)
                # total_matches counts before min_degree removes isolated nodes.
                self.assertEqual(limited_graph["total_matches"], 3)
                self.assertTrue(limited_graph["truncated"])
                self.assertEqual(graph["total_matches"], 3)
                self.assertFalse(graph["truncated"])
                self.assertEqual(len(graph["nodes"]), 2)
                self.assertEqual(len(graph["edges"]), 1)
                from rabanito.cli import _graph_export
                cli_graph = _graph_export(settings, 1, False)
                self.assertEqual(len(cli_graph["nodes"]), 1)
                self.assertEqual(cli_graph["node_limit"], 1)
                self.assertGreater(cli_graph["total_matches"], 1)
                self.assertTrue(cli_graph["truncated"])
                self.assertTrue(all(node["project_name"] == "Proyecto Ñ & Local" for node in graph["nodes"]))
                self.assertTrue(all("source_root" not in node and "project_root_path" not in node for node in graph["nodes"]))
                self.assertNotIn(str(project_root), json.dumps(graph, ensure_ascii=False))
                with Database(settings.database_path) as db:
                    project_doc_id = int(db.one(
                        "SELECT document_id FROM documents WHERE source_kind='projects' AND source_root=? AND relative_path='README.md'",
                        (str(project_root),),
                    )["document_id"])
                    db.execute(
                        "UPDATE documents SET frontmatter_json=? WHERE document_id=?",
                        (json.dumps({"ordinary": {"note": "kept", "source_path": r"C:\Private\HiddenRoot\memo.md"}}), project_doc_id),
                    )
                    db.execute(
                        "INSERT INTO links(source_document_id,target_raw,status,resolution_reason,line_number) VALUES(?,?,?,?,?)",
                        (project_doc_id, "file:///C:/Private/HiddenRoot/nota%20privada.md", "broken", "invalid_file_reference", 99),
                    )
                    db.commit()
                with urlopen(origin + f"/api/doc/{project_doc_id}") as response:
                    document_view = json.loads(response.read())
                self.assertNotIn("absolute_path", document_view)
                self.assertNotIn("source_root", document_view)
                self.assertNotIn("project_root_path", document_view)
                self.assertNotIn(str(project_root), json.dumps(document_view, ensure_ascii=False))
                serialized_document = json.dumps(document_view, ensure_ascii=False)
                self.assertNotIn(r"C:\Private\HiddenRoot", serialized_document)
                self.assertNotIn("file:///C:/Private/HiddenRoot", serialized_document)
                self.assertIn("[URI de archivo omitida] · nota privada.md", serialized_document)
                self.assertEqual(document_view["frontmatter"]["ordinary"]["note"], "kept")
                with urlopen(origin + f"/api/related/{project_doc_id}") as response:
                    related_view = json.loads(response.read())["results"]
                self.assertTrue(related_view)
                self.assertNotIn(str(project_root), json.dumps(related_view, ensure_ascii=False))
                self.assertTrue(all("absolute_path" not in item and "frontmatter_json" not in item for item in related_view))
                self.assertEqual(graph["edges"][0]["kind"], "explicit")

                for route in ("/api/index", "/api/audit", "/api/link"):
                    request = Request(
                        origin + route, data=b"{}", method="POST",
                        headers={"Content-Type": "application/json", "Origin": origin},
                    )
                    with urlopen(request) as response:
                        payload = json.loads(response.read())
                    self.assertEqual(response.status, 200)
                    self.assertIsInstance(payload, dict)
                audit_files = list((settings.knowledge_root / "quality-reports").glob("*-audit.json"))
                self.assertTrue(audit_files)
                for audit_file in audit_files:
                    saved_audit = audit_file.read_text(encoding="utf-8")
                    self.assertNotIn(str(project_root), saved_audit)
                    self.assertNotIn(r"C:\Private\HiddenRoot", saved_audit)
                    self.assertNotIn("file:///C:/Private/HiddenRoot", saved_audit)
                report_name = audit_files[-1].name
                private_static_routes = (
                    f"/knowledge/quality-reports/{report_name}",
                    f"/%6bnowledge/quality-reports/{report_name}",
                    f"/knowledge%2fquality-reports%2f{report_name}",
                    f"/%2e%2e/knowledge/quality-reports/{report_name}",
                    "/knowledge/quality-reports/%2e%2e/%2e%2e/data/rabanito.db",
                )
                for route in private_static_routes:
                    with self.subTest(private_static_route=route):
                        with self.assertRaises(HTTPError) as report_static:
                            urlopen(origin + route)
                        self.assertEqual(report_static.exception.code, 404)
                        report_static.exception.close()

                with Database(settings.database_path) as db:
                    project_document = db.one(
                        "SELECT document_id FROM documents WHERE source_kind='projects' AND source_root=? AND relative_path='README.md'",
                        (str(project_root),),
                    )
                    obsidian_document = db.one(
                        "SELECT document_id FROM documents WHERE source_kind='obsidian' AND relative_path='Nota aparte.md'"
                    )
                    db.execute(
                        "INSERT INTO link_suggestions(source_document_id,target_document_id,score,reason,created_at) VALUES(?,?,?,?,?)",
                        (int(project_document["document_id"]), int(obsidian_document["document_id"]), 0.75,
                         "shared terms: local, architecture", "2026-10-13T00:00:00+00:00"),
                    )
                    db.commit()

                related_request = Request(
                    origin + "/api/graph",
                    data=json.dumps({"project_id": project_id, "suggestions": "1"}).encode(),
                    method="POST", headers={"Content-Type": "application/json", "Origin": origin},
                )
                with urlopen(related_request) as response:
                    related_graph = json.loads(response.read())
                limited_suggestions_request = Request(
                    origin + "/api/graph",
                    data=json.dumps({"project_id": project_id, "limit": 3, "suggestions": "1"}).encode(),
                    method="POST", headers={"Content-Type": "application/json", "Origin": origin},
                )
                with urlopen(limited_suggestions_request) as response:
                    limited_suggestions_graph = json.loads(response.read())
                self.assertEqual(len(limited_suggestions_graph["nodes"]), 3)
                self.assertEqual(limited_suggestions_graph["total_matches"], 3)
                self.assertTrue(limited_suggestions_graph["truncated"])
                related_note = next(node for node in related_graph["nodes"] if node["source_kind"] == "obsidian")
                self.assertEqual(related_note["relative_path"], "Nota aparte.md")
                self.assertTrue(related_note["related_via_suggestion"])
                self.assertTrue(any(edge["kind"] == "suggested" for edge in related_graph["edges"]))
                self.assertFalse(any(
                    node.get("source_kind") == "projects" and node.get("relative_path") == "README.md" and node.get("project_name") == "Proyecto similar aislado"
                    for node in related_graph["nodes"]
                ))
                self.assertTrue(all(
                    node["project_name"] == "Proyecto Ñ & Local"
                    or (node["source_kind"] == "obsidian" and node["related_via_suggestion"])
                    for node in related_graph["nodes"]
                ))

                with urlopen(origin + "/") as response:
                    self.assertEqual(response.headers.get("Cache-Control"), "no-store")
                    self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
                    self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
                    self.assertEqual(response.headers.get("Referrer-Policy"), "no-referrer")
                    html = response.read().decode("utf-8")
                self.assertIn("3D Brain · grafo real del índice", html)
                self.assertIn("relations_suggested", html)
                self.assertIn("Nota Obsidian añadida por sugerencia", html)
                self.assertIn("Etiqueta exacta", html)
                self.assertIn("/api/tags", html)
                self.assertNotRegex(html, r"<script[^>]+src=[\"']https?://")
                for private_query_route in ("/api/search?", "/api/context?", "/api/graph?", "/api/decisions?"):
                    self.assertNotIn(private_query_route, html)
                self.assertIn("p.project_id=", html)
                self.assertIn("project_id:project.project_id", html)
                with urlopen(origin + "/api/stats") as response:
                    api_stats = json.loads(response.read())
                self.assertEqual(api_stats["documents_active"], stats(settings)["documents_active"])
                self.assertIn("links_directories", api_stats)
                self.assertEqual(api_stats["relations_suggested"], stats(settings)["relations_suggested"])
                self.assertNotIn(str(settings.projects_root), json.dumps(api_stats, ensure_ascii=False))

                with patch("builtins.print") as log:
                    private_search = Request(
                        origin + "/api/search", data=json.dumps({"q": "PRIVATE_QUERY_SENTINEL"}).encode(),
                        method="POST", headers={"Content-Type": "application/json", "Origin": origin},
                    )
                    with urlopen(private_search) as response:
                        self.assertEqual(json.loads(response.read())["results"], [])
                logged = " ".join(str(call.args) for call in log.call_args_list)
                self.assertIn("POST status=200", logged)
                self.assertNotIn("PRIVATE_QUERY_SENTINEL", logged)
                self.assertNotIn("/api/search", logged)
                self.assertNotIn("?q=", private_search.full_url)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_dashboard_scan_history_is_bounded_and_omits_private_scan_fields(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            sentinel = str(Path(temp) / "Sensitive Source" / "internal-note.md")
            with Database(settings.database_path) as db:
                db.executemany(
                    """INSERT INTO scan_runs(
                        started_at,status,files_seen,added,modified,unchanged,removed,skipped,errors,
                        source_summary_json,error_message
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    [
                        (
                            f"2026-10-13T00:00:{index:02d}+00:00", "error" if index == 34 else "ok",
                            index, 1, 2, 3, 4, 5, 6,
                            json.dumps({
                                "local": {
                                    "source_path": sentinel, "seen": index, "errors": 0,
                                    "added": "12", "duration_ms": 12,
                                },
                                "obsidian": {"seen": 1, "errors": 2 if index == 34 else 0},
                                sentinel: {"errors": 99},
                            }),
                            f"failure at {sentinel} PRIVATE_SCAN_ERROR_SENTINEL",
                        )
                        for index in range(35)
                    ],
                )
                db.commit()

            handler = type("TestRabanitoHandler", (RabanitoHandler,), {"settings": settings})
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                with urlopen(origin + "/api/scans") as response:
                    payload = json.loads(response.read())
                with urlopen(origin + "/api/stats") as response:
                    latest = json.loads(response.read())["latest_scan"]
                scans = payload["scans"]
                self.assertEqual(len(scans), 30)
                self.assertEqual(scans[0]["scan_id"], 35)
                self.assertEqual(scans[-1]["scan_id"], 6)
                expected_sources = {
                    "local": {"seen": 34, "errors": 0},
                    "obsidian": {"seen": 1, "errors": 2},
                }
                self.assertEqual(scans[0]["source_summary"], expected_sources)
                self.assertEqual(latest["source_summary"], expected_sources)
                self.assertFalse(scans[0]["source_summary_truncated"])
                allowed = {
                    "scan_id", "started_at", "finished_at", "status", "files_seen", "added",
                    "modified", "unchanged", "removed", "skipped", "errors", "duration_ms",
                    "source_summary", "source_summary_truncated",
                }
                self.assertTrue(all(set(scan) <= allowed for scan in scans))
                encoded = json.dumps(payload, ensure_ascii=False)
                self.assertNotIn(sentinel, encoded)
                self.assertNotIn("source_path", encoded)
                self.assertNotIn("PRIVATE_SCAN_ERROR_SENTINEL", encoded)
                self.assertNotIn("source_summary_json", encoded)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_dashboard_source_summary_rejects_untrusted_fields_and_bounds_types(self) -> None:
        summary = {
            f"source{index:03d}": {
                "seen": index, "errors": index, "added": index, "source_root": "PRIVATE_ROOT_SENTINEL",
                "modified": True, "duration_ms": 123,
            }
            for index in range(101)
        }
        summary["../PRIVATE_PATH_SENTINEL"] = {"errors": 99}
        projected = RabanitoHandler._dashboard_scan_summary({"source_summary": summary})
        self.assertEqual(len(projected["source_summary"]), 100)
        self.assertTrue(projected["source_summary_truncated"])
        self.assertNotIn("source100", projected["source_summary"])
        self.assertNotIn("../PRIVATE_PATH_SENTINEL", projected["source_summary"])
        self.assertEqual(projected["source_summary"]["source005"], {"seen": 5, "errors": 5, "added": 5})
        encoded = json.dumps(projected, ensure_ascii=False)
        self.assertNotIn("PRIVATE_ROOT_SENTINEL", encoded)
        self.assertNotIn("PRIVATE_PATH_SENTINEL", encoded)

        corrupt = RabanitoHandler._dashboard_scan_summary({"source_summary_json": "not-json"})
        self.assertEqual(corrupt["source_summary"], {})
        self.assertTrue(corrupt["source_summary_truncated"])

        delimiters_in_string_json = json.dumps({
            "obsidian": {"seen": 1, "note": "literal " + ("[[{{" * 32) + " ]]}"}
        })
        delimiters_in_string = RabanitoHandler._dashboard_scan_summary(
            {"source_summary_json": delimiters_in_string_json}
        )
        self.assertEqual(delimiters_in_string["source_summary"], {"obsidian": {"seen": 1}})
        self.assertFalse(delimiters_in_string["source_summary_truncated"])

        oversized_json = '{"filler":"' + ("x" * 300_000) + '","obsidian":{"errors":1}}'
        oversized = RabanitoHandler._dashboard_scan_summary({"source_summary_json": oversized_json})
        self.assertEqual(oversized["source_summary"], {})
        self.assertTrue(oversized["source_summary_truncated"])

        deeply_nested_json = '{"obsidian":' + ("[" * 1500) + "0" + ("]" * 1500) + "}"
        deeply_nested = RabanitoHandler._dashboard_scan_summary({"source_summary_json": deeply_nested_json})
        self.assertEqual(deeply_nested["source_summary"], {})
        self.assertTrue(deeply_nested["source_summary_truncated"])

        oversized_integer_json = '{"obsidian":{"errors":' + ("9" * 5000) + "}}"
        oversized_integer = RabanitoHandler._dashboard_scan_summary(
            {"source_summary_json": oversized_integer_json}
        )
        self.assertEqual(oversized_integer["source_summary"], {})
        self.assertTrue(oversized_integer["source_summary_truncated"])

    def test_dashboard_source_summary_database_reads_are_character_bounded(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            source_summary = '{"filler":"' + ("x" * 300_000) + '","tailkind":{"errors":9}}'
            with Database(settings.database_path) as db:
                db.execute(
                    "INSERT INTO scan_runs(started_at,status,source_summary_json) VALUES(?,?,?)",
                    ("2026-10-13T00:00:00Z", "partial", source_summary),
                )
                db.commit()

            observed_lengths = []
            observed_sql_limits = []

            class CapturingStatsDatabase(Database):
                def one(self, sql, params=()):
                    if "FROM scan_runs" in sql:
                        observed_sql_limits.append(tuple(params))
                    return super().one(sql, params)

            def capture_projection(scan):
                observed_lengths.append(len(scan.get("source_summary_json", "")))
                return RabanitoHandler._dashboard_scan_summary(scan)

            handler = type("TestRabanitoHandler", (RabanitoHandler,), {
                "settings": settings,
                "_dashboard_scan_summary": staticmethod(capture_projection),
            })
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                with patch("rabanito.search.Database", CapturingStatsDatabase):
                    programmatic_latest = stats(settings)["latest_scan"]
                    with urlopen(origin + "/api/scans") as response:
                        scans = json.loads(response.read())["scans"]
                    with urlopen(origin + "/api/stats") as response:
                        latest = json.loads(response.read())["latest_scan"]
                self.assertEqual(programmatic_latest["source_summary"], {})
                self.assertTrue(programmatic_latest["source_summary_truncated"])
                self.assertEqual(observed_sql_limits, [(262_145,), (262_145,)])
                self.assertEqual(observed_lengths, [262_145, 0])
                for summary in (scans[0], latest):
                    self.assertEqual(summary["source_summary"], {})
                    self.assertTrue(summary["source_summary_truncated"])
                self.assertNotIn("tailkind", json.dumps(scans, ensure_ascii=False))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_dashboard_change_journal_is_bounded_and_hides_excluded_sources(self) -> None:
        with self.temporary_directory() as temp:
            settings = self.make_settings(Path(temp))
            (settings.vault_root / "Nota visible.md").write_text("# Nota visible\n\nContenido local.\n", encoding="utf-8")
            project = settings.projects_root / "Proyecto excluido"
            project.mkdir()
            (project / "README.md").write_text("# Proyecto excluido\n\nREADME local.\n", encoding="utf-8")
            active_project = settings.projects_root / "Proyecto activo"
            active_project.mkdir()
            (active_project / "README.md").write_text("# Proyecto activo\n\nREADME visible.\n", encoding="utf-8")
            extra = Path(temp) / "Fuente adicional"
            extra.mkdir()
            (extra / "Referencia.md").write_text("# Referencia\n\nFuente adicional local.\n", encoding="utf-8")
            settings.raw["additional_sources"] = [{"name": "Referencia temporal", "kind": "research", "path": str(extra), "enabled": True}]
            settings.raw["source_policy"]["research"] = {"extensions": [".md"], "exclude_dirs": [], "exclude_names": []}
            index_all(settings)
            # Simulate an exclusion changed in config before the next index pass. The
            # database status is intentionally still active during this window.
            settings.raw["excluded_projects"] = [str(project)]
            with Database(settings.database_path) as db:
                excluded_project_id = int(db.one("SELECT project_id FROM projects WHERE root_path=?", (str(project),))["project_id"])
                active_project_id = int(db.one("SELECT project_id FROM projects WHERE root_path=?", (str(active_project),))["project_id"])
                self.assertEqual(db.one("SELECT status FROM projects WHERE project_id=?", (excluded_project_id,))["status"], "active")
            settings.raw["additional_sources"][0]["enabled"] = False

            handler = type("TestRabanitoHandler", (RabanitoHandler,), {"settings": settings})
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                with urlopen(origin + "/api/changes?limit=100") as response:
                    payload = json.loads(response.read())
                changes = payload["changes"]
                self.assertTrue(any(change["title"] == "Nota visible" for change in changes))
                self.assertTrue(any(change["title"] == "Proyecto activo" and change["source_kind"] == "projects" for change in changes))
                self.assertFalse(any(change.get("project") == "Proyecto excluido" for change in changes))
                self.assertFalse(any(change.get("source_kind") == "research" for change in changes))
                self.assertTrue(all(set(change) <= {
                    "change_id", "scan_id", "document_id", "change_type", "reason", "occurred_at",
                    "title", "source_kind", "project", "relative_path", "document_status",
                } for change in changes))
                encoded = json.dumps(payload, ensure_ascii=False)
                self.assertNotIn(str(settings.vault_root), encoded)
                self.assertNotIn(str(project), encoded)
                self.assertNotIn(str(extra), encoded)
                with urlopen(origin + "/api/changes?limit=1") as response:
                    self.assertEqual(len(json.loads(response.read())["changes"]), 1)
                with urlopen(origin + f"/api/changes?limit=100&project_id={active_project_id}") as response:
                    scoped = json.loads(response.read())["changes"]
                self.assertTrue(scoped)
                self.assertTrue(all(change.get("project") == "Proyecto activo" for change in scoped))
                with self.assertRaises(HTTPError) as excluded_project_response:
                    urlopen(origin + f"/api/changes?project_id={excluded_project_id}")
                self.assertEqual(excluded_project_response.exception.code, 400)
                excluded_project_response.exception.close()
                with urlopen(origin + "/api/changes?limit=0") as response:
                    self.assertEqual(json.loads(response.read()), {"changes": []})
                with self.assertRaises(HTTPError) as invalid_project:
                    urlopen(origin + "/api/changes?project_id=not-an-id")
                self.assertEqual(invalid_project.exception.code, 400)
                invalid_project.exception.close()
                with self.assertRaises(HTTPError) as invalid_limit:
                    urlopen(origin + "/api/changes?limit=not-a-number")
                self.assertEqual(invalid_limit.exception.code, 400)
                invalid_limit.exception.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
