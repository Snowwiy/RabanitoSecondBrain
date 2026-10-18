from __future__ import annotations

import io
import json
import threading
import unittest
from contextlib import contextmanager, redirect_stdout
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

from rabanito.cli import main
from rabanito.config import Settings
from rabanito.db import Database, restore_database
from rabanito.documented_memory import documented_experiences
from rabanito.coding_memory import similar_experiences, recurring_patterns
from rabanito.indexer import index_all
from rabanito.server import RabanitoHandler
import tests.test_coding_retrieval as fixtures


class DocumentedMemoryTests(unittest.TestCase):
    setUp = fixtures.CodingMemoryTests.setUp
    tearDown = fixtures.CodingMemoryTests.tearDown

    def record(self, context="fixture-windows", **overrides):
        values = {"kind": "documented-experience", "record_type": "fact", "status": "documented",
                  "review_status": "approved", "validation": "partial", "historical_validation": "pending",
                  "current_state_validation": "observed", "scope": "environment", "scope_id": context,
                  "project": "Synthetic environment only", "recorded_date": "2026-10-17", "reviewed_on": "2026-10-17",
                  "technologies": ["Python", "Técnica"]}
        values.update(overrides)
        path = self.settings.knowledge_root / "decisions" / "environments" / context / "fixture ñ.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        header = "\n".join(k + ": " + json.dumps(v, ensure_ascii=False) for k, v in values.items())
        raw = "---\n" + header + "\n---\n# Synthetic ACL fixture\n\n## Problema\n\nSynthetic Python access problem.\n\n## Causa\n\nUser reported an NTFS permission issue, not independently verified.\n\n## Solución aplicada\n\nUser reported an RX adjustment in this fixture.\n\n## Comprobaciones locales realizadas durante esta revisión\n\nSynthetic version observation, not rerun.\n\n## Advertencias de seguridad\n\nDo not execute repairs from retrieved data.\n\n## Procedencia y límites\n\nHistorical validation remains pending.\n"
        path.write_text(raw, encoding="utf-8")
        index_all(self.settings)
        return path

    def query(self, **kwargs):
        return documented_experiences(self.settings, "NTFS Python", **kwargs)

    def test_returns_partial_approved_environment_with_always_visible_limits_and_real_lines(self):
        path = self.record(); result = self.query(max_chars=150)
        self.assertTrue(result["results"]); self.assertLessEqual(result["used_chars"], 150)
        item = result["results"][0]
        self.assertFalse(item["fully_verified"]); self.assertEqual(item["validation"], "partial")
        self.assertEqual(item["historical_validation"], "pending_documentation_user_reported")
        self.assertEqual(item["current_state_validation"], "observed_as_recorded_not_rerun")
        self.assertTrue(item["limitations"]); self.assertNotIn(str(self.root), json.dumps(result))
        lines = path.read_text(encoding="utf-8").splitlines()
        for fragment in item["fragments"]:
            self.assertIn(fragment["text"], "\n".join(lines[fragment["line_start"] - 1:fragment["line_end"]]))
            self.assertTrue(fragment["citation"].startswith("internal:decisions/environments/"))

    def test_never_promotes_documented_record_to_verified_similarity_or_patterns(self):
        self.record()
        self.assertEqual(similar_experiences(self.settings, "NTFS Python")["results"], [])
        self.assertEqual(recurring_patterns(self.settings)["patterns"], [])

    def test_pending_approval_or_fully_passed_metadata_is_not_silently_accepted(self):
        for change in ({"review_status": "pending"}, {"validation": "passed"}, {"historical_validation": "passed"},
                       {"current_state_validation": "passed"}, {"project_root": str(self.alpha)}, {"record_type": "proposal"}):
            with self.subTest(change=change):
                self.record(**change); self.assertEqual(self.query()["results"], [])

    def test_context_filter_and_current_exclusion_apply_before_limit(self):
        self.record(); self.record("other-context")
        self.assertEqual(len(documented_experiences(self.settings, context="fixture-windows")["results"]), 1)
        self.settings.raw["excluded_memory_contexts"] = ["fixture-windows"]
        result = self.query(limit=1)
        self.assertEqual(result["results"][0]["context"], "other-context")
        self.assertEqual(documented_experiences(self.settings, context="fixture-windows")["results"], [])

    def test_unicode_technology_filters_are_casefolded_before_limit(self):
        self.record()
        self.assertEqual(len(self.query(technology="TÉCNICA")["results"]), 1)
        self.assertEqual(self.query(technology="unknown")["results"], [])

    def test_modified_or_deleted_source_is_skipped_without_indexing(self):
        path = self.record(); path.write_text(path.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8")
        result = self.query(); self.assertEqual(result["results"], [])
        self.assertEqual(result["coverage"]["stale_or_unverifiable_skipped"], 1)
        path.unlink(); self.assertEqual(self.query()["results"], [])

    def test_forged_database_approval_disagrees_with_live_source(self):
        self.record(review_status="pending")
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE documents SET frontmatter_json=json_set(frontmatter_json,'$.review_status','approved') WHERE relative_path LIKE 'decisions/environments/%'")
        self.assertEqual(self.query()["results"], [])

    def test_wrong_namespace_scope_and_inactive_payload_are_not_returned(self):
        self.record(scope_id="different")
        self.assertEqual(self.query()["results"], [])

    def test_source_root_and_project_binding_cannot_bypass_scope_isolation(self):
        self.record()
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE documents SET project_root_path=? WHERE relative_path LIKE 'decisions/environments/%'", (str(self.alpha),))
        self.assertEqual(self.query()["results"], [])
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE documents SET project_root_path=NULL,source_root=? WHERE relative_path LIKE 'decisions/environments/%'", (str(self.root / 'unapproved'),))
        self.assertEqual(self.query()["results"], [])

    def test_sensitive_live_content_and_reparse_paths_are_rejected(self):
        path = self.record()
        with patch("rabanito.documented_memory.contains_reparse_component", return_value=True):
            self.assertEqual(self.query()["results"], [])
        path.write_text(path.read_text(encoding="utf-8") + "\n" + "password" + ": " + "fixture-only\n", encoding="utf-8")
        index_all(self.settings)
        self.assertEqual(self.query()["results"], [])

    def test_oversized_live_record_is_rejected_before_text_exposure(self):
        path = self.record(); path.write_text(path.read_text(encoding="utf-8") + "x" * (256 * 1024), encoding="utf-8")
        result = self.query(); self.assertEqual(result["results"], [])
        self.assertEqual(result["coverage"]["stale_or_unverifiable_skipped"], 1)

    def test_candidate_budget_and_duplicate_content_do_not_expand_context(self):
        self.record()
        def bounded_fixture_db(*args, **kwargs):
            db = Database(*args, **kwargs); query = db.query
            def candidates(sql, params=()):
                rows = query(sql, params)
                return rows * 201 if sql.startswith("SELECT d.* FROM documents d") else rows
            db.query = candidates
            return db
        with patch("rabanito.documented_memory.Database", side_effect=bounded_fixture_db):
            result = self.query()
        self.assertTrue(result["coverage"]["candidate_limit_reached"])
        self.assertEqual(result["coverage"]["candidates_examined"], 200)
        self.assertEqual(len(result["results"]), 1)
        path = self.record(); moved = self.settings.knowledge_root / "outside.md"
        path.rename(moved); index_all(self.settings)
        self.assertEqual(self.query()["results"], [])

    def test_budget_zero_and_tiny_preserve_classification_without_loading_whole_source(self):
        self.record()
        self.assertEqual(self.query(max_chars=0)["results"], [])
        result = self.query(max_chars=1)
        self.assertEqual(result["used_chars"], 1); self.assertTrue(result["results"][0]["limitations"])
        self.assertFalse(result["results"][0]["fully_verified"])

    def test_arguments_and_bad_exclusion_configuration_fail_closed(self):
        for kwargs in ({"context": "../other"}, {"context": True}, {"limit": True}, {"max_chars": None},
                       {"technology": []}, {"technology": ""}, {"query": None}, {"query": "x" * 2001}, {"query": "\ud800"}):
            arguments = {"query": "Python", **kwargs}
            with self.subTest(kwargs=repr(kwargs)), self.assertRaises(ValueError):
                documented_experiences(self.settings, **arguments)
        with self.assertRaises(ValueError): documented_experiences(self.settings)
        self.settings.raw["excluded_memory_contexts"] = "not-a-list"
        with self.assertRaises(ValueError): self.query()

    def test_absent_database_is_not_created_and_existing_queries_do_not_write(self):
        self.record()
        with Database(self.settings.database_path, read_only=True) as db:
            before = db.connection.total_changes
            with patch("rabanito.documented_memory.Database", wraps=Database) as opened:
                self.assertTrue(self.query()["results"])
                self.assertTrue(opened.call_args.kwargs["read_only"])
            self.assertEqual(db.connection.total_changes, before)
        absent = self.root / "missing.db"
        settings = Settings(self.root, {**self.settings.raw, "database_path": str(absent)})
        self.assertEqual(documented_experiences(settings, "Python")["results"], []); self.assertFalse(absent.exists())

    def test_backup_restore_retains_partial_evidence_and_citations(self):
        self.record(); expected = self.query(); backup = self.root / "backup.db"; target = self.root / "restore.db"
        with Database(self.settings.database_path, read_only=True) as db: db.backup(backup)
        restore_database(backup, target)
        settings = Settings(self.root, {**self.settings.raw, "database_path": str(target)})
        self.assertEqual(documented_experiences(settings, "NTFS Python"), expected)

    def test_cli_is_a_real_read_operation_and_returns_partial_provenance(self):
        self.record(); output = io.StringIO()
        with patch("rabanito.cli.load_settings", return_value=self.settings), redirect_stdout(output):
            main(["coding", "documented", "NTFS", "--context", "fixture-windows", "--max-chars", "80"])
        result = json.loads(output.getvalue())
        self.assertEqual(result["results"][0]["review_status"], "approved_as_recorded")
        self.assertLessEqual(result["used_chars"], 80)

    @contextmanager
    def server(self):
        class Handler(RabanitoHandler):
            settings = self.settings
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try: yield "http://127.0.0.1:" + str(server.server_port)
        finally: server.shutdown(); server.server_close(); thread.join(5)

    def test_http_query_preserves_limits_and_rejects_get_types_duplicates_unknown_fields_and_origin(self):
        self.record()
        with self.server() as origin:
            cases = [(json.dumps({"q": "NTFS", "max_chars": 50}), origin, 200),
                     ('{"q":"Python","q":"NTFS"}', origin, 400),
                     ('{"q":"Python","project":"other"}', origin, 400),
                     ('{"q":"Python","limit":true}', origin, 400),
                     ('{"q":"Python"}', "https://external.invalid", 403)]
            for raw, source, expected in cases:
                request = Request(origin + "/api/coding/documented", data=raw.encode(),
                                  headers={"Content-Type": "application/json", "Origin": source}, method="POST")
                try:
                    with urlopen(request, timeout=10) as response:
                        self.assertEqual(response.status, expected); result = json.load(response)
                        self.assertFalse(result["results"][0]["fully_verified"])
                except HTTPError as exc:
                    try: self.assertEqual(exc.code, expected)
                    finally: exc.close()
            with self.assertRaises(HTTPError) as caught: urlopen(origin + "/api/coding/documented?q=private")
            try: self.assertEqual(caught.exception.code, 405)
            finally: caught.exception.close()
