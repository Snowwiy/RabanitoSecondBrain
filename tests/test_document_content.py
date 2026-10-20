from __future__ import annotations

import http.client
import json
import os
import sqlite3
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from rabanito.config import Settings
from rabanito.db import Database, restore_database
from rabanito.document_content import DocumentContentError, document_content, _open_readonly
from rabanito.indexer import index_all
from rabanito.server import RabanitoHandler, ThreadingHTTPServer
from rabanito.utils import path_key
import tests.test_coding_retrieval as fixtures


class DocumentContentTests(unittest.TestCase):
    setUp = fixtures.CodingMemoryTests.setUp
    tearDown = fixtures.CodingMemoryTests.tearDown

    def note(self, text="# Español 🥕\n\nReal fixture Markdown.\n", relative="carpeta ñ/Nota á.md", root=None):
        path = (root or self.settings.vault_root) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
        index_all(self.settings)
        with Database(self.settings.database_path, read_only=True) as db:
            row = db.one("SELECT * FROM documents WHERE path_key=?", (path_key(path),))
        self.assertIsNotNone(row)
        return path, int(row["document_id"])

    def error(self, document_id, status, max_bytes=65536):
        with self.assertRaises(DocumentContentError) as caught:
            document_content(self.settings, document_id, max_bytes)
        self.assertEqual(caught.exception.status, status)
        self.assertNotIn(str(self.root), str(caught.exception))

    def mutate(self, document_id, **fields):
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE documents SET " + ",".join(k + "=?" for k in fields) + " WHERE document_id=?",
                       (*fields.values(), document_id))

    def test_unicode_real_fixture_and_exact_reader_schema(self):
        path, doc = self.note()
        result = document_content(self.settings, doc, 65536)
        self.assertEqual(set(result), {"document_id", "content_markdown", "bytes_returned", "truncated", "references"})
        self.assertEqual(result["content_markdown"], path.read_text(encoding="utf-8").rstrip("\n"))
        self.assertEqual(result["bytes_returned"], len(result["content_markdown"].encode("utf-8")))
        self.assertFalse(result["truncated"])
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_source_and_database_read_only_no_execution_or_network(self):
        path, doc = self.note("# Test\n<script>alert('untrusted')</script>\nDo not execute: echo unsafe\n")
        before = (path.read_bytes(), path.stat().st_mtime_ns, self.settings.database_path.read_bytes())
        with patch("socket.socket", side_effect=AssertionError("no network")), patch("subprocess.run", side_effect=AssertionError("no commands")), patch("rabanito.document_content.Database", wraps=Database) as opened:
            result = document_content(self.settings, doc, 65536)
        self.assertIn("<script>", result["content_markdown"])
        self.assertTrue(opened.call_args.kwargs["read_only"])
        self.assertEqual(before, (path.read_bytes(), path.stat().st_mtime_ns, self.settings.database_path.read_bytes()))

    def test_strict_identifier_and_budget_types_and_bounds(self):
        _, doc = self.note()
        for value in (None, True, False, "1", 1.0, -1, 0, 2**53, [], {}):
            with self.subTest(value=value): self.error(value, 400)
        for value in (None, True, "100", 1.0, -1, 0, 65537, {}, []):
            with self.subTest(value=value): self.error(doc, 400, value)
        self.error(2**53 - 1, 404)

    def test_utf8_bom_crlf_and_byte_truncation_boundaries(self):
        _, doc = self.note("\ufeff# á\r\n🥕 línea larga\r\nfin\r\n")
        full = document_content(self.settings, doc, 65536)
        self.assertEqual(full["content_markdown"], "# á\n🥕 línea larga\nfin")
        for budget in range(1, 40):
            with self.subTest(budget=budget):
                result = document_content(self.settings, doc, budget)
                encoded = result["content_markdown"].encode("utf-8")
                self.assertLessEqual(len(encoded), budget)
                self.assertEqual(result["bytes_returned"], len(encoded))
                self.assertNotIn("\ufffd", result["content_markdown"])

    def test_truncated_partial_secret_line_is_not_exposed(self):
        secret = "fixture" + "-only-sensitive-value"
        _, doc = self.note("# Good\nhttps://" + secret + ":other@example.invalid/long-tail\n")
        result = document_content(self.settings, doc, 25)
        self.assertEqual(result["content_markdown"], "# Good")
        self.assertTrue(result["truncated"])
        self.assertNotIn(secret[:8], result["content_markdown"])

    def test_redacts_detectable_secrets_and_absolute_paths_but_preserves_relative_links(self):
        token = "gh" + "p_" + "x" * 36
        secret = "synthetic" + "-value"
        text = ("# Public\npassword" + ": " + secret + "\n" + token + "\nBearer " + "a" * 24
                + "\nfile:///C:/Private/hidden.md\n" + "C:" + "\\Private\\note.md\n"
                + str(self.settings.vault_root / "hidden.md") + "\n[ok](Relative.md)\nhttps://example.invalid/public\n")
        _, doc = self.note(text)
        result = document_content(self.settings, doc, 65536)["content_markdown"]
        for value in (token, secret, str(self.root), "Private", "a" * 24): self.assertNotIn(value, result)
        self.assertIn("[REDACTED", result)
        self.assertIn("[ok](Relative.md)", result)
        self.assertIn("https://example.invalid/public", result)

    def test_multiline_yaml_and_unclosed_private_keys_are_redacted(self):
        marker = "-----BEGIN " + "PRIVATE KEY-----"
        _, doc = self.note("---\npassword" + ": |\n  synthetic-hidden\n---\n# Good\n" + marker + "\nfixture-key-body\n")
        content = document_content(self.settings, doc, 65536)["content_markdown"]
        self.assertNotIn("synthetic-hidden", content); self.assertNotIn("fixture-key-body", content)

    def test_changed_source_returns_conflict_without_reindexing(self):
        path, doc = self.note(); path.write_bytes(path.read_bytes() + b"changed")
        self.error(doc, 409)
        index_all(self.settings)
        self.assertIn("changed", document_content(self.settings, doc, 65536)["content_markdown"])

    def test_same_size_and_mtime_tampering_is_caught_by_full_hash(self):
        path, doc = self.note("# before\n")
        st = path.stat(); path.write_bytes(b"# after!\n"); os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
        self.error(doc, 409)

    def test_deleted_and_tombstoned_document_never_returns_fts_body(self):
        path, doc = self.note(); path.unlink(); self.error(doc, 409)
        index_all(self.settings); self.error(doc, 404)

    def test_current_source_policy_and_excluded_directory_are_rechecked(self):
        _, doc = self.note(relative="future-private/fixture.md")
        self.settings.raw["source_policy"]["obsidian"]["exclude_dirs"] = ["future-private"]
        self.error(doc, 404)
        self.settings.raw["source_policy"]["obsidian"]["exclude_dirs"] = []
        self.settings.raw["source_policy"]["obsidian"]["extensions"] = []
        self.error(doc, 404)

    def test_current_excluded_missing_and_unregistered_projects_are_hidden(self):
        _, doc = self.note(root=self.alpha, relative="README.md")
        self.assertTrue(document_content(self.settings, doc, 65536)["content_markdown"])
        self.settings.raw["excluded_projects"] = [str(self.alpha)]; self.error(doc, 404)
        self.settings.raw["excluded_projects"] = []
        with Database(self.settings.database_path) as db: db.execute("UPDATE projects SET status='missing'")
        self.error(doc, 404)
        with Database(self.settings.database_path) as db: db.execute("DELETE FROM projects")
        self.error(doc, 404)

    def test_internal_environment_exclusion(self):
        _, doc = self.note(root=self.settings.knowledge_root, relative="decisions/environments/fixture/record.md")
        self.assertTrue(document_content(self.settings, doc, 65536)["content_markdown"])
        self.settings.raw["excluded_memory_contexts"] = ["fixture"]; self.error(doc, 404)

    def test_additional_source_requires_exact_enabled_kind_and_root(self):
        extra = self.root / "extra"; extra.mkdir()
        self.settings.raw["additional_sources"] = [{"kind": "local", "path": str(extra), "enabled": True}]
        _, doc = self.note(root=extra)
        self.assertTrue(document_content(self.settings, doc, 65536)["content_markdown"])
        self.settings.raw["additional_sources"][0]["enabled"] = False; self.error(doc, 404)
        self.settings.raw["additional_sources"][0]["enabled"] = True
        self.mutate(doc, source_kind="forged"); self.error(doc, 404)

    def test_forged_index_paths_traversal_ads_and_special_names_fail_closed(self):
        _, doc = self.note()
        for relative in ("../escape.md", "/escape.md", "C:/escape.md", "x.md:stream", "..\\escape.md", "x/./note.md", "NUL.md", "x//note.md", "x/evil. /note.md", "x/\x00.md"):
            with self.subTest(relative=relative):
                self.mutate(doc, relative_path=relative); self.error(doc, 404)
        self.mutate(doc, relative_path="carpeta ñ/Nota á.md", absolute_path=str(self.root / "elsewhere.md"))
        self.error(doc, 404)

    def test_forged_source_root_and_inactive_document_are_hidden(self):
        _, doc = self.note()
        self.mutate(doc, source_root=str(self.root)); self.error(doc, 404)
        self.mutate(doc, source_root=str(self.settings.vault_root), status="deleted"); self.error(doc, 404)

    def test_indexed_id_cannot_be_retargeted_to_env_or_code(self):
        path, doc = self.note()
        for name in (".env", "private.key", "source.py", "auth.json"):
            target = path.parent / name; target.write_bytes(b"fixture only")
            relative = target.relative_to(self.settings.vault_root).as_posix()
            self.mutate(doc, relative_path=relative, absolute_path=str(target), path_key=path_key(target))
            with patch("rabanito.document_content._open_readonly", side_effect=AssertionError("must not open")):
                self.error(doc, 404)

    def test_nested_project_cannot_inherit_parent_authorization(self):
        nested = self.alpha / "component"; nested.mkdir()
        _, doc = self.note(root=nested, relative="README.md")
        with Database(self.settings.database_path) as db:
            db.execute("INSERT INTO projects(name,root_path,path_key,first_seen,last_seen,status) VALUES(?,?,?,'fixture','fixture','excluded')",
                       ("component", str(nested), path_key(nested)))
        self.error(doc, 404)
        self.mutate(doc, source_root=str(nested), project_root_path=str(nested), relative_path="README.md")
        self.error(doc, 404)
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE projects SET status='active' WHERE root_path=?", (str(nested),))
        self.assertTrue(document_content(self.settings, doc, 65536)["content_markdown"])
        self.settings.raw["excluded_projects"] = [str(self.alpha)]; self.error(doc, 404)

    def test_real_directory_junction_or_symlink_is_denied(self):
        outside = self.root / "not-authorized"; outside.mkdir()
        (outside / "note.md").write_bytes(b"# Outside authorized source\n")
        link = self.settings.vault_root / "linked"
        if os.name == "nt":
            import _winapi
            _winapi.CreateJunction(str(outside), str(link))
        else:
            link.symlink_to(outside, target_is_directory=True)
        try:
            with self.assertRaises(DocumentContentError) as caught:
                with _open_readonly(link / "note.md") as stream:
                    self.fail("must not expose a stream through the junction")
            self.assertEqual(caught.exception.status, 404) if os.name == "nt" else None
        except OSError:
            if os.name == "nt": raise
        finally:
            link.rmdir() if os.name == "nt" else link.unlink()

    def test_actual_junction_swap_between_authorization_and_read_does_not_leak(self):
        path, doc = self.note(relative="sub/note.md")
        outside = self.root / "outside-swap"; outside.mkdir()
        (outside / path.name).write_bytes(b"# Must not read me\n")
        real_open = _open_readonly
        @contextmanager
        def swap(p):
            original = p.parent; parked = original.with_name("parked")
            original.rename(parked)
            try:
                if os.name == "nt":
                    import _winapi
                    _winapi.CreateJunction(str(outside), str(original))
                else:
                    original.symlink_to(outside, target_is_directory=True)
                try:
                    with real_open(p) as stream: yield stream
                finally:
                    original.rmdir() if os.name == "nt" else original.unlink()
            finally:
                parked.rename(original)
        with patch("rabanito.document_content._open_readonly", swap):
            with self.assertRaises((DocumentContentError, OSError)):
                document_content(self.settings, doc, 65536)
        self.assertTrue(path.is_file())

    def test_size_limit_is_enforced_before_open(self):
        _, doc = self.note(); self.settings.raw["max_document_bytes"] = 1
        with patch("rabanito.document_content._open_readonly", side_effect=AssertionError("must not open")):
            self.error(doc, 413)

    def test_invalid_utf8_and_binary_sources_are_not_returned(self):
        path, doc = self.note()
        for raw in (b"# test\n\xff\n", b"# test\n\x00\n"):
            path.write_bytes(raw); index_all(self.settings); self.error(doc, 400)

    def test_reparse_guard_and_actual_hardlink_fail_closed(self):
        path, doc = self.note()
        with patch("rabanito.document_content.contains_reparse_component", side_effect=lambda p: Path(p) == path):
            self.error(doc, 404)
        link = self.root / "hardlink.md"
        os.link(path, link)
        self.error(doc, 404)
        link.unlink()

    def test_bounded_read_and_changed_handle_identity_are_checked(self):
        path, doc = self.note("# First\n" + "x" * 10000)
        @contextmanager
        def spy(p):
            with _open_readonly(p) as source:
                class Proxy:
                    def fileno(self): return source.fileno()
                    def read(inner, size):
                        self.assertEqual(size, 30)
                        return source.read(size)
                yield Proxy()
        with patch("rabanito.document_content._open_readonly", spy):
            self.assertTrue(document_content(self.settings, doc, 30)["truncated"])
        @contextmanager
        def replacement(p):
            other = self.root / "different.md"; other.write_bytes(b"outside")
            with _open_readonly(other) as source: yield source
        with patch("rabanito.document_content._open_readonly", replacement): self.error(doc, 409)

    def test_windows_handle_disallows_concurrent_source_write_without_changing_acl(self):
        path, _ = self.note()
        with _open_readonly(path):
            if os.name == "nt":
                with self.assertRaises(OSError):
                    with path.open("r+b"): pass

    def test_references_only_resolved_and_authorized_without_target_bodies(self):
        _, target = self.note("# Destination\n", "Destino.md")
        _, doc = self.note("# Source\n[[Destino]]\n[[Missing]]\n")
        def minimal_read(*args, **kwargs):
            db = Database(*args, **kwargs)
            def authorizer(action, table, column, *unused):
                if action == sqlite3.SQLITE_READ and table == "documents" and column in {"frontmatter_json", "tags_json", "parse_error"}:
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            db.connection.set_authorizer(authorizer)
            return db
        with patch("rabanito.document_content.Database", side_effect=minimal_read):
            refs = document_content(self.settings, doc, 65536)["references"]
        self.assertEqual(len(refs), 1); self.assertEqual(refs[0]["target_document_id"], target)
        self.assertEqual(set(refs[0]), {"target_document_id", "target_raw", "title", "relative_path", "status"})
        self.assertEqual(refs[0]["status"], "resolved")
        self.mutate(target, source_root=str(self.root)); self.assertEqual(document_content(self.settings, doc, 65536)["references"], [])

    def test_reference_limit_and_sensitive_metadata_do_not_leak(self):
        _, target = self.note("# Destination\n", "Destino.md")
        _, doc = self.note("# Source\n[[Destino]]\n")
        with Database(self.settings.database_path) as db:
            db.execute("DELETE FROM links WHERE source_document_id=?", (doc,))
            for n in range(520):
                db.execute("INSERT INTO links(source_document_id,target_document_id,target_raw,status,line_number) VALUES(?,?,?,'resolved',?)", (doc, target, "alias" + str(n), n))
        self.assertEqual(len(document_content(self.settings, doc, 65536)["references"]), 512)
        self.mutate(target, title="file:///C:/private/example.md")
        self.assertEqual(document_content(self.settings, doc, 65536)["references"], [])

    def test_suggested_ambiguous_external_or_excluded_targets_are_not_references(self):
        _, target = self.note("# Destination\n", "Destino.md")
        _, doc = self.note("# Source\n[[Destino]]\n")
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE links SET relation_type='suggested' WHERE source_document_id=?", (doc,))
        self.assertEqual(document_content(self.settings, doc, 65536)["references"], [])
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE links SET relation_type='wikilink',target_raw='https://example.invalid/x' WHERE source_document_id=?", (doc,))
        self.assertEqual(document_content(self.settings, doc, 65536)["references"], [])
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE links SET target_raw='Destino',status='ambiguous' WHERE source_document_id=?", (doc,))
        self.assertEqual(document_content(self.settings, doc, 65536)["references"], [])

    def test_http_stale_and_size_errors_keep_existing_structured_format(self):
        path, doc = self.note()
        raw = json.dumps({"document_id": doc, "max_bytes": 65536})
        with self.server() as port:
            self.settings.raw["max_document_bytes"] = 1
            self.assertEqual(self.request(port, raw)[0], 413)
            self.settings.raw["max_document_bytes"] = 2_097_152
            path.write_bytes(path.read_bytes() + b"changed")
            status, payload, _ = self.request(port, raw)
            self.assertEqual(status, 409); self.assertEqual(payload, {"error": "document_changed_reindex_required"})

    def test_missing_or_incompatible_database_is_not_created_or_migrated(self):
        absent = self.root / "missing.db"
        settings = Settings(self.root, {**self.settings.raw, "database_path": str(absent)})
        with self.assertRaises(DocumentContentError) as caught: document_content(settings, 1, 100)
        self.assertEqual(caught.exception.status, 503); self.assertFalse(absent.exists())
        absent.write_bytes(b"not sqlite")
        before = absent.read_bytes()
        with self.assertRaises(DocumentContentError): document_content(settings, 1, 100)
        self.assertEqual(absent.read_bytes(), before)

    def test_restore_preserves_content_and_authorized_references(self):
        _, doc = self.note(); expected = document_content(self.settings, doc, 65536)
        backup, restored = self.root / "backup.db", self.root / "restored.db"
        with Database(self.settings.database_path, read_only=True) as db: db.backup(backup)
        restore_database(backup, restored)
        settings = Settings(self.root, {**self.settings.raw, "database_path": str(restored)})
        self.assertEqual(document_content(settings, doc, 65536), expected)

    @contextmanager
    def server(self):
        class Handler(RabanitoHandler):
            settings = self.settings
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        try: yield server.server_port
        finally: server.shutdown(); server.server_close(); worker.join(5)

    def request(self, port, body, *, method="POST", path="/api/doc/content", headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            connection.request(method, path, body=body, headers={"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}", **(headers or {})})
            response = connection.getresponse()
            return response.status, json.loads(response.read()), response.getheader("Cache-Control")
        finally: connection.close()

    def test_http_success_and_existing_metadata_endpoint_regression(self):
        _, doc = self.note()
        with self.server() as port:
            status, body, cache = self.request(port, json.dumps({"document_id": doc, "max_bytes": 65536}))
            self.assertEqual(status, 200); self.assertEqual(cache, "no-store")
            self.assertEqual(body, document_content(self.settings, doc, 65536))
            status, body, _ = self.request(port, None, method="GET", path=f"/api/doc/{doc}")
            self.assertEqual(status, 200); self.assertNotIn("content_markdown", body)

    def test_http_invalid_fields_json_duplicate_keys_and_url_filters(self):
        _, doc = self.note()
        with self.server() as port:
            for body in ('{}', '[]', '{', '{"document_id":1,"document_id":2,"max_bytes":10}',
                         json.dumps({"document_id": doc, "max_bytes": 10, "path": "../private"}),
                         json.dumps({"document_id": True, "max_bytes": 10}), b'\xff'):
                status, payload, _ = self.request(port, body)
                self.assertEqual(status, 400); self.assertEqual(set(payload), {"error"})
                self.assertNotIn("private", payload["error"])
            status, _, _ = self.request(port, '{}', path="/api/doc/content?document_id=1")
            self.assertEqual(status, 400)
            self.assertEqual(self.request(port, None, method="GET")[0], 405)

    def test_http_host_origin_body_limits_and_structured_errors(self):
        _, doc = self.note()
        raw = json.dumps({"document_id": doc, "max_bytes": 50})
        with self.server() as port:
            for headers in ({"Origin": "https://external.invalid"}, {"Host": "external.invalid"},
                            {"Origin": f"http://user@127.0.0.1:{port}"}, {"Origin": f"http://127.0.0.1:{port}/x"},
                            {"Content-Type": "text/plain"}):
                for _ in range(5):
                    self.assertEqual(self.request(port, raw, headers=headers)[0], 403)
            self.assertEqual(self.request(port, " " * 2049)[0], 413)
            self.assertEqual(self.request(port, raw, headers={"Transfer-Encoding": "chunked"})[0], 400)

    def test_http_duplicate_length_and_missing_origin_are_rejected(self):
        with self.server() as port:
            for origin in (False, True):
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                try:
                    connection.putrequest("POST", "/api/doc/content")
                    connection.putheader("Content-Type", "application/json")
                    connection.putheader("Content-Length", "2")
                    if origin:
                        connection.putheader("Origin", f"http://127.0.0.1:{port}")
                        connection.putheader("Content-Length", "2")
                    connection.endheaders(b"{}")
                    response = connection.getresponse()
                    self.assertEqual(response.status, 400 if origin else 403)
                    self.assertEqual(set(json.loads(response.read())), {"error"})
                finally: connection.close()
