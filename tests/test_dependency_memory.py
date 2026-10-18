from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from rabanito.cli import main
from rabanito.db import Database, restore_database
from rabanito.dependency_memory import (export_openvex, review_inventory, reviewed_inventory,
                                        revoke_review, snapshot_inventory)
from rabanito.utils import path_key
from tests.test_cyber import GHSA, NOW, osv
from tests import test_dependencies as dependency_fixtures
from tests.test_dependencies import component


class DependencyMemoryTests(unittest.TestCase):
    setUp = dependency_fixtures.DependencyTests.setUp
    tearDown = dependency_fixtures.DependencyTests.tearDown
    register = dependency_fixtures.DependencyTests.register
    seed = dependency_fixtures.DependencyTests.seed
    write = dependency_fixtures.DependencyTests.write

    def setup_review(self):
        self.seed()
        self.write()
        (self.project / "review ñ.md").write_text("# Fixture evidence\nDocumented mitigation for this inventory only.\n", encoding="utf-8")
        return {"project": str(self.project), "relative_path": self.path.name, "advisory": GHSA,
                "component_pointer": "/components/0", "status": "not_affected", "reviewer": "Fixture Reviewer",
                "reason": "The fixture documents a build-time mitigation; tests are not re-executed.",
                "expires": "2026-11-16", "evidence": ["review ñ.md"], "justification": "vulnerable_code_not_present",
                "impact": "The reviewed fixture build excludes the affected code.", "now": NOW}

    def approve(self, arguments):
        preview = review_inventory(self.settings, **arguments)
        return review_inventory(self.settings, **arguments, approve_digest=preview["approval_digest"])

    def view(self, **kwargs):
        return reviewed_inventory(self.settings, str(self.project), self.path.name, now=NOW, **kwargs)

    def test_previews_are_read_only_and_original_candidate_is_preserved(self):
        args = self.setup_review()
        original = self.path.read_bytes()
        before = hashlib.sha256(self.settings.database_path.read_bytes()).hexdigest()
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            preview = review_inventory(self.settings, **args)
            snapshot = snapshot_inventory(self.settings, str(self.project), self.path.name)
            view = self.view()
        self.assertEqual(preview["persistence"], "preview")
        self.assertEqual(snapshot["persistence"], "preview")
        self.assertEqual(view["reviews"], [])
        self.assertEqual(view["report"]["findings"][0]["assessment"], "potentially_affected")
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(hashlib.sha256(self.settings.database_path.read_bytes()).hexdigest(), before)
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertIsNone(db.one("SELECT 1 FROM sqlite_master WHERE name='dependency_migrations'"))

    def test_approval_is_exact_idempotent_and_backed_up_before_migration(self):
        args = self.setup_review()
        first = self.approve(args)
        self.assertTrue(first["created"])
        backup = self.settings.data_dir / "backups" / first["migration_backup"]
        self.assertTrue(backup.is_file())
        with Database(backup, read_only=True) as db:
            self.assertIsNone(db.one("SELECT 1 FROM sqlite_master WHERE name='dependency_migrations'"))
        second = self.approve(args)
        self.assertFalse(second["created"])
        self.assertEqual(first["review_id"], second["review_id"])
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(db.one("SELECT count(*) n FROM dependency_reviews")["n"], 1)
            self.assertEqual(db.one("SELECT count(*) n FROM dependency_review_events")["n"], 1)
        view = self.view()
        self.assertEqual(view["reviews"][0]["effective_state"], "current")
        self.assertEqual(view["report"]["findings"][0]["assessment"], "potentially_affected")
        self.assertNotIn(str(self.root), json.dumps(view, ensure_ascii=False))

    def test_wrong_or_changed_preview_digest_never_writes(self):
        args = self.setup_review()
        preview = review_inventory(self.settings, **args)
        for changed in ({**args, "reason": "Different reviewed reason"},
                        {**args, "reviewer": "Another reviewer"}):
            with self.assertRaisesRegex(ValueError, "digest_mismatch"):
                review_inventory(self.settings, **changed, approve_digest=preview["approval_digest"])
        (self.project / "review ñ.md").write_text("Changed before approval", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "digest_mismatch"):
            review_inventory(self.settings, **args, approve_digest=preview["approval_digest"])

    def test_input_change_while_waiting_for_lock_rejects_approval(self):
        args = self.setup_review()
        preview = review_inventory(self.settings, **args)
        @contextlib.contextmanager
        def change_before_lock(_):
            (self.project / "review ñ.md").write_text("Concurrent edit", encoding="utf-8")
            yield
        with patch("rabanito.dependency_memory._index_lock", side_effect=change_before_lock):
            with self.assertRaisesRegex(ValueError, "changed_retry_preview"):
                review_inventory(self.settings, **args, approve_digest=preview["approval_digest"])

    def test_review_validation_requires_evidence_expiry_and_status_fields(self):
        args = self.setup_review()
        for changes in ({"evidence": []}, {"evidence": ["missing.md"]}, {"expires": "2026-10-16"},
                        {"expires": "2029-01-01"}, {"status": "safe"}, {"status": []},
                        {"justification": "not_used"}, {"impact": ""}, {"reviewer": ""},
                        {"status": "affected", "justification": "", "action": ""},
                        {"advisory": "CVE-2024-12345"}, {"component_pointer": "/components/1"},
                        {"reason": "password=" + "fixture_marker_value"}):
            with self.subTest(changes=list(changes)):
                with self.assertRaises((ValueError, OSError)):
                    review_inventory(self.settings, **{**args, **changes})
        with self.assertRaisesRegex(ValueError, "sensitive"):
            review_inventory(self.settings, **{**args, "reason": "gh" + "p_" + "Z" * 36})

    def test_evidence_paths_cannot_escape_or_cross_project_boundaries(self):
        args = self.setup_review()
        nested = self.project / "child"
        nested.mkdir()
        self.register(nested)
        (nested / "README.md").write_text("Other project", encoding="utf-8")
        for evidence in (["../outside.md"], ["child/README.md"], [".env"], ["secrets/notes.md"]):
            with self.subTest(evidence=evidence):
                with self.assertRaises(ValueError):
                    review_inventory(self.settings, **{**args, "evidence": evidence})

    def test_expiry_evidence_changes_and_inventory_changes_require_review(self):
        args = self.setup_review()
        self.approve(args)
        expired = reviewed_inventory(self.settings, str(self.project), self.path.name, now=NOW + timedelta(days=32))
        self.assertEqual(expired["reviews"][0]["effective_state"], "expired")
        (self.project / "review ñ.md").write_text("Changed evidence", encoding="utf-8")
        self.assertEqual(self.view()["reviews"][0]["effective_state"], "stale_evidence")
        self.write([component(version="1.5")])
        self.assertEqual(self.view()["reviews"][0]["effective_state"], "stale_inputs")

    def test_public_advisory_revision_stales_prior_claim(self):
        args = self.setup_review()
        self.approve(args)
        payload = osv()
        payload["modified"] = "2026-10-16T15:00:00Z"
        payload["details"] = "Changed public applicability"
        self.seed(payload)
        self.assertEqual(self.view()["reviews"][0]["effective_state"], "stale_inputs")

    def test_exclusions_are_enforced_at_query_and_revoke_time(self):
        args = self.setup_review()
        saved = self.approve(args)
        self.settings.raw["excluded_projects"] = [str(self.project)]
        with self.assertRaises(ValueError):
            self.view()
        with self.assertRaises(ValueError):
            revoke_review(self.settings, str(self.project), saved["review_id"], reviewer="Reviewer", reason="Revoke")

    def test_conflicting_claims_are_not_latest_wins_or_exported(self):
        args = self.setup_review()
        self.approve(args)
        self.approve({**args, "status": "affected", "justification": "", "impact": "", "action": "Review and test an upgrade"})
        view = self.view()
        self.assertEqual(view["report"]["findings"][0]["review_resolution"], "conflicting_claims")
        self.assertEqual(view["report"]["findings"][0]["assessment"], "potentially_affected")
        with self.assertRaisesRegex(ValueError, "conflicting"):
            export_openvex(self.settings, str(self.project), self.path.name, now=NOW)

    def test_revocation_preserves_history_and_never_reactivates_identical_draft(self):
        args = self.setup_review()
        saved = self.approve(args)
        kwargs = {"reviewer": "Reviewer", "reason": "Evidence no longer sufficient"}
        preview = revoke_review(self.settings, str(self.project), saved["review_id"], **kwargs)
        self.assertEqual(self.view()["reviews"][0]["effective_state"], "current")
        revoked = revoke_review(self.settings, str(self.project), saved["review_id"], **kwargs, approve_digest=preview["approval_digest"])
        self.assertTrue(revoked["changed"])
        self.assertEqual(self.view()["reviews"][0]["effective_state"], "revoked")
        self.assertTrue(self.approve(args)["revoked"])
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(db.one("SELECT count(*) n FROM dependency_review_events")["n"], 2)

    def test_snapshot_incremental_updates_only_changed_head_and_retains_history(self):
        self.setup_review()
        first = snapshot_inventory(self.settings, str(self.project), self.path.name, save=True)
        same = snapshot_inventory(self.settings, str(self.project), self.path.name, save=True)
        self.assertTrue(first["changed"])
        self.assertFalse(same["changed"])
        self.assertFalse(same["new_snapshot"])
        self.write([component(version="1.5")])
        changed = snapshot_inventory(self.settings, str(self.project), self.path.name, save=True)
        self.assertTrue(changed["changed"])
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(db.one("SELECT count(*) n FROM dependency_analyses")["n"], 2)
            self.assertEqual(db.one("SELECT count(*) n FROM dependency_analysis_heads")["n"], 1)
            self.assertEqual(db.one("SELECT analysis_id FROM dependency_analysis_heads")["analysis_id"], changed["report"]["analysis_id"])

    def test_concurrent_identical_approvals_create_one_event_and_record(self):
        args = self.setup_review()
        preview = review_inventory(self.settings, **args)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: review_inventory(self.settings, **args, approve_digest=preview["approval_digest"]), range(2)))
        self.assertEqual(sum(r["created"] for r in results), 1)
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(db.one("SELECT count(*) n FROM dependency_review_events")["n"], 1)
            self.assertEqual(db.one("PRAGMA integrity_check")[0], "ok")

    def test_event_failure_rolls_back_entire_approval(self):
        args = self.setup_review()
        snapshot_inventory(self.settings, str(self.project), self.path.name, save=True)
        with Database(self.settings.database_path) as db:
            db.execute("CREATE TRIGGER fixture_abort BEFORE INSERT ON dependency_review_events BEGIN SELECT RAISE(ABORT,'fixture_failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.approve(args)
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(db.one("SELECT count(*) n FROM dependency_reviews")["n"], 0)

    def test_backup_restore_retains_review_and_analysis(self):
        args = self.setup_review()
        self.approve(args)
        snapshot_inventory(self.settings, str(self.project), self.path.name, save=True)
        backup = self.settings.data_dir / "test-restore.db"
        restored = self.settings.data_dir / "restored.db"
        with Database(self.settings.database_path, read_only=True) as db:
            db.backup(backup)
        restore_database(backup, restored)
        with Database(restored, read_only=True) as db:
            self.assertEqual(db.one("PRAGMA integrity_check")[0], "ok")
            self.assertEqual(db.query("PRAGMA foreign_key_check"), [])
            self.assertEqual(db.one("SELECT count(*) n FROM dependency_reviews")["n"], 1)
            self.assertEqual(db.one("SELECT count(*) n FROM dependency_analyses")["n"], 1)

    def test_schema_and_review_checksums_are_verified_without_migration_on_read(self):
        args = self.setup_review()
        saved = self.approve(args)
        with Database(self.settings.database_path) as db:
            row = db.one("SELECT payload_json FROM dependency_reviews WHERE review_id=?", (saved["review_id"],))
            payload = json.loads(row["payload_json"])
            payload["reason"] = "Tampered"
            db.execute("UPDATE dependency_reviews SET payload_json=?", (json.dumps(payload),))
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.view()
        with Database(self.settings.database_path) as db:
            db.execute("UPDATE dependency_migrations SET checksum='invalid'")
        with self.assertRaisesRegex(ValueError, "migration"):
            self.view()

    def test_openvex_export_is_local_scoped_and_does_not_claim_binary_hash(self):
        args = self.setup_review()
        self.approve(args)
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            exported = export_openvex(self.settings, str(self.project), self.path.name, now=NOW)
        doc = exported["documents"][0]
        self.assertEqual(doc["@context"], "https://openvex.dev/ns/v0.2.0")
        self.assertEqual(doc["author"], "Fixture Reviewer")
        statement = doc["statements"][0]
        self.assertEqual(statement["vulnerability"]["name"], GHSA)
        self.assertEqual(statement["products"][0]["subcomponents"][0]["@id"], "pkg:pypi/parser@1.0")
        self.assertNotIn("hashes", statement["products"][0])
        self.assertIn("Local expiry", statement["status_notes"])
        self.assertEqual(exported["remote_requests"], 0)

    def test_manifest_snapshots_and_cli_preview(self):
        self.seed()
        manifest = self.project / "requirements.txt"
        manifest.write_text("parser==1.0\n", encoding="utf-8")
        snapshot = snapshot_inventory(self.settings, str(self.project), manifest.name, kind="manifest", save=True)
        self.assertTrue(snapshot["changed"])
        config = self.root / "config.json"
        config.write_text(json.dumps({**self.settings.raw, "project_root": str(self.root)}), encoding="utf-8")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            main(["--config", str(config), "dependency", "snapshot", "--project", str(self.project), "--manifest", manifest.name])
        self.assertEqual(json.loads(output.getvalue())["persistence"], "preview")

    def test_output_outside_configured_project_is_rejected_before_write(self):
        args = self.setup_review()
        self.settings.raw["data_dir"] = str(self.root.parent)
        with self.assertRaisesRegex(ValueError, "output_outside"):
            self.approve(args)

    def test_missing_evidence_is_not_exported_and_omission_is_explicit(self):
        args = self.setup_review()
        self.approve(args)
        (self.project / "review ñ.md").unlink()
        self.assertEqual(self.view()["reviews"][0]["effective_state"], "unverifiable_evidence")
        exported = export_openvex(self.settings, str(self.project), self.path.name, now=NOW)
        self.assertEqual(exported["documents"], [])
        self.assertEqual(exported["omitted_reviews"], {"unverifiable_evidence": 1})

    def test_same_evidence_is_hashed_once_per_view_and_authors_remain_distinct(self):
        from rabanito import dependency_memory as memory
        args = self.setup_review()
        self.approve(args)
        self.approve({**args, "reviewer": "Second Reviewer"})
        with patch.object(memory, "_evidence", wraps=memory._evidence) as evidence_reader:
            view = self.view()
        self.assertEqual(evidence_reader.call_count, 1)
        self.assertEqual(view["evidence_checks"]["cached_reference_sets"], 1)
        exported = export_openvex(self.settings, str(self.project), self.path.name, now=NOW)
        self.assertEqual({d["author"] for d in exported["documents"]}, {"Fixture Reviewer", "Second Reviewer"})

    def test_review_cap_is_explicit_and_prevents_incomplete_export(self):
        from rabanito.dependency_memory import _digest
        args = self.setup_review()
        saved = self.approve(args)
        with Database(self.settings.database_path) as db:
            for number in range(100):
                payload = {**saved["review"], "reason": "Synthetic bounded fixture " + str(number)}
                db.execute("INSERT INTO dependency_reviews VALUES (?,?,?,?,?,?,NULL)",
                           (_digest(payload), payload["project_id"], "sbom", self.path.name,
                            json.dumps(payload), NOW.isoformat()))
        view = self.view()
        self.assertTrue(view["reviews_truncated"])
        self.assertEqual(len(view["reviews"]), 100)
        self.assertEqual(view["report"]["findings"][0]["review_resolution"], "needs_review_truncated")
        with self.assertRaisesRegex(ValueError, "truncated"):
            export_openvex(self.settings, str(self.project), self.path.name, now=NOW)

    def test_revocation_does_not_need_a_still_existing_inventory(self):
        args = self.setup_review()
        saved = self.approve(args)
        self.path.unlink()
        preview = revoke_review(self.settings, str(self.project), saved["review_id"], reviewer="Reviewer", reason="Inventory removed")
        revoked = revoke_review(self.settings, str(self.project), saved["review_id"], reviewer="Reviewer", reason="Inventory removed",
                                approve_digest=preview["approval_digest"])
        self.assertTrue(revoked["changed"])

    def test_failed_additive_schema_leaves_original_database_and_no_partial_tables(self):
        from rabanito import dependency_memory as memory
        self.setup_review()
        with patch.object(memory, "SCHEMA", memory.SCHEMA + "\nTHIS IS INVALID SQL;"):
            with self.assertRaises(sqlite3.OperationalError):
                snapshot_inventory(self.settings, str(self.project), self.path.name, save=True)
        with Database(self.settings.database_path, read_only=True) as db:
            self.assertEqual(db.one("PRAGMA integrity_check")[0], "ok")
            self.assertIsNone(db.one("SELECT 1 FROM sqlite_master WHERE name='dependency_migrations'"))
            self.assertEqual(db.one("SELECT count(*) n FROM projects")["n"], 1)

    def test_cli_review_requires_exact_preview_and_preserves_original_finding(self):
        args = self.setup_review()
        config = self.root / "config.json"
        config.write_text(json.dumps({**self.settings.raw, "project_root": str(self.root)}), encoding="utf-8")
        command = ["--config", str(config), "dependency", "review", "--project", str(self.project), "--sbom", self.path.name]
        for key in ("advisory", "component_pointer", "status", "reviewer", "reason", "expires", "justification", "impact"):
            command.extend(["--" + key.replace("_", "-"), args[key]])
        command.extend(["--evidence", args["evidence"][0]])
        preview_out, save_out = io.StringIO(), io.StringIO()
        with patch("rabanito.dependency_memory._today", return_value=NOW.date()):
            with contextlib.redirect_stdout(preview_out):
                main(command)
            preview = json.loads(preview_out.getvalue())
            self.assertEqual(preview["persistence"], "preview")
            with contextlib.redirect_stdout(save_out):
                main([*command, "--approve-digest", preview["approval_digest"]])
        self.assertTrue(json.loads(save_out.getvalue())["created"])
        self.assertEqual(self.view()["report"]["findings"][0]["assessment"], "potentially_affected")
