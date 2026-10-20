"""Local inventory snapshots and explicitly reviewed VEX claims, never suppression.

The reviewer's identity/claim is recorded, not authenticated or independently
proven. Imported documents cannot approve a claim. No network or package tools.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import quote

from .config import Settings
from .db import Database
from .dependencies import ECOSYSTEMS, _authorized_file, inspect_inventory, package_key
from .indexer import _index_lock
from .utils import contains_reparse_component, iso_now, path_key, redact_sensitive_lines, safe_relative


SCHEMA_VERSION = 1
SCHEMA = """
CREATE TABLE dependency_migrations(version INTEGER PRIMARY KEY,checksum TEXT NOT NULL,applied_at TEXT NOT NULL);
CREATE TABLE dependency_analyses(analysis_id TEXT PRIMARY KEY,project_id INTEGER NOT NULL REFERENCES projects(project_id),
 inventory_kind TEXT NOT NULL,relative_path TEXT NOT NULL,source_sha256 TEXT NOT NULL,
 report_json TEXT NOT NULL CHECK(json_valid(report_json)),created_at TEXT NOT NULL);
CREATE TABLE dependency_analysis_heads(project_id INTEGER NOT NULL REFERENCES projects(project_id),
 inventory_kind TEXT NOT NULL,relative_path TEXT NOT NULL,analysis_id TEXT NOT NULL REFERENCES dependency_analyses(analysis_id),
 PRIMARY KEY(project_id,inventory_kind,relative_path));
CREATE TABLE dependency_reviews(review_id TEXT PRIMARY KEY,project_id INTEGER NOT NULL REFERENCES projects(project_id),
 inventory_kind TEXT NOT NULL,relative_path TEXT NOT NULL,payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
 created_at TEXT NOT NULL,revoked_at TEXT);
CREATE INDEX dependency_review_scope ON dependency_reviews(project_id,inventory_kind,relative_path,created_at DESC);
CREATE TABLE dependency_review_events(event_id INTEGER PRIMARY KEY,review_id TEXT NOT NULL REFERENCES dependency_reviews(review_id),
 kind TEXT NOT NULL CHECK(kind IN ('approved','revoked')),actor TEXT NOT NULL,reason TEXT NOT NULL,created_at TEXT NOT NULL);
"""
STATUSES = {"affected", "not_affected", "fixed", "under_investigation"}
JUSTIFICATIONS = {"component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
                  "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist"}
CREDENTIAL_PATTERN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|"
                                r"(?:AKIA|ASIA)[A-Z0-9]{16}|sk-(?:proj-|ant-api\d+-)?[A-Za-z0-9_-]{24,}|"
                                r"eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,})\b")


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value: object) -> str:
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _text(value: object, *, required: bool = True, maximum: int = 2000) -> str:
    if (not isinstance(value, str) or len(value) > maximum or required and not value.strip()
            or re.search(r"[\x00-\x08\x0b-\x1f\x7f]", value)
            or CREDENTIAL_PATTERN.search(value)
            or redact_sensitive_lines(value).splitlines() != value.splitlines()):
        raise ValueError("invalid_or_sensitive_review_text")
    return value.strip()


def _today(now: datetime | None = None) -> date:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("review_clock_requires_timezone")
    return current.astimezone(timezone.utc).date()


def _project(settings: Settings, identifier: str) -> dict:
    if not isinstance(identifier, str) or not identifier.strip():
        raise ValueError("invalid_project_identifier")
    with Database(settings.database_path, read_only=True) as db:
        rows = db.query("SELECT project_id,name,root_path FROM projects WHERE status='active'")
    matches = [dict(r) for r in rows if not settings.is_project_excluded(r["root_path"])
               and safe_relative(Path(r["root_path"]), settings.projects_root) is not None
               and not contains_reparse_component(r["root_path"])
               and Path(r["root_path"]).is_dir()
               and ((Path(identifier).is_absolute() and path_key(identifier) == path_key(r["root_path"]))
                    or (not Path(identifier).is_absolute() and identifier.strip().casefold() == r["name"].casefold()))]
    if len(matches) != 1:
        raise ValueError("active_authorized_project_not_found_or_ambiguous")
    return matches[0]


def _schema(db: Database, *, create: bool = False) -> bool:
    exists = db.one("SELECT 1 FROM sqlite_master WHERE type='table' AND name='dependency_migrations'") is not None
    checksum = hashlib.sha256(SCHEMA.encode()).hexdigest()
    if exists:
        rows = db.query("SELECT version,checksum FROM dependency_migrations ORDER BY version")
        if len(rows) != 1 or rows[0]["version"] != SCHEMA_VERSION or rows[0]["checksum"] != checksum:
            raise ValueError("unsupported_dependency_migration")
        return True
    if not create:
        return False
    try:
        db.connection.executescript("BEGIN IMMEDIATE;\n" + SCHEMA)
        db.execute("INSERT INTO dependency_migrations VALUES (1,?,?)", (checksum, iso_now()))
        db.commit()
    except BaseException:
        db.connection.rollback()
        raise
    return True


def _prepare_write(settings: Settings, db: Database) -> str | None:
    if _schema(db):
        return None
    target = settings.data_dir / "backups" / ("pre-dependency-schema1-" + uuid.uuid4().hex + ".db")
    db.backup(target)
    _schema(db, create=True)
    return target.name


def _own_outputs(settings: Settings) -> None:
    for target in (settings.data_dir, settings.database_path, settings.data_dir / "backups"):
        if safe_relative(target, settings.root) in {None, ".", ""} or contains_reparse_component(target):
            raise ValueError("dependency_output_outside_project_or_unsafe")


def _evidence(settings: Settings, project: str, references: list[str]) -> list[dict]:
    if not isinstance(references, list) or not 1 <= len(references) <= 4 or any(not isinstance(v, str) for v in references):
        raise ValueError("review_requires_one_to_four_evidence_files")
    result = {}
    for reference in sorted(set(references)):
        if Path(reference).suffix.casefold() not in {".md", ".markdown", ".rst", ".txt"}:
            raise ValueError("review_evidence_requires_project_documentation")
        _, path, relative = _authorized_file(settings, project, reference, "evidence")
        _text(relative, maximum=1000)
        before = path.stat()
        if before.st_size > 256 * 1024:
            raise ValueError("review_evidence_size_limit")
        with path.open("rb") as handle:
            import os
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or contains_reparse_component(path):
                raise ValueError("review_evidence_changed_during_read")
            payload = handle.read(256 * 1024 + 1)
        after = path.stat()
        if len(payload) > 256 * 1024 or (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("review_evidence_changed_during_read")
        # Store only relative reference/hash, not contents or commands in evidence.
        result[relative] = {"relative_path": relative, "sha256": hashlib.sha256(payload).hexdigest()}
    return [result[key] for key in sorted(result)]


def snapshot_inventory(settings: Settings, project: str, relative_path: str, *, kind: str = "sbom", save: bool = False) -> dict:
    report = inspect_inventory(settings, project, relative_path, kind=kind)
    selected, _, relative = _authorized_file(settings, project, relative_path, kind)
    result = {"report": report, "persistence": "preview", "changed": False}
    if not save:
        return result
    _own_outputs(settings)
    with _index_lock(settings), Database(settings.database_path) as db:
        # Recompute under the shared lock: don't persist an inventory/OSV preview
        # that changed while waiting for another writer.
        current = inspect_inventory(settings, project, relative_path, kind=kind)
        if current["analysis_id"] != report["analysis_id"]:
            raise ValueError("analysis_changed_retry_preview")
        backup = _prepare_write(settings, db)
        encoded = _json(report)
        if len(encoded.encode()) > 4 * 1024 * 1024:
            raise ValueError("saved_analysis_size_limit")
        db.execute("BEGIN IMMEDIATE")
        existing = db.one("SELECT project_id FROM dependency_analyses WHERE analysis_id=?", (report["analysis_id"],))
        if existing is not None:
            from .dependency_cache import reuse_saved
            if reuse_saved(db, report["analysis_id"], selected, kind, relative, report["source"]["sha256"], report["engine_version"]) is None:
                raise ValueError("existing_analysis_not_reusable_review_required")
        head = db.one("SELECT analysis_id FROM dependency_analysis_heads WHERE project_id=? AND inventory_kind=? AND relative_path=?",
                      (selected["project_id"], kind, relative))
        if existing is None:
            db.execute("INSERT INTO dependency_analyses VALUES (?,?,?,?,?,?,?)",
                       (report["analysis_id"], selected["project_id"], kind, relative, report["source"]["sha256"], encoded, iso_now()))
        changed = head is None or head["analysis_id"] != report["analysis_id"]
        if changed:
            db.execute("INSERT INTO dependency_analysis_heads VALUES (?,?,?,?) ON CONFLICT(project_id,inventory_kind,relative_path) "
                       "DO UPDATE SET analysis_id=excluded.analysis_id", (selected["project_id"], kind, relative, report["analysis_id"]))
        result.update(persistence="saved", changed=changed, new_snapshot=existing is None, migration_backup=backup)
    return result


def review_inventory(settings: Settings, project: str, relative_path: str, *, advisory: str, component_pointer: str,
                     status: str, reviewer: str, reason: str, expires: str, evidence: list[str], kind: str = "sbom",
                     justification: str = "", impact: str = "", action: str = "", approve_digest: str | None = None,
                     now: datetime | None = None) -> dict:
    report = inspect_inventory(settings, project, relative_path, kind=kind)
    selected, _, relative = _authorized_file(settings, project, relative_path, kind)
    if not isinstance(status, str) or status not in STATUSES or not isinstance(expires, str):
        raise ValueError("invalid_review_status_or_expiry")
    try:
        expiry = date.fromisoformat(expires)
    except ValueError:
        raise ValueError("invalid_review_expiry") from None
    if expires != expiry.isoformat() or not 0 < (expiry - _today(now)).days <= 366:
        raise ValueError("review_expiry_must_be_future_within_366_days")
    reviewer, reason = _text(reviewer, maximum=200), _text(reason)
    if any(char in reviewer for char in "\n\t"):
        raise ValueError("reviewer_requires_single_line")
    impact, action = _text(impact, required=False), _text(action, required=False)
    if not isinstance(justification, str) or justification and (status != "not_affected" or justification not in JUSTIFICATIONS):
        raise ValueError("invalid_vex_justification")
    if status == "not_affected" and (not justification or not impact) or status == "affected" and not action:
        raise ValueError("review_requires_impact_justification_or_action")
    components = [c for c in report["components"] if c["pointer"] == component_pointer and not c["identity_issue"]]
    if len(components) != 1 or not any(f["advisory"] == advisory and f["component_pointer"] == component_pointer for f in report["findings"]):
        raise ValueError("review_requires_exact_observed_component_and_advisory")
    with Database(settings.database_path, read_only=True) as db:
        row = db.one("SELECT fingerprint FROM cyber_records WHERE source='osv' AND source_id=? AND active=1", (advisory,))
    if row is None:
        raise ValueError("review_advisory_not_available")
    component = components[0]
    payload = {"schema_version": 1, "project": selected["name"], "project_id": selected["project_id"],
               "project_scope": hashlib.sha256(path_key(selected["root_path"]).encode()).hexdigest(),
               "inventory_kind": kind, "inventory": report["source"], "analysis_id": report["analysis_id"],
               "component": {k: component[k] for k in ("ecosystem", "name", "version", "pointer")},
               "advisory": advisory, "advisory_fingerprint": row["fingerprint"], "status": status, "reviewer": reviewer,
               "reason": reason, "expires": expires, "justification": justification, "impact": impact, "action": action,
               "evidence": _evidence(settings, project, evidence), "validation": "reviewed_claim_not_independently_tested"}
    digest = _digest(payload)
    result = {"persistence": "preview", "approval_digest": digest, "review": payload,
              "policy": "human_review_required; original_OSV_findings_are_not_suppressed; unsigned_local_claim"}
    if approve_digest is None:
        return result
    if not isinstance(approve_digest, str) or approve_digest != digest:
        raise ValueError("review_approval_digest_mismatch")
    _own_outputs(settings)
    with _index_lock(settings), Database(settings.database_path) as db:
        # Rebuild the exact preview after acquiring the writer lock.
        refreshed = review_inventory(settings, project, relative_path, advisory=advisory, component_pointer=component_pointer,
            status=status, reviewer=reviewer, reason=reason, expires=expires, evidence=evidence, kind=kind,
            justification=justification, impact=impact, action=action, now=now)
        if refreshed["approval_digest"] != digest:
            raise ValueError("review_changed_retry_preview")
        backup = _prepare_write(settings, db)
        db.execute("BEGIN IMMEDIATE")
        old = db.one("SELECT revoked_at FROM dependency_reviews WHERE review_id=?", (digest,))
        if old is None:
            timestamp = iso_now()
            db.execute("INSERT INTO dependency_reviews VALUES (?,?,?,?,?,?,NULL)",
                       (digest, selected["project_id"], kind, relative, _json(payload), timestamp))
            db.execute("INSERT INTO dependency_review_events(review_id,kind,actor,reason,created_at) VALUES (?,'approved',?,?,?)",
                       (digest, reviewer, reason, timestamp))
        result.update(persistence="saved", review_id=digest, created=old is None,
                      revoked=old is not None and old["revoked_at"] is not None, migration_backup=backup)
    return result


def reviewed_inventory(settings: Settings, project: str, relative_path: str, *, kind: str = "sbom",
                       now: datetime | None = None) -> dict:
    report = inspect_inventory(settings, project, relative_path, kind=kind)
    selected, _, relative = _authorized_file(settings, project, relative_path, kind)
    with Database(settings.database_path, read_only=True) as db:
        rows = db.query("SELECT * FROM dependency_reviews WHERE project_id=? AND inventory_kind=? AND relative_path=? "
                        "ORDER BY created_at DESC,review_id LIMIT 101", (selected["project_id"], kind, relative)) if _schema(db) else []
    reviews, evidence_cache = [], {}
    evidence_bytes = 0
    evidence_budget_exhausted = False
    for row in rows[:100]:
        if len(row["payload_json"].encode()) > 32768:
            raise ValueError("invalid_stored_review")
        payload = json.loads(row["payload_json"])
        if _digest(payload) != row["review_id"]:
            raise ValueError("stored_review_checksum_mismatch")
        state = "current"
        if row["revoked_at"]:
            state = "revoked"
        elif payload["expires"] <= _today(now).isoformat():
            state = "expired"
        elif (payload["inventory"]["sha256"] != report["source"]["sha256"]
              or payload["analysis_id"] != report["analysis_id"]
              or payload["project_scope"] != hashlib.sha256(path_key(selected["root_path"]).encode()).hexdigest()):
            state = "stale_inputs"
        else:
            try:
                references = tuple(e["relative_path"] for e in payload["evidence"])
                if references not in evidence_cache:
                    # Conservative aggregate bound in addition to the per-file
                    # cap; don't rehash identical evidence for every review.
                    evidence_bytes += len(references) * 256 * 1024
                    if evidence_bytes > 16 * 1024 * 1024:
                        evidence_budget_exhausted = True
                        raise ValueError("review_evidence_budget_exhausted")
                    evidence_cache[references] = _evidence(settings, project, list(references))
                if evidence_cache[references] != payload["evidence"]:
                    state = "stale_evidence"
            except (ValueError, OSError):
                state = "unverifiable_evidence"
        reviews.append({"review_id": row["review_id"], "effective_state": state, "created_at": row["created_at"],
                        "revoked_at": row["revoked_at"], "review": payload})
    for finding in report["findings"]:
        matching = [r for r in reviews if r["review"]["component"]["pointer"] == finding["component_pointer"]
                    and r["review"]["advisory"] == finding["advisory"]]
        finding["reviews"] = [{"review_id": r["review_id"], "effective_state": r["effective_state"],
                               "status": r["review"]["status"]} for r in matching]
        current = {r["review"]["status"] for r in matching if r["effective_state"] == "current"}
        finding["review_resolution"] = "needs_review_truncated" if len(rows) > 100 else "conflicting_claims" if len(current) > 1 else "reviewed_claim" if current else "no_current_review"
    # This view decorates findings with current claims. Preserve the base
    # checksum separately, never label the modified report with its old hash.
    base_result_sha256 = report.pop("result_sha256", None)
    return {"report": report, "analysis_result_sha256": base_result_sha256, "reviews": reviews, "reviews_truncated": len(rows) > 100,
            "evidence_checks": {"max_bytes": 16 * 1024 * 1024, "budget_exhausted": evidence_budget_exhausted,
                                "cached_reference_sets": len(evidence_cache), "contents_executed": False},
            "policy": "No original finding is hidden or reclassified by VEX. Review evidence is not re-executed."}


def revoke_review(settings: Settings, project: str, review_id: str, *, reviewer: str, reason: str,
                  approve_digest: str | None = None) -> dict:
    selected = _project(settings, project)
    if not isinstance(review_id, str) or not re.fullmatch(r"[0-9a-f]{64}", review_id):
        raise ValueError("invalid_review_identifier")
    reviewer, reason = _text(reviewer, maximum=200), _text(reason)
    if any(char in reviewer for char in "\n\t"):
        raise ValueError("reviewer_requires_single_line")
    with Database(settings.database_path, read_only=True) as db:
        row = db.one("SELECT revoked_at FROM dependency_reviews WHERE review_id=? AND project_id=?", (review_id, selected["project_id"])) if _schema(db) else None
    if row is None:
        raise ValueError("review_not_found_in_authorized_project")
    draft = {"operation": "revoke", "review_id": review_id, "project_id": selected["project_id"],
             "reviewer": reviewer, "reason": reason, "already_revoked": row["revoked_at"] is not None}
    digest = _digest(draft)
    result = {"persistence": "preview", "approval_digest": digest, **draft}
    if approve_digest is None:
        return result
    if approve_digest != digest:
        raise ValueError("review_approval_digest_mismatch")
    _own_outputs(settings)
    with _index_lock(settings), Database(settings.database_path) as db:
        _schema(db)
        current = _project(settings, project)
        if current["project_id"] != selected["project_id"]:
            raise ValueError("review_scope_changed")
        db.execute("BEGIN IMMEDIATE")
        changed = db.execute("UPDATE dependency_reviews SET revoked_at=? WHERE review_id=? AND project_id=? AND revoked_at IS NULL",
                             (iso_now(), review_id, selected["project_id"])).rowcount
        if changed:
            db.execute("INSERT INTO dependency_review_events(review_id,kind,actor,reason,created_at) VALUES (?,'revoked',?,?,?)",
                       (review_id, reviewer, reason, iso_now()))
        result.update(persistence="saved", changed=bool(changed))
    return result


def export_openvex(settings: Settings, project: str, relative_path: str, *, kind: str = "sbom", now: datetime | None = None) -> dict:
    view = reviewed_inventory(settings, project, relative_path, kind=kind, now=now)
    if view["reviews_truncated"]:
        raise ValueError("cannot_export_truncated_reviews")
    current = [r for r in view["reviews"] if r["effective_state"] == "current"]
    if any(f["review_resolution"] == "conflicting_claims" for f in view["report"]["findings"]):
        raise ValueError("cannot_export_conflicting_reviews")
    # One statement/document per reviewed claim, preserving its self-declared
    # author. Never mislabel the inventory hash as a software binary hash.
    documents = []
    for record in current:
        review, rid = record["review"], record["review_id"]
        component = review["component"]
        package = package_key(component["ecosystem"], component["name"])
        reverse = {value: key for key, value in ECOSYSTEMS.items()}
        package_name = package[1].replace(":", "/") if component["ecosystem"] == "Maven" else package[1]
        purl = "pkg:" + reverse[component["ecosystem"]] + "/" + quote(package_name, safe="/") + "@" + quote(component["version"], safe="")
        statement = {"vulnerability": {"name": review["advisory"]},
                     "products": [{"@id": "urn:rabanito:inventory-scope:" + _digest([review["project_scope"], review["inventory"]]),
                                   "subcomponents": [{"@id": purl}]}], "status": review["status"],
                     "status_notes": "Inventory-scoped unsigned reviewer claim, not installed-state proof. Local expiry: " + review["expires"] + ". " + review["reason"]}
        if review["status"] == "not_affected":
            statement.update(justification=review["justification"], impact_statement=review["impact"])
        if review["status"] == "affected":
            statement["action_statement"] = review["action"]
        documents.append({"@context": "https://openvex.dev/ns/v0.2.0", "@id": "urn:rabanito:review:" + rid,
                          "author": review["reviewer"], "timestamp": record["created_at"], "version": 1,
                          "tooling": "Rabanito Second Brain local reviewed claims", "statements": [statement]})
    omitted = {}
    for record in view["reviews"]:
        if record["effective_state"] != "current":
            state = record["effective_state"]
            omitted[state] = omitted.get(state, 0) + 1
    return {"documents": documents, "count": len(documents), "remote_requests": 0, "omitted_reviews": omitted,
            "scope": "OpenVEX 0.2.0 structural export; no signature, external trust validation or remote JSON-LD resolution"}
