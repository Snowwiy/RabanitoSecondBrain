"""Offline, bounded queries against published ATT&CK collection memberships."""
from __future__ import annotations

import json
import re
from contextlib import contextmanager

from .attack import META, TYPES, _id
from .attack_capture import DOMAINS, VERSION, SHA256
from .attack_store import schema
from .db import Database


def _budget(value, maximum, minimum=1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("invalid_attack_query_budget")
    return value


def _scope(domain, release=None, kind=None):
    if not isinstance(domain, str) or domain not in DOMAINS:
        raise ValueError("invalid_attack_query_domain")
    if release is not None and (not isinstance(release, str) or not (VERSION.fullmatch(release) or SHA256.fullmatch(release))):
        raise ValueError("invalid_attack_query_release")
    if kind is not None and (not isinstance(kind, str) or kind not in TYPES - META):
        raise ValueError("invalid_attack_query_kind")


@contextmanager
def _database(settings):
    if not settings.database_path.is_file():
        yield None
        return
    with Database(settings.database_path, read_only=True) as db:
        yield db if schema(db) else None


def _release(db, domain, release):
    if release is None:
        return db.one("SELECT r.* FROM attack_heads h JOIN attack_releases r ON r.release_id=h.release_id WHERE h.domain=?", (domain,))
    return db.one("SELECT * FROM attack_releases WHERE domain=? AND (version=? OR release_id=?) ORDER BY rowid DESC LIMIT 1",
                  (domain, release, release))


def _provenance(release):
    meta = json.loads(release["data_json"])
    return {"release_id": release["release_id"], "release": release["version"], "domain": release["domain"],
            "citation": meta["source_url"], "source_commit": release["source_commit"], "source_sha256": release["body_sha256"],
            "captured_at": release["captured_at"], "published_at": release["published_at"],
            "collection_modified": release["collection_modified"], "license_url": meta["license_url"],
            "license_sha256": meta["license_sha256"]}


def _record(row, release):
    return {**json.loads(row["data_json"]), **_provenance(release), "locator": row["locator"],
            "revision_id": row["revision_id"], "present_in_selected_release": True, "untrusted_data": True}


def search_attack(settings, query="", *, domain="enterprise-attack", release=None, kind=None,
                  include_inactive=False, limit=20, offset=0) -> dict:
    _scope(domain, release, kind)
    _budget(limit, 100)
    _budget(offset, 100000, 0)
    if not isinstance(query, str) or len(query) > 500 or type(include_inactive) is not bool:
        raise ValueError("invalid_attack_search_query")
    tokens = re.findall(r"[\w.-]+", query, re.UNICODE)[:30]
    if query.strip() and not tokens:
        raise ValueError("attack_query_requires_search_terms")
    result = {"results": [], "total": 0, "limit": limit, "offset": offset, "truncated": False,
              "requests": 0, "retrieval": "sqlite_fts", "domain": domain}
    with _database(settings) as db:
        selected = _release(db, domain, release) if db else None
        if selected is None:
            return result
        conditions, params = ["m.release_id=?"], [selected["release_id"]]
        # Ordinary search is for knowledge objects, not procedure descriptions.
        if kind:
            conditions.append("r.kind=?")
            params.append(kind)
        else:
            conditions.append("r.kind!='relationship'")
        if not include_inactive:
            conditions.extend(["r.revoked=0", "r.deprecated=0"])
        join = " FROM attack_members m JOIN attack_revisions r ON r.revision_id=m.revision_id"
        if tokens:
            join += " JOIN attack_fts f ON f.revision_id=r.revision_id"
            conditions.append("attack_fts MATCH ?")
            params.append(" AND ".join('"'+t+'"' for t in tokens))
        where = " WHERE " + " AND ".join(conditions)
        total = db.one("SELECT count(*)" + join + where, params)[0]
        order = ("CASE WHEN r.stix_id=? OR EXISTS(SELECT 1 FROM json_each(r.data_json,'$.attack_ids') WHERE value=? COLLATE NOCASE) "
                 "THEN 0 ELSE 1 END,bm25(attack_fts),") if tokens else ""
        order_params = [query.strip(), query.strip()] if tokens else []
        rows = db.query("SELECT r.data_json,r.revision_id,m.locator" + join + where + " ORDER BY " + order +
                        "r.stix_id LIMIT ? OFFSET ?", [*params, *order_params, limit, offset])
        return {**result, "results": [_record(r, selected) for r in rows], "total": total,
                "truncated": offset+len(rows) < total, "selected_release": _provenance(selected)}


def get_attack_object(settings, identifier, *, domain="enterprise-attack", release=None, kind=None) -> dict:
    _scope(domain, release, kind)
    if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}", identifier):
        raise ValueError("invalid_attack_lookup_identifier")
    if "--" in identifier:
        _id(identifier)
    result = {"matches": [], "ambiguous": False, "total": 0, "requests": 0}
    with _database(settings) as db:
        selected = _release(db, domain, release) if db else None
        if selected is None:
            return result
        params = [selected["release_id"], identifier, identifier]
        where = "m.release_id=? AND (r.stix_id=? OR EXISTS(SELECT 1 FROM json_each(r.data_json,'$.attack_ids') WHERE value=?))"
        if kind is not None:
            where += " AND r.kind=?"
            params.append(kind)
        join = " FROM attack_members m JOIN attack_revisions r ON r.revision_id=m.revision_id WHERE " + where
        total = db.one("SELECT count(*)" + join, params)[0]
        rows = db.query("SELECT r.data_json,r.revision_id,m.locator"+join+" ORDER BY r.kind,r.stix_id LIMIT 20", params)
        return {**result, "matches": [_record(r, selected) for r in rows], "total": total, "ambiguous": total>1,
                "truncated": total>20, "selected_release": _provenance(selected)}


def attack_context(settings, query, *, max_chars=6000, limit=5, **filters) -> dict:
    _budget(max_chars, 12000)
    _budget(limit, 50)
    if not isinstance(query, str) or not query.strip():
        raise ValueError("attack_context_requires_query")
    matches = search_attack(settings, query, limit=limit, **filters)
    fragments, used = [], 0
    for item in matches["results"]:
        if used >= max_chars:
            break
        text = item["description"] or item.get("name", item.get("relationship_type", ""))
        excerpt = text[:max_chars-used]
        used += len(excerpt)
        fragments.append({k: v for k, v in item.items() if k not in {"description", "aliases", "platforms", "domains"}} |
                         {"text": excerpt, "text_truncated": len(excerpt)<len(text)})
    return {"fragments": fragments, "total_matches": matches["total"], "used_chars": used, "max_chars": max_chars,
            "truncated": len(fragments)<matches["total"], "requests": 0, "retrieval": "sqlite_fts",
            "selected_release": matches.get("selected_release"), "untrusted_data": True}


def attack_relations(settings, identifier, *, domain="enterprise-attack", release=None, direction="both",
                     include_inactive=False, limit=20, offset=0) -> dict:
    _scope(domain, release)
    _id(identifier)
    _budget(limit, 100)
    _budget(offset, 100000, 0)
    if direction not in ("both", "outgoing", "incoming") or type(include_inactive) is not bool:
        raise ValueError("invalid_attack_relation_filter")
    result = {"relations": [], "total": 0, "limit": limit, "offset": offset, "truncated": False, "requests": 0}
    with _database(settings) as db:
        selected = _release(db, domain, release) if db else None
        if selected is None:
            return result
        where, params = ["m.release_id=?", "r.kind='relationship'"], [selected["release_id"]]
        if direction == "both":
            where.append("(r.source_ref=? OR r.target_ref=?)")
            params += [identifier, identifier]
        else:
            where.append("r." + ("source_ref" if direction == "outgoing" else "target_ref") + "=?")
            params.append(identifier)
        join = (" FROM attack_members m JOIN attack_revisions r ON r.revision_id=m.revision_id "
                "JOIN attack_members sm ON sm.release_id=m.release_id AND sm.stix_id=r.source_ref "
                "JOIN attack_revisions sr ON sr.revision_id=sm.revision_id "
                "JOIN attack_members tm ON tm.release_id=m.release_id AND tm.stix_id=r.target_ref "
                "JOIN attack_revisions tr ON tr.revision_id=tm.revision_id")
        if not include_inactive:
            where += [f"{p}.{flag}=0" for p in ("r", "sr", "tr") for flag in ("revoked", "deprecated")]
        clause = " WHERE " + " AND ".join(where)
        total = db.one("SELECT count(*)"+join+clause, params)[0]
        rows = db.query("SELECT r.data_json,r.revision_id,m.locator,sr.title AS source_title,tr.title AS target_title,"
                        "sr.revoked AS source_revoked,sr.deprecated AS source_deprecated,tr.revoked AS target_revoked,"
                        "tr.deprecated AS target_deprecated"+join+clause+" ORDER BY r.stix_id LIMIT ? OFFSET ?", [*params, limit, offset])
        relations = []
        for row in rows:
            item = _record(row, selected)
            item["source"] = {"id": item["source_ref"], "title": row["source_title"], "revoked": bool(row["source_revoked"]), "deprecated": bool(row["source_deprecated"])}
            item["target"] = {"id": item["target_ref"], "title": row["target_title"], "revoked": bool(row["target_revoked"]), "deprecated": bool(row["target_deprecated"])}
            relations.append(item)
        return {**result, "relations": relations, "total": total, "truncated": offset+len(rows)<total,
                "selected_release": _provenance(selected)}


def attack_history(settings, identifier, *, domain="enterprise-attack", limit=20, before=None) -> dict:
    _scope(domain)
    _id(identifier)
    _budget(limit, 50)
    if before is not None:
        _budget(before, 2**63-1)
    result = {"revisions": [], "total": 0, "next_before": None, "requests": 0,
              "scope": "locally_observed_changes_not_publisher_history"}
    with _database(settings) as db:
        if db is None:
            return result
        where, params = "domain=? AND stix_id=?", [domain, identifier]
        total = db.one("SELECT count(*) FROM attack_revisions WHERE "+where, params)[0]
        if before is not None:
            where += " AND revision_id<?"
            params.append(before)
        rows = db.query("SELECT revision_id,event,fingerprint,modified,revoked,deprecated,present,release_id,"
                        "citation_release_id,locator,observed_at FROM attack_revisions WHERE "+where+
                        " ORDER BY revision_id DESC LIMIT ?", [*params, limit+1])
        revisions = []
        for row in rows[:limit]:
            cite = db.one("SELECT * FROM attack_releases WHERE release_id=?", (row["citation_release_id"],))
            observed = db.one("SELECT * FROM attack_releases WHERE release_id=?", (row["release_id"],))
            revisions.append({**dict(row), "citation": _provenance(cite), "revoked": bool(row["revoked"]),
                              "deprecated": bool(row["deprecated"]), "present": bool(row["present"]),
                              "observed_in_release": _provenance(observed)})
        return {**result, "revisions": revisions, "total": total,
                "next_before": rows[limit-1]["revision_id"] if len(rows)>limit else None}


def attack_status(settings, *, domain="enterprise-attack") -> dict:
    _scope(domain)
    result = {"domain": domain, "head": None, "releases": 0, "present_objects": 0, "present_relationships": 0,
              "retired": 0, "revisions": 0, "requests": 0}
    with _database(settings) as db:
        if db is None:
            return result
        head = _release(db, domain, None)
        result["head"] = _provenance(head) if head else None
        result["releases"] = db.one("SELECT count(*) FROM attack_releases WHERE domain=?", (domain,))[0]
        result["revisions"] = db.one("SELECT count(*) FROM attack_revisions WHERE domain=?", (domain,))[0]
        for row in db.query("SELECT c.present,r.kind,count(*) AS n FROM attack_records c JOIN attack_revisions r "
                            "ON r.revision_id=c.revision_id WHERE c.domain=? GROUP BY c.present,r.kind", (domain,)):
            key = "retired" if not row["present"] else "present_relationships" if row["kind"]=="relationship" else "present_objects"
            result[key] += row["n"]
        return result
