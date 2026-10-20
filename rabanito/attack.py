"""Bounded read-only projection of official STIX 2.1 release captures.

This is a deliberately selected reader, not a complete ADM/STIX validator,
threat detector, vulnerability feed, TAXII service or compliance assessment.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections import Counter
from datetime import datetime

from .attack_capture import DOMAINS, MAX_BYTES, VERSION, read_capture
from .cyber.model import InvalidFeed
from .cyber.transport import _unique_object


TYPES = frozenset({"attack-pattern", "campaign", "course-of-action", "intrusion-set", "malware", "tool",
    "x-mitre-matrix", "x-mitre-tactic", "x-mitre-analytic", "x-mitre-data-component", "x-mitre-data-source",
    "x-mitre-detection-strategy", "x-mitre-asset", "relationship", "identity", "marking-definition", "x-mitre-collection"})
META = frozenset({"identity", "marking-definition", "x-mitre-collection"})
STIX_ID = re.compile(r"([a-z][a-z0-9-]{0,63})--[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z\Z")
COLLECTION_NAMES = {"enterprise-attack": "Enterprise ATT&CK", "mobile-attack": "Mobile ATT&CK", "ics-attack": "ICS ATT&CK"}


def _text(value, cap=65536, *, empty=True):
    if (not isinstance(value, str) or len(value) > cap or "\0" in value or not empty and not value.strip()
            or any(0xD800 <= ord(c) <= 0xDFFF for c in value)):
        raise InvalidFeed("invalid_attack_text")
    return value


def _stamp(value):
    if not isinstance(value, str) or not STAMP.fullmatch(value):
        raise InvalidFeed("invalid_attack_timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise InvalidFeed("invalid_attack_timestamp") from None


def _id(value, kind=None):
    if not isinstance(value, str) or not (match := STIX_ID.fullmatch(value)) or kind and match[1] != kind:
        raise InvalidFeed("invalid_attack_stix_id")
    return value


def _strings(value, cap=500, length=256):
    if not isinstance(value, list) or len(value) > cap:
        raise InvalidFeed("invalid_attack_string_array")
    return [_text(x, length, empty=False) for x in value]


def _finite(value):
    number = float(value)
    if not math.isfinite(number):
        raise InvalidFeed("nonfinite_attack_json")
    return number


def _tree(value):
    # Limits include ignored fields; unknown payload cannot evade the budget.
    pending, visited = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if visited > 2000000 or depth > 64:
            raise InvalidFeed("attack_json_complexity_limit")
        if isinstance(item, dict):
            for key in item:
                _text(key, 512, empty=False)
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
        elif isinstance(item, str):
            _text(item, 2 * 1024 * 1024)


def normalize_bundle(raw: bytes, domain: str, version: str, *, max_objects=100000) -> dict:
    """Validate the entire bundle before returning any provisional records.

    Memory includes the raw bundle and its decoded Python tree (not a hard RAM
    cap). All source relationships retain their IDs and direction; no inferred
    technique/tactic, project, CVE, transitive or applicability edges are made.
    """
    if (domain not in DOMAINS or not isinstance(version, str) or not VERSION.fullmatch(version)
            or type(max_objects) is not int or not 1 <= max_objects <= 100000):
        raise ValueError("invalid_attack_normalization_scope")
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_BYTES:
        raise InvalidFeed("attack_bundle_byte_limit")
    try:
        bundle = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object, parse_float=_finite,
                            parse_constant=lambda _: (_ for _ in ()).throw(InvalidFeed("nonfinite_attack_json")))
    except InvalidFeed:
        raise
    except (UnicodeError, RecursionError, ValueError):
        raise InvalidFeed("invalid_attack_json") from None
    _tree(bundle)
    if (not isinstance(bundle, dict) or set(bundle) != {"type", "id", "objects"} or bundle["type"] != "bundle"
            or not isinstance(bundle["objects"], list) or not 1 <= len(bundle["objects"]) <= max_objects):
        raise InvalidFeed("invalid_attack_bundle")
    _id(bundle["id"], "bundle")
    objects, pointers, duplicates = {}, {}, 0
    for ordinal, item in enumerate(bundle["objects"]):
        if (not isinstance(item, dict) or not isinstance(item.get("type"), str)
                or item["type"] not in TYPES or item.get("spec_version") != "2.1"):
            raise InvalidFeed("unsupported_attack_object_or_spec")
        identity = _id(item.get("id"), item["type"])
        if identity in objects:
            if item != objects[identity]:
                raise InvalidFeed("conflicting_attack_object_versions")
            duplicates += 1
            continue
        objects[identity], pointers[identity] = item, f"/objects/{ordinal}"
        created = _stamp(item.get("created"))
        if item["type"] != "marking-definition" and _stamp(item.get("modified")) < created:
            raise InvalidFeed("attack_object_chronology")
        for field in ("revoked", "x_mitre_deprecated", "x_mitre_is_subtechnique"):
            if field in item and type(item[field]) is not bool:
                raise InvalidFeed("invalid_attack_boolean")
        domains = _strings(item.get("x_mitre_domains", []), 3, 32)
        if (item["type"] not in META | {"relationship"} and not domains
                or domains and (domain not in domains or not set(domains) <= set(DOMAINS))):
            raise InvalidFeed("attack_object_domain_mismatch")
    collections = [x for x in objects.values() if x["type"] == "x-mitre-collection"]
    if len(collections) != 1:
        raise InvalidFeed("attack_collection_required")
    collection = collections[0]
    if collection.get("x_mitre_version") != version or collection.get("name") != COLLECTION_NAMES[domain]:
        raise InvalidFeed("attack_collection_scope_mismatch")
    contents = collection.get("x_mitre_contents")
    if not isinstance(contents, list) or not 1 <= len(contents) <= max_objects:
        raise InvalidFeed("invalid_attack_collection_contents")
    members = set()
    for member in contents:
        if not isinstance(member, dict) or set(member) != {"object_ref", "object_modified"}:
            raise InvalidFeed("invalid_attack_collection_member")
        identity = _id(member["object_ref"])
        _stamp(member["object_modified"])
        if identity in members or identity not in objects or member["object_modified"] != objects[identity].get("modified"):
            raise InvalidFeed("attack_collection_member_mismatch")
        members.add(identity)
    expected = {x["id"] for x in objects.values() if x["type"] not in {"x-mitre-collection", "marking-definition"}}
    if members != expected:
        raise InvalidFeed("attack_collection_incomplete")
    records, relationships = [], []
    for identity, item in objects.items():
        kind = item["type"]
        for marking in _strings(item.get("object_marking_refs", []), 20, 128):
            if objects.get(marking, {}).get("type") != "marking-definition":
                raise InvalidFeed("attack_unresolved_marking")
        for field in ("created_by_ref", "x_mitre_modified_by_ref"):
            if field in item and objects.get(_id(item[field], "identity"), {}).get("type") != "identity":
                raise InvalidFeed("attack_unresolved_identity")
        if kind in META:
            continue
        record = {"id": identity, "type": kind, "created": item["created"], "modified": item["modified"],
                  "revoked": item.get("revoked", False), "deprecated": item.get("x_mitre_deprecated", False),
                  "description": _text(item.get("description", "")),
                  "object_version": _text(item.get("x_mitre_version", ""), 40),
                  "attack_spec_version": _text(item.get("x_mitre_attack_spec_version", ""), 40)}
        if kind == "relationship":
            source, target = _id(item.get("source_ref")), _id(item.get("target_ref"))
            if (source not in expected or target not in expected
                    or objects[source]["type"] in META | {"relationship"} or objects[target]["type"] in META | {"relationship"}):
                raise InvalidFeed("attack_unresolved_relationship")
            relation = _text(item.get("relationship_type"), 80, empty=False)
            if not re.fullmatch(r"[a-z][a-z-]{0,79}", relation):
                raise InvalidFeed("invalid_attack_relationship_type")
            record.update(source_ref=source, target_ref=target, relationship_type=relation, validation="source_documented")
            relationships.append(record)
        else:
            references = item.get("external_references", [])
            if not isinstance(references, list) or len(references) > 100:
                raise InvalidFeed("invalid_attack_references")
            ids = []
            for ref in references:
                if not isinstance(ref, dict):
                    raise InvalidFeed("invalid_attack_reference")
                if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
                    value = _text(ref["external_id"], 80, empty=False)
                    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", value):
                        raise InvalidFeed("invalid_attack_external_id")
                    ids.append(value)
            record.update(name=_text(item.get("name"), 512, empty=False), attack_ids=sorted(set(ids)),
                          domains=_strings(item.get("x_mitre_domains", []), 3, 32),
                          platforms=_strings(item.get("x_mitre_platforms", []), 100, 128),
                          aliases=_strings(item.get("aliases", []), 500, 512),
                          is_subtechnique=item.get("x_mitre_is_subtechnique", False))
            records.append(record)
        # Order/pointer is provenance, not identity or content fingerprint.
        record["fingerprint"] = hashlib.sha256(json.dumps(item, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
        record["locator"] = pointers[identity]
    return {"domain": domain, "version": version, "bundle_id": bundle["id"], "collection_id": collection["id"],
            "collection_modified": collection["modified"], "objects": records, "relationships": relationships,
            "coverage": {"raw_objects": len(bundle["objects"]), "unique_objects": len(objects),
                         "duplicate_objects": duplicates, "types": dict(Counter(x["type"] for x in objects.values())),
                         "semantic_objects": len(records), "source_relationships": len(relationships),
                         "scope": "one_complete_release_domain", "full_adm_validation": False,
                         "custom_property_edges_project_applicability_and_transitive_edges": "not_derived"}}


def inspect_capture(settings, manifest_name: str) -> dict:
    raw, meta = read_capture(settings, manifest_name)
    data = normalize_bundle(raw, meta["domain"], meta["version"])
    return {k: v for k, v in data.items() if k not in {"objects", "relationships"}} | {
        "manifest": manifest_name, "source_url": meta["source_url"], "commit": meta["commit"],
        "sha256": meta["sha256"], "captured_at": meta["captured_at"], "license_sha256": meta["license_sha256"],
        "requests": 0, "database_written": False}


def _fold(text):
    return "".join(c for c in unicodedata.normalize("NFKD", text.casefold()) if not unicodedata.combining(c))


def capture_context(settings, manifest_name: str, query: str, *, kind=None, include_inactive=False, limit=5, max_chars=6000) -> dict:
    """Offline bounded excerpts; scans one capture, not a persistent FTS index."""
    if (not isinstance(query, str) or not query.strip() or len(query) > 500
            or kind is not None and (not isinstance(kind, str) or kind not in TYPES - META - {"relationship"})
            or type(include_inactive) is not bool or type(limit) is not int or not 1 <= limit <= 50
            or type(max_chars) is not int or not 1 <= max_chars <= 12000):
        raise ValueError("invalid_attack_context_query")
    raw, meta = read_capture(settings, manifest_name)
    data = normalize_bundle(raw, meta["domain"], meta["version"])
    tokens = _fold(query).split()
    matches = []
    for item in data["objects"]:
        if (kind and item["type"] != kind or not include_inactive and (item["revoked"] or item["deprecated"])):
            continue
        haystack = _fold(" ".join([item["name"], *item["attack_ids"], *item["aliases"], item["description"]]))
        if all(token in haystack for token in tokens):
            score = 100 if query.upper() in item["attack_ids"] else 0
            score += sum(5 for token in tokens if token in _fold(item["name"]))
            matches.append((-score, item["id"], item))
    matches.sort(key=lambda m: (m[0], m[1]))
    fragments, used = [], 0
    for _, _, item in matches[:limit]:
        if used >= max_chars:
            break
        passage = item["description"] or item["name"]
        start = min((p for token in tokens if (p := _fold(passage).find(token)) >= 0), default=0)
        # Offsets in normalized text are not source line/byte offsets. Start at
        # zero for non-ASCII to avoid inventing an exact Unicode offset.
        start = max(0, start - 80) if passage.isascii() else 0
        excerpt = passage[start:start + max_chars - used]
        used += len(excerpt)
        fragments.append({k: item[k] for k in ("id", "type", "name", "attack_ids", "modified", "object_version", "revoked", "deprecated", "locator")} | {
            "text": excerpt, "citation": meta["source_url"], "source_commit": meta["commit"], "source_sha256": meta["sha256"],
            "release": meta["version"], "domain": meta["domain"], "captured_at": meta["captured_at"],
            "text_truncated": start > 0 or len(excerpt) < len(passage)})
    return {"total_matches": len(matches), "fragments": fragments, "used_chars": used, "max_chars": max_chars,
            "truncated": len(fragments) < len(matches), "requests": 0, "database_written": False,
            "retrieval": "offline_capture_scan_not_sqlite_fts", "license": meta["license"],
            "license_sha256": meta["license_sha256"], "untrusted_data": True}
