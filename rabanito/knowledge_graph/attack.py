"""Published ATT&CK head objects/SROs, never inferred project applicability."""
from __future__ import annotations

import json

from ..attack import COLLECTION_NAMES, _id
from ..attack_capture import DOMAINS, SHA256, release_url
from .store import encode


KINDS = {
    "attack-pattern": "attack_technique", "campaign": "attack_campaign", "course-of-action": "attack_mitigation",
    "intrusion-set": "threat_group", "malware": "attack_software", "tool": "attack_software",
    "x-mitre-matrix": "attack_matrix", "x-mitre-tactic": "attack_tactic", "x-mitre-analytic": "attack_analytic",
    "x-mitre-data-component": "attack_data_component", "x-mitre-data-source": "attack_data_source",
    "x-mitre-detection-strategy": "attack_detection_strategy", "x-mitre-asset": "attack_asset",
}


def node_id(domain, identity):
    if domain not in DOMAINS:
        raise ValueError("invalid_graph_attack_domain")
    return "attack:" + domain + ":" + _id(identity)


def load_attack(db, item):
    if item["family"] == "attack-collection":
        params = (item["native"],)
        sql = ("SELECT a.* FROM attack_heads h JOIN attack_releases a ON a.release_id=h.release_id AND a.domain=h.domain "
               "WHERE h.domain=?")
    else:
        params = tuple(json.loads(item["native"]))
        sql = ("SELECT m.stix_id,m.locator,r.data_json AS object_json,r.kind,r.fingerprint,a.domain,a.version,"
               "a.collection_modified,a.source_commit,a.body_sha256,a.captured_at,a.published_at,a.release_id,a.data_json "
               "FROM attack_heads h JOIN attack_releases a ON a.release_id=h.release_id AND a.domain=h.domain "
               "JOIN attack_members m ON m.release_id=h.release_id AND m.domain=h.domain "
               "JOIN attack_revisions r ON r.revision_id=m.revision_id AND r.domain=m.domain AND r.stix_id=m.stix_id AND r.present=1 "
               "WHERE h.domain=? AND m.stix_id=?")
    raw = db.one(sql, params)
    if raw is None:
        raise ValueError("graph_attack_source_disappeared")
    row = dict(raw)
    row.pop("license_text", None)  # Stored for redistribution, not repeated in every graph response.
    if item["family"] == "attack-relation":
        data = json.loads(row["object_json"])
        endpoints = []
        for identity in (data["source_ref"], data["target_ref"]):
            endpoint = db.one("SELECT r.revoked,r.deprecated,r.kind FROM attack_members m JOIN attack_revisions r "
                "ON r.revision_id=m.revision_id AND r.domain=m.domain AND r.stix_id=m.stix_id AND r.present=1 "
                "WHERE m.release_id=? AND m.domain=? AND m.stix_id=?", (row["release_id"], row["domain"], identity))
            if endpoint is None or endpoint["kind"] not in KINDS:
                raise ValueError("graph_attack_endpoint_unavailable")
            endpoints.append({"id": identity, "revoked": bool(endpoint["revoked"]), "deprecated": bool(endpoint["deprecated"])})
        row["endpoints"] = endpoints
    if len(encode(row).encode()) > 8 * 1024 * 1024:
        raise ValueError("graph_attack_source_size_limit")
    return row


def build_attack(out, item, row):
    meta = json.loads(row["data_json"])
    domain = row["domain"]
    if (domain not in DOMAINS or meta.get("domain") != domain or meta.get("release_id") != row["release_id"]
            or meta.get("commit") != row["source_commit"] or meta.get("sha256") != row["body_sha256"]
            or not SHA256.fullmatch(row["body_sha256"])
            or meta.get("source_url") != release_url(domain, row["version"], row["source_commit"])):
        raise ValueError("invalid_graph_attack_provenance")
    citation = meta["source_url"]
    provenance = {"domain": domain, "release": row["version"], "release_id": row["release_id"],
                  "source_commit": row["source_commit"], "source_sha256": row["body_sha256"],
                  "captured_at": row["captured_at"], "published_at": row["published_at"],
                  "collection_modified": row["collection_modified"], "license_url": meta["license_url"],
                  "license_sha256": meta["license_sha256"], "scope": "public_knowledge_not_observed_local_attack"}
    collection = "attack:" + domain + ":collection"
    if item["family"] == "attack-collection":
        out.node(collection, "attack_collection", COLLECTION_NAMES[domain] + " " + row["version"], citation, public=True,
                 category=domain, updated=row["collection_modified"], data={**provenance, "stix_id": meta["collection_id"],
                 "locator": "STIX ID " + meta["collection_id"], "revoked": False, "deprecated": False})
        return
    data = json.loads(row["object_json"])
    if (data.get("id") != row["stix_id"] or data.get("type") != row["kind"] or data.get("fingerprint") != row["fingerprint"]
            or type(data.get("revoked")) is not bool or type(data.get("deprecated")) is not bool):
        raise ValueError("invalid_graph_attack_object_identity")
    payload = {**provenance, "stix_id": data["id"], "stix_type": data["type"], "locator": row["locator"],
               "revoked": data["revoked"], "deprecated": data["deprecated"], "modified": data["modified"],
               "object_version": data["object_version"], "present_in_head_collection": True}
    if item["family"] == "attack-object":
        ids = data.get("attack_ids", [])
        if not isinstance(ids, list) or len(ids) > 100 or any(not isinstance(v, str) or len(v)>80 for v in ids):
            raise ValueError("invalid_graph_attack_external_ids")
        label = ", ".join(ids) + " · " + data["name"] if ids else data["name"]
        identity = node_id(domain, data["id"])
        out.node(identity, KINDS[data["type"]], label, citation, public=True, category=domain, updated=data["modified"],
                 data={**payload, "attack_ids": ids, "is_subtechnique": data.get("is_subtechnique", False),
                       "date_basis": "stix_modified"})
        out.edge(identity, collection, "member_of_attack_collection", citation, data=payload,
                 identity=["attack-membership", domain, data["id"]])
    else:
        source, target = row["endpoints"]
        out.edge(node_id(domain, source["id"]), node_id(domain, target["id"]), data["relationship_type"], citation,
                 data={**payload, "source_state": source, "target_state": target},
                 identity=["attack-sro", domain, data["id"]])
