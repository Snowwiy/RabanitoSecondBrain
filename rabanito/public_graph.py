"""Bounded, typed public subgraphs adapted to the existing document renderer."""
from __future__ import annotations

import hashlib
import json

from .config import Settings
from .cyber.model import public_url
from .cyber.store import search_vulnerabilities
from .security import search_security
from .db import Database


def public_graph(settings: Settings, domain: str, *, limit: int = 250, query: str = "",
                 source: str | None = None, min_degree: int = 0) -> dict:
    if domain not in {"cyber", "security"}:
        raise ValueError("Unknown public graph domain")
    limit, min_degree = min(max(int(limit), 0), 1000), min(max(int(min_degree), 0), 1000)
    roots_limit = (min(max(1, limit // 2), 100) if domain == "cyber" else min(limit, 100)) if limit else 0
    found = (search_vulnerabilities(settings, query, source=source, limit=roots_limit)
             if domain == "cyber" else search_security(settings, query, limit=roots_limit)) if limit else {"results": [], "total": 0}
    nodes, identities, edges, edge_keys = {}, {}, [], set()
    relation_truncated = False
    records, security_targets, security_relations = {}, {}, {}
    requested_ids = [item["id"] for item in found["results"]]
    if requested_ids:
        placeholders = ",".join("?" for _ in requested_ids)
        with Database(settings.database_path, read_only=True) as db:
            if domain == "cyber":
                records = {row["vulnerability_id"]: json.loads(row["data_json"]) for row in db.query(
                    f"SELECT vulnerability_id,data_json FROM cyber_entities WHERE vulnerability_id IN ({placeholders})", requested_ids)}
            else:
                relations = db.query(f"SELECT * FROM security_relations WHERE source_id IN ({placeholders}) "
                                     "ORDER BY source_id,target_id,relation_type LIMIT 5001", requested_ids)
                relation_truncated = len(relations) > 5000
                for relation in relations[:5000]:
                    security_relations.setdefault(relation["source_id"], []).append(dict(relation))
                target_ids = sorted({r["target_id"] for r in relations[:5000]})
                if target_ids:
                    target_slots = ",".join("?" for _ in target_ids)
                    security_targets = {row["entry_id"]: json.loads(row["data_json"]) for row in db.query(
                        f"SELECT entry_id,data_json FROM security_entries WHERE active=1 AND entry_id IN ({target_slots})", target_ids)}

    def add_node(key: str, title: str, kind: str, *, reference: str | None = None, summary: str = "", modified=None):
        nonlocal relation_truncated
        node_id = -int(hashlib.sha256(key.encode()).hexdigest()[:12], 16) - 1
        if node_id in identities and identities[node_id] != key:
            raise ValueError("Public graph identifier collision")
        if node_id not in nodes:
            if len(nodes) >= limit:
                relation_truncated = True
                return None
            identities[node_id] = key
            nodes[node_id] = {"document_id": node_id, "entity_id": key.split(":", 1)[1], "entity_kind": kind,
                              "title": title, "source_kind": domain, "category": kind, "relative_path": key,
                              "reference_url": public_url(reference), "summary": summary[:700], "mtime_iso": modified,
                              "project_name": None, "degree": 0}
        return node_id

    def edge(left, right, relation, citation, editorial=False):
        nonlocal relation_truncated
        if left is None or right is None or left == right:
            return
        key = (left, right, relation)
        if key in edge_keys:
            return
        if len(edges) >= min(limit * 12, 5000):
            relation_truncated = True
            return
        edge_keys.add(key)
        edges.append({"source": left, "target": right, "kind": "suggested" if editorial else "explicit",
                      "relation_type": relation, "citation": citation,
                      "validation": "unvalidated_editorial" if editorial else "provider_documented"})

    # Reserve roots before expanding context, so a large first advisory cannot
    # crowd later root CVEs out of this bounded view.
    roots = []
    for item in found["results"]:
        key = domain + ":" + item["id"]
        roots.append((item, add_node(key, item["id"] if domain == "cyber" else item["title"],
                      item.get("record_kind", "vulnerability") if domain == "cyber" else item["kind"],
                     reference=item.get("source_url"), summary=item.get("description", item.get("summary", "")),
                     modified=item.get("modified", item.get("reviewed_on")))))
    if domain == "cyber":
        for item, root_id in roots:
            record = records.get(item["id"])
            if not record:
                continue
            if root_id is not None:
                nodes[root_id]["record_status"] = record["status"]
                if record["status"] != "published":
                    nodes[root_id]["summary"] = ("[" + record["status"] + "] " + nodes[root_id]["summary"])[:700]
                nodes[root_id]["reference_url"] = nodes[root_id]["reference_url"] or next(
                    (public_url(o.get("source_url")) for o in record.get("observations", []) if public_url(o.get("source_url"))), None)
            for observation in record.get("observations", []):
                if observation["record_status"] != "published":
                    continue
                citation = observation["source_url"]
                if root_id is not None and not nodes[root_id]["reference_url"]:
                    nodes[root_id]["reference_url"] = public_url(citation)
                for cwe in observation["cwes"][:40]:
                    target = add_node("weakness:" + cwe, cwe, "weakness", reference="https://cwe.mitre.org/data/definitions/" + cwe[4:] + ".html")
                    edge(root_id, target, "classified_as", citation)
                for affected in observation["affected"][:40]:
                    if affected.get("package"):
                        label = affected.get("ecosystem", "") + ":" + affected["package"]
                        relation = "advisory_reports_package"
                    elif affected.get("product"):
                        label = affected.get("vendor", "") + ":" + affected["product"]
                        relation = "kev_catalog_lists_product_no_version_claim"
                    elif affected.get("criteria"):
                        label = affected["criteria"]
                        relation = "cpe_configuration_condition_not_project_applicability"
                    else:
                        continue
                    target = add_node("technology:" + label, label, "technology", reference=citation)
                    edge(root_id, target, relation, citation)
                if len(observation["cwes"]) > 40 or len(observation["affected"]) > 40:
                    relation_truncated = True
    else:
        for item, root_id in roots:
            for relation in security_relations.get(item["id"], []):
                if relation["source_id"] != item["id"]:
                    continue
                target = security_targets.get(relation["target_id"])
                if not target:
                    continue
                target_id = add_node("security:" + target["id"], target["title"], target["kind"],
                                     reference=target["source_url"], summary=target["summary"], modified=target["reviewed_on"])
                edge(root_id, target_id, relation["relation_type"], item["source_url"], relation["validation"] == "unvalidated_editorial")
    for relation in edges:
        nodes[relation["source"]]["degree"] += 1
        nodes[relation["target"]]["degree"] += 1
    visible = {node_id for node_id, node in nodes.items() if node["degree"] >= min_degree}
    return {"nodes": [node for node_id, node in nodes.items() if node_id in visible],
            "edges": [e for e in edges if e["source"] in visible and e["target"] in visible],
            "domain": domain, "node_limit": limit, "root_limit": roots_limit,
            "root_total_matches": found["total"], "total_matches": max(found["total"], len(nodes)),
            "truncated": found["total"] > len(roots) or relation_truncated,
            "count_basis": "root_total_matches counts CVEs/catalog entries; context nodes have a separate visual cap",
            "scope_note": "Public-source assertions and editorial suggestions only; no project applicability is inferred."}
