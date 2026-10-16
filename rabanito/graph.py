from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .db import Database


_GRAPH_QUERY_BATCH_SIZE = 450  # Keep bound ID lists below SQLite's 999-variable limit.


def graph_suggestion_edges(db: Database, document_ids: Iterable[int]) -> list[Any]:
    """Return suggested edges incident to these nodes, including outside neighbors."""
    ids = sorted({int(document_id) for document_id in document_ids})
    if not ids:
        return []
    selected = set(ids)
    edges: list[Any] = []
    for offset in range(0, len(ids), _GRAPH_QUERY_BATCH_SIZE):
        batch = ids[offset:offset + _GRAPH_QUERY_BATCH_SIZE]
        placeholders = ",".join("?" for _ in batch)
        edges.extend(db.query(
            "SELECT source_document_id AS source, target_document_id AS target, "
            "'suggested' AS kind, status, score FROM link_suggestions "
            f"WHERE status='suggested' AND source_document_id IN ({placeholders})",
            batch,
        ))
        incoming = db.query(
            "SELECT source_document_id AS source, target_document_id AS target, "
            "'suggested' AS kind, status, score FROM link_suggestions "
            f"WHERE status='suggested' AND target_document_id IN ({placeholders})",
            batch,
        )
        # Edges whose two endpoints are selected were already returned by the
        # source-side query. Keep only truly external incoming neighbors here.
        edges.extend(row for row in incoming if int(row["source"]) not in selected)
    return edges


def graph_edges_for_nodes(
    db: Database,
    document_ids: Iterable[int],
    include_suggestions: bool = False,
    *,
    include_suggestion_scores: bool = True,
) -> list[dict[str, Any]]:
    """Return only edges whose endpoints are both in the selected node set."""
    ids = sorted({int(document_id) for document_id in document_ids})
    if not ids:
        return []
    selected = set(ids)
    edges: list[dict[str, Any]] = []
    for offset in range(0, len(ids), _GRAPH_QUERY_BATCH_SIZE):
        batch = ids[offset:offset + _GRAPH_QUERY_BATCH_SIZE]
        placeholders = ",".join("?" for _ in batch)
        explicit = db.query(
            "SELECT source_document_id AS source, target_document_id AS target, "
            "'explicit' AS kind, status FROM links "
            f"WHERE status='resolved' AND target_document_id IS NOT NULL AND source_document_id IN ({placeholders})",
            batch,
        )
        edges.extend(dict(row) for row in explicit if int(row["target"]) in selected)
    if include_suggestions:
        for row in graph_suggestion_edges(db, ids):
            if int(row["source"]) not in selected or int(row["target"]) not in selected:
                continue
            edge = dict(row)
            if not include_suggestion_scores:
                edge.pop("score", None)
            edges.append(edge)
    return edges
