"""Cited, incremental graph projection; no remote or implicit index updates."""
from .projection import sync_graph
from .query import graph_neighbors, graph_page

__all__ = ["sync_graph", "graph_neighbors", "graph_page"]
