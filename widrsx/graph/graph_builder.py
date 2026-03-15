"""Builds a communication graph from traffic records."""

import logging
from typing import Any, Dict, Optional, cast

import networkx as nx


logger = logging.getLogger(__name__)


class GraphBuilder:
    """Communication graph builder."""

    def __init__(self, database=None):
        self.graph = nx.DiGraph()
        self.database = database

    def add_record(self, record: dict):
        """Add a traffic record to the communication graph."""
        src = record.get("src_ip")
        dst = record.get("dst_ip")
        if not src or not dst or src == "unknown" or dst == "unknown":
            return

        self.graph.add_node(src)
        self.graph.add_node(dst)

        if self.graph.has_edge(src, dst):
            edge = cast(Dict[str, Any], self.graph[src][dst])
            current_weight = cast(int, edge.get("weight", 0))
            edge["weight"] = current_weight + 1
        else:
            self.graph.add_edge(src, dst, weight=1)

        if self.database is not None:
            try:
                self.database.upsert_graph_edge(src, dst, weight=1)
            except Exception:
                logger.exception("Failed to persist graph edge")

        logger.debug("Updated graph edge %s -> %s (weight=%s)", src, dst, self.graph[src][dst]["weight"])
