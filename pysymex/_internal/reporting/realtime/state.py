# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Shared realtime visualizer state and HTTP handler."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler
from typing import TYPE_CHECKING, TypedDict
from urllib.parse import parse_qs, urlsplit

from pysymex._internal.reporting.realtime.template import HTML_TEMPLATE

if TYPE_CHECKING:
    from pathlib import Path


class RealtimeStats(TypedDict):
    """Schema representation of execution statistics tracked by the visualizer.

    Attributes:
        paths: Number of explored paths.
        total_issues: Count of all issues identified.
        scan_errors: Count of analysis exceptions encountered.
        degraded_scans: Count of verification steps executing in concrete fallback.
        files: Count of processed files.
        active_func: Name of the function currently under analysis.
        pc: Current program counter bytecode offset.
        opname: Name of the current opcode.

    """

    paths: int
    total_issues: int
    scan_errors: int
    degraded_scans: int
    files: int
    active_func: str
    pc: int
    opname: str


class RealtimeNode(TypedDict):
    """Graph node emitted to the realtime browser visualizer."""

    id: str
    label: str
    type: str
    status: str


class RealtimeEdge(TypedDict):
    """Directed graph edge emitted to the realtime browser visualizer."""

    source: str
    target: str


class GlobalState:
    """Shared mutable state for the real-time visualiser.

    Stores the D3 graph node/edge data and live engine statistics.
    Access is serialised via :attr:`lock`.

    Attributes:
        nodes: List of node dicts (``id``, ``label``, ``type``, ``status``).
        edges: List of edge dicts (``source``, ``target``).
        active_file: Currently scanned file, or ``None``.
        stats: Live engine counters (paths, issues, PC, etc.).
        lock: Threading lock guarding all mutable fields.

    """

    def __init__(self) -> None:
        """Initialize the shared mutable visualizer state.

        Sets up default structures to track live D3 graph nodes, connection edges,
        active file references, counters, and the lock guarding concurrent access.
        """
        self.nodes: list[RealtimeNode] = []
        self.edges: list[RealtimeEdge] = []
        self.issues_list: list[dict[str, object]] = []
        self.visited_functions: list[str] = []
        self.active_file: Path | None = None
        self.stats: RealtimeStats = {
            "paths": 0,
            "total_issues": 0,
            "scan_errors": 0,
            "degraded_scans": 0,
            "pc": 0,
            "opname": "IDLE",
            "files": 0,
            "active_func": "<module>",
        }
        self.graph_revision = 0
        self.stats_revision = 0
        self._node_index: dict[str, RealtimeNode] = {}
        self._edge_keys: set[tuple[str, str]] = set()
        self.lock = threading.Lock()

    def replace_graph(self, nodes: list[RealtimeNode], edges: list[RealtimeEdge]) -> None:
        """Replace graph nodes and rebuild lookup indexes.

        Callers must hold :attr:`lock`.
        """
        self.nodes = nodes
        self.edges = edges
        self._node_index = {node["id"]: node for node in nodes}
        self._edge_keys = {(edge["source"], edge["target"]) for edge in edges}
        self.graph_revision += 1

    def get_node(self, node_id: str) -> RealtimeNode | None:
        """Return a graph node by identifier.

        Callers must hold :attr:`lock`.
        """
        return self._node_index.get(node_id)

    def add_node(self, node: RealtimeNode) -> bool:
        """Add a graph node if it does not already exist.

        Returns:
            ``True`` when the graph changed.

        Callers must hold :attr:`lock`.

        """
        if node["id"] in self._node_index:
            return False
        self.nodes.append(node)
        self._node_index[node["id"]] = node
        self.graph_revision += 1
        return True

    def add_edge(self, source: str, target: str) -> bool:
        """Add a directed graph edge if it does not already exist.

        Returns:
            ``True`` when the graph changed.

        Callers must hold :attr:`lock`.

        """
        key = (source, target)
        if key in self._edge_keys:
            return False
        self.edges.append({"source": source, "target": target})
        self._edge_keys.add(key)
        self.graph_revision += 1
        return True

    def set_node_status(self, node_id: str, status: str) -> bool:
        """Update a node status if the node exists and the value changed.

        Returns:
            ``True`` when the graph changed.

        Callers must hold :attr:`lock`.

        """
        node = self._node_index.get(node_id)
        if node is None or node["status"] == status:
            return False
        node["status"] = status
        self.graph_revision += 1
        return True

    def set_node_type_and_status(self, node_id: str, node_type: str, status: str) -> bool:
        """Update node type and status together.

        Returns:
            ``True`` when the graph changed.

        Callers must hold :attr:`lock`.

        """
        node = self._node_index.get(node_id)
        if node is None:
            return False
        changed = False
        if node["type"] != node_type:
            node["type"] = node_type
            changed = True
        if node["status"] != status:
            node["status"] = status
            changed = True
        if changed:
            self.graph_revision += 1
        return changed

    def touch_stats(self) -> None:
        """Mark non-graph state as updated.

        Callers must hold :attr:`lock`.
        """
        self.stats_revision += 1

    def get_json(
        self,
        *,
        client_graph_revision: int | None = None,
        include_graph: bool = True,
    ) -> str:
        """Return the current state as a JSON string.

        Args:
            client_graph_revision: Graph revision already held by the browser.
                When it matches the current revision, nodes and edges are omitted
                to avoid resending large unchanged graphs.
            include_graph: If ``False``, omit nodes and edges even when the graph
                changed. This is used while the browser has paused graph updates.

        """
        with self.lock:
            graph_unchanged = client_graph_revision == self.graph_revision
            payload: dict[str, object] = {
                "issues_list": self.issues_list,
                "visited_functions": self.visited_functions,
                "active_file": str(self.active_file.name) if self.active_file else None,
                "stats": self.stats,
                "graph_revision": self.graph_revision,
                "stats_revision": self.stats_revision,
                "node_count": len(self.nodes),
                "edge_count": len(self.edges),
            }
            if include_graph and not graph_unchanged:
                payload["nodes"] = self.nodes
                payload["edges"] = self.edges
            else:
                payload["graph_unchanged"] = True
            return json.dumps(payload)


global_state = GlobalState()


class VisHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the real-time visualisation server.

    Serves the D3 HTML page on ``/`` and the live JSON state on
    ``/state``.
    """

    def log_message(self, format: str, *args: object) -> None:
        """Override handler logging to suppress HTTP console logs.

        Args:
            format: Format string parameter.
            *args: Formatting arguments.

        """

    def do_GET(self) -> None:
        """Handle ``GET`` requests for ``/`` (HTML) and ``/state`` (JSON)."""
        parsed = urlsplit(self.path)
        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
        elif parsed.path == "/state":
            query = parse_qs(parsed.query)
            graph_revision = _parse_graph_revision(query.get("graph_revision", []))
            include_graph = query.get("skip_graph", ["0"])[0] != "1"
            self.send_response(200)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(
                global_state.get_json(
                    client_graph_revision=graph_revision,
                    include_graph=include_graph,
                ).encode("utf-8"),
            )
        else:
            self.send_response(404)
            self.end_headers()


def _parse_graph_revision(values: list[str]) -> int | None:
    """Parse the optional browser graph revision query value."""
    if not values:
        return None
    try:
        return int(values[0])
    except ValueError:
        return None
