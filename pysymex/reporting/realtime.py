"""Real-time network map visualizer for pysymex."""

from __future__ import annotations

import dataclasses
import json
import logging
import threading
import time
import webbrowser
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

from pysymex.analysis.detectors import Issue
from pysymex.execution.executor import ExecutionConfig, SymbolicExecutor
from pysymex.plugins.base import (
    HookPlugin,
    PluginMetadata,
    PluginPriority,
    PluginType,
)
from pysymex.scanner.core import get_code_objects_with_context
from pysymex.scanner.types import ScanResult

if TYPE_CHECKING:
    from pysymex.execution.executor import SymbolicExecutor as SymbolicEngine

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>pysymex Map Visualizer</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #1e1e1e; color: #fff; margin: 0; overflow: hidden; }
        .node circle { stroke: #fff; stroke-width: 1.5px; }
        .node text { font: 12px sans-serif; fill: #fff; pointer-events: none; }
        .link { fill: none; stroke: #555; stroke-width: 1.5px; opacity: 0.6; }
        #info { position: absolute; top: 20px; right: 20px; width: 350px; background: rgba(45,45,45,0.9); padding: 15px; border-radius: 8px; border: 1px solid #444; box-shadow: 0 4px 6px rgba(0,0,0,0.5); }
        h1 { color: #4a90e2; margin-top: 0; font-size: 1.5rem; text-align: center; }
        .status-header { font-weight: bold; margin-bottom: 5px; color: #aaa; margin-top: 15px; border-bottom: 1px solid #555; padding-bottom: 5px; }
        .stat-row { display: flex; justify-content: space-between; margin-bottom: 5px; font-family: monospace; font-size: 14px; }
        .stat-label { color: #ccc; }
        .active-file { font-family: monospace; font-size: 14px; color: #f1c40f; word-break: break-all; margin-bottom: 10px; }
        .legend { margin-top: 20px; font-size: 12px; display: grid; grid-template-columns: 1fr 1fr; gap: 5px; }
        .legend div { display: flex; align-items: center; }
        .legend span { display: inline-block; width: 12px; height: 12px; border-radius: 50%; border: 1px solid #fff; margin-right: 8px; }
    </style>
</head>
<body>
    <div id="graph"></div>
    <div id="info">
        <h1>🔮 PySyMex Live Map</h1>
        <div id="details">Waiting for engine connection...</div>

        <div class="legend">
            <div><span style="background: #3498db"></span> Pending File</div>
            <div><span style="background: #95a5a6"></span> Directory</div>
            <div><span style="background: #f1c40f"></span> Actively Scanning</div>
            <div><span style="background: #2ecc71"></span> Clean / Pass</div>
            <div><span style="background: #e74c3c"></span> Issues Found</div>
        </div>
    </div>
    <script>
        const width = window.innerWidth;
        const height = window.innerHeight;

        // Add Zoom capabilities
        const zoom = d3.zoom().scaleExtent([0.1, 4]).on("zoom", function (event) {
            svg.attr("transform", event.transform)
        });

        const svg = d3.select("#graph").append("svg")
            .attr("width", width)
            .attr("height", height)
            .call(zoom)
            .append("g");

        let simulation = d3.forceSimulation()
            .force("link", d3.forceLink().id(d => d.id).distance(150))
            .force("charge", d3.forceManyBody().strength(-1500))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collide", d3.forceCollide().radius(60));

        let link = svg.append("g").attr("class", "links").selectAll(".link");
        let node = svg.append("g").attr("class", "nodes").selectAll(".node");

        function getColor(status, type) {
            if (status === "active") return "#f1c40f"; // Yellow
            if (status === "done_clean") return "#2ecc71"; // Green
            if (status === "done_issues") return "#e74c3c"; // Red
            return type === "dir" ? "#95a5a6" : "#3498db"; // Grey/Blue for pending
        }

        function getRadius(type) {
            return type === "dir" ? 10 : 8; // Directories are slightly bigger dots
        }

        let firstLoad = true;
        let nodeData = [];
        let edgeData = [];

        async function fetchState() {
            try {
                const res = await fetch('/state');
                const data = await res.json();

                document.getElementById('details').innerHTML = `
                    <div class="status-header">Current File</div>
                    <div class="active-file">${data.active_file || "Network idle..."}</div>

                    <div class="status-header">Live Engine Stats</div>
                    <div class="stat-row"><span class="stat-label">Active Func:</span> <span style="color: #3498db">${data.stats.active_func}</span></div>
                    <div class="stat-row"><span class="stat-label">Files Scanned:</span> <span>${data.stats.files} / ${data.nodes.filter(n => n.type==='file').length}</span></div>
                    <div class="stat-row"><span class="stat-label">Issues Detected:</span> <span style="color: ${data.stats.total_issues > 0 ? '#e74c3c' : '#2ecc71'}">${data.stats.total_issues}</span></div>
                    <div class="stat-row"><span class="stat-label">Paths Explored:</span> <span style="color: #f39c12">${data.stats.paths}</span></div>

                    <div class="status-header">VM Cycle PC Memory</div>
                    <div class="stat-row"><span class="stat-label">Prog. Counter:</span> <span>${data.stats.pc}</span></div>
                    <div class="stat-row"><span class="stat-label">Instruction:</span> <span style="color: #9b59b6">${data.stats.opname}</span></div>
                `;

                if (firstLoad && data.nodes.length > 0) {
                    nodeData = data.nodes;
                    edgeData = data.edges;

                    link = link.data(edgeData)
                        .enter().append("line")
                        .attr("class", "link");

                    node = node.data(nodeData)
                        .enter().append("g")
                        .attr("class", "node")
                        .call(d3.drag()
                            .on("start", dragstarted)
                            .on("drag", dragged)
                            .on("end", dragended));

                    node.append("circle")
                        .attr("r", d => getRadius(d.type))
                        .style("fill", d => getColor(d.status, d.type));

                    node.append("text")
                        .attr("text-anchor", "middle")
                        .attr("dy", 22)
                        .text(d => d.label);

                    simulation.nodes(nodeData).on("tick", ticked);
                    simulation.force("link").links(edgeData);

                    // Center the view on load automatically
                    setTimeout(() => {
                        const contentBBox = svg.node().getBBox();
                        const scale = Math.min(width/contentBBox.width, height/contentBBox.height) * 0.8;
                        const centerX = width/2 - (contentBBox.x + contentBBox.width/2) * scale;
                        const centerY = height/2 - (contentBBox.y + contentBBox.height/2) * scale;
                        d3.select("#graph svg").transition().duration(750)
                            .call(zoom.transform, d3.zoomIdentity.translate(centerX, centerY).scale(scale));
                    }, 500);

                    firstLoad = false;
                } else if (!firstLoad) {
                    // Update states dynamically
                    const colorMap = {};
                    data.nodes.forEach(n => colorMap[n.id] = n.status);

                    nodeData.forEach(n => {
                        if(colorMap[n.id]) n.status = colorMap[n.id];
                    });

                    // Animate the actively scanning node by pulsating
                    node.select("circle")
                        .transition()
                        .duration(150)
                        .style("fill", d => getColor(d.status, d.type))
                        .attr("r", d => d.status === "active" ? 22 : getRadius(d.type));
                }
            } catch (e) {
                console.error("Polling error:", e);
            }
        }

        function ticked() {
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
            node
                .attr("transform", d => `translate(${d.x},${d.y})`);
        }

        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }
        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }
        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }

        // Poll API to update logic every 100 milliseconds
        setInterval(fetchState, 100);
    </script>
</body>
</html>
"""


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
        self.nodes: list[dict[str, object]] = []
        self.edges: list[dict[str, str]] = []
        self.active_file: Path | None = None
        self.stats: dict[str, object] = {
            "paths": 0,
            "total_issues": 0,
            "pc": 0,
            "opname": "IDLE",
            "files": 0,
            "active_func": "<module>",
        }
        self.lock = threading.Lock()

    def get_json(self) -> str:
        """Return the current state as a JSON string (thread-safe)."""
        with self.lock:
            return json.dumps(
                {
                    "nodes": self.nodes,
                    "edges": self.edges,
                    "active_file": str(self.active_file.name) if self.active_file else None,
                    "stats": self.stats,
                }
            )


global_state = GlobalState()


class VisHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the real-time visualisation server.

    Serves the D3 HTML page on ``/`` and the live JSON state on
    ``/state``.
    """

    def log_message(self, format: str, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        """Handle ``GET`` requests for ``/`` (HTML) and ``/state`` (JSON)."""
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
        elif self.path == "/state":
            self.send_response(200)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(global_state.get_json().encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


class RealtimeVisualizationPlugin(HookPlugin):
    """Plugin that feeds live execution data to the realtime visualizer.

    Registers a ``pre_step`` hook that updates :data:`global_state` with the
    current program counter, opcode name, and path-exploration count on every
    symbolic-execution step.

    Usage (via plugin system)::

        from pysymex.reporting.realtime import RealtimeVisualizationPlugin
        plugin = RealtimeVisualizationPlugin()
        engine.load_plugins(...)          # or register manually
        plugin.activate(engine)

    For backward-compatible shorthand see
    :func:`start_realtime_visualization`.
    """

    metadata = PluginMetadata(
        name="realtime-visualization",
        version="1.0.0",
        description="Live execution visualizer feeding the D3 network map",
        author="pysymex",
        plugin_type=PluginType.HOOK,
        priority=PluginPriority.LOW,
    )

    def __init__(self, throttle_every: int = 5, sleep_ms: float = 5.0) -> None:
        super().__init__()
        self._throttle_every = throttle_every
        self._sleep_seconds = sleep_ms / 1000.0

    def get_hooks(self) -> dict[str, Callable[..., object]]:
        """Return the ``pre_step`` hook used by the visualizer."""
        return {"pre_step": self._pre_step_hook}

    def activate(self, engine: SymbolicEngine) -> None:
        """Register hooks with *engine* via the standard plugin path."""
        hooks = self.get_hooks()
        for hook_name, handler in hooks.items():
            if hasattr(engine, "register_hook"):
                engine.register_hook(hook_name, handler)

    def _pre_step_hook(self, executor_self: object, state: object) -> None:
        """Update :data:`global_state` before each execution step."""
        instr = (
            executor_self._instructions[state.pc]
            if state.pc < len(executor_self._instructions)
            else None
        )
        opname: str = getattr(instr, "opname", "OOB") if instr else "EOF"

        with global_state.lock:
            global_state.stats["pc"] = state.pc
            global_state.stats["opname"] = opname
            global_state.stats["paths"] = executor_self._paths_explored

        if state.pc % self._throttle_every == 0:
            time.sleep(self._sleep_seconds)


def start_realtime_visualization(executor: object) -> RealtimeVisualizationPlugin:
    """Create and register a :class:`RealtimeVisualizationPlugin` on *executor*.

    This is the backward-compatible helper that existing call-sites
    (e.g. ``run_realtime_scan``) can use instead of manually instantiating
    and activating the plugin.
    """
    plugin = RealtimeVisualizationPlugin()
    plugin.activate(executor)
    return plugin


def run_realtime_scan(
    path: Path, recursive: bool = True, max_paths: int = 1000, timeout: float = 60.0
) -> list[ScanResult]:
    """Run a scan with a live D3 network-map visualiser.

    Starts an HTTP server on ``http://127.0.0.1:8080``, opens a
    browser, and streams scan progress as live graph updates.

    Args:
        path: File or directory to scan.
        recursive: Recurse into sub-directories.
        max_paths: Maximum execution paths per function.
        timeout: Per-file timeout in seconds.

    Returns:
        List of :class:`~pysymex.scanner.types.ScanResult` objects.
    """
    if path.is_file():
        files = [path]
        root_dir = path.parent
    else:
        pattern = "**/*.py" if recursive else "*.py"
        files = sorted(path.glob(pattern))
        root_dir = path

    if not files:
        return []

    with global_state.lock:
        nodes = [
            {
                "id": str(root_dir.resolve()),
                "label": root_dir.name,
                "type": "dir",
                "status": "pending",
            }
        ]
        edges: list[dict[str, str]] = []

        dir_set = {str(root_dir.resolve())}
        for f in files:
            parts = f.resolve().relative_to(root_dir.resolve()).parts
            current_path = root_dir.resolve()

            for i, part in enumerate(parts):
                parent_path = str(current_path)
                current_path = current_path / part
                curr_str = str(current_path)

                if curr_str not in dir_set:
                    dir_set.add(curr_str)
                    is_file = i == len(parts) - 1
                    nodes.append(
                        {
                            "id": curr_str,
                            "label": part,
                            "type": "file" if is_file else "dir",
                            "status": "pending",
                        }
                    )
                    edges.append({"source": parent_path, "target": curr_str})

        global_state.nodes = nodes
        global_state.edges = edges

    server = HTTPServer(("127.0.0.1", 8080), VisHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    import atexit

    atexit.register(server.shutdown)

    webbrowser.open("http://127.0.0.1:8080")
    print("\n" + "=" * 70)
    print("🔮 PySyMex Live Directory Map Server Running!")
    print("🔗 http://127.0.0.1:8080")
    print("=" * 70 + "\n")
    print("Analyzing target directory paths and broadcasting dots data...")
    time.sleep(1.5)

    results: list[ScanResult] = []

    vis_plugin = RealtimeVisualizationPlugin()

    for file_path in files:
        path_str = str(file_path.resolve())
        with global_state.lock:
            global_state.active_file = file_path
            for n in global_state.nodes:
                if n["id"] == path_str:
                    n["status"] = "active"

            parent = file_path.resolve().parent
            while str(parent) in dir_set:
                for n in global_state.nodes:
                    if n["id"] == str(parent):
                        n["status"] = "active"
                if parent == root_dir.resolve():
                    break
                parent = parent.parent

        result = ScanResult(
            file_path=str(file_path),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
        )

        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()
            code_obj = compile(content, str(file_path), "exec")
            all_code_with_context = get_code_objects_with_context(code_obj)

            config = ExecutionConfig(max_paths=max_paths, timeout_seconds=timeout * 5)
            executor = SymbolicExecutor(config=config)
            vis_plugin.activate(executor)

            total_paths = 0
            all_issues: list[Issue] = []

            module_item = all_code_with_context[0] if all_code_with_context else None
            other_items = all_code_with_context[1:] if len(all_code_with_context) > 1 else []
            module_globals = {}

            if module_item:
                code, class_name, full_path = module_item
                with global_state.lock:
                    global_state.stats["active_func"] = "<module>"
                symbolic_vars = dict.fromkeys(code.co_varnames[: code.co_argcount], "int")
                try:
                    exec_result = executor.execute_code(code, symbolic_vars=symbolic_vars)
                    module_globals = exec_result.final_locals
                    for issue in exec_result.issues:
                        issue = dataclasses.replace(
                            issue,
                            function_name=code.co_name,
                            class_name=class_name,
                            full_path=full_path,
                        )
                        all_issues.append(issue)
                    total_paths += exec_result.paths_explored
                except Exception:
                    logger.debug("Symbolic execution failed for %s", code.co_name, exc_info=True)

            for code, class_name, full_path in other_items:
                with global_state.lock:
                    global_state.stats["active_func"] = code.co_name
                executor = SymbolicExecutor(config=config)
                vis_plugin.activate(executor)
                symbolic_vars = dict.fromkeys(code.co_varnames[: code.co_argcount], "int")
                try:
                    exec_result = executor.execute_code(
                        code, symbolic_vars=symbolic_vars, initial_globals=module_globals
                    )
                    for issue in exec_result.issues:
                        issue = dataclasses.replace(
                            issue,
                            function_name=code.co_name,
                            class_name=class_name,
                            full_path=full_path,
                        )
                        all_issues.append(issue)
                    total_paths += exec_result.paths_explored
                except Exception:
                    logger.debug("Symbolic execution failed for %s", code.co_name, exc_info=True)

            seen: set[str] = set()
            for issue in all_issues:
                msg = f"[{issue .kind .name }] {issue .message } (Line {issue .line_number })"
                if msg not in seen:
                    seen.add(msg)
                    result.issues.append(
                        {
                            "kind": issue.kind.name,
                            "message": issue.message,
                            "line": issue.line_number,
                            "counterexample": issue.get_counterexample(),
                        }
                    )
            result.paths_explored = total_paths
        except Exception as e:
            result.error = str(e)

        results.append(result)

        with global_state.lock:
            global_state.stats["files"] += 1
            global_state.stats["total_issues"] += len(result.issues)

            status = "done_issues" if len(result.issues) > 0 else "done_clean"
            for n in global_state.nodes:
                if n["id"] == path_str:
                    n["status"] = status

            parent = file_path.resolve().parent
            while str(parent) in dir_set:
                for n in global_state.nodes:
                    if n["id"] == str(parent):
                        n["status"] = "pending"
                if parent == root_dir.resolve():
                    break
                parent = parent.parent

    print("[*] Symbolic network scan completion successful!")
    print(
        "[*] Will leave the graphical network server alive for 15 seconds so you can browse the graph dots."
    )
    time.sleep(15)
    server.shutdown()

    return results
