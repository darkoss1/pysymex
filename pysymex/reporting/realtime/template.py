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

"""Define the HTML/D3 template source for real-time visualization.

Aggregates page styling, D3 tree-layout graph setup, and polling logic
to render active symbolic execution paths as a growing root tree.
"""

from __future__ import annotations

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>pysymex — Live Execution Tree</title>
    <meta name="description" content="Real-time symbolic execution tree visualizer for pysymex">
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');

        *,*::before,*::after { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Inter', system-ui, sans-serif;
            background: #111;
            color: #d4d4d4;
            overflow: hidden;
            height: 100vh;
            width: 100vw;
        }

        #canvas {
            position: absolute;
            inset: 0;
        }

        #canvas svg {
            width: 100%;
            height: 100%;
            display: block;
        }

        /* ── Panel ── */
        #panel {
            position: absolute;
            top: 0;
            right: 0;
            width: 300px;
            height: 100vh;
            overflow-y: auto;
            background: #1a1a1a;
            border-left: 1px solid #262626;
            padding: 24px 20px;
            display: flex;
            flex-direction: column;
            gap: 20px;
            z-index: 10;
        }

        #panel::-webkit-scrollbar { width: 3px; }
        #panel::-webkit-scrollbar-thumb { background: #333; border-radius: 2px; }

        .panel-brand {
            font-size: 13px;
            font-weight: 600;
            color: #737373;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        .section { display: flex; flex-direction: column; gap: 6px; }

        .section-title {
            font-size: 11px;
            font-weight: 500;
            color: #525252;
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }

        .file-path {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: #a3a3a3;
            word-break: break-all;
            line-height: 1.5;
        }

        .row {
            display: flex;
            justify-content: space-between;
            align-items: baseline;
            font-size: 13px;
            line-height: 1.8;
        }

        .row-label { color: #737373; }
        .row-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: #d4d4d4;
        }

        .graph-controls {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            padding-top: 4px;
        }

        .graph-button {
            appearance: none;
            border: 1px solid #333;
            background: #202020;
            color: #d4d4d4;
            font: 500 11px 'Inter', system-ui, sans-serif;
            padding: 5px 8px;
            cursor: pointer;
        }

        .graph-button:hover { border-color: #555; }
        .graph-button.active {
            border-color: #8ab4d4;
            color: #8ab4d4;
        }

        .divider {
            height: 1px;
            background: #262626;
        }

        .list-box {
            max-height: 110px;
            overflow-y: auto;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            line-height: 1.8;
            color: #a3a3a3;
        }

        .list-box::-webkit-scrollbar { width: 2px; }
        .list-box::-webkit-scrollbar-thumb { background: #333; }

        .fn-entry { color: #b4a0d4; }

        .issue-entry {
            padding: 4px 0;
            border-bottom: 1px solid #222;
        }
        .issue-entry:last-child { border-bottom: none; }

        .issue-loc {
            font-size: 11px;
            color: #d97575;
            font-weight: 500;
        }
        .issue-msg {
            font-size: 10px;
            color: #737373;
            margin-top: 1px;
        }

        .empty { color: #404040; font-style: italic; font-size: 11px; }

        .legend-row {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 10px;
            color: #525252;
            line-height: 2;
        }
        .dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            flex-shrink: 0;
        }

        /* ── Tree nodes ── */
        .tree-link {
            fill: none;
            stroke-width: 1.2;
            opacity: 0.4;
        }
        .tree-link.dead-link {
            stroke-dasharray: 4 3;
            opacity: 0.25;
        }

        .tree-node text {
            font-family: 'Inter', sans-serif;
            font-size: 10px;
            fill: #737373;
            pointer-events: none;
        }

        .tree-node circle {
            stroke: #111;
            stroke-width: 1.5;
        }

        /* Dead-end cross marker */
        .dead-marker line {
            stroke: #b05050;
            stroke-width: 1.5;
            stroke-linecap: round;
        }

        /* Active pulse ring */
        .pulse-ring {
            fill: none;
            stroke-width: 1;
            opacity: 0;
        }
        .tree-node.scanning .pulse-ring {
            animation: scan-pulse 2s ease-in-out infinite;
        }
        @keyframes scan-pulse {
            0%   { opacity: 0.5; r: 10; }
            100% { opacity: 0;   r: 20; }
        }
    </style>
</head>
<body>
    <div id="canvas"></div>

    <div id="panel">
        <div class="panel-brand">pysymex</div>

        <div class="section">
            <div class="section-title">Scanning</div>
            <div class="file-path" id="p-file">Waiting for engine…</div>
        </div>

        <div class="divider"></div>

        <div class="section">
            <div class="section-title">Statistics</div>
            <div class="row"><span class="row-label">Files</span><span class="row-value" id="p-files">0</span></div>
            <div class="row"><span class="row-label">Paths explored</span><span class="row-value" id="p-paths">0</span></div>
            <div class="row"><span class="row-label">Issues</span><span class="row-value" id="p-issues">0</span></div>
            <div class="row"><span class="row-label">Errors</span><span class="row-value" id="p-errors">0</span></div>
            <div class="row"><span class="row-label">Degraded</span><span class="row-value" id="p-degraded">0</span></div>
        </div>

        <div class="divider"></div>

        <div class="section">
            <div class="section-title">Graph</div>
            <div class="row"><span class="row-label">Rendered</span><span class="row-value" id="p-rendered">0/0</span></div>
            <div class="row"><span class="row-label">Mode</span><span class="row-value" id="p-mode">Live</span></div>
            <div class="graph-controls">
                <button type="button" class="graph-button" id="g-fit">Fit</button>
                <button type="button" class="graph-button" id="g-pause">Pause</button>
                <button type="button" class="graph-button" id="g-full">Full</button>
            </div>
        </div>

        <div class="divider"></div>

        <div class="section">
            <div class="section-title">VM</div>
            <div class="row"><span class="row-label">Function</span><span class="row-value" id="p-func">&lt;module&gt;</span></div>
            <div class="row"><span class="row-label">PC</span><span class="row-value" id="p-pc">0</span></div>
            <div class="row"><span class="row-label">Opcode</span><span class="row-value" id="p-op">IDLE</span></div>
        </div>

        <div class="divider"></div>

        <div class="section">
            <div class="section-title">Visited Functions</div>
            <div class="list-box" id="p-fns"><span class="empty">—</span></div>
        </div>

        <div class="divider"></div>

        <div class="section">
            <div class="section-title">Detected Issues</div>
            <div class="list-box" id="p-iss"><span class="empty">—</span></div>
        </div>

        <div class="divider"></div>

        <div class="section">
            <div class="section-title">Legend</div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:0 12px">
                <div class="legend-row"><div class="dot" style="background:#737373"></div>Directory</div>
                <div class="legend-row"><div class="dot" style="background:#8ab4d4"></div>File</div>
                <div class="legend-row"><div class="dot" style="background:#c9a84c"></div>Scanning</div>
                <div class="legend-row"><div class="dot" style="background:#6bb38a"></div>Clean</div>
                <div class="legend-row"><div class="dot" style="background:#b4a0d4"></div>Function</div>
                <div class="legend-row"><div class="dot" style="background:#6bb38a"></div>Path</div>
                <div class="legend-row"><div class="dot" style="background:#b05050"></div>Dead end</div>
                <div class="legend-row"><div class="dot" style="background:#d97575"></div>Issue</div>
            </div>
        </div>
    </div>

    <script>
    (function() {
        "use strict";

        const PW = 300;
        const W = window.innerWidth - PW;
        const H = window.innerHeight;
        const POLL_MS = 250;
        const LARGE_GRAPH_NODE_COUNT = 600;
        const MAX_RENDERED_GRAPH_NODES = 1800;

        const svgEl = d3.select("#canvas").append("svg")
            .attr("width", window.innerWidth).attr("height", H);

        const rootG = svgEl.append("g");
        const linkG = rootG.append("g");
        const nodeG = rootG.append("g");
        let currentTransform = d3.zoomIdentity;

        const zoomBehavior = d3.zoom()
            .scaleExtent([0.01, 8])
            .on("zoom", e => {
                currentTransform = e.transform;
                rootG.attr("transform", currentTransform);
                updateLabelVisibility();
            });
        svgEl.call(zoomBehavior);

        /* ── Colors ── */
        const C = {
            dir:      "#737373",
            file:     "#8ab4d4",
            func:     "#b4a0d4",
            path:     "#6bb38a",
            dead:     "#b05050",
            issue:    "#d97575",
            active:   "#c9a84c",
            clean:    "#6bb38a",
            err:      "#7a3030",
            degraded: "#c9884c",
            link:     "#333",
        };

        function nodeColor(d) {
            const t = d.type, s = d.status;
            if (t === "issue")      return C.issue;
            if (t === "dead_path")  return C.dead;
            if (t === "path_node")  return C.path;
            if (t === "function")   return C.func;
            if (s === "active")     return C.active;
            if (s === "done_clean") return C.clean;
            if (s === "done_issues")return C.issue;
            if (s === "done_error") return C.err;
            if (s === "done_degraded") return C.degraded;
            if (t === "dir")        return C.dir;
            return C.file;
        }

        function nodeR(d) {
            const t = d.type;
            if (t === "dir")        return 7;
            if (t === "file")       return 6;
            if (t === "function")   return 5;
            if (t === "path_node")  return 4;
            if (t === "dead_path")  return 4;
            if (t === "issue")      return 5;
            return 4;
        }

        /* ── Hierarchy builder ── */
        function toTree(nodes, edges) {
            const map = new Map();
            nodes.forEach(n => map.set(n.id, { ...n, children: [] }));

            const children = new Set();
            edges.forEach(e => {
                const p = map.get(e.source), c = map.get(e.target);
                if (p && c) { p.children.push(c); children.add(e.target); }
            });

            let root = null;
            for (const [id] of map) {
                if (!children.has(id)) { root = map.get(id); break; }
            }
            return root || (nodes.length > 0 ? map.get(nodes[0].id) : null);
        }

        /* Curved vertical link */
        function curveV(d) {
            const sx = d.source.x, sy = d.source.y;
            const tx = d.target.x, ty = d.target.y;
            const mid = (sy + ty) / 2;
            return "M" + sx + "," + sy + " C" + sx + "," + mid + " " + tx + "," + mid + " " + tx + "," + ty;
        }

        let positions = new Map();
        let didZoom = false;
        let lastGraphRevision = -1;
        let lastRawNodes = [];
        let lastRawEdges = [];
        let isPaused = false;
        let showFullGraph = false;
        let lastRenderMeta = { rendered: 0, total: 0, mode: "Live", compact: false };

        function graphNodeLabel(d, compact) {
            if (compact && (d.type === "path_node" || d.type === "dead_path")) return "";
            return d.label;
        }

        function selectRenderedGraph(nodes, edges) {
            const total = nodes.length;
            if (showFullGraph || total <= MAX_RENDERED_GRAPH_NODES) {
                return {
                    nodes,
                    edges,
                    rendered: total,
                    total,
                    mode: showFullGraph && total > MAX_RENDERED_GRAPH_NODES ? "Full" : "Live",
                };
            }

            const sourceByTarget = new Map();
            edges.forEach(e => sourceByTarget.set(e.target, e.source));

            const keep = new Set();
            const dynamicNodes = [];
            nodes.forEach(n => {
                if (n.type === "path_node" || n.type === "dead_path") {
                    dynamicNodes.push(n);
                } else {
                    keep.add(n.id);
                }
            });

            dynamicNodes.slice(-MAX_RENDERED_GRAPH_NODES).forEach(n => {
                let id = n.id;
                let guard = 0;
                while (id && !keep.has(id) && guard < MAX_RENDERED_GRAPH_NODES) {
                    keep.add(id);
                    id = sourceByTarget.get(id);
                    guard += 1;
                }
                if (id) keep.add(id);
            });

            const visibleNodes = nodes.filter(n => keep.has(n.id));
            const visibleEdges = edges.filter(e => keep.has(e.source) && keep.has(e.target));
            return {
                nodes: visibleNodes,
                edges: visibleEdges,
                rendered: visibleNodes.length,
                total,
                mode: "Auto",
            };
        }

        function applyDuration(selection, duration) {
            return duration > 0 ? selection.transition().duration(duration) : selection;
        }

        function updateGraphMeta(meta) {
            lastRenderMeta = meta;
            document.getElementById("p-rendered").textContent = meta.rendered + "/" + meta.total;
            document.getElementById("p-mode").textContent = isPaused ? "Paused" : meta.mode;
        }

        function updateLabelVisibility() {
            const showLabels = !lastRenderMeta.compact || currentTransform.k >= 0.35;
            nodeG.selectAll("text").style("display", showLabels ? null : "none");
        }

        function fitToGraph(duration) {
            const node = rootG.node();
            if (!node) return;
            const bb = node.getBBox();
            if (!bb.width || !bb.height) return;
            const pad = 50;
            const sc = Math.min(W / (bb.width + pad * 2), H / (bb.height + pad * 2), 1.2);
            const cx = W / 2 - (bb.x + bb.width / 2) * sc;
            const cy = H / 2 - (bb.y + bb.height / 2) * sc;
            svgEl.transition().duration(duration).ease(d3.easeCubicOut)
                .call(zoomBehavior.transform, d3.zoomIdentity.translate(cx, cy).scale(sc));
        }

        /* ── Render ── */
        function render(raw, rawEdges) {
            if (!raw || raw.length === 0) return;
            const display = selectRenderedGraph(raw, rawEdges);
            const compact = display.total > LARGE_GRAPH_NODE_COUNT;
            updateGraphMeta({ ...display, compact });

            const root = toTree(display.nodes, display.edges);
            if (!root) return;

            const hier = d3.hierarchy(root, d => d.children.length ? d.children : null);
            const leaves = hier.leaves().length;
            const depth  = hier.height;
            const xGap = compact ? 28 : 60;
            const yGap = compact ? 80 : 110;
            const tw = Math.max(500, leaves * xGap);
            const th = Math.max(300, (depth + 1) * yGap);
            const duration = compact ? 0 : 300;

            d3.tree().size([tw, th])(hier);

            const allNodes = hier.descendants();
            const allLinks = hier.links();
            allLinks.forEach(l => { l.tdata = l.target.data; });

            /* Links */
            const lSel = linkG.selectAll("path.tree-link").data(allLinks, d => d.source.data.id + ">" + d.target.data.id);
            applyDuration(lSel.exit(), duration).attr("opacity", 0).remove();

            const lEnter = lSel.enter().append("path")
                .attr("class", d => "tree-link" + (d.tdata.type === "dead_path" ? " dead-link" : ""))
                .attr("opacity", 0)
                .attr("d", curveV)
                .attr("stroke", d => {
                    if (!d.tdata) return C.link;
                    if (d.tdata.type === "dead_path") return C.dead;
                    if (d.tdata.type === "issue") return C.issue;
                    if (d.tdata.type === "path_node") return C.path;
                    if (d.tdata.type === "function") return C.func;
                    return C.link;
                });

            applyDuration(lEnter.merge(lSel), duration)
                .attr("d", curveV)
                .attr("opacity", d => d.tdata.type === "dead_path" ? 0.25 : 0.4);

            /* Nodes */
            const nSel = nodeG.selectAll("g.tree-node").data(allNodes, d => d.data.id);
            applyDuration(nSel.exit(), duration).attr("opacity", 0).remove();

            const nEnter = nSel.enter().append("g")
                .attr("class", d => "tree-node" + (d.data.status === "active" ? " scanning" : ""))
                .attr("transform", d => {
                    const old = positions.get(d.data.id);
                    const px = old ? old.x : (d.parent ? d.parent.x : d.x);
                    const py = old ? old.y : (d.parent ? d.parent.y : d.y);
                    return "translate(" + px + "," + py + ")";
                })
                .attr("opacity", 0);

            /* Pulse ring for active */
            nEnter.append("circle").attr("class", "pulse-ring")
                .attr("r", 10)
                .attr("stroke", d => nodeColor(d.data));

            /* Main circle */
            nEnter.append("circle").attr("class", "nd")
                .attr("r", d => nodeR(d.data))
                .attr("fill", d => nodeColor(d.data));

            /* Label */
            nEnter.append("text")
                .attr("dy", d => nodeR(d.data) + 13)
                .attr("text-anchor", "middle")
                .text(d => graphNodeLabel(d.data, compact));

            /* Dead-end cross marker */
            nEnter.filter(d => d.data.type === "dead_path").append("g")
                .attr("class", "dead-marker")
                .each(function(d) {
                    const s = 4;
                    d3.select(this).append("line").attr("x1", -s).attr("y1", -s).attr("x2", s).attr("y2", s);
                    d3.select(this).append("line").attr("x1", s).attr("y1", -s).attr("x2", -s).attr("y2", s);
                });

            /* Dead-end reason label */
            nEnter.filter(d => d.data.type === "dead_path" && d.data.status)
                .append("text")
                .attr("class", "dead-reason")
                .attr("dy", d => -(nodeR(d.data) + 6))
                .attr("text-anchor", "middle")
                .attr("fill", "#805050")
                .attr("font-size", "8px")
                .text(d => {
                    if (compact) return "";
                    const s = String(d.data.status);
                    return s.startsWith("pruned") ? s.replace("pruned ", "").replace(/[()]/g, "") : s;
                });

            const merged = nEnter.merge(nSel);

            const moved = applyDuration(
                merged.classed("scanning", d => d.data.status === "active"),
                duration
            );
            moved
                .attr("transform", d => "translate(" + d.x + "," + d.y + ")")
                .attr("opacity", 1);

            applyDuration(merged.select("circle.nd"), duration)
                .attr("r", d => nodeR(d.data))
                .attr("fill", d => nodeColor(d.data));

            merged.select("circle.pulse-ring")
                .attr("stroke", d => nodeColor(d.data));

            merged.select("text").text(d => graphNodeLabel(d.data, compact));

            /* Update dead-end markers on existing nodes that became dead */
            merged.each(function(d) {
                const g = d3.select(this);
                const hasMark = !g.select(".dead-marker").empty();
                if (d.data.type === "dead_path" && !hasMark) {
                    const mk = g.append("g").attr("class", "dead-marker");
                    const s = 4;
                    mk.append("line").attr("x1", -s).attr("y1", -s).attr("x2", s).attr("y2", s);
                    mk.append("line").attr("x1", s).attr("y1", -s).attr("x2", -s).attr("y2", s);

                    if (d.data.status) {
                        const reason = String(d.data.status);
                        g.append("text")
                            .attr("class", "dead-reason")
                            .attr("dy", -(nodeR(d.data) + 6))
                            .attr("text-anchor", "middle")
                            .attr("fill", "#805050")
                            .attr("font-size", "8px")
                            .text(compact ? "" : reason.startsWith("pruned") ? reason.replace("pruned ", "").replace(/[()]/g, "") : reason);
                    }
                }
            });

            positions = new Map();
            allNodes.forEach(n => positions.set(n.data.id, { x: n.x, y: n.y }));
            updateLabelVisibility();

            if (!didZoom && allNodes.length > 1) {
                didZoom = true;
                setTimeout(() => fitToGraph(600), 250);
            }
        }

        /* ── Sidebar updates ── */
        function updatePanel(d) {
            const s = d.stats;
            document.getElementById("p-file").textContent = d.active_file || "Idle";
            document.getElementById("p-files").textContent = s.files;
            document.getElementById("p-paths").textContent = s.paths;

            const ie = document.getElementById("p-issues");
            ie.textContent = s.total_issues;
            ie.style.color = s.total_issues > 0 ? "#d97575" : "#6bb38a";

            const ee = document.getElementById("p-errors");
            ee.textContent = s.scan_errors;
            ee.style.color = s.scan_errors > 0 ? "#d97575" : "#d4d4d4";

            const de = document.getElementById("p-degraded");
            de.textContent = s.degraded_scans;
            de.style.color = s.degraded_scans > 0 ? "#c9884c" : "#d4d4d4";

            document.getElementById("p-func").textContent = s.active_func;
            document.getElementById("p-pc").textContent = s.pc;
            document.getElementById("p-op").textContent = s.opname;
            if (typeof d.node_count === "number" && lastRenderMeta.total === 0) {
                document.getElementById("p-rendered").textContent = "0/" + d.node_count;
            }
            document.getElementById("p-mode").textContent = isPaused
                ? "Paused"
                : lastRenderMeta.mode;

            /* Functions */
            const fb = document.getElementById("p-fns");
            fb.replaceChildren();
            if (d.visited_functions && d.visited_functions.length) {
                d.visited_functions.slice(-80).forEach(fn => {
                    const el = document.createElement("div");
                    el.className = "fn-entry";
                    el.textContent = fn + "()";
                    fb.appendChild(el);
                });
            } else {
                const sp = document.createElement("span");
                sp.className = "empty";
                sp.textContent = "\\u2014";
                fb.appendChild(sp);
            }

            /* Issues */
            const ib = document.getElementById("p-iss");
            ib.replaceChildren();
            if (d.issues_list && d.issues_list.length) {
                d.issues_list.slice(-80).forEach(iss => {
                    const entry = document.createElement("div");
                    entry.className = "issue-entry";
                    const loc = document.createElement("div");
                    loc.className = "issue-loc";
                    loc.textContent = "[" + iss.kind + "] " + (iss.filename || iss.file || "") + ":" + (iss.line || iss.line_number || "");
                    entry.appendChild(loc);
                    if (iss.message) {
                        const msg = document.createElement("div");
                        msg.className = "issue-msg";
                        msg.textContent = iss.message;
                        entry.appendChild(msg);
                    }
                    ib.appendChild(entry);
                });
            } else {
                const sp = document.createElement("span");
                sp.className = "empty";
                sp.textContent = "\\u2014";
                ib.appendChild(sp);
            }
        }

        /* ── Poll ── */
        async function poll() {
            try {
                const query = isPaused
                    ? "skip_graph=1"
                    : "graph_revision=" + encodeURIComponent(String(lastGraphRevision));
                const res = await fetch("/state?" + query);
                const data = await res.json();
                updatePanel(data);
                if (Array.isArray(data.nodes) && Array.isArray(data.edges)) {
                    lastRawNodes = data.nodes;
                    lastRawEdges = data.edges;
                    lastGraphRevision = data.graph_revision;
                    render(lastRawNodes, lastRawEdges);
                }
            } catch (_) { /* retry */ }
        }

        document.getElementById("g-fit").addEventListener("click", () => fitToGraph(250));
        document.getElementById("g-pause").addEventListener("click", event => {
            isPaused = !isPaused;
            event.currentTarget.classList.toggle("active", isPaused);
            event.currentTarget.textContent = isPaused ? "Resume" : "Pause";
            updateGraphMeta(lastRenderMeta);
            if (!isPaused) {
                lastGraphRevision = -1;
                poll();
            }
        });
        document.getElementById("g-full").addEventListener("click", event => {
            showFullGraph = !showFullGraph;
            event.currentTarget.classList.toggle("active", showFullGraph);
            event.currentTarget.textContent = showFullGraph ? "Auto" : "Full";
            if (lastRawNodes.length) render(lastRawNodes, lastRawEdges);
        });

        poll();
        setInterval(poll, POLL_MS);
    })();
    </script>
</body>
</html>
"""

__all__ = ["HTML_TEMPLATE"]
