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

"""Core graph setup script section for the realtime visualizer template."""

from __future__ import annotations

REALTIME_TEMPLATE_SCRIPT_CORE = """    <script>
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

"""
