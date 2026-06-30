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

"""Graph rendering script section for the realtime visualizer template."""

from __future__ import annotations

REALTIME_TEMPLATE_SCRIPT_RENDER = """        /* ── Render ── */
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

"""
