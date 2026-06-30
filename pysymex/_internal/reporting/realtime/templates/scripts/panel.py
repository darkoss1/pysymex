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

"""Panel update and polling script section for the realtime visualizer template."""

from __future__ import annotations

REALTIME_TEMPLATE_SCRIPT_PANEL = """        /* ── Sidebar updates ── */
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
    </script>"""
