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

"""Body markup for the realtime HTML visualizer template."""

from __future__ import annotations

REALTIME_TEMPLATE_BODY = """    <div id="canvas"></div>

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

"""
