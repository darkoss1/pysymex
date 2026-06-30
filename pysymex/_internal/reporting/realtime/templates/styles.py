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

"""CSS styles for the realtime HTML visualizer template."""

from __future__ import annotations

REALTIME_TEMPLATE_STYLES = """    <style>
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
    </style>"""
