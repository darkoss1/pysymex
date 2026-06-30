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

"""Define component-level CSS templates for PySymex HTML reports."""

from __future__ import annotations

HTML_STYLES_COMPONENTS = """        .input-block {{
            font-family: var(--mono);
            font-size: 0.8125rem;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 10px 12px;
            overflow-x: auto;
        }}
        .input-block strong {{
            display: block;
            font-family: var(--sans);
            font-size: 0.6875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 6px;
        }}
        .input-block code {{ color: var(--accent); }}
        .analysis-error {{
            background: var(--danger-bg);
            border: 1px solid #fecdca;
            border-left: 3px solid var(--danger);
            border-radius: var(--radius);
            margin-bottom: 16px;
            padding: 12px 16px;
            font-size: 0.875rem;
        }}
        .analysis-error strong {{
            color: var(--danger);
        }}
        .empty-state {{
            padding: 28px 20px;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.875rem;
        }}
        .empty-state h3 {{
            font-size: 0.9375rem;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 6px;
        }}
        .empty-state--error h3 {{
            color: var(--danger);
        }}
        .empty-state--ok h3 {{
            color: var(--ok);
        }}
        .resource-empty {{
            padding: 16px 20px;
            color: var(--text-muted);
            font-size: 0.875rem;
        }}"""
