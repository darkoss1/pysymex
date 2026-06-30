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

"""Define layout-level CSS templates for PySymex HTML reports.

Light, document-style layout intended for archived scan artifacts: flat panels,
diagnostic issue rows, and tabular resource metrics.
"""

from __future__ import annotations

HTML_STYLES_LAYOUT = """        :root {{
            --bg: #f4f5f7;
            --surface: #ffffff;
            --surface-muted: #eef0f3;
            --text: #1a1d21;
            --text-muted: #5c6570;
            --border: #d8dde3;
            --border-strong: #b8c0ca;
            --accent: #0f4c81;
            --danger: #b42318;
            --danger-bg: #fef3f2;
            --warn: #b54708;
            --warn-bg: #fffaeb;
            --ok: #067647;
            --ok-bg: #ecfdf3;
            --info: #175cd3;
            --info-bg: #eff8ff;
            --mono: ui-monospace, "Cascadia Code", "SF Mono", Consolas, monospace;
            --sans: "Segoe UI", system-ui, -apple-system, sans-serif;
            --radius: 4px;
            --max: 960px;
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: var(--sans);
            font-size: 15px;
            line-height: 1.55;
            color: var(--text);
            background: var(--bg);
            padding: 24px 16px 48px;
        }}
        .page {{
            max-width: var(--max);
            margin: 0 auto;
        }}
        .report-header {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 20px 24px;
            margin-bottom: 16px;
        }}
        .report-header__top {{
            display: flex;
            flex-wrap: wrap;
            align-items: baseline;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 16px;
        }}
        .report-title {{
            font-size: 1.125rem;
            font-weight: 600;
            letter-spacing: -0.01em;
        }}
        .report-badge {{
            font-family: var(--mono);
            font-size: 0.75rem;
            padding: 2px 8px;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            color: var(--text-muted);
            background: var(--surface-muted);
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 8px 24px;
            font-size: 0.8125rem;
        }}
        .meta-grid dt {{
            color: var(--text-muted);
            font-weight: 500;
            margin-bottom: 2px;
        }}
        .meta-grid dd {{
            font-family: var(--mono);
            font-size: 0.8125rem;
            word-break: break-all;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1px;
            background: var(--border);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            overflow: hidden;
            margin-bottom: 16px;
        }}
        .summary__cell {{
            background: var(--surface);
            padding: 14px 16px;
        }}
        .summary__label {{
            font-size: 0.6875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--text-muted);
            margin-bottom: 4px;
        }}
        .summary__value {{
            font-size: 1.25rem;
            font-weight: 600;
            font-variant-numeric: tabular-nums;
        }}
        .summary__value--danger {{ color: var(--danger); }}
        .summary__value--ok {{ color: var(--ok); }}
        .summary__value--warn {{ color: var(--warn); }}
        .summary__value--neutral {{ color: var(--text); }}
        .section {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            margin-bottom: 16px;
        }}
        .section__head {{
            padding: 12px 20px;
            border-bottom: 1px solid var(--border);
            font-size: 0.8125rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
        }}
        .section__body {{
            padding: 0;
        }}
        .issue {{
            border-bottom: 1px solid var(--border);
            border-left: 3px solid var(--border-strong);
        }}
        .issue--critical {{ border-left-color: var(--danger); }}
        .issue--warning {{ border-left-color: var(--warn); }}
        .issue--info {{ border-left-color: var(--info); }}
        .issue:last-child {{ border-bottom: none; }}
        .issue__static {{
            padding: 12px 20px 12px 17px;
        }}
        .issue summary {{
            list-style: none;
            cursor: pointer;
            padding: 12px 20px 12px 17px;
            display: block;
            position: relative;
        }}
        .issue summary::-webkit-details-marker {{ display: none; }}
        .issue summary:hover {{ background: var(--surface-muted); }}
        .issue__title {{
            display: flex;
            flex-wrap: wrap;
            align-items: baseline;
            justify-content: space-between;
            gap: 8px 16px;
            margin-bottom: 4px;
            padding-right: 1.25rem;
        }}
        .issue summary::after {{
            content: "+";
            position: absolute;
            right: 20px;
            top: 14px;
            font-family: var(--mono);
            color: var(--text-muted);
            font-size: 0.875rem;
            line-height: 1;
        }}
        .issue[open] summary::after {{ content: "−"; }}
        .issue__heading {{
            display: flex;
            flex-wrap: wrap;
            align-items: baseline;
            gap: 0.35em 0.5em;
            min-width: 0;
        }}
        .issue__rank {{
            font-family: var(--mono);
            font-size: 0.75rem;
            font-weight: 500;
            text-transform: lowercase;
        }}
        .issue__rank--critical {{ color: var(--danger); }}
        .issue__rank--warning {{ color: var(--warn); }}
        .issue__rank--info {{ color: var(--info); }}
        .issue__kind {{
            font-family: var(--mono);
            font-weight: 600;
            font-size: 0.875rem;
            letter-spacing: 0.02em;
        }}
        .issue__loc {{
            font-family: var(--mono);
            font-size: 0.75rem;
            color: var(--text-muted);
            white-space: nowrap;
        }}
        .issue__msg {{
            color: var(--text-muted);
            font-size: 0.875rem;
            padding-right: 1.25rem;
        }}
        .issue__detail {{
            padding: 0 20px 14px 17px;
            border-top: 1px dashed var(--border);
            background: var(--surface-muted);
        }}
        .metrics {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }}
        .metrics th,
        .metrics td {{
            padding: 10px 20px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        .metrics th {{
            font-size: 0.6875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            background: var(--surface-muted);
            width: 40%;
        }}
        .metrics td {{
            font-family: var(--mono);
            font-variant-numeric: tabular-nums;
        }}
        .metrics tr:last-child th,
        .metrics tr:last-child td {{ border-bottom: none; }}
        .report-footer {{
            font-size: 0.8125rem;
            color: var(--text-muted);
            text-align: center;
            padding-top: 8px;
        }}
        .report-footer a {{
            color: var(--accent);
            text-decoration: none;
        }}
        .report-footer a:hover {{ text-decoration: underline; }}
        @media (max-width: 640px) {{
            .summary {{ grid-template-columns: repeat(2, 1fr); }}
        }}"""
