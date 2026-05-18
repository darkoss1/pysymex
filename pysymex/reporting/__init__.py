# pysymex: Python Symbolic Execution & Formal Verification
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

"""Reporting module for pysymex.

Lazy-loaded: symbols are resolved on first access via ``__getattr__``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from pysymex._lazy import lazy_dir, lazy_getattr

if TYPE_CHECKING:
    from pysymex.reporting.formatters import (
        Formatter as Formatter,
        HTMLFormatter as HTMLFormatter,
        JSONFormatter as JSONFormatter,
        MarkdownFormatter as MarkdownFormatter,
        TextFormatter as TextFormatter,
        format_result as format_result,
    )
    from pysymex.reporting.html import (
        AnalysisReport as AnalysisReport,
        IssueReport as IssueReport,
        create_report_from_result as create_report_from_result,
        generate_html_report as generate_html_report,
        save_html_report as save_html_report,
    )
    from pysymex.reporting.sarif import (
        SECURITY_RULES as SECURITY_RULES,
        SARIFGenerator as SARIFGenerator,
        SARIFLog as SARIFLog,
        SARIFResult as SARIFResult,
        generate_sarif as generate_sarif,
    )

_EXPORTS: dict[str, tuple[str, str]] = {
    "Formatter": ("pysymex.reporting.formatters", "Formatter"),
    "HTMLFormatter": ("pysymex.reporting.formatters", "HTMLFormatter"),
    "JSONFormatter": ("pysymex.reporting.formatters", "JSONFormatter"),
    "MarkdownFormatter": ("pysymex.reporting.formatters", "MarkdownFormatter"),
    "TextFormatter": ("pysymex.reporting.formatters", "TextFormatter"),
    "format_result": ("pysymex.reporting.formatters", "format_result"),
    "AnalysisReport": ("pysymex.reporting.html", "AnalysisReport"),
    "IssueReport": ("pysymex.reporting.html", "IssueReport"),
    "create_report_from_result": ("pysymex.reporting.html", "create_report_from_result"),
    "generate_html_report": ("pysymex.reporting.html", "generate_html_report"),
    "save_html_report": ("pysymex.reporting.html", "save_html_report"),
    "SECURITY_RULES": ("pysymex.reporting.sarif", "SECURITY_RULES"),
    "SARIFGenerator": ("pysymex.reporting.sarif", "SARIFGenerator"),
    "SARIFLog": ("pysymex.reporting.sarif", "SARIFLog"),
    "SARIFResult": ("pysymex.reporting.sarif", "SARIFResult"),
    "generate_sarif": ("pysymex.reporting.sarif", "generate_sarif"),
}


def __getattr__(name: str) -> object:
    """Getattr."""
    return lazy_getattr(name, __name__, _EXPORTS, globals())


def __dir__() -> list[str]:
    """Dir."""
    return lazy_dir(_EXPORTS, globals(), include_namespace=False)


__all__ = [
    "AnalysisReport",
    "Formatter",
    "HTMLFormatter",
    "IssueReport",
    "JSONFormatter",
    "MarkdownFormatter",
    "SARIFGenerator",
    "SARIFLog",
    "SARIFResult",
    "SECURITY_RULES",
    "TextFormatter",
    "create_report_from_result",
    "format_result",
    "generate_html_report",
    "generate_sarif",
    "save_html_report",
]
