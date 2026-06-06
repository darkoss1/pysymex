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

"""Reporting module for pysymex.

Lazy-loaded: symbols are resolved on first access via ``__getattr__``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from pysymex.lazy import lazy_dir, lazy_getattr

if TYPE_CHECKING:
    from pysymex.reporting.formatters import (
        Formatter,
        HTMLFormatter,
        JSONFormatter,
        MarkdownFormatter,
        TextFormatter,
        format_result,
    )
    from pysymex.reporting.html.conversion import (
        create_report_from_result,
        save_html_report,
    )
    from pysymex.reporting.html.models import (
        AnalysisReport,
        IssueReport,
    )
    from pysymex.reporting.html.rendering import (
        generate_html_report,
    )
    from pysymex.reporting.sarif import (
        SECURITY_RULES,
        SARIFGenerator,
        SARIFLog,
        SARIFResult,
        generate_sarif,
    )

_EXPORTS: dict[str, tuple[str, str]] = {
    "Formatter": ("pysymex.reporting.formatters", "Formatter"),
    "HTMLFormatter": ("pysymex.reporting.formatters", "HTMLFormatter"),
    "JSONFormatter": ("pysymex.reporting.formatters", "JSONFormatter"),
    "MarkdownFormatter": ("pysymex.reporting.formatters", "MarkdownFormatter"),
    "TextFormatter": ("pysymex.reporting.formatters", "TextFormatter"),
    "format_result": ("pysymex.reporting.formatters", "format_result"),
    "AnalysisReport": ("pysymex.reporting.html.models", "AnalysisReport"),
    "IssueReport": ("pysymex.reporting.html.models", "IssueReport"),
    "create_report_from_result": (
        "pysymex.reporting.html.conversion",
        "create_report_from_result",
    ),
    "generate_html_report": ("pysymex.reporting.html.rendering", "generate_html_report"),
    "save_html_report": ("pysymex.reporting.html.conversion", "save_html_report"),
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
