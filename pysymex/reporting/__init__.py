# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

from importlib import import_module

_EXPORTS: dict[str, tuple[str, str]] = {
    "Formatter": ("pysymex.reporting.formatters", "Formatter"),
    "HTMLFormatter": ("pysymex.reporting.formatters", "HTMLFormatter"),
    "JSONFormatter": ("pysymex.reporting.formatters", "JSONFormatter"),
    "MarkdownFormatter": ("pysymex.reporting.formatters", "MarkdownFormatter"),
    "TextFormatter": ("pysymex.reporting.formatters", "TextFormatter"),
    "format_result": ("pysymex.reporting.formatters", "format_result"),
    "AnalysisReport": ("pysymex.reporting.html_report", "AnalysisReport"),
    "IssueReport": ("pysymex.reporting.html_report", "IssueReport"),
    "create_report_from_result": ("pysymex.reporting.html_report", "create_report_from_result"),
    "generate_html_report": ("pysymex.reporting.html_report", "generate_html_report"),
    "save_html_report": ("pysymex.reporting.html_report", "save_html_report"),
    "SECURITY_RULES": ("pysymex.reporting.sarif", "SECURITY_RULES"),
    "SARIFGenerator": ("pysymex.reporting.sarif", "SARIFGenerator"),
    "SARIFLog": ("pysymex.reporting.sarif", "SARIFLog"),
    "SARIFResult": ("pysymex.reporting.sarif", "SARIFResult"),
    "generate_sarif": ("pysymex.reporting.sarif", "generate_sarif"),
}


def __getattr__(name: str) -> object:
    """Getattr."""
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'pysymex.reporting' has no attribute {name!r}")
    module_path, attr_name = target
    module = import_module(module_path)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Dir."""
    return list(_EXPORTS.keys())


__all__: list[str] = [
    "SECURITY_RULES",
    "AnalysisReport",
    "Formatter",
    "HTMLFormatter",
    "IssueReport",
    "JSONFormatter",
    "MarkdownFormatter",
    "SARIFGenerator",
    "SARIFLog",
    "SARIFResult",
    "TextFormatter",
    "create_report_from_result",
    "format_result",
    "generate_html_report",
    "generate_sarif",
    "save_html_report",
]
