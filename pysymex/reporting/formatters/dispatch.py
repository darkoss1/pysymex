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

"""Formatter dispatch helper."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from pysymex.reporting.formatters.json import JSONFormatter
from pysymex.reporting.formatters.markup import HTMLFormatter, MarkdownFormatter
from pysymex.reporting.formatters.rich import RichFormatter
from pysymex.reporting.formatters.text import TextFormatter

if TYPE_CHECKING:
    from pysymex.execution.results.result import ExecutionResult


def format_result(
    result: ExecutionResult,
    format_type: str = "text",
    **kwargs: object,
) -> str:
    """
    Format an execution result.
    Args:
        result: The execution result to format
        format_type: One of "text", "json", "html", "markdown", "sarif", "rich"
        **kwargs: Additional formatter options
    Returns:
        Formatted string
    Notes:
        - "text": Human-readable output with icons and formatting
        - "json": Machine-readable JSON for programmatic access
        - "html": Rich HTML report for browsers
        - "markdown": Documentation-friendly format
        - "sarif": SARIF 2.1.0 for CI/CD integration (GitHub, VS Code, etc.)
        - "rich": Rich terminal output with colors and panels
    """
    formatters = {
        "text": TextFormatter,
        "json": JSONFormatter,
        "html": HTMLFormatter,
        "markdown": MarkdownFormatter,
        "md": MarkdownFormatter,
        "rich": RichFormatter,
    }
    if format_type.lower() == "sarif":
        if hasattr(result, "to_sarif"):
            return json.dumps(result.to_sarif(), indent=2)
        return "{}"
    formatter_class = formatters.get(format_type.lower(), TextFormatter)
    if formatter_class is TextFormatter:
        color = kwargs.get("color", True)
        verbose = kwargs.get("verbose", False)
        formatter = TextFormatter(
            color=color if isinstance(color, bool) else True,
            verbose=verbose if isinstance(verbose, bool) else False,
        )
    elif formatter_class is RichFormatter:
        color = kwargs.get("color", True)
        verbose = kwargs.get("verbose", False)
        formatter = RichFormatter(
            color=color if isinstance(color, bool) else True,
            verbose=verbose if isinstance(verbose, bool) else False,
        )
    elif formatter_class is JSONFormatter:
        indent = kwargs.get("indent", 2)
        include_constraints = kwargs.get("include_constraints", False)
        formatter = JSONFormatter(
            indent=indent if isinstance(indent, int) else 2,
            include_constraints=(
                include_constraints if isinstance(include_constraints, bool) else False
            ),
        )
    else:
        formatter = formatter_class()
    return formatter.format(result)


__all__ = ["format_result"]
