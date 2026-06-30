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

"""CLI formatters for command-level scan reports.

These adapters aggregate static, pipeline, symbolic, and verify command result
shapes. Single-execution-result rendering is owned by
``pysymex._internal.reporting.formatters``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.cli.formatters.html import HtmlFormatter
from pysymex._internal.cli.formatters.json import JsonFormatter
from pysymex._internal.cli.formatters.markdown import CliMarkdownFormatter
from pysymex._internal.cli.formatters.sarif import SarifFormatter
from pysymex._internal.cli.formatters.text.formatter import CliTextFormatter

if TYPE_CHECKING:
    from pysymex._internal.cli.formatters.base import CliFormatter


def get_formatter(format_name: str) -> CliFormatter:
    """Factory for creating the appropriate formatter instance.

    Args:
        format_name: "json", "sarif", "rich", "text", "html", or "markdown".

    Returns:
        An instance implementing Formatter.

    """
    if format_name == "json":
        return JsonFormatter()
    if format_name == "sarif":
        return SarifFormatter()
    if format_name == "rich":
        return CliTextFormatter(use_rich=True)
    if format_name == "text":
        return CliTextFormatter(use_rich=True)
    if format_name == "html":
        return HtmlFormatter()
    if format_name == "markdown":
        return CliMarkdownFormatter()

    msg = f"Unsupported formatter: {format_name}"
    raise ValueError(msg)
