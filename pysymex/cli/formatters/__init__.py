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

"""CLI formatters for pysymex scan reports.

Provides a unified interface for JSON, SARIF, and Text/Rich formatting.
"""

from __future__ import annotations

from pysymex.cli.formatters.base import Formatter
from pysymex.cli.formatters.json_fmt import JsonFormatter
from pysymex.cli.formatters.sarif_fmt import SarifFormatter
from pysymex.cli.formatters.text_fmt import TextFormatter
from pysymex.cli.formatters.html_fmt import HtmlFormatter
from pysymex.cli.formatters.markdown_fmt import MarkdownFormatter


def get_formatter(format_name: str) -> Formatter:
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
        return TextFormatter(use_rich=True)
    if format_name == "html":
        return HtmlFormatter()
    if format_name == "markdown":
        return MarkdownFormatter()

    # Default is text (which might fallback to ascii if rich isn't installed
    # but the user requested 'text'. Actually in pysymex 'text' means use rich
    # gracefully fallback to ascii)
    return TextFormatter(use_rich=True)
