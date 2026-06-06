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

"""Formatters for individual symbolic execution results.

These formatters render one execution result through the reporting API. CLI
scan aggregation across files and command modes is owned by
``pysymex.cli.formatters``.
"""

from __future__ import annotations

from pysymex.reporting.formatters.base import Formatter
from pysymex.reporting.formatters.dispatch import format_result
from pysymex.reporting.formatters.json import JSONFormatter
from pysymex.reporting.formatters.markup import (
    HTMLFormatter,
    MarkdownFormatter,
)
from pysymex.reporting.formatters.rich import RichFormatter
from pysymex.reporting.formatters.text import TextFormatter

__all__ = [
    "Formatter",
    "HTMLFormatter",
    "JSONFormatter",
    "MarkdownFormatter",
    "RichFormatter",
    "TextFormatter",
    "format_result",
]
