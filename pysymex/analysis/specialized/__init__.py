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

"""
String Analysis for pysymex.
This module analyzes string operations including:
- Format string validation (% operator, .format(), f-strings)
- String interpolation safety
- Regex pattern validation
- SQL injection detection in string building
- Path traversal in string concatenation
"""

from __future__ import annotations

from pysymex.analysis.specialized.strings import (
    FStringAnalyzer,
    PathTraversalAnalyzer,
    PrintfFormatAnalyzer,
    RegexAnalyzer,
    SQLInjectionAnalyzer,
    StrFormatAnalyzer,
    StringAnalyzer,
    StringMultiplicationAnalyzer,
    StringWarning,
    StringWarningKind,
)

__all__ = [
    "StringWarningKind",
    "StringWarning",
    "PrintfFormatAnalyzer",
    "StrFormatAnalyzer",
    "FStringAnalyzer",
    "RegexAnalyzer",
    "SQLInjectionAnalyzer",
    "PathTraversalAnalyzer",
    "StringMultiplicationAnalyzer",
    "StringAnalyzer",
]
