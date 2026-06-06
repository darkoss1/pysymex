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

"""Orchestrate string safety analysis across format, f-string, regex, and security checks."""

from __future__ import annotations

from pysymex.logger import get_logger
from types import CodeType

from pysymex.analysis.domains.exceptions.analyzer.core import analyze_nested_code_objects
from pysymex.analysis.domains.strings.fstrings import FStringAnalyzer
from pysymex.analysis.domains.strings.multiplication import StringMultiplicationAnalyzer
from pysymex.analysis.domains.strings.security import PathTraversalAnalyzer, SQLInjectionAnalyzer
from pysymex.analysis.domains.strings.types import StringWarning

logger = get_logger(__name__)


class StringAnalyzer:
    """
    High-level interface for string analysis.
    """

    def __init__(self) -> None:
        self.fstring_analyzer = FStringAnalyzer()
        self.sql_analyzer = SQLInjectionAnalyzer()
        self.path_analyzer = PathTraversalAnalyzer()
        self.mult_analyzer = StringMultiplicationAnalyzer()

    def analyze_source(
        self,
        source: str,
        file_path: str = "<unknown>",
    ) -> list[StringWarning]:
        """Analyze source for string issues."""
        warnings: list[StringWarning] = []
        warnings.extend(self.fstring_analyzer.analyze_source(source, file_path))
        warnings.extend(self.sql_analyzer.analyze_source(source, file_path))
        warnings.extend(self.path_analyzer.analyze_source(source, file_path))
        return warnings

    def analyze_function(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[StringWarning]:
        """Analyze function for string issues."""
        warnings: list[StringWarning] = []
        warnings.extend(self.mult_analyzer.analyze(code, file_path))
        return warnings

    def analyze_file(self, file_path: str) -> list[StringWarning]:
        """Analyze file for string issues."""
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                source = f.read()
            warnings = self.analyze_source(source, file_path)
            code = compile(source, file_path, "exec")
            warnings.extend(self.analyze_function(code, file_path))
            analyze_nested_code_objects(code, file_path, warnings, self.analyze_function)
            return warnings
        except (OSError, SyntaxError):
            logger.debug("String analysis failed for file %s", file_path, exc_info=True)
            return []
