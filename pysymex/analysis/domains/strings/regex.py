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

"""Analyse regex patterns for syntax errors, catastrophic backtracking, and security risks."""

from __future__ import annotations

import re

from pysymex.analysis.domains.strings.types import StringWarning, StringWarningKind


class RegexAnalyzer:
    """
    Analyzes regex patterns for validity and performance.
    """

    def analyze(
        self,
        pattern: str,
        line: int,
        file_path: str,
    ) -> list[StringWarning]:
        """Analyze regex pattern."""
        warnings: list[StringWarning] = []
        try:
            re.compile(pattern)
        except re.error as e:
            warnings.append(
                StringWarning(
                    kind=StringWarningKind.INVALID_REGEX,
                    file=file_path,
                    line=line,
                    message=f"Invalid regex pattern: {e}",
                    code_snippet=pattern,
                    severity="error",
                )
            )
            return warnings
        if re.search(r"\([^)]*[+*][^)]*\)[+*]", pattern):
            warnings.append(
                StringWarning(
                    kind=StringWarningKind.REGEX_PERFORMANCE,
                    file=file_path,
                    line=line,
                    message="Nested quantifiers can cause exponential backtracking (ReDoS)",
                    code_snippet=pattern,
                    severity="warning",
                )
            )
        if ".*" in pattern and not pattern.endswith(".*"):
            if pattern.count(".*") > 1:
                warnings.append(
                    StringWarning(
                        kind=StringWarningKind.REGEX_PERFORMANCE,
                        file=file_path,
                        line=line,
                        message="Multiple .* can cause excessive backtracking",
                        code_snippet=pattern,
                    )
                )
        return warnings
