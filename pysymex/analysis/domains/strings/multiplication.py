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

"""Detect string multiplication with negative or excessively large factors."""

from __future__ import annotations

from types import CodeType

from pysymex.core.bytecode import get_starts_line
from pysymex.analysis.domains.strings.types import StringWarning, StringWarningKind
from pysymex.core.cache import get_instructions as cached_get_instructions


class StringMultiplicationAnalyzer:
    """
    Analyzes string multiplication operations.
    """

    def analyze(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[StringWarning]:
        """Analyze bytecode for string multiplication issues."""
        warnings: list[StringWarning] = []
        instructions = cached_get_instructions(code)
        current_line = code.co_firstlineno
        last_const: object | None = None
        for instr in instructions:
            line = get_starts_line(instr)
            if line is not None:
                current_line = line
            opname = instr.opname
            arg = instr.argval
            if opname == "LOAD_CONST":
                last_const = arg
            elif opname == "BINARY_MULTIPLY":
                if isinstance(last_const, int) and last_const < 0:
                    warnings.append(
                        StringWarning(
                            kind=StringWarningKind.STRING_MULTIPLICATION,
                            file=file_path,
                            line=current_line,
                            message="String multiplication by negative number produces empty string",
                            severity="warning",
                        )
                    )
            else:
                last_const = None
        return warnings
