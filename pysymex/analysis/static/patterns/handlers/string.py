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

"""Pattern handlers for string formatting and encoding operations."""

from __future__ import annotations

import dis
from collections.abc import Sequence

from pysymex.core.bytecode import get_starts_line
from pysymex.analysis.static.patterns.base import PatternHandler
from pysymex.analysis.static.patterns.kinds import PatternKind, PatternMatch
from pysymex.analysis.static.types import PyType, TypeEnvironment, TypeKind

_safe_line = get_starts_line


class StringMultiplyHandler(PatternHandler):
    """Handles string multiplication patterns (str * int)."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.STRING_MULTIPLY}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match string multiplication pattern."""
        if start_idx + 2 >= len(instructions):
            return None
        for i in range(start_idx, min(start_idx + 5, len(instructions))):
            instr = instructions[i]
            if instr.opname == "BINARY_OP" and instr.argrepr == "*":
                operand_types = self._get_operand_types(instructions, i, env)
                if operand_types:
                    left_type, right_type = operand_types
                    if (left_type.kind == TypeKind.STR and right_type.kind == TypeKind.INT) or (
                        left_type.kind == TypeKind.INT and right_type.kind == TypeKind.STR
                    ):
                        return PatternMatch(
                            kind=PatternKind.STRING_MULTIPLY,
                            confidence=0.95,
                            start_pc=instructions[start_idx].offset,
                            end_pc=instr.offset,
                            line=_safe_line(instructions[start_idx]),
                            type_refinements={"_result": PyType.str_type()},
                            guarantees=["valid_string_multiply"],
                        )
        return None

    def _get_operand_types(
        self,
        instructions: Sequence[dis.Instruction],
        op_idx: int,
        env: TypeEnvironment,
    ) -> tuple[PyType, PyType] | None:
        """Get types of operands for a binary operation."""
        types: list[PyType] = []
        for i in range(op_idx - 1, max(0, op_idx - 5), -1):
            instr = instructions[i]
            if instr.opname == "LOAD_CONST":
                val = instr.argval
                if isinstance(val, str):
                    types.append(PyType.str_type())
                elif isinstance(val, int):
                    types.append(PyType.int_type())
                elif isinstance(val, float):
                    types.append(PyType.float_type())
                else:
                    types.append(PyType.unknown())
            elif instr.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
                types.append(env.get_type(instr.argval))
            if len(types) >= 2:
                break
        if len(types) >= 2:
            return (types[1], types[0])
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        """Can raise error."""
        if error_type == "TypeError":
            return False
        return True


__all__ = ["StringMultiplyHandler"]
