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

"""Optional-chain and null-coalesce pattern handlers."""

from __future__ import annotations

import dis
from collections.abc import Sequence

from pysymex.core.bytecode import get_starts_line
from pysymex.analysis.static.patterns.base import PatternHandler
from pysymex.analysis.static.patterns.kinds import PatternKind, PatternMatch
from pysymex.analysis.static.types import TypeEnvironment

_safe_line = get_starts_line


class OptionalChainHandler(PatternHandler):
    """Handles optional chaining patterns (x and x.attr)."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.OPTIONAL_CHAIN}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match x and x.attr pattern."""
        _ = env
        if start_idx + 3 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            return None
        var_name = instr.argval
        for i in range(start_idx + 1, min(start_idx + 3, len(instructions))):
            check_instr = instructions[i]
            if check_instr.opname in {"JUMP_IF_FALSE_OR_POP", "POP_JUMP_IF_FALSE"}:
                if i + 2 < len(instructions):
                    next_load = instructions[i + 1]
                    if (
                        next_load.opname in {"LOAD_FAST", "LOAD_NAME"}
                        and next_load.argval == var_name
                    ):
                        if instructions[i + 2].opname in {"LOAD_ATTR", "LOAD_METHOD"}:
                            return PatternMatch(
                                kind=PatternKind.OPTIONAL_CHAIN,
                                confidence=0.9,
                                start_pc=instr.offset,
                                end_pc=instructions[i + 2].offset,
                                line=_safe_line(instr),
                                variables={"var_name": var_name},
                                guarantees=["safe_attribute_access", "short_circuits_on_falsy"],
                            )
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        """Can raise error."""
        if error_type == "AttributeError":
            return False
        return True


class NullCoalesceHandler(PatternHandler):
    """Handles null coalesce patterns (x or default)."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.NULL_COALESCE}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match x or default pattern."""
        _ = env
        if start_idx + 2 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            return None
        for i in range(start_idx + 1, min(start_idx + 3, len(instructions))):
            check_instr = instructions[i]
            if check_instr.opname in {"JUMP_IF_TRUE_OR_POP", "POP_JUMP_IF_TRUE"}:
                return PatternMatch(
                    kind=PatternKind.NULL_COALESCE,
                    confidence=0.9,
                    start_pc=instr.offset,
                    end_pc=check_instr.offset,
                    line=_safe_line(instr),
                    variables={"var_name": instr.argval},
                    guarantees=["provides_default_value", "result_never_none_if_default_not_none"],
                )
        return None


__all__ = ["NullCoalesceHandler", "OptionalChainHandler"]
