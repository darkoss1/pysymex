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

"""Pattern handlers for dictionary subscript accesses."""

from __future__ import annotations

import dis
from collections.abc import Sequence

from pysymex.core.bytecode import get_starts_line
from pysymex.analysis.static.patterns.base import PatternHandler
from pysymex.analysis.static.patterns.kinds import PatternKind, PatternMatch
from pysymex.analysis.static.types import PyType, TypeEnvironment, TypeKind

_safe_line = get_starts_line


class DefaultDictAccessHandler(PatternHandler):
    """Handles defaultdict[key] access pattern."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.DEFAULTDICT_ACCESS}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match defaultdict subscript access."""
        if start_idx + 2 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            return None
        var_name = instr.argval
        var_type = env.get_type(var_name)
        if var_type.kind != TypeKind.DEFAULTDICT:
            return None
        for i in range(start_idx + 1, min(start_idx + 5, len(instructions))):
            if instructions[i].opname == "BINARY_SUBSCR":
                return PatternMatch(
                    kind=PatternKind.DEFAULTDICT_ACCESS,
                    confidence=0.99,
                    start_pc=instr.offset,
                    end_pc=instructions[i].offset,
                    line=_safe_line(instr),
                    variables={"dict_var": var_name},
                    guarantees=["never_raises_key_error", "returns_default_factory_value"],
                )
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        """Can raise error."""
        if error_type == "KeyError":
            return False
        return True


class CounterAccessHandler(PatternHandler):
    """Handles Counter[key] access pattern."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.COUNTER_ACCESS}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match Counter subscript access."""
        if start_idx + 2 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            return None
        var_name = instr.argval
        var_type = env.get_type(var_name)
        if var_type.kind != TypeKind.COUNTER:
            return None
        for i in range(start_idx + 1, min(start_idx + 5, len(instructions))):
            if instructions[i].opname == "BINARY_SUBSCR":
                return PatternMatch(
                    kind=PatternKind.COUNTER_ACCESS,
                    confidence=0.99,
                    start_pc=instr.offset,
                    end_pc=instructions[i].offset,
                    line=_safe_line(instr),
                    variables={"dict_var": var_name},
                    type_refinements={"_result": PyType.int_type()},
                    guarantees=["never_raises_key_error", "returns_zero_for_missing"],
                )
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        """Can raise error."""
        if error_type == "KeyError":
            return False
        return True


__all__ = ["CounterAccessHandler", "DefaultDictAccessHandler"]
