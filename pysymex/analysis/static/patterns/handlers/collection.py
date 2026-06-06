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

"""Pattern handlers for collection mutation operations (``append``, ``extend``, etc.)."""

from __future__ import annotations

import dis
from collections.abc import Sequence

from pysymex.core.bytecode import get_starts_line
from pysymex.analysis.static.patterns._calls import call_arg_count, is_positional_call_instruction
from pysymex.analysis.static.patterns.base import PatternHandler
from pysymex.analysis.static.patterns.kinds import PatternKind, PatternMatch
from pysymex.analysis.static.types import TypeEnvironment, TypeKind

_safe_line = get_starts_line


class SafeCollectionHandler(PatternHandler):
    """Handles safe collection operations that don't raise errors."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {
            PatternKind.LIST_APPEND,
            PatternKind.LIST_EXTEND,
            PatternKind.SET_ADD,
            PatternKind.SET_DISCARD,
        }

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match safe collection operations."""
        if start_idx + 2 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            return None
        var_name = instr.argval
        var_type = env.get_type(var_name)
        for i in range(start_idx + 1, min(start_idx + 3, len(instructions))):
            attr_instr = instructions[i]
            if attr_instr.opname not in {"LOAD_ATTR", "LOAD_METHOD"}:
                continue
            method = attr_instr.argval
            call_idx = self._find_one_arg_positional_call(instructions, i + 1)
            if call_idx < 0:
                continue
            if var_type.kind == TypeKind.LIST and method in {"append", "extend"}:
                kind_map = {"append": PatternKind.LIST_APPEND, "extend": PatternKind.LIST_EXTEND}
                return PatternMatch(
                    kind=kind_map.get(method, PatternKind.LIST_APPEND),
                    confidence=0.95,
                    start_pc=instr.offset,
                    end_pc=instructions[call_idx].offset,
                    line=_safe_line(instr),
                    variables={"collection_var": var_name, "method": method},
                    guarantees=["safe_mutation", "no_index_error"],
                )
            if var_type.kind == TypeKind.SET and method in {"add", "discard"}:
                kind_map = {"add": PatternKind.SET_ADD, "discard": PatternKind.SET_DISCARD}
                return PatternMatch(
                    kind=kind_map.get(method, PatternKind.SET_ADD),
                    confidence=0.95,
                    start_pc=instr.offset,
                    end_pc=instructions[call_idx].offset,
                    line=_safe_line(instr),
                    variables={"collection_var": var_name, "method": method},
                    guarantees=["safe_mutation", "no_key_error"],
                )
        return None

    def _find_one_arg_positional_call(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
    ) -> int:
        for i in range(start_idx, min(start_idx + 10, len(instructions))):
            instr = instructions[i]
            if is_positional_call_instruction(instr) and call_arg_count(instr) == 1:
                return i
        return -1

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        """Can raise error."""
        method = match.variables.get("method")
        if method == "discard" and error_type == "KeyError":
            return False
        if method in {"append", "extend", "add"} and error_type in {"IndexError", "KeyError"}:
            return False
        return True


__all__ = ["SafeCollectionHandler"]
