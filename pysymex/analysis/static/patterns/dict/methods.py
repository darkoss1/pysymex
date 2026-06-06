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

"""Pattern handlers for dictionary method calls (``get``, ``setdefault``, etc.)."""

from __future__ import annotations

import dis
from collections.abc import Sequence

from pysymex.core.bytecode import get_starts_line
from pysymex.analysis.static.patterns._calls import (
    call_arg_count,
    call_has_keyword_metadata,
    is_positional_call_instruction,
)
from pysymex.analysis.static.patterns.base import PatternHandler
from pysymex.analysis.static.patterns.kinds import PatternKind, PatternMatch
from pysymex.analysis.static.types import TypeEnvironment, TypeKind

_safe_line = get_starts_line


class DictGetHandler(PatternHandler):
    """Handles dict.get(key, default) pattern."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.DICT_GET}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match dict.get pattern."""
        if start_idx + 2 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            return None
        dict_var = instr.argval
        dict_type = env.get_type(dict_var)
        if dict_type.kind != TypeKind.DICT and dict_type.kind != TypeKind.UNKNOWN:
            return None
        attr_idx = self._find_load_attr(instructions, start_idx + 1, "get")
        if attr_idx < 0:
            return None
        call_idx = self._find_call(instructions, attr_idx + 1, {1, 2})
        if call_idx < 0:
            return None
        arg_count = call_arg_count(instructions[call_idx])
        if arg_count is None:
            return None
        return PatternMatch(
            kind=PatternKind.DICT_GET,
            confidence=0.95,
            start_pc=instr.offset,
            end_pc=instructions[call_idx].offset,
            line=_safe_line(instr),
            variables={"dict_var": dict_var, "has_default": arg_count == 2},
            guarantees=["never_raises_key_error", "returns_default_or_value"],
        )

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        """Can raise error."""
        if error_type == "KeyError":
            return False
        return True

    def _find_load_attr(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        attr_name: str,
    ) -> int:
        """Find LOAD_ATTR/LOAD_METHOD with given attribute name."""
        for i in range(start_idx, min(start_idx + 5, len(instructions))):
            instr = instructions[i]
            if instr.opname in {"LOAD_ATTR", "LOAD_METHOD"} and instr.argval == attr_name:
                return i
        return -1

    def _find_call(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        arg_counts: set[int],
    ) -> int:
        """Find CALL instruction with specified argument count."""
        for i in range(start_idx, min(start_idx + 10, len(instructions))):
            instr = instructions[i]
            if is_positional_call_instruction(instr):
                if call_has_keyword_metadata(instructions, i):
                    return -1
                if call_arg_count(instr) in arg_counts:
                    return i
        return -1


class DictSetdefaultHandler(PatternHandler):
    """Handles dict.setdefault(key, default) pattern."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.DICT_SETDEFAULT}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match dict.setdefault pattern."""
        if start_idx + 2 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            return None
        for i in range(start_idx + 1, min(start_idx + 5, len(instructions))):
            if instructions[i].opname in {"LOAD_ATTR", "LOAD_METHOD"}:
                if instructions[i].argval == "setdefault":
                    call_idx = self._find_positional_call(instructions, i + 1)
                    if call_idx < 0:
                        return None
                    return PatternMatch(
                        kind=PatternKind.DICT_SETDEFAULT,
                        confidence=0.95,
                        start_pc=instr.offset,
                        end_pc=instructions[call_idx].offset,
                        line=_safe_line(instr),
                        variables={"dict_var": instr.argval},
                        guarantees=["never_raises_key_error", "key_always_exists_after"],
                    )
        return None

    def _find_positional_call(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
    ) -> int:
        for i in range(start_idx, min(start_idx + 10, len(instructions))):
            instr = instructions[i]
            if (
                is_positional_call_instruction(instr)
                and not call_has_keyword_metadata(instructions, i)
                and call_arg_count(instr) in {1, 2}
            ):
                return i
        return -1

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        """Can raise error."""
        if error_type == "KeyError":
            return False
        return True


__all__ = ["DictGetHandler", "DictSetdefaultHandler"]
