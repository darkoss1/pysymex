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

"""Recognise safe iteration patterns (e.g. ``for item in seq``) to suppress false positives."""

from __future__ import annotations

import dis
from collections.abc import Sequence

from pysymex.core.bytecode import get_starts_line
from pysymex.analysis.static.patterns._calls import is_call_instruction
from pysymex.analysis.static.patterns.base import PatternHandler
from pysymex.analysis.static.patterns.kinds import PatternKind, PatternMatch
from pysymex.analysis.static.types import TypeEnvironment

_safe_line = get_starts_line


class SafeIterationHandler(PatternHandler):
    """Handles safe iteration patterns that can't cause index errors."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {
            PatternKind.ENUMERATE_ITER,
            PatternKind.ZIP_ITER,
            PatternKind.DICT_ITEMS_ITER,
            PatternKind.DICT_KEYS_ITER,
            PatternKind.DICT_VALUES_ITER,
            PatternKind.RANGE_ITER,
        }

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match safe iteration patterns."""
        if start_idx >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname == "GET_ITER":
            return self._match_iteration_source(instructions, start_idx, env)
        return None

    def _match_iteration_source(
        self,
        instructions: Sequence[dis.Instruction],
        get_iter_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Identify the source of iteration."""
        _ = env
        if get_iter_idx < 1:
            return None
        prev_idx = get_iter_idx - 1
        while prev_idx >= 0:
            prev_instr = instructions[prev_idx]
            if is_call_instruction(prev_instr):
                return self._identify_iterable_call(instructions, prev_idx, get_iter_idx, env)
            if prev_instr.opname in {"LOAD_ATTR", "LOAD_METHOD"}:
                match = self._match_dict_iteration_method(prev_instr, instructions[get_iter_idx])
                if match is not None:
                    return match
            prev_idx -= 1
            if prev_idx < get_iter_idx - 10:
                break
        return None

    @staticmethod
    def _match_dict_iteration_method(
        prev_instr: dis.Instruction,
        get_iter_instr: dis.Instruction,
    ) -> PatternMatch | None:
        attr = prev_instr.argval
        if attr not in {"items", "keys", "values"}:
            return None
        kind_map = {
            "items": PatternKind.DICT_ITEMS_ITER,
            "keys": PatternKind.DICT_KEYS_ITER,
            "values": PatternKind.DICT_VALUES_ITER,
        }
        return PatternMatch(
            kind=kind_map[attr],
            confidence=0.9,
            start_pc=prev_instr.offset,
            end_pc=get_iter_instr.offset,
            line=_safe_line(prev_instr),
            guarantees=["safe_iteration", "no_index_error"],
        )

    def _identify_iterable_call(
        self,
        instructions: Sequence[dis.Instruction],
        call_idx: int,
        get_iter_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Identify calls that produce safe iterables."""
        _ = env
        for i in range(call_idx - 1, max(0, call_idx - 10), -1):
            instr = instructions[i]
            if instr.opname not in {"LOAD_GLOBAL", "LOAD_NAME", "LOAD_BUILTIN"}:
                continue
            func_name = instr.argval
            if func_name == "enumerate":
                return self._call_match(
                    PatternKind.ENUMERATE_ITER,
                    instr,
                    instructions[get_iter_idx],
                    ["index_always_valid", "yields_index_value_pairs"],
                )
            if func_name == "zip":
                return self._call_match(
                    PatternKind.ZIP_ITER, instr, instructions[get_iter_idx], ["stops_at_shortest"]
                )
            if func_name == "range":
                return self._call_match(
                    PatternKind.RANGE_ITER, instr, instructions[get_iter_idx], ["bounded_iteration"]
                )
        return None

    @staticmethod
    def _call_match(
        kind: PatternKind,
        instr: dis.Instruction,
        get_iter_instr: dis.Instruction,
        guarantees: list[str],
    ) -> PatternMatch:
        return PatternMatch(
            kind=kind,
            confidence=0.95,
            start_pc=instr.offset,
            end_pc=get_iter_instr.offset,
            line=_safe_line(instr),
            guarantees=["safe_iteration", *guarantees],
        )

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        """Can raise error."""
        if error_type == "IndexError" and "safe_iteration" in match.guarantees:
            return False
        return True


__all__ = ["SafeIterationHandler"]
