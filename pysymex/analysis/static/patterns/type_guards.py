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

"""Recognise type, None, and attribute guard patterns from bytecode."""

from __future__ import annotations

import dis
from collections.abc import Sequence

from pysymex.core.bytecode import get_starts_line
from pysymex.analysis.static.patterns._calls import call_arg_count, is_positional_call_instruction
from pysymex.analysis.static.patterns.base import PatternHandler
from pysymex.analysis.static.patterns.kinds import PatternKind, PatternMatch
from pysymex.analysis.static.types import PyType, TypeEnvironment

_safe_line = get_starts_line


class IsinstanceHandler(PatternHandler):
    """Handles isinstance(x, T) type guard pattern."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.ISINSTANCE_CHECK}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match isinstance check pattern."""
        _ = env
        if start_idx + 3 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_GLOBAL", "LOAD_NAME", "LOAD_BUILTIN"}:
            return None
        if instr.argval != "isinstance":
            return None
        var_name = None
        type_checked = None
        call_idx = -1
        for i in range(start_idx + 1, min(start_idx + 10, len(instructions))):
            check_instr = instructions[i]
            if check_instr.opname in {"LOAD_FAST", "LOAD_NAME"} and var_name is None:
                var_name = check_instr.argval
            if check_instr.opname in {"LOAD_GLOBAL", "LOAD_NAME"}:
                name = check_instr.argval
                if name in {"int", "str", "float", "bool", "list", "dict", "tuple", "set"}:
                    type_checked = name
            if is_positional_call_instruction(check_instr):
                if call_arg_count(check_instr) != 2:
                    return None
                call_idx = i
                break
        if var_name is None or call_idx < 0:
            return None
        return PatternMatch(
            kind=PatternKind.ISINSTANCE_CHECK,
            confidence=0.98,
            start_pc=instr.offset,
            end_pc=instructions[call_idx].offset,
            line=_safe_line(instr),
            variables={"var_name": var_name, "type_checked": type_checked},
            type_refinements=_type_refinements(var_name, type_checked),
            guarantees=["type_narrowing"],
        )


def _type_refinements(var_name: object, type_checked: object) -> dict[str, PyType]:
    if not isinstance(var_name, str):
        return {}
    type_map = {
        "int": PyType.int_type(),
        "str": PyType.str_type(),
        "float": PyType.float_type(),
        "bool": PyType.bool_type(),
        "list": PyType.list_type(),
        "dict": PyType.dict_type(),
        "tuple": PyType.tuple_type(),
        "set": PyType.set_type(),
    }
    if isinstance(type_checked, str) and type_checked in type_map:
        return {var_name: type_map[type_checked]}
    return {}


class NoneCheckHandler(PatternHandler):
    """Handles None check patterns (is None / is not None)."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.NONE_CHECK}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match None check pattern."""
        _ = env
        if start_idx + 2 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            return None
        var_name = instr.argval
        for i in range(start_idx + 1, min(start_idx + 5, len(instructions))):
            check_instr = instructions[i]
            if check_instr.opname == "LOAD_CONST" and check_instr.argval is None:
                if i + 1 < len(instructions) and instructions[i + 1].opname == "IS_OP":
                    is_op = instructions[i + 1]
                    return self._none_match(instr, is_op, var_name, is_op.argval == 1)
            if check_instr.opname in {"POP_JUMP_IF_NONE", "POP_JUMP_IF_NOT_NONE"}:
                return self._none_match(
                    instr,
                    check_instr,
                    var_name,
                    check_instr.opname == "POP_JUMP_IF_NOT_NONE",
                )
        return None

    @staticmethod
    def _none_match(
        instr: dis.Instruction,
        end_instr: dis.Instruction,
        var_name: object,
        is_not_none: bool,
    ) -> PatternMatch:
        return PatternMatch(
            kind=PatternKind.NONE_CHECK,
            confidence=0.99,
            start_pc=instr.offset,
            end_pc=end_instr.offset,
            line=_safe_line(instr),
            variables={"var_name": var_name, "is_not_none": is_not_none},
            guarantees=["none_check", "type_narrowing"],
        )


class HasattrHandler(PatternHandler):
    """Handles hasattr check patterns."""

    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.HASATTR_CHECK, PatternKind.HASATTR_GETATTR}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        """Match hasattr pattern."""
        _ = env
        if start_idx + 3 >= len(instructions):
            return None
        instr = instructions[start_idx]
        if instr.opname not in {"LOAD_GLOBAL", "LOAD_NAME", "LOAD_BUILTIN"}:
            return None
        if instr.argval != "hasattr":
            return None
        for i in range(start_idx + 1, min(start_idx + 10, len(instructions))):
            if not is_positional_call_instruction(instructions[i]):
                continue
            if call_arg_count(instructions[i]) != 2:
                return None
            return PatternMatch(
                kind=PatternKind.HASATTR_CHECK,
                confidence=0.95,
                start_pc=instr.offset,
                end_pc=instructions[i].offset,
                line=_safe_line(instr),
                guarantees=["attribute_check", "safe_before_access"],
            )
        return None


__all__ = ["HasattrHandler", "IsinstanceHandler", "NoneCheckHandler"]
