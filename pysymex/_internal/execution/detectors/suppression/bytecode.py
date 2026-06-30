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

"""Consolidated bytecode analysis for exception-handler suppression."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from pysymex._internal.core.bytecode import DIRECT_CALL_OPCODES
from pysymex._internal.core.exceptions.builtins import BUILTIN_EXCEPTIONS

if TYPE_CHECKING:
    import dis

_BUILTIN_EXCEPTION_TYPES_BY_NAME: Final[dict[str, type[BaseException]]] = {
    exc_type.__name__: exc_type for exc_type in BUILTIN_EXCEPTIONS
}

_CALL_PREFIX_NOOPS: Final[frozenset[str]] = frozenset(("CACHE", "PRECALL", "PUSH_NULL"))

_CONTROL_TRANSFER_OPS: Final[frozenset[str]] = frozenset(
    (
        "JUMP",
        "JUMP_ABSOLUTE",
        "JUMP_BACKWARD",
        "JUMP_BACKWARD_NO_INTERRUPT",
        "JUMP_FORWARD",
        "JUMP_IF_FALSE_OR_POP",
        "JUMP_IF_TRUE_OR_POP",
        "JUMP_NO_INTERRUPT",
        "POP_JUMP_BACKWARD_IF_FALSE",
        "POP_JUMP_BACKWARD_IF_NONE",
        "POP_JUMP_BACKWARD_IF_NOT_NONE",
        "POP_JUMP_BACKWARD_IF_TRUE",
        "POP_JUMP_FORWARD_IF_FALSE",
        "POP_JUMP_FORWARD_IF_NONE",
        "POP_JUMP_FORWARD_IF_NOT_NONE",
        "POP_JUMP_FORWARD_IF_TRUE",
        "POP_JUMP_IF_FALSE",
        "POP_JUMP_IF_NONE",
        "POP_JUMP_IF_NOT_NONE",
        "POP_JUMP_IF_TRUE",
    ),
)

_NAME_LOAD_OPS: Final[frozenset[str]] = frozenset(
    (
        "LOAD_CLASSDEREF",
        "LOAD_DEREF",
        "LOAD_FAST",
        "LOAD_FAST_CHECK",
        "LOAD_FROM_DICT_OR_DEREF",
        "LOAD_GLOBAL",
        "LOAD_NAME",
    ),
)


class SuppressionBytecodeOps:
    """Bytecode introspection operations for detector issue suppression."""

    @classmethod
    def catches_name(cls, exception_name: str, caught_names: set[str]) -> bool:
        """Return whether named exception-handler types catch *exception_name*."""
        raised_type = _BUILTIN_EXCEPTION_TYPES_BY_NAME.get(exception_name)
        if raised_type is not None:
            for caught_name in caught_names:
                handler_type = _BUILTIN_EXCEPTION_TYPES_BY_NAME.get(caught_name)
                if handler_type is not None and issubclass(raised_type, handler_type):
                    return True

        parent_names = {exception_name, "Exception", "BaseException"}
        if exception_name == "ZeroDivisionError":
            parent_names.add("ArithmeticError")
        return bool(parent_names & caught_names)

    @classmethod
    def cleanup_replaces_original_at(
        cls,
        instructions: list[dis.Instruction],
        handler_target: int,
    ) -> bool:
        """Return whether cleanup definitely replaces the active exception before reraise.

        The helper is intentionally conservative: conditional control transfer before
        the replacement raise is treated as not definite, preserving the original
        exception report for paths where cleanup may fall through to ``RERAISE``.
        """
        started = False
        for instr in instructions:
            if instr.offset == handler_target:
                started = True
            if not started:
                continue
            if instr.opname in {"CHECK_EXC_MATCH", "WITH_EXCEPT_START", "RERAISE"}:
                return False
            if instr.opname.startswith("RETURN"):
                return True
            if instr.opname == "RAISE_VARARGS":
                return isinstance(instr.arg, int) and instr.arg > 0
            if instr.opname in _CONTROL_TRANSFER_OPS:
                return False
        return False

    @classmethod
    def cleanup_reraise_at(
        cls,
        instructions: list[dis.Instruction],
        handler_target: int,
    ) -> int | None:
        """Return a cleanup-only handler epilogue's re-raise offset, if present."""
        started = False
        for instr in instructions:
            if instr.offset == handler_target:
                started = True
            if not started:
                continue
            if instr.opname == "CHECK_EXC_MATCH":
                return None
            if instr.opname == "RERAISE":
                return instr.offset
            if instr.opname.startswith("RETURN") or instr.opname in {
                "JUMP_FORWARD",
                "JUMP_ABSOLUTE",
            }:
                return None
        return None

    @classmethod
    def infer_caught_at(
        cls,
        instructions: list[dis.Instruction],
        handler_target: int,
    ) -> set[str]:
        """Infer caught exception types from handler starting at *handler_target*."""
        caught: set[str] = set()
        started = False
        type_stack: list[list[str]] = []
        saw_handler_setup = False
        saw_match_check = False
        saw_bare_handler_exit = False
        saw_reraise = False
        for instr in instructions:
            if instr.offset == handler_target:
                started = True
            if not started:
                continue
            if instr.opname == "PUSH_EXC_INFO":
                saw_handler_setup = True
                continue
            if instr.opname in _NAME_LOAD_OPS:
                name = instr.argval
                if isinstance(name, str):
                    type_stack.append([name])
                continue
            if instr.opname == "LOAD_CONST":
                value = instr.argval
                if isinstance(value, type):
                    type_stack.append([value.__name__])
                continue
            if instr.opname == "BUILD_TUPLE":
                count = instr.arg if isinstance(instr.arg, int) else 0
                if count <= 0 or count > len(type_stack):
                    type_stack.clear()
                    continue
                merged: list[str] = []
                for _ in range(count):
                    merged.extend(type_stack.pop())
                type_stack.append(merged)
                continue
            if instr.opname == "CHECK_EXC_MATCH":
                saw_match_check = True
                if type_stack:
                    caught.update(type_stack[-1])
                continue
            if instr.opname == "RERAISE":
                if not caught and saw_handler_setup and saw_bare_handler_exit:
                    break
                saw_reraise = True
                break
            if instr.opname == "POP_EXCEPT":
                saw_bare_handler_exit = True
                continue
            if instr.opname in {"END_FINALLY", "JUMP_FORWARD", "JUMP_ABSOLUTE"}:
                saw_bare_handler_exit = True
                continue
            if instr.opname.startswith("RETURN"):
                saw_bare_handler_exit = True
                continue
        if not caught:
            if saw_match_check or saw_reraise:
                return set()
            if saw_bare_handler_exit:
                caught = {"BaseException"}
        return caught

    @classmethod
    def infer_with_manager_call_at(
        cls,
        instructions: list[dis.Instruction],
        protected_start: int,
        handler_target: int,
    ) -> tuple[str, tuple[str, ...]] | None:
        """Recognize a named context-manager call around a protected region."""
        by_offset = {instr.offset: index for index, instr in enumerate(instructions)}
        handler_index = by_offset.get(handler_target)
        start_index = by_offset.get(protected_start)
        if handler_index is None or start_index is None or handler_index + 1 >= len(instructions):
            return None
        if (
            instructions[handler_index].opname != "PUSH_EXC_INFO"
            or instructions[handler_index + 1].opname != "WITH_EXCEPT_START"
        ):
            return None

        before_with_index = start_index - 1
        if before_with_index < 0 or instructions[before_with_index].opname != "BEFORE_WITH":
            return None
        call_index = before_with_index - 1
        while call_index >= 0 and instructions[call_index].opname in {"CACHE", "PRECALL"}:
            call_index -= 1
        if call_index < 0 or instructions[call_index].opname not in DIRECT_CALL_OPCODES:
            return None
        arg_count = instructions[call_index].arg
        if not isinstance(arg_count, int) or arg_count < 0:
            return None

        type_names: list[str] = []
        cursor = cls._previous_call_operand_index(instructions, call_index - 1)
        for _ in range(arg_count):
            if cursor < 0 or instructions[cursor].opname not in _NAME_LOAD_OPS:
                return None
            type_name = instructions[cursor].argval
            if not isinstance(type_name, str):
                return None
            type_names.append(type_name)
            cursor = cls._previous_call_operand_index(instructions, cursor - 1)
        if cursor < 0 or instructions[cursor].opname not in _NAME_LOAD_OPS:
            return None
        manager_name = instructions[cursor].argval
        if not isinstance(manager_name, str):
            return None
        return manager_name, tuple(reversed(type_names))

    @classmethod
    def _previous_call_operand_index(
        cls,
        instructions: list[dis.Instruction],
        cursor: int,
    ) -> int:
        """Skip non-operand call-layout opcodes before a manager or argument load."""
        while cursor >= 0 and instructions[cursor].opname in _CALL_PREFIX_NOOPS:
            cursor -= 1
        return cursor
