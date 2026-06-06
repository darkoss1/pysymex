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

"""Detect bytecode after unconditional returns, raises, or jumps that can never execute."""

from __future__ import annotations

import dis
import inspect
from collections.abc import Sequence
from types import CodeType

from pysymex.analysis.static.dead_code.bytecode_helpers import cached_get_instructions
from pysymex.analysis.static.dead_code.types import DeadCode, DeadCodeKind


class UnreachableCodeDetector:
    """Detects unreachable code after control-flow terminators."""

    _GENERATOR_FLAG = inspect.CO_GENERATOR
    _ASYNC_GENERATOR_FLAG = inspect.CO_ASYNC_GENERATOR
    _COROUTINE_FLAG = inspect.CO_COROUTINE

    def detect(self, code: CodeType, file_path: str = "<unknown>") -> list[DeadCode]:
        """Walk bytecode for instructions following terminators that are never reached."""
        dead_code: list[DeadCode] = []
        instructions = cached_get_instructions(code)
        if not instructions:
            return dead_code
        is_generator = bool(code.co_flags & self._GENERATOR_FLAG)
        is_async = bool(code.co_flags & self._COROUTINE_FLAG)
        is_async_gen = bool(code.co_flags & self._ASYNC_GENERATOR_FLAG)
        is_genexpr = (
            code.co_qualname.endswith(".<genexpr>")
            if hasattr(code, "co_qualname")
            else code.co_name == "<genexpr>"
        )
        jump_targets = {instr.offset for instr in instructions if instr.is_jump_target}
        unreachable = False
        unreachable_start: int | None = None
        unreachable_start_idx: int | None = None
        terminator_line: int | None = None
        current_line = code.co_firstlineno
        for i, instr in enumerate(instructions):
            current_line = self._line_for_instruction(instr, current_line)
            if instr.offset in jump_targets or instr.opname == "PUSH_EXC_INFO":
                if unreachable and unreachable_start and instr.opname != "PUSH_EXC_INFO":
                    if self._region_has_user_code(
                        instructions, unreachable_start_idx, i, terminator_line
                    ):
                        dead_code.append(
                            DeadCode(
                                kind=DeadCodeKind.UNREACHABLE_CODE,
                                file=file_path,
                                line=unreachable_start,
                                end_line=current_line - 1,
                                message="Unreachable code after return/raise",
                            )
                        )
                unreachable = False
                unreachable_start = None
                unreachable_start_idx = None
            if unreachable:
                continue
            if instr.opname in {"RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS", "RERAISE"}:
                if i + 1 < len(instructions) and instructions[i + 1].offset not in jump_targets:
                    unreachable = True
                    unreachable_start_idx = i + 1
                    terminator_line = current_line
                    unreachable_start = self._line_for_instruction(
                        instructions[i + 1], current_line
                    )
        if unreachable and unreachable_start:
            if (
                is_genexpr
                or is_generator
                or is_async
                or is_async_gen
                or self._is_only_implicit_return(
                    instructions, unreachable_start_idx, len(instructions)
                )
            ):
                return dead_code
            if self._region_has_user_code(
                instructions, unreachable_start_idx, len(instructions), terminator_line
            ):
                dead_code.append(
                    DeadCode(
                        kind=DeadCodeKind.UNREACHABLE_CODE,
                        file=file_path,
                        line=unreachable_start,
                        message="Unreachable code at end of function",
                    )
                )
        return dead_code

    @staticmethod
    def _line_for_instruction(instr: dis.Instruction, current_line: int) -> int:
        """Retrieve the source line number for an instruction.

        Args:
            instr: The bytecode instruction.
            current_line: The default fallback line number.

        Returns:
            The associated line number for the instruction.
        """
        is_start = instr.starts_line
        if is_start:
            if type(is_start) is int:
                return is_start
            if hasattr(instr, "positions") and instr.positions and instr.positions.lineno:
                return instr.positions.lineno
        return current_line

    @staticmethod
    def _region_has_user_code(
        instructions: Sequence[dis.Instruction],
        start_idx: int | None,
        end_idx: int,
        terminator_line: int | None,
    ) -> bool:
        """Check if an instruction range contains user code lines after a terminator line.

        Args:
            instructions: Sequence of bytecode instructions.
            start_idx: Starting index of the region.
            end_idx: Ending index of the region.
            terminator_line: The source line number containing the terminator.

        Returns:
            True if the region contains user code that executes after the terminator,
            otherwise False.
        """
        if start_idx is None:
            return False
        for j in range(start_idx, end_idx):
            line_val = UnreachableCodeDetector._line_for_instruction(instructions[j], 0)
            if line_val and (terminator_line is None or line_val > terminator_line):
                return True
        return False

    @staticmethod
    def _is_only_implicit_return(
        instructions: Sequence[dis.Instruction],
        start_idx: int | None,
        end_idx: int,
    ) -> bool:
        """Check if the instruction region contains only implicit return bytecode.

        Args:
            instructions: Sequence of bytecode instructions.
            start_idx: Starting index of the region.
            end_idx: Ending index of the region.

        Returns:
            True if the region contains only implicit clean-up and return instructions
            (e.g., return None), otherwise False.
        """
        if start_idx is None or start_idx >= end_idx:
            return False
        allowed = {
            "RETURN_VALUE",
            "RETURN_CONST",
            "LOAD_CONST",
            "NOP",
            "RESUME",
            "POP_TOP",
            "PUSH_NULL",
        }
        return all(instructions[i].opname in allowed for i in range(start_idx, end_idx))


__all__ = ["UnreachableCodeDetector"]
