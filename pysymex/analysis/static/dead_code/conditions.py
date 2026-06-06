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

"""Detect conditions whose truthiness is compile-time constant (always-true / always-false)."""

from __future__ import annotations

from types import CodeType

from pysymex.analysis.static.dead_code.bytecode_helpers import cached_get_instructions
from pysymex.analysis.static.dead_code.types import DeadCode, DeadCodeKind


class RedundantConditionDetector:
    """Detects conditions that always evaluate to the same value."""

    def detect(self, code: CodeType, file_path: str = "<unknown>") -> list[DeadCode]:
        """Scan bytecode for conditional jumps preceded by constant loads."""
        dead_code: list[DeadCode] = []
        current_line = code.co_firstlineno
        stack: list[bool | None] = []
        for instr in cached_get_instructions(code):
            if instr.starts_line and type(instr.starts_line) is int:
                current_line = instr.starts_line
            opname = instr.opname
            arg = instr.argval
            if opname == "LOAD_CONST":
                stack.append(self._constant_truthiness(arg))
            elif opname == "TO_BOOL":
                if stack:
                    stack[-1] = None
            elif opname in {
                "SEND",
                "GET_AWAITABLE",
                "YIELD_VALUE",
                "RESUME",
                "GET_ITER",
                "FOR_ITER",
                "END_SEND",
            }:
                stack.clear()
            elif opname in {
                "POP_JUMP_IF_TRUE",
                "POP_JUMP_IF_FALSE",
                "POP_JUMP_FORWARD_IF_TRUE",
                "POP_JUMP_FORWARD_IF_FALSE",
            }:
                self._record_jump_condition(stack, dead_code, file_path, current_line)
            elif opname.startswith("LOAD_"):
                stack.append(None)
            elif opname.startswith("STORE_") or opname == "POP_TOP":
                if stack:
                    stack.pop()
            elif opname.startswith("BINARY_") or opname == "COMPARE_OP":
                if len(stack) >= 2:
                    stack.pop()
                    stack.pop()
                stack.append(None)
        return dead_code

    @staticmethod
    def _constant_truthiness(value: object) -> bool | None:
        """Evaluate the constant truthiness of a literal value.

        Args:
            value: The literal object value to check.

        Returns:
            True if the value is statically true, False if statically false,
            or None if the truthiness is dynamic or not easily determined statically.
        """
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        if isinstance(value, (int, float)) and value == 0:
            return False
        if isinstance(value, str) and value == "":
            return False
        return None

    @staticmethod
    def _record_jump_condition(
        stack: list[bool | None],
        dead_code: list[DeadCode],
        file_path: str,
        current_line: int,
    ) -> None:
        """Record a redundant condition issue if the top of the stack is constant.

        Detects the REDUNDANT_CONDITION bug class when a conditional jump relies
        on a value with statically known truthiness.

        Args:
            stack: The simulated constant-truthiness stack.
            dead_code: List of detected dead code occurrences to append to.
            file_path: The file path where the redundant condition was found.
            current_line: The line number in the source file.
        """
        if not stack:
            return
        cond = stack.pop()
        if cond is None:
            return
        dead_code.append(
            DeadCode(
                kind=DeadCodeKind.REDUNDANT_CONDITION,
                file=file_path,
                line=current_line,
                message=f"Condition is always {cond}",
                confidence=0.95,
            )
        )


__all__ = ["RedundantConditionDetector"]
