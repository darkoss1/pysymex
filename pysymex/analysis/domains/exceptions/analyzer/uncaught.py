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

"""Infer bytecode operations that may raise uncaught exceptions."""

from __future__ import annotations

import dis
from collections import defaultdict
from collections.abc import Sequence
from types import CodeType

from pysymex.core.bytecode import get_starts_line
from pysymex.core.cache import get_instructions as cached_get_instructions


class UncaughtExceptionAnalyzer:
    """Analyzes which exceptions might propagate out of functions."""

    OPERATION_EXCEPTIONS: dict[str, list[str]] = {
        "BINARY_SUBSCR": ["KeyError", "IndexError", "TypeError"],
        "BINARY_TRUE_DIVIDE": ["ZeroDivisionError"],
        "BINARY_FLOOR_DIVIDE": ["ZeroDivisionError"],
        "BINARY_MODULO": ["ZeroDivisionError"],
        "INPLACE_TRUE_DIVIDE": ["ZeroDivisionError"],
        "INPLACE_FLOOR_DIVIDE": ["ZeroDivisionError"],
        "INPLACE_MODULO": ["ZeroDivisionError"],
        "STORE_SUBSCR": ["KeyError", "IndexError", "TypeError"],
        "DELETE_SUBSCR": ["KeyError", "IndexError", "TypeError"],
        "LOAD_ATTR": ["AttributeError"],
        "STORE_ATTR": ["AttributeError"],
        "DELETE_ATTR": ["AttributeError"],
        "IMPORT_NAME": ["ImportError", "ModuleNotFoundError"],
        "IMPORT_FROM": ["ImportError"],
    }
    BINARY_OP_EXCEPTIONS: dict[str, list[str]] = {
        "/": ["ZeroDivisionError"],
        "//": ["ZeroDivisionError"],
        "%": ["ZeroDivisionError"],
        "/=": ["ZeroDivisionError"],
        "//=": ["ZeroDivisionError"],
        "%=": ["ZeroDivisionError"],
    }

    def analyze(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> dict[str, set[str]]:
        """
        Analyze what exceptions might be raised by a function.
        Returns mapping of operation -> potential exceptions.
        """
        _ = file_path
        potential_exceptions: dict[str, set[str]] = defaultdict(set)
        instructions = cached_get_instructions(code)
        current_line = code.co_firstlineno
        protected_ranges: list[tuple[int, int, set[str]]] = []
        self._build_protected_ranges(instructions, protected_ranges)
        for instr in instructions:
            line = get_starts_line(instr)
            if line is not None:
                current_line = line
            opname = instr.opname
            exc_types = self._exceptions_for_instruction(instr)
            if exc_types:
                is_protected = False
                for start, end, caught in protected_ranges:
                    if start <= instr.offset <= end:
                        for exc in exc_types:
                            if exc in caught or "Exception" in caught or "BaseException" in caught:
                                is_protected = True
                                break
                if not is_protected:
                    for exc in exc_types:
                        potential_exceptions[str(current_line)].add(exc)
            if opname == "RAISE_VARARGS":
                pass
        return dict(potential_exceptions)

    @classmethod
    def _exceptions_for_instruction(cls, instr: dis.Instruction) -> list[str]:
        """Return conservative exception types for one bytecode instruction."""
        if instr.opname == "BINARY_OP":
            return cls.BINARY_OP_EXCEPTIONS.get(instr.argrepr, [])
        return cls.OPERATION_EXCEPTIONS.get(instr.opname, [])

    @staticmethod
    def _build_protected_ranges(
        instructions: Sequence[dis.Instruction],
        protected_ranges: list[tuple[int, int, set[str]]],
    ) -> None:
        """Populate *protected_ranges* from exception-handling bytecode.

        Works across Python versions:
        - Python < 3.11: ``SETUP_FINALLY``/``SETUP_EXCEPT`` through ``POP_BLOCK``
        - Python 3.11+: ``PUSH_EXC_INFO`` through ``POP_EXCEPT`` with
          ``CHECK_EXC_MATCH`` indicating which types are caught.
        """

        handler_info: list[tuple[int, int, set[str]]] = []
        for i, instr in enumerate(instructions):
            if instr.opname != "PUSH_EXC_INFO":
                continue
            caught: set[str] = set()
            for j in range(i + 1, min(i + 40, len(instructions))):
                if instructions[j].opname == "CHECK_EXC_MATCH":
                    if j > 0 and instructions[j - 1].opname in {
                        "LOAD_GLOBAL",
                        "LOAD_NAME",
                    }:
                        caught.add(str(instructions[j - 1].argval))
                elif instructions[j].opname == "RERAISE" and instructions[j].arg == 0:
                    break
            if not caught:
                caught = {"Exception"}
            handler_info.append((i, instr.offset, caught))

        for _idx, handler_offset, caught in handler_info:
            try_end = handler_offset
            try_start = 0

            for _prev_idx, prev_off, _ in handler_info:
                if prev_off < handler_offset and prev_off > try_start:
                    try_start = prev_off
            protected_ranges.append((try_start, try_end, caught))


__all__ = ["UncaughtExceptionAnalyzer"]
