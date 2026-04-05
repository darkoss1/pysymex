# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Escape analysis for pysymex.

Determines which objects escape their allocation scope, enabling
optimizations such as stack allocation and dead-allocation elimination.

The canonical ``EscapeAnalyzer`` walks Python bytecode to track how
freshly allocated objects (BUILD_LIST, BUILD_TUPLE, etc.) flow through
stores, returns, and function calls. Results are used by
``CrossFunctionAnalyzer`` to annotate allocation sites with their
escape state.
"""

from __future__ import annotations

import types
from dataclasses import dataclass, field
from enum import Enum, auto

from pysymex._compat import get_starts_line
from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions


class EscapeState(Enum):
    """Escape state of an allocated object.

    Ordered by increasing "escape distance":

    * ``NO_ESCAPE`` – object never leaves its allocating scope
    * ``ARG_ESCAPE`` – passed as argument (may be captured by callee)
    * ``RETURN_ESCAPE`` – returned from the allocating function
    * ``GLOBAL_ESCAPE`` – stored into a global or attribute (escapes completely)
    """

    NO_ESCAPE = auto()
    ARG_ESCAPE = auto()
    RETURN_ESCAPE = auto()
    GLOBAL_ESCAPE = auto()


@dataclass
class EscapeInfo:
    """Per-allocation escape information.

    *escape_sites* records ``(line_number, description)`` pairs for each
    point where the object's escape state was escalated.
    """

    state: EscapeState
    escape_sites: list[tuple[int, str]] = field(default_factory=list[tuple[int, str]])


class EscapeAnalyzer:
    """Bytecode-level escape analyzer.

    Walks ``_cached_get_instructions(code)`` maintaining a virtual operand
    stack to track which allocation sites flow to returns, stores, or
    calls.

    Usage::

        ea = EscapeAnalyzer()
        results = ea.analyze_function(code_object)
        for pc, info in results.items():
            print(pc, info.state, info.escape_sites)
    """

    @staticmethod
    def analyze_function(code: types.CodeType) -> dict[int, EscapeInfo]:
        """Analyze object escape in a function's bytecode.

        Returns a mapping from bytecode offset (allocation site) to
        ``EscapeInfo``.
        """
        allocations: dict[int, EscapeInfo] = {}
        stack: list[int | None] = []
        instructions = _cached_get_instructions(code)
        current_line = code.co_firstlineno

        for instr in instructions:
            line = get_starts_line(instr)
            if line is not None:
                current_line = line

            opname = instr.opname
            arg = instr.argval
            pc = instr.offset

            if opname in {"BUILD_LIST", "BUILD_TUPLE", "BUILD_SET", "BUILD_MAP"}:
                count = arg or 0
                for _ in range(count if opname != "BUILD_MAP" else count * 2):
                    if stack:
                        stack.pop()
                allocations[pc] = EscapeInfo(state=EscapeState.NO_ESCAPE)
                stack.append(pc)

            elif (
                opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}
                or opname == "LOAD_CONST"
            ):
                stack.append(None)

            elif opname in {"STORE_FAST", "STORE_NAME", "STORE_DEREF"}:
                if stack:
                    stack.pop()
            elif opname == "STORE_GLOBAL":
                if stack:
                    alloc_pc = stack.pop()
                    if alloc_pc is not None and alloc_pc in allocations:
                        allocations[alloc_pc].state = EscapeState.GLOBAL_ESCAPE
                        allocations[alloc_pc].escape_sites.append(
                            (current_line, f"stored to global {arg}")
                        )
            elif opname == "STORE_ATTR":
                if len(stack) >= 2:
                    stack.pop()
                    alloc_pc = stack.pop()
                    if alloc_pc is not None and alloc_pc in allocations:
                        allocations[alloc_pc].state = EscapeState.GLOBAL_ESCAPE
                        allocations[alloc_pc].escape_sites.append(
                            (current_line, f"stored to attribute {arg}")
                        )

            elif opname == "RETURN_VALUE":
                if stack:
                    alloc_pc = stack.pop()
                    if alloc_pc is not None and alloc_pc in allocations:
                        if allocations[alloc_pc].state.value < EscapeState.RETURN_ESCAPE.value:
                            allocations[alloc_pc].state = EscapeState.RETURN_ESCAPE
                            allocations[alloc_pc].escape_sites.append((current_line, "returned"))

            elif opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD"}:
                arg_count = arg if arg is not None else 0
                for _ in range(arg_count):
                    if stack:
                        alloc_pc = stack.pop()
                        if alloc_pc is not None and alloc_pc in allocations:
                            if allocations[alloc_pc].state == EscapeState.NO_ESCAPE:
                                allocations[alloc_pc].state = EscapeState.ARG_ESCAPE
                                allocations[alloc_pc].escape_sites.append(
                                    (current_line, "passed as argument")
                                )
                if stack:
                    stack.pop()
                stack.append(None)

            elif opname.startswith("BINARY_") or opname == "COMPARE_OP":
                if len(stack) >= 2:
                    stack.pop()
                    stack.pop()
                stack.append(None)
            elif opname.startswith("UNARY_"):
                if stack:
                    stack.pop()
                stack.append(None)
            elif opname == "POP_TOP":
                if stack:
                    stack.pop()
            elif opname == "DUP_TOP":
                if stack:
                    stack.append(stack[-1])

        return allocations


__all__ = [
    "EscapeAnalyzer",
    "EscapeInfo",
    "EscapeState",
]
