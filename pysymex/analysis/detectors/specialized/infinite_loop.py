# pysymex: Python Symbolic Execution & Formal Verification
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

from __future__ import annotations

import z3
from typing import TYPE_CHECKING

from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, DisInstruction, IsSatFn

if TYPE_CHECKING:
    from pysymex.core.state import VMState


class InfiniteLoopDetector(Detector):
    """Detects potential infinite loops via iteration counting and condition analysis.

    Attributes:
        _loop_counters: Per-PC iteration count.
        _max_iterations: Threshold that triggers an infinite-loop report.
    """

    name = "infinite-loop"
    description = "Detects potential infinite loops"
    issue_kind = IssueKind.INFINITE_LOOP
    relevant_opcodes = frozenset(
        {"JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT", "POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE"}
    )

    def __init__(self) -> None:
        self._loop_counters: dict[int, int] = {}
        self._max_iterations = 1000

    def check(
        self,
        state: VMState,
        instruction: DisInstruction,
        is_satisfiable_fn: IsSatFn,
    ) -> Issue | None:
        """Check for infinite loop patterns."""
        if instruction.opname in ("JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT"):
            pc = state.pc
            self._loop_counters[pc] = self._loop_counters.get(pc, 0) + 1
            if self._loop_counters[pc] > self._max_iterations:
                return Issue(
                    kind=IssueKind.INFINITE_LOOP,
                    message=f"Potential infinite loop detected (>{self._max_iterations} iterations)",
                    pc=state.pc,
                )
        if instruction.opname in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE"):
            if state.stack:
                from pysymex.core.types.scalars import SymbolicValue

                cond = state.peek()
                if isinstance(cond, SymbolicValue):
                    always_true = [
                        *state.path_constraints,
                        cond.could_be_truthy(),
                    ]
                    can_be_false = [
                        *state.path_constraints,
                        z3.Not(cond.could_be_truthy()),
                    ]

                    if is_satisfiable_fn(always_true) and not is_satisfiable_fn(can_be_false):
                        target_pc = instruction.argval if instruction.argval is not None else 0
                        is_backward = target_pc < state.pc

                        if is_backward:
                            return Issue(
                                kind=IssueKind.INFINITE_LOOP,
                                message="Potential infinite loop detected (condition always true)",
                                pc=state.pc,
                            )
                        else:
                            return None
        return None
