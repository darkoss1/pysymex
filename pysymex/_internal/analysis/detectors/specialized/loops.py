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

"""Infinite Loop detector module.

Detects potential infinite loops from structural back-edge evidence and trivial
jump conditions.

Bug Class Detected:
    Infinite Loop.

Required Evidence:
    A self-looping back edge or a constant true loop condition.

Issue Kinds:
    IssueKind.INFINITE_LOOP
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.analysis.detectors.detector.contract import Detector
from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
from pysymex._internal.core.outcome import IssueKind

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState


class InfiniteLoopDetector(Detector):
    """Detect potential infinite loops from structural and condition evidence."""

    name = "infinite-loop"
    description = "Detects potential infinite loops"
    issue_kind = IssueKind.INFINITE_LOOP
    relevant_opcodes = frozenset(
        ("JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT", "POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE"),
    )

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        is_satisfiable_fn: IsSatFn,
    ) -> Issue | None:
        """Check for infinite loop patterns."""
        _ = is_satisfiable_fn
        if instruction.opname in ("JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT"):
            target_pc = instruction.argval if isinstance(instruction.argval, int) else None
            if target_pc is not None and target_pc == instruction.offset:
                return Issue(
                    kind=IssueKind.INFINITE_LOOP,
                    message="Potential infinite loop detected (self-looping backward jump)",
                    pc=state.pc,
                    confidence=0.8,
                )
        if instruction.opname in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE"):
            if not isinstance(instruction.argval, int):
                return None
            if instruction.argval >= instruction.offset:
                return None
            if state.stack:
                from pysymex._internal.core.types.scalars.values import SymbolicValue

                cond = state.peek()
                if isinstance(cond, bool):
                    if cond:
                        return Issue(
                            kind=IssueKind.INFINITE_LOOP,
                            message="Potential infinite loop detected (condition always true)",
                            pc=state.pc,
                        )
                    return None
                if isinstance(cond, z3.BoolRef) and z3.is_true(cond):
                    return Issue(
                        kind=IssueKind.INFINITE_LOOP,
                        message="Potential infinite loop detected (condition always true)",
                        pc=state.pc,
                    )
                if isinstance(cond, SymbolicValue) and z3.is_true(cond.could_be_truthy()):
                    return Issue(
                        kind=IssueKind.INFINITE_LOOP,
                        message="Potential infinite loop detected (condition always true)",
                        pc=state.pc,
                    )
        return None
