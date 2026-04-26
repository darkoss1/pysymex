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

import dis
import z3
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state import VMState

from pysymex.core.solver.engine import get_model, is_satisfiable
from pysymex.core.types.scalars import (
    SymbolicValue,
)
from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, IsSatFn, GetModelFn


def _pure_check_overflow(
    left: SymbolicValue,
    right: SymbolicValue,
    op: str,
    path_constraints: list[z3.BoolRef],
    pc: int,
    min_val: int,
    max_val: int,
    is_satisfiable_fn: IsSatFn = is_satisfiable,
    get_model_fn: GetModelFn = get_model,
) -> Issue | None:
    """Pure: check if arithmetic *op* on *left*/*right* can overflow."""
    if op == "<<":
        shift_overflow = [
            *path_constraints,
            left.is_int,
            right.is_int,
            right.z3_int > 63,
        ]
        if is_satisfiable_fn(shift_overflow):
            return Issue(
                kind=IssueKind.OVERFLOW,
                message=f"Excessive bit shift: {right.name} could be > 63",
                constraints=shift_overflow,
                model=get_model_fn(shift_overflow),
                pc=pc,
            )
        return None
    if op == "**":
        power_overflow = [
            *path_constraints,
            left.is_int,
            right.is_int,
            left.z3_int > 2,
            right.z3_int > 62,
        ]
        if is_satisfiable_fn(power_overflow):
            return Issue(
                kind=IssueKind.OVERFLOW,
                message="Potential overflow in exponentiation",
                constraints=power_overflow,
                model=get_model_fn(power_overflow),
                pc=pc,
            )
        return None
    result: z3.ArithRef
    if op == "*":
        result = left.z3_int * right.z3_int
    elif op == "+":
        result = left.z3_int + right.z3_int
    elif op == "-":
        result = left.z3_int - right.z3_int
    else:
        return None
    overflow_constraint = [
        *path_constraints,
        left.is_int,
        right.is_int,
        z3.Or(result > max_val, result < min_val),
    ]
    if is_satisfiable_fn(overflow_constraint):
        return Issue(
            kind=IssueKind.OVERFLOW,
            message=f"Possible integer overflow in {op} operation",
            constraints=overflow_constraint,
            model=get_model_fn(overflow_constraint),
            pc=pc,
        )
    return None


class OverflowDetector(Detector):
    """Detects integer overflow conditions."""

    name = "overflow"
    description = "Detects integer overflow"
    issue_kind = IssueKind.OVERFLOW
    relevant_opcodes = frozenset({"BINARY_OP"})
    BOUNDS = {
        "32bit": (-(2**31), 2**31 - 1),
        "64bit": (-(2**63), 2**63 - 1),
        "size_t": (0, 2**64 - 1),
    }

    def __init__(self, bound_type: str = "64bit") -> None:
        self.min_val, self.max_val = self.BOUNDS.get(bound_type, self.BOUNDS["64bit"])

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check."""
        if instruction.opname != "BINARY_OP":
            return None
        op = instruction.argrepr
        if op not in {"*", "+", "-", "**", "<<"}:
            return None
        if len(state.stack) < 2:
            return None
        left = state.stack[-2]
        right = state.stack[-1]
        if not isinstance(left, SymbolicValue) or not isinstance(right, SymbolicValue):
            return None
        return _pure_check_overflow(
            left,
            right,
            op,
            list(state.path_constraints),
            state.pc,
            self.min_val,
            self.max_val,
        )
