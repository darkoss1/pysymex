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
from pysymex.core.types.havoc import is_havoc

if TYPE_CHECKING:
    from pysymex.core.state import VMState


def pure_check_bounded_overflow(
    left: object,
    right: object,
    argrepr: str,
    path_constraints: list[z3.BoolRef],
    pc: int,
    bits: int,
    min_val: int,
    max_val: int,
    is_satisfiable_fn: IsSatFn,
) -> Issue | None:
    """Pure: check whether arithmetic on *left*/*right* can overflow within *bits*."""
    from pysymex.core.types.scalars import SymbolicValue

    if is_havoc(left) or is_havoc(right):
        return None
    if not (isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue)):
        return None
    if argrepr == "+":
        result_expr = left.z3_int + right.z3_int
    elif argrepr == "*":
        result_expr = left.z3_int * right.z3_int
    else:
        result_expr = left.z3_int - right.z3_int
    overflow_check = [
        *path_constraints,
        left.is_int,
        right.is_int,
        z3.Or(result_expr > max_val, result_expr < min_val),
    ]
    if is_satisfiable_fn(overflow_check):
        from pysymex.core.solver.engine import get_model

        return Issue(
            kind=IssueKind.OVERFLOW,
            message=f"Potential {bits}-bit integer overflow",
            constraints=overflow_check,
            model=get_model(overflow_check),
            pc=pc,
        )
    return None


class IntegerOverflowDetector(Detector):
    """Detects potential integer overflow issues.
    While Python integers don't overflow, this is useful for:
    - Bounded integer analysis
    - Interfacing with C extensions
    - Array index bounds
    """

    name = "bounded-overflow"
    description = "Detects potential bounded integer overflow"
    issue_kind = IssueKind.OVERFLOW
    relevant_opcodes = frozenset({"BINARY_OP"})
    INT32_MIN = -(2**31)
    INT32_MAX = 2**31 - 1
    INT64_MIN = -(2**63)
    INT64_MAX = 2**63 - 1

    def __init__(self, bits: int = 64) -> None:
        self.bits = bits
        self.min_val = -(2 ** (bits - 1))
        self.max_val = 2 ** (bits - 1) - 1

    def check(
        self,
        state: VMState,
        instruction: DisInstruction,
        is_satisfiable_fn: IsSatFn,
    ) -> Issue | None:
        """Check for integer overflow using BINARY_OP (Python 3.12+)."""
        if instruction.opname != "BINARY_OP":
            return None
        if instruction.argrepr not in ("+", "*", "-"):
            return None
        if len(state.stack) < 2:
            return None
        return pure_check_bounded_overflow(
            state.peek(1),
            state.peek(),
            instruction.argrepr,
            list(state.path_constraints),
            state.pc,
            self.bits,
            self.min_val,
            self.max_val,
            is_satisfiable_fn,
        )
