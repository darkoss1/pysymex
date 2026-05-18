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

from typing import TYPE_CHECKING

import z3

from pysymex.analysis.detectors.base import DisInstruction, IsSatFn, Issue
from pysymex.analysis.detectors.runtime.overflow import OverflowDetector, as_symbolic_int
from pysymex.core.solver.engine import get_model

if TYPE_CHECKING:
    from pysymex.core.state import VMState

_as_symbolic_int = as_symbolic_int


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
    """Pure check for bounded integer overflow using runtime overflow semantics."""
    _ = bits
    symbolic_left = _as_symbolic_int(left)
    symbolic_right = _as_symbolic_int(right)
    if symbolic_left is None or symbolic_right is None:
        return None
    op = argrepr[:-1] if argrepr.endswith("=") else argrepr
    if op not in {"*", "+", "-", "**", "<<"}:
        return None
    int_like_left = z3.Or(symbolic_left.is_int, symbolic_left.is_bool)
    int_like_right = z3.Or(symbolic_right.is_int, symbolic_right.is_bool)

    if op == "<<":
        constraints = [*path_constraints, int_like_left, int_like_right, symbolic_right.z3_int > 63]
        if is_satisfiable_fn(constraints):
            return Issue(
                kind=IntegerOverflowDetector.issue_kind,
                message=f"Potential {bits}-bit integer overflow",
                constraints=constraints,
                model=get_model(constraints),
                pc=pc,
            )
        return None
    if op == "**":
        constraints = [
            *path_constraints,
            int_like_left,
            int_like_right,
            symbolic_left.z3_int > 2,
            symbolic_right.z3_int > 62,
        ]
        if is_satisfiable_fn(constraints):
            return Issue(
                kind=IntegerOverflowDetector.issue_kind,
                message=f"Potential {bits}-bit integer overflow",
                constraints=constraints,
                model=get_model(constraints),
                pc=pc,
            )
        return None

    result: z3.ArithRef
    if op == "*":
        result = symbolic_left.z3_int * symbolic_right.z3_int
    elif op == "+":
        result = symbolic_left.z3_int + symbolic_right.z3_int
    else:
        result = symbolic_left.z3_int - symbolic_right.z3_int
    constraints = [
        *path_constraints,
        int_like_left,
        int_like_right,
        z3.Or(result > max_val, result < min_val),
    ]
    if not is_satisfiable_fn(constraints):
        return None
    return Issue(
        kind=IntegerOverflowDetector.issue_kind,
        message=f"Potential {bits}-bit integer overflow",
        constraints=constraints,
        model=get_model(constraints),
        pc=pc,
    )


class IntegerOverflowDetector(OverflowDetector):
    """Compatibility detector for bounded-overflow checks built on runtime OverflowDetector."""

    name = "bounded-overflow"
    description = "Detects potential bounded integer overflow"
    relevant_opcodes = frozenset({"BINARY_OP"})

    def __init__(self, bits: int = 64) -> None:
        """Create detector with explicit signed integer width bounds."""
        super().__init__(bound_type="32bit" if bits == 32 else "64bit")
        self.bits = bits
        if bits not in (32, 64):
            self.min_val = -(2 ** (bits - 1))
            self.max_val = 2 ** (bits - 1) - 1

    def check(
        self,
        state: VMState,
        instruction: DisInstruction,
        is_satisfiable_fn: IsSatFn,
    ) -> Issue | None:
        """Check for overflow under the configured bit-width bounds."""
        return super().check(state, instruction, is_satisfiable_fn)
