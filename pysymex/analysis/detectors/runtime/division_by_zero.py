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
from pysymex.core.types.checks import is_overloaded_arithmetic
from pysymex.core.types.scalars import (
    SymbolicValue,
)
from pysymex.analysis.detectors.base import (
    Detector,
    Issue,
    IssueKind,
    IsSatFn,
    GetModelFn,
)


def pure_check_division_by_zero(
    divisor: object,
    dividend: object,
    path_constraints: list[z3.BoolRef],
    pc: int,
    is_satisfiable_fn: IsSatFn = is_satisfiable,
    get_model_fn: GetModelFn = get_model,
) -> Issue | None:
    """Pure: decide whether *divisor* can be zero.

    No I/O, no global state access – all inputs are passed explicitly.
    """
    if (
        isinstance(dividend, SymbolicValue)
        and isinstance(divisor, SymbolicValue)
        and is_overloaded_arithmetic(dividend, divisor)
    ):
        return None

    if not isinstance(divisor, SymbolicValue):
        try:
            if isinstance(divisor, (int, float, str)) and float(divisor) == 0:
                return Issue(
                    kind=IssueKind.DIVISION_BY_ZERO,
                    message="Division by concrete zero",
                    pc=pc,
                )
        except (ValueError, TypeError):
            pass
        return None

    zero_constraint = [
        *path_constraints,
        z3.Or(
            z3.And(divisor.is_int, divisor.z3_int == 0),
            z3.And(divisor.is_float, z3.fpIsZero(divisor.z3_float)),
        ),
    ]
    if is_satisfiable_fn(zero_constraint):
        return Issue(
            kind=IssueKind.DIVISION_BY_ZERO,
            message=f"Possible division by zero: {divisor.name} can be 0",
            constraints=zero_constraint,
            model=get_model_fn(zero_constraint),
            pc=pc,
        )
    return None


class DivisionByZeroDetector(Detector):
    """Detects potential division by zero and modulo-by-zero errors.

    Checks ``BINARY_OP`` and legacy ``BINARY_TRUE_DIVIDE`` /
    ``BINARY_FLOOR_DIVIDE`` / ``BINARY_MODULO`` opcodes.
    """

    name = "division-by-zero"
    description = "Detects division by zero"
    issue_kind = IssueKind.DIVISION_BY_ZERO
    relevant_opcodes = frozenset(
        {"BINARY_OP", "BINARY_TRUE_DIVIDE", "BINARY_FLOOR_DIVIDE", "BINARY_MODULO"}
    )
    DIVISION_OPS = {"BINARY_TRUE_DIVIDE", "BINARY_FLOOR_DIVIDE", "BINARY_MODULO"}

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check for division by zero or modulo zero."""
        if instruction.opname == "BINARY_OP":
            op_name = instruction.argrepr or ""
            if "/" not in op_name and "%" not in op_name:
                return None
        elif instruction.opname not in self.DIVISION_OPS:
            return None
        if len(state.stack) < 2:
            return None

        dividend = state.stack[-2]
        if isinstance(dividend, str) or type(dividend).__name__ == "SymbolicString":
            return None

        return pure_check_division_by_zero(
            state.stack[-1],
            state.stack[-2],
            list(state.path_constraints),
            state.pc,
        )
