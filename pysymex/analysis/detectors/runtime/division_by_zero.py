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
from pysymex.core.types import SymbolicValue
from pysymex.analysis.detectors.base import (
    Detector,
    Issue,
    IssueKind,
    IsSatFn,
    GetModelFn,
)
from pysymex.analysis.detectors.runtime.overflow import resolve_binary_op_symbol


def extract_argc(instruction: dis.Instruction) -> int:
    """Extract argument count from call-like instructions."""
    if isinstance(instruction.argval, int):
        return instruction.argval
    if isinstance(instruction.arg, int):
        return instruction.arg
    return 0


def resolve_call_target_name(state: VMState, argc: int) -> str | None:
    """Resolve call target name from stack around call arguments."""
    candidate_indices = (len(state.stack) - argc - 2, len(state.stack) - argc - 1)
    for index in candidate_indices:
        if index < 0 or index >= len(state.stack):
            continue
        candidate = state.stack[index]
        candidate_type_name = type(candidate).__name__
        if candidate_type_name == "SymbolicNone":
            continue
        for attr in ("__name__", "__qualname__", "qualname", "name", "origin"):
            value = getattr(candidate, attr, None)
            if isinstance(value, str) and value:
                lowered = value.lower()
                if lowered in {"none", "null", "push_null_none"}:
                    continue
                return value
    return None


_extract_argc = extract_argc
_resolve_call_target_name = resolve_call_target_name


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
        {
            "BINARY_OP",
            "BINARY_TRUE_DIVIDE",
            "BINARY_FLOOR_DIVIDE",
            "BINARY_MODULO",
            "CALL",
            "CALL_FUNCTION",
            "CALL_METHOD",
        }
    )
    DIVISION_OPS = {"BINARY_TRUE_DIVIDE", "BINARY_FLOOR_DIVIDE", "BINARY_MODULO"}
    DIVISION_CALL_SUFFIXES = (".truediv", ".floordiv", ".mod", ".modulo")
    BINARY_OP_DIVISION_SYMBOLS = frozenset({"/", "//", "%", "/=", "//=", "%="})
    BINARY_OP_DIVISION_ARGS = frozenset({2, 6, 11, 15, 19, 24})

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check for division by zero or modulo zero."""
        if instruction.opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD"}:
            argc = extract_argc(instruction)
            if argc < 2 or len(state.stack) < argc:
                return None
            target_name = resolve_call_target_name(state, argc)
            if target_name is None:
                return None
            lowered_target = target_name.lower()
            if not lowered_target.endswith(self.DIVISION_CALL_SUFFIXES):
                return None
            divisor = state.stack[-1]
            dividend = state.stack[-2]
            return pure_check_division_by_zero(
                divisor,
                dividend,
                list(state.path_constraints),
                state.pc,
                is_satisfiable_fn=_solver_check,
            )

        if instruction.opname == "BINARY_OP":
            op_symbol = resolve_binary_op_symbol(instruction)
            if (
                op_symbol not in self.BINARY_OP_DIVISION_SYMBOLS
                and instruction.arg not in self.BINARY_OP_DIVISION_ARGS
            ):
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
            is_satisfiable_fn=_solver_check,
        )
