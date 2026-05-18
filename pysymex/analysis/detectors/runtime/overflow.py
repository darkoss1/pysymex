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
from pysymex.core.types import SymbolicValue
from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, IsSatFn, GetModelFn

_BINARY_OP_SYMBOL_BY_ARG: dict[int, str] = {
    0: "+",
    1: "&",
    2: "//",
    3: "<<",
    4: "@",
    5: "*",
    6: "%",
    7: "|",
    8: "**",
    9: ">>",
    10: "-",
    11: "/",
    12: "^",
    13: "+=",
    14: "&=",
    15: "//=",
    16: "<<=",
    17: "@=",
    18: "*=",
    19: "%=",
    20: "|=",
    21: "**=",
    22: ">>=",
    23: "-=",
    24: "/=",
    25: "^=",
}


def resolve_binary_op_symbol(instruction: dis.Instruction) -> str:
    """Resolve operator symbol for ``BINARY_OP`` instructions."""
    if instruction.argrepr:
        return instruction.argrepr
    if isinstance(instruction.argval, str):
        return instruction.argval
    if not isinstance(instruction.arg, int):
        return ""
    return _BINARY_OP_SYMBOL_BY_ARG.get(instruction.arg, "")


_resolve_binary_op_symbol = resolve_binary_op_symbol


def _fresh_concrete_int(value: int, *, is_bool: bool = False) -> SymbolicValue:
    int_value = int(value)
    return SymbolicValue(
        _name=str(value),
        z3_int=z3.IntVal(int_value),
        is_int=z3.BoolVal(not is_bool),
        z3_bool=z3.BoolVal(bool(value)),
        is_bool=z3.BoolVal(is_bool),
        is_float=z3.BoolVal(False),
        is_path=z3.BoolVal(False),
        _constant_value=bool(value) if is_bool else int_value,
        affinity_type="bool" if is_bool else "int",
        min_val=int_value,
        max_val=int_value,
    )


def as_symbolic_int(value: object) -> SymbolicValue | None:
    """Convert supported numeric values into SymbolicValue form."""
    if isinstance(value, SymbolicValue):
        return value
    if isinstance(value, bool):
        return _fresh_concrete_int(1 if value else 0, is_bool=True)
    if isinstance(value, int):
        return _fresh_concrete_int(value)
    return None


_as_symbolic_int = as_symbolic_int


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
    int_like_left = z3.Or(left.is_int, left.is_bool)
    int_like_right = z3.Or(right.is_int, right.is_bool)

    if op == "<<":
        shift_overflow = [
            *path_constraints,
            int_like_left,
            int_like_right,
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
            int_like_left,
            int_like_right,
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
        int_like_left,
        int_like_right,
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
        op_symbol = resolve_binary_op_symbol(instruction)
        if not op_symbol:
            return None
        op = op_symbol[:-1] if op_symbol.endswith("=") else op_symbol
        if op not in {"*", "+", "-", "**", "<<"}:
            return None
        if len(state.stack) < 2:
            return None
        left = _as_symbolic_int(state.stack[-2])
        right = _as_symbolic_int(state.stack[-1])
        if left is None or right is None:
            return None
        return _pure_check_overflow(
            left,
            right,
            op,
            list(state.path_constraints),
            state.pc,
            self.min_val,
            self.max_val,
            is_satisfiable_fn=_solver_check,
        )
