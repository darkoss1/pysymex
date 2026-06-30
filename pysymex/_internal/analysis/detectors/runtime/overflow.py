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

"""Bounded Integer Overflow detection module.

This module provides detection for bounded integer overflow/underflow errors on binary operations,
specifically supporting signed 32-bit, signed 64-bit, and unsigned size_t integer representations.

Bug Class Detected:
    Integer Overflow / Underflow.

Required Evidence:
    Satisfiable path constraints extended with a boundary violation condition (e.g. result < MIN or result > MAX).

Issue Kinds:
    IssueKind.OVERFLOW
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.bytecode import resolve_binary_op_symbol
from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.constraints.values import ConstraintValues

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState

from pysymex._internal.analysis.detectors.detector.contract import Detector
from pysymex._internal.analysis.detectors.detector.types import GetModelFn, IsSatFn, Issue
from pysymex._internal.analysis.detectors.feasibility import get_model_if_satisfiable_result
from pysymex._internal.core.solver.constraints.arithmetic import (
    BOUNDED_OVERFLOW_OPERATORS,
    bounded_integer_overflow_condition,
    normalize_assignment_operator,
)
from pysymex._internal.core.solver.engine.policies import path_may_be_feasible
from pysymex._internal.core.solver.engine.queries import get_model
from pysymex._internal.core.types.scalars.values import SymbolicValue


def _fresh_concrete_int(value: int, *, is_bool: bool = False) -> SymbolicValue:
    """Wrap a concrete integer *value* in a :class:`SymbolicValue` for overflow analysis.

    Args:
        value: The concrete integer to wrap.
        is_bool: Whether to represent the value as a boolean type.

    Returns:
        A :class:`SymbolicValue` with Z3 integer and boolean tags set.

    """
    int_value = int(value)
    bool_value = bool(value)
    return SymbolicValue(
        _name=str(value),
        z3_int=ConstraintValues.int(int_value),
        is_int=Z3_FALSE if is_bool else Z3_TRUE,
        z3_bool=Z3_TRUE if bool_value else Z3_FALSE,
        is_bool=Z3_TRUE if is_bool else Z3_FALSE,
        is_float=Z3_FALSE,
        is_path=Z3_FALSE,
        _constant_value=bool_value if is_bool else int_value,
        affinity_type="bool" if is_bool else "int",
        min_val=int_value,
        max_val=int_value,
    )


def as_symbolic_int(value: object) -> SymbolicValue | None:
    """Return *value* wrapped as a :class:`SymbolicValue`, or ``None`` if unsupported.

    Accepts existing :class:`SymbolicValue` instances, ``bool``, or ``int``.
    Returns ``None`` for other types (e.g. ``float``, ``str``).
    """
    if isinstance(value, SymbolicValue):
        return value
    if isinstance(value, bool):
        return _fresh_concrete_int(1 if value else 0, is_bool=True)
    if isinstance(value, int):
        return _fresh_concrete_int(value)
    return None


def _pure_check_overflow(
    left: SymbolicValue,
    right: SymbolicValue,
    op: str,
    path_constraints: list[z3.BoolRef],
    pc: int,
    min_val: int,
    max_val: int,
    is_satisfiable_fn: IsSatFn = path_may_be_feasible,
    get_model_fn: GetModelFn = get_model,
) -> Issue | None:
    """Determine whether *op* applied to *left* and *right* can overflow *[min_val, max_val]*.

    Pure function — no I/O, no global state.  Extends *path_constraints*
    with a boundary-violation condition and queries the solver.

    Args:
        left: Symbolic left operand.
        right: Symbolic right operand.
        op: Binary operator symbol (e.g. ``"+"``, ``"<<"``, ``"**"``).
        path_constraints: Current path constraint list.
        pc: Bytecode offset of the operation.
        min_val: Lower bound of the target integer type.
        max_val: Upper bound of the target integer type.
        is_satisfiable_fn: Solver satisfiability callback.
        get_model_fn: Solver model-extraction callback.

    Returns:
        An :class:`Issue` if overflow is feasible on the current path,
        ``None`` otherwise.

    """
    normalized_op = normalize_assignment_operator(op)
    int_like_left = z3.Or(left.is_int, left.is_bool)
    int_like_right = z3.Or(right.is_int, right.is_bool)

    overflow_condition = bounded_integer_overflow_condition(
        left.z3_int,
        right.z3_int,
        normalized_op,
        min_val,
        max_val,
    )
    if overflow_condition is None:
        return None

    constraints = [
        *path_constraints,
        int_like_left,
        int_like_right,
        overflow_condition,
    ]
    message = _overflow_message(normalized_op, right)
    return _overflow_issue_if_satisfiable(
        constraints,
        message,
        pc,
        is_satisfiable_fn,
        get_model_fn,
    )


def _overflow_message(normalized_op: str, right: SymbolicValue) -> str:
    """Return the stable overflow report message for *normalized_op*."""
    if normalized_op == "<<":
        return f"Excessive bounded-width bit shift: {right.name} could be > 63"
    if normalized_op == "**":
        return "Potential bounded integer overflow in exponentiation"
    return f"Possible bounded integer overflow in {normalized_op} operation"


def _overflow_issue_if_satisfiable(
    constraints: list[z3.BoolRef],
    message: str,
    pc: int,
    is_satisfiable_fn: IsSatFn,
    get_model_fn: GetModelFn,
) -> Issue | None:
    """Return an overflow issue only when *constraints* are satisfiable."""
    model = get_model_if_satisfiable_result(
        constraints,
        is_satisfiable_fn,
        get_model_fn,
    ).model
    if model is None:
        return None
    return Issue(
        kind=IssueKind.OVERFLOW,
        message=message,
        constraints=constraints,
        model=model,
        pc=pc,
    )


class OverflowDetector(Detector):
    """Detect bounded-width integer overflow on arithmetic operations.

    Bug class:
        Signed overflow (32-bit or 64-bit) or unsigned overflow (``size_t``)
        in ``+``, ``-``, ``*``, ``**``, and ``<<`` operations.

    Evidence:
        Satisfiable path constraints extended with a boundary violation
        condition (result outside ``[min_val, max_val]``).

    Issue kind:
        ``IssueKind.OVERFLOW``.

    Known limitations:
        Only checks ``BINARY_OP`` opcode; does not detect in-place
        operators or augmented assignments as separate opcodes on older
        CPython.  Python integers are unbounded by default; this detector
        is useful when interfacing with bounded foreign types.
    """

    name = "overflow"
    description = "Detects bounded-width integer overflow"
    issue_kind = IssueKind.OVERFLOW
    relevant_opcodes = frozenset(("BINARY_OP",))
    BOUNDS = {
        "32bit": (-(2**31), 2**31 - 1),
        "64bit": (-(2**63), 2**63 - 1),
        "size_t": (0, 2**64 - 1),
    }

    def __init__(self, bound_type: str = "64bit") -> None:
        """Initialise with a specific integer boundary width.

        Args:
            bound_type: One of ``"32bit"``, ``"64bit"``, or ``"size_t"``.
                Defaults to ``"64bit"``.

        """
        self.min_val, self.max_val = self.BOUNDS.get(bound_type, self.BOUNDS["64bit"])

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Inspect *instruction* for a ``BINARY_OP`` that may overflow the configured bounds."""
        if instruction.opname != "BINARY_OP":
            return None
        op_symbol = resolve_binary_op_symbol(instruction)
        if not op_symbol:
            return None
        op = normalize_assignment_operator(op_symbol)
        if op not in BOUNDED_OVERFLOW_OPERATORS:
            return None
        if len(state.stack) < 2:
            return None
        left = as_symbolic_int(state.stack[-2])
        right = as_symbolic_int(state.stack[-1])
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
