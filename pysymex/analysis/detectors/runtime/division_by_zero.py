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

"""Division by zero and modulo zero error detector module.

This module provides detection capability for runtime division/modulo by zero exceptions
triggered by both concrete and symbolic divisors during execution.

Bug Class Detected:
    Division / Modulo by Zero (ZeroDivisionError).

Required Evidence:
    For concrete divisors, a value of 0. For symbolic divisors, a satisfiable path constraint
    extended with the constraint that the divisor equals 0.

Issue Kinds:
    IssueKind.DIVISION_BY_ZERO
    IssueKind.MODULO_BY_ZERO
"""

from __future__ import annotations

import dis
import z3
from typing import TYPE_CHECKING

from pysymex.analysis.detectors.calls import extract_argc, resolve_call_target_name
from pysymex.logger import get_logger

logger = get_logger(__name__)
_SIMPLIFY_FAILURES = (z3.Z3Exception, OSError, RuntimeError, ValueError)

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

from pysymex.core.solver.engine.policies import path_may_be_feasible
from pysymex.core.solver.engine.queries import get_model
from pysymex.core.types.checks import is_overloaded_arithmetic
from pysymex.core.types.advanced_float import AdvancedSymbolicFloat
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.analysis.detectors.detector.contract import Detector
from pysymex.analysis.detectors.detector.issue_evidence import (
    constraints_extend_inconclusive_path,
    issue_from_feasibility_evidence,
)
from pysymex.analysis.detectors.detector.types import GetModelFn, IsSatFn, Issue, IssueKind
from pysymex.analysis.detectors.feasibility import get_model_if_satisfiable_result
from pysymex.analysis.detectors.runtime.overflow import resolve_binary_op_symbol
from pysymex.analysis.static.arithmetic.conditions import tagged_numeric_zero_condition


def pure_check_division_by_zero(
    divisor: object,
    dividend: object,
    path_constraints: list[z3.BoolRef],
    pc: int,
    is_satisfiable_fn: IsSatFn = path_may_be_feasible,
    get_model_fn: GetModelFn = get_model,
    is_truediv: bool = False,
    issue_kind: IssueKind = IssueKind.DIVISION_BY_ZERO,
    last_inconclusive_feasibility_len: int = -1,
) -> Issue | None:
    """Determine whether *divisor* can be zero on a feasible path.

    Pure function — no I/O, no global state access.  All inputs are
    passed explicitly.

    For symbolic divisors, extends *path_constraints* with a
    zero-constraint and queries the solver.  For concrete ``0``,
    checks path feasibility directly.

    Args:
        divisor: Right-hand operand (may be concrete or symbolic).
        dividend: Left-hand operand (used only to detect overloaded ops).
        path_constraints: Current path constraint list.
        pc: Bytecode offset of the operation.
        is_satisfiable_fn: Solver satisfiability callback.
        get_model_fn: Solver model-extraction callback.
        is_truediv: ``True`` for true-divide vs floor-divide.
        issue_kind: Issue kind to emit (division or modulo).
        last_inconclusive_feasibility_len: Length of an already-inconclusive path prefix.

    Returns:
        An :class:`Issue` if the divisor can be zero on a feasible path,
        or a low-confidence model-less issue when the zero-divisor query extends
        an already-inconclusive path prefix. Returns ``None`` otherwise.
    """
    if (
        isinstance(dividend, SymbolicValue)
        and isinstance(divisor, SymbolicValue)
        and is_overloaded_arithmetic(dividend, divisor)
    ):
        return None

    if isinstance(divisor, AdvancedSymbolicFloat):
        zero_condition = divisor.is_zero()
        zero_constraint = [*path_constraints, zero_condition]
        return _issue_from_zero_evidence(
            path_constraints=path_constraints,
            zero_constraint=zero_constraint,
            issue_condition=zero_condition,
            is_satisfiable_fn=is_satisfiable_fn,
            get_model_fn=get_model_fn,
            issue_kind=issue_kind,
            message=_symbolic_zero_message(divisor.name, issue_kind),
            pc=pc,
            last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
        )

    if not isinstance(divisor, SymbolicValue):
        try:
            if isinstance(divisor, (int, float)) and float(divisor) == 0:
                return _issue_from_zero_evidence(
                    path_constraints=path_constraints,
                    zero_constraint=path_constraints,
                    is_satisfiable_fn=is_satisfiable_fn,
                    get_model_fn=get_model_fn,
                    issue_kind=issue_kind,
                    message=(
                        "Modulo by concrete zero"
                        if issue_kind == IssueKind.MODULO_BY_ZERO
                        else "Division by concrete zero"
                    ),
                    pc=pc,
                    last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
                )
        except (ValueError, TypeError):
            logger.debug("Concrete divisor parse failed; continuing symbolically", exc_info=True)
        return None

    zero_condition = tagged_numeric_zero_condition(
        concrete_value=divisor.value,
        affinity_type=divisor.affinity_type,
        is_int=divisor.is_int,
        int_expr=divisor.z3_int,
        is_bool=divisor.is_bool,
        bool_expr=divisor.z3_bool,
        is_float=divisor.is_float,
        float_expr=divisor.z3_float,
        include_float=True,
    )
    zero_constraint = [
        *path_constraints,
        zero_condition,
    ]
    return _issue_from_zero_evidence(
        path_constraints=path_constraints,
        zero_constraint=zero_constraint,
        issue_condition=zero_condition,
        is_satisfiable_fn=is_satisfiable_fn,
        get_model_fn=get_model_fn,
        issue_kind=issue_kind,
        message=_symbolic_zero_message(divisor.name, issue_kind),
        pc=pc,
        last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
    )


def _issue_from_zero_evidence(
    *,
    path_constraints: list[z3.BoolRef],
    zero_constraint: list[z3.BoolRef],
    issue_condition: z3.BoolRef | None = None,
    is_satisfiable_fn: IsSatFn,
    get_model_fn: GetModelFn,
    issue_kind: IssueKind,
    message: str,
    pc: int,
    last_inconclusive_feasibility_len: int,
) -> Issue | None:
    """Build a zero-divisor issue without converting inconclusive evidence to certainty."""
    if _condition_is_locally_false(issue_condition):
        return None
    model_result = get_model_if_satisfiable_result(
        zero_constraint,
        is_satisfiable_fn,
        get_model_fn,
    )
    path_is_inconclusive = constraints_extend_inconclusive_path(
        path_constraints=path_constraints,
        constraints=zero_constraint,
        last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
    )
    if model_result.is_inconclusive and not path_is_inconclusive:
        return None
    return issue_from_feasibility_evidence(
        result=model_result,
        kind=issue_kind,
        message=message,
        constraints=zero_constraint,
        pc=pc,
        path_is_inconclusive=path_is_inconclusive,
    )


def _condition_is_locally_false(condition: z3.BoolRef | None) -> bool:
    """Return whether the detector-specific zero predicate is locally impossible."""
    if condition is None:
        return False
    try:
        return z3.is_false(z3.simplify(condition))
    except _SIMPLIFY_FAILURES:
        logger.debug("Zero-divisor condition simplification failed; continuing with solver policy")
        return False


def _symbolic_zero_message(divisor_name: str, issue_kind: IssueKind) -> str:
    """Return the stable user-facing zero-divisor message for symbolic divisors."""
    if issue_kind == IssueKind.MODULO_BY_ZERO:
        return f"Possible modulo by zero: {divisor_name} can be 0"
    return f"Possible division by zero: {divisor_name} can be 0"


class DivisionByZeroDetector(Detector):
    """Detect division-by-zero and modulo-by-zero on feasible paths.

    Bug class:
        ``ZeroDivisionError`` from ``/``, ``//``, ``%``, and their
        in-place variants.  Also catches dunder calls (``__truediv__``,
        ``__floordiv__``, ``__mod__``).

    Evidence:
        Concrete divisor of ``0``, or a satisfiable path constraint
        with the divisor constrained to zero.

    Issue kinds:
        ``IssueKind.DIVISION_BY_ZERO``, ``IssueKind.MODULO_BY_ZERO``.

    Known false-positive suppression:
        Skipped when both operands have overloaded arithmetic or when
        the dividend is a string (``%``-formatting).
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
        """Inspect *instruction* for a division/modulo whose divisor may be zero.

        Pops the top-of-stack divisor and dividend, queries the solver
        via :func:`pure_check_division_by_zero`, and returns an issue if
        the zero-divisor constraint is satisfiable.
        """
        is_truediv = False
        if instruction.opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD"}:
            argc = extract_argc(instruction)
            if argc != 2 or len(state.stack) < argc + 1:
                return None
            target_name = resolve_call_target_name(state, argc)
            if target_name is None:
                return None
            lowered_target = target_name.lower()
            if not lowered_target.endswith(self.DIVISION_CALL_SUFFIXES):
                return None
            if lowered_target.endswith(".truediv"):
                is_truediv = True
            issue_kind = (
                IssueKind.MODULO_BY_ZERO
                if lowered_target.endswith((".mod", ".modulo"))
                else IssueKind.DIVISION_BY_ZERO
            )
            divisor = state.stack[-1]
            dividend = state.stack[-2]
            return pure_check_division_by_zero(
                divisor,
                dividend,
                list(state.path_constraints),
                state.pc,
                is_satisfiable_fn=_solver_check,
                is_truediv=is_truediv,
                issue_kind=issue_kind,
                last_inconclusive_feasibility_len=state.last_inconclusive_feasibility_len,
            )

        issue_kind = IssueKind.DIVISION_BY_ZERO
        if instruction.opname == "BINARY_OP":
            op_symbol = resolve_binary_op_symbol(instruction)
            if (
                op_symbol not in self.BINARY_OP_DIVISION_SYMBOLS
                and instruction.arg not in self.BINARY_OP_DIVISION_ARGS
                and op_symbol not in {"/", "/="}
            ):
                return None
            if op_symbol in {"/", "/="} or instruction.arg == 11:
                is_truediv = True
            if op_symbol in {"%", "%="} or instruction.arg in {6, 19}:
                issue_kind = IssueKind.MODULO_BY_ZERO
        elif instruction.opname not in self.DIVISION_OPS:
            return None
        else:
            if instruction.opname == "BINARY_TRUE_DIVIDE":
                is_truediv = True
            if instruction.opname == "BINARY_MODULO":
                issue_kind = IssueKind.MODULO_BY_ZERO

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
            is_truediv=is_truediv,
            issue_kind=issue_kind,
            last_inconclusive_feasibility_len=state.last_inconclusive_feasibility_len,
        )
