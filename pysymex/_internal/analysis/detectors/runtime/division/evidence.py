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

"""Zero-divisor feasibility evidence and issue construction."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.analysis.detectors.detector.issue_evidence import (
    constraints_extend_inconclusive_path,
    issue_from_feasibility_evidence,
)
from pysymex._internal.analysis.detectors.feasibility import get_model_if_satisfiable_result
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.constraints.arithmetic import tagged_numeric_zero_condition
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.engine.policies import path_may_be_feasible
from pysymex._internal.core.solver.engine.queries import get_model
from pysymex._internal.core.types.checks import is_overloaded_arithmetic
from pysymex._internal.core.types.havoc import is_havoc
from pysymex._internal.core.types.numeric.float import SymbolicFloat
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pysymex._internal.analysis.detectors.detector.types import GetModelFn, IsSatFn, Issue

logger = get_logger(__name__)
_SIMPLIFY_FAILURES = (z3.Z3Exception, OSError, RuntimeError, ValueError)
_LOCAL_UNSAT_TIMEOUT_MS = 20
_HAVOC_ZERO_DIVISOR_CONFIDENCE = 0.5


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
    """Determine whether a divisor can be zero on a feasible path.

    For symbolic divisors, this extends ``path_constraints`` with a zero
    predicate and queries the solver. For concrete ``0``, it checks path
    feasibility directly. Solver unknown and timeout remain inconclusive
    unless the query extends an already inconclusive path prefix.
    """
    if _uses_overloaded_arithmetic(divisor, dividend):
        return None

    if isinstance(divisor, SymbolicFloat):
        return _issue_for_symbolic_float_divisor(
            divisor,
            path_constraints,
            pc,
            is_satisfiable_fn,
            get_model_fn,
            issue_kind,
            last_inconclusive_feasibility_len,
        )

    if not isinstance(divisor, SymbolicValue):
        return _issue_for_concrete_divisor(
            divisor,
            path_constraints,
            pc,
            is_satisfiable_fn,
            get_model_fn,
            issue_kind,
            last_inconclusive_feasibility_len,
        )

    return _issue_for_symbolic_value_divisor(
        divisor,
        path_constraints,
        pc,
        is_satisfiable_fn,
        get_model_fn,
        issue_kind,
        last_inconclusive_feasibility_len,
    )


def _uses_overloaded_arithmetic(divisor: object, dividend: object) -> bool:
    """Return whether overloaded arithmetic should suppress this detector."""
    return (
        isinstance(dividend, SymbolicValue)
        and isinstance(divisor, SymbolicValue)
        and is_overloaded_arithmetic(dividend, divisor)
    )


def _issue_for_symbolic_float_divisor(
    divisor: SymbolicFloat,
    path_constraints: list[z3.BoolRef],
    pc: int,
    is_satisfiable_fn: IsSatFn,
    get_model_fn: GetModelFn,
    issue_kind: IssueKind,
    last_inconclusive_feasibility_len: int,
) -> Issue | None:
    """Build zero-divisor evidence for a symbolic float divisor."""
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
        confidence=_zero_divisor_confidence(divisor),
        likelihood=_zero_divisor_confidence(divisor),
        last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
    )


def _issue_for_concrete_divisor(
    divisor: object,
    path_constraints: list[z3.BoolRef],
    pc: int,
    is_satisfiable_fn: IsSatFn,
    get_model_fn: GetModelFn,
    issue_kind: IssueKind,
    last_inconclusive_feasibility_len: int,
) -> Issue | None:
    """Build zero-divisor evidence for concrete numeric divisors."""
    try:
        if isinstance(divisor, (int, float)) and float(divisor) == 0:
            return _issue_from_zero_evidence(
                path_constraints=path_constraints,
                zero_constraint=path_constraints,
                is_satisfiable_fn=is_satisfiable_fn,
                get_model_fn=get_model_fn,
                issue_kind=issue_kind,
                message=_concrete_zero_message(issue_kind),
                pc=pc,
                last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
            )
    except (ValueError, TypeError):
        logger.debug("Concrete divisor parse failed; continuing symbolically", exc_info=True)
    return None


def _issue_for_symbolic_value_divisor(
    divisor: SymbolicValue,
    path_constraints: list[z3.BoolRef],
    pc: int,
    is_satisfiable_fn: IsSatFn,
    get_model_fn: GetModelFn,
    issue_kind: IssueKind,
    last_inconclusive_feasibility_len: int,
) -> Issue | None:
    """Build zero-divisor evidence for tagged symbolic scalar divisors."""
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
        confidence=_zero_divisor_confidence(divisor),
        likelihood=_zero_divisor_confidence(divisor),
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
    confidence: float = 1.0,
    likelihood: float = 1.0,
) -> Issue | None:
    """Build a zero-divisor issue without converting inconclusive evidence to certainty."""
    if _condition_is_locally_false(issue_condition):
        return None
    if _constraints_are_locally_unsat(zero_constraint):
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
        confidence=confidence,
        likelihood=likelihood,
        path_is_inconclusive=path_is_inconclusive,
    )


def _condition_is_locally_false(condition: z3.BoolRef | None) -> bool:
    """Return whether the detector-specific zero predicate is locally impossible."""
    if condition is None:
        return False
    try:
        return z3.is_false(simplify_expr(condition))
    except _SIMPLIFY_FAILURES:
        logger.debug("Zero-divisor condition simplification failed; continuing with solver policy")
        return False


def _constraints_are_locally_unsat(constraints: list[z3.BoolRef]) -> bool:
    """Return whether a bounded local solver proves the detector query impossible."""
    try:
        solver = z3.Solver()
        solver.set("timeout", _LOCAL_UNSAT_TIMEOUT_MS)
        solver.add(*constraints)
        return solver.check() == z3.unsat
    except _SIMPLIFY_FAILURES:
        logger.debug("Zero-divisor local UNSAT proof failed; continuing with solver policy")
        return False


def _symbolic_zero_message(divisor_name: str, issue_kind: IssueKind) -> str:
    """Return the stable user-facing zero-divisor message for symbolic divisors."""
    if issue_kind == IssueKind.MODULO_BY_ZERO:
        return f"Possible modulo by zero: {divisor_name} can be 0"
    return f"Possible division by zero: {divisor_name} can be 0"


def _concrete_zero_message(issue_kind: IssueKind) -> str:
    """Return the stable user-facing zero-divisor message for concrete divisors."""
    if issue_kind == IssueKind.MODULO_BY_ZERO:
        return "Modulo by concrete zero"
    return "Division by concrete zero"


def _zero_divisor_confidence(divisor: object) -> float:
    """Return detector confidence for zero evidence sourced from a divisor value."""
    if is_havoc(divisor):
        return _HAVOC_ZERO_DIVISOR_CONFIDENCE
    return 1.0
