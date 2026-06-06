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

"""Pure Z3-backed index bounds checks for list, tuple, string, and sequence accesses.

Provides :func:`pure_check_index_bounds`, the stateless SAT-checked
primitive for ``IndexError`` detection, and :func:`_unwrap_symbolic_sequence`
for normalising symbolic wrappers before bounds analysis.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import z3

from pysymex.analysis.detectors.detector.types import GetModelFn, IsSatFn, Issue, IssueKind
from pysymex.analysis.detectors.detector.issue_evidence import (
    constraints_extend_inconclusive_path,
    issue_from_feasibility_evidence,
)
from pysymex.analysis.detectors.feasibility import get_model_if_satisfiable_result
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.solver.engine.policies import path_may_be_feasible
from pysymex.core.solver.engine.queries import get_model
from pysymex.core.z3_utils import safe_z3_eq
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.containers.sequences import SymbolicTuple
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.types.checks import is_type_subscription
from pysymex.core.types.havoc import is_havoc
from pysymex.core.types.containers.slices import extract_slice_bounds
from pysymex.typing import is_list_of_objects, is_tuple_of_objects


class IndexBoundsCheckStatus(Enum):
    """Outcome of a pure index-bounds detector query."""

    OUT_OF_BOUNDS = "out_of_bounds"
    IN_BOUNDS = "in_bounds"
    NO_OUT_OF_BOUNDS_EVIDENCE = "no_out_of_bounds_evidence"
    INCONCLUSIVE = "inconclusive"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class IndexBoundsCheckResult:
    """Structured index-bounds evidence without collapsing uncertainty."""

    status: IndexBoundsCheckStatus
    issue: Issue | None = None
    reason: str | None = None

    @property
    def has_issue(self) -> bool:
        """Return true only when model-backed out-of-bounds evidence exists."""
        return self.status is IndexBoundsCheckStatus.OUT_OF_BOUNDS and self.issue is not None

    @staticmethod
    def out_of_bounds(issue: Issue) -> IndexBoundsCheckResult:
        """Create a model-backed out-of-bounds result."""
        return IndexBoundsCheckResult(IndexBoundsCheckStatus.OUT_OF_BOUNDS, issue=issue)

    @staticmethod
    def in_bounds(reason: str) -> IndexBoundsCheckResult:
        """Create a result for locally proved in-bounds access."""
        return IndexBoundsCheckResult(IndexBoundsCheckStatus.IN_BOUNDS, reason=reason)

    @staticmethod
    def no_evidence(reason: str) -> IndexBoundsCheckResult:
        """Create a result when no satisfiable OOB evidence was found."""
        return IndexBoundsCheckResult(
            IndexBoundsCheckStatus.NO_OUT_OF_BOUNDS_EVIDENCE,
            reason=reason,
        )

    @staticmethod
    def inconclusive(reason: str, issue: Issue | None = None) -> IndexBoundsCheckResult:
        """Create an inconclusive bounds-check result."""
        return IndexBoundsCheckResult(
            IndexBoundsCheckStatus.INCONCLUSIVE,
            issue=issue,
            reason=reason,
        )

    @staticmethod
    def unsupported(reason: str) -> IndexBoundsCheckResult:
        """Create a result for unsupported bounds-check shapes."""
        return IndexBoundsCheckResult(IndexBoundsCheckStatus.UNSUPPORTED, reason=reason)


def _unwrap_symbolic_sequence(container: object) -> object:
    """Return concrete sequence payloads stored in constant symbolic values."""
    if not isinstance(container, SymbolicValue):
        return container
    value: object = container.value
    if (
        is_list_of_objects(value)
        or is_tuple_of_objects(value)
        or isinstance(value, (SymbolicTuple, str, bytes, bytearray, range))
    ):
        return value
    return container


def pure_check_index_bounds(
    container: object,
    index: object,
    path_constraints: list[z3.BoolRef],
    pc: int,
    is_satisfiable_fn: IsSatFn = path_may_be_feasible,
    get_model_fn: GetModelFn = get_model,
    last_inconclusive_feasibility_len: int = -1,
) -> Issue | None:
    """Check whether *index* can be out-of-bounds for *container* under *path_constraints*.

    This is a pure (stateless) function: it never mutates VM state.
    Supports :class:`SymbolicList`, :class:`SymbolicTuple`, :class:`SymbolicString`,
    concrete ``list``, ``tuple``, ``str``, ``bytes``, ``bytearray``, and ``range``.

    Args:
        container: The sequence object being subscripted.
        index: The symbolic index value.
        path_constraints: Active path constraints to append the OOB test to.
        pc: Bytecode offset for issue location metadata.
        is_satisfiable_fn: SAT oracle (defaults to :func:`path_may_be_feasible`).
        get_model_fn: Model-extraction callback (defaults to :func:`get_model`).

    Returns:
        An :class:`Issue` with kind ``INDEX_ERROR`` if the OOB constraint is
        satisfiable. If the caller provides an inconclusive path prefix, a
        low-confidence model-less issue may be returned instead. Returns
        ``None`` if provably in-bounds, container type is unsupported, or the
        index is a slice.
    """
    return pure_check_index_bounds_result(
        container,
        index,
        path_constraints,
        pc,
        is_satisfiable_fn,
        get_model_fn,
        last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
    ).issue


def pure_check_index_bounds_result(
    container: object,
    index: object,
    path_constraints: list[z3.BoolRef],
    pc: int,
    is_satisfiable_fn: IsSatFn = path_may_be_feasible,
    get_model_fn: GetModelFn = get_model,
    last_inconclusive_feasibility_len: int = -1,
) -> IndexBoundsCheckResult:
    """Check index bounds while preserving unsupported and inconclusive states."""
    if is_type_subscription(container):
        return IndexBoundsCheckResult.unsupported("type_subscription")
    if not isinstance(index, SymbolicValue):
        return IndexBoundsCheckResult.unsupported("non_symbolic_index")
    if extract_slice_bounds(index) is not None:
        return IndexBoundsCheckResult.unsupported("slice_index")
    container = _unwrap_symbolic_sequence(container)

    lower_bound: z3.ArithRef
    upper_bound: z3.ArithRef
    container_name: str
    confidence = 1.0

    if isinstance(container, SymbolicList):
        lower_bound = -container.z3_len
        upper_bound = container.z3_len
        container_name = container.name
        if is_havoc(index) or is_havoc(container):
            confidence = 0.5
        elif hasattr(index, "affinity_type") and index.affinity_type == "int":
            confidence = 0.9
    elif isinstance(container, SymbolicTuple):
        concrete_len = len(container)
        lower_bound = get_int_val(-concrete_len)
        upper_bound = get_int_val(concrete_len)
        container_name = container.name
        if is_havoc(index):
            confidence = 0.5
        elif hasattr(index, "affinity_type") and index.affinity_type == "int":
            confidence = 0.9
    elif isinstance(container, SymbolicString):
        lower_bound = -container.z3_len
        upper_bound = container.z3_len
        container_name = container.name
        if is_havoc(index):
            confidence = 0.5
        elif hasattr(index, "affinity_type") and index.affinity_type == "int":
            confidence = 0.9
    elif isinstance(container, (str, bytes, bytearray, range)):
        concrete_len = len(container)
        lower_bound = get_int_val(-concrete_len)
        upper_bound = get_int_val(concrete_len)
        container_name = type(container).__name__
        if is_havoc(index):
            confidence = 0.5
        elif hasattr(index, "affinity_type") and index.affinity_type == "int":
            confidence = 0.9
    elif is_list_of_objects(container):
        concrete_len = len(container)
        lower_bound = get_int_val(-concrete_len)
        upper_bound = get_int_val(concrete_len)
        container_name = "list"
        if is_havoc(index):
            confidence = 0.5
        elif hasattr(index, "affinity_type") and index.affinity_type == "int":
            confidence = 0.9
    elif is_tuple_of_objects(container):
        concrete_len = len(container)
        lower_bound = get_int_val(-concrete_len)
        upper_bound = get_int_val(concrete_len)
        container_name = "list"
        if is_havoc(index):
            confidence = 0.5
        elif hasattr(index, "affinity_type") and index.affinity_type == "int":
            confidence = 0.9
    else:
        return IndexBoundsCheckResult.unsupported("unsupported_container")

    if _definitely_in_bounds(index, lower_bound, upper_bound):
        return IndexBoundsCheckResult.in_bounds("definitely_in_bounds")
    if _path_constraints_prove_in_bounds(index.z3_int, lower_bound, upper_bound, path_constraints):
        return IndexBoundsCheckResult.in_bounds("path_constraints_prove_in_bounds")

    oob_constraint = [
        *path_constraints,
        index.is_int,
        z3.Or(
            index.z3_int < lower_bound,
            index.z3_int >= upper_bound,
        ),
    ]
    model_result = get_model_if_satisfiable_result(
        oob_constraint,
        is_satisfiable_fn,
        get_model_fn,
        allow_witness_model=True,
    )
    issue = issue_from_feasibility_evidence(
        result=model_result,
        kind=IssueKind.INDEX_ERROR,
        message=f"Possible index out of bounds: {container_name}[{index.name}]",
        constraints=oob_constraint,
        pc=pc,
        confidence=confidence,
        path_is_inconclusive=constraints_extend_inconclusive_path(
            path_constraints=path_constraints,
            constraints=oob_constraint,
            last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
        ),
    )
    if model_result.is_inconclusive:
        return IndexBoundsCheckResult.inconclusive(
            model_result.reason or "model_inconclusive",
            issue=issue,
        )
    if issue is None:
        return IndexBoundsCheckResult.no_evidence(model_result.reason or "no_sat_evidence")
    return IndexBoundsCheckResult.out_of_bounds(issue)


def _definitely_in_bounds(
    index: SymbolicValue,
    lower_bound: z3.ArithRef,
    upper_bound: z3.ArithRef,
) -> bool:
    """Return True when concrete index and bounds prove the access in-bounds."""
    if z3.is_false(index.is_int):
        return False
    if not z3.is_true(index.is_int) and not z3.is_true(z3.simplify(index.is_int)):
        return False
    concrete_index = _symbolic_value_int(index)
    if concrete_index is None:
        return False
    lower = _concrete_int_value(lower_bound)
    if lower is None:
        return False
    upper = _concrete_int_value(upper_bound)
    if upper is None:
        return False
    return lower <= concrete_index < upper


def _path_constraints_prove_in_bounds(
    index_expr: z3.ArithRef,
    lower_bound: z3.ArithRef,
    upper_bound: z3.ArithRef,
    path_constraints: list[z3.BoolRef],
) -> bool:
    """Return true when simple active bounds make the OOB disjunction impossible."""
    if not _has_strict_upper_bound(path_constraints, index_expr, upper_bound):
        return False
    if _has_lower_bound(path_constraints, index_expr, lower_bound):
        return True
    return (
        _is_negative_of(lower_bound, upper_bound)
        and _has_lower_bound(path_constraints, index_expr, get_int_val(0))
        and _expr_known_nonnegative(upper_bound, path_constraints)
    )


def _has_strict_upper_bound(
    constraints: list[z3.BoolRef],
    index_expr: z3.ArithRef,
    upper_bound: z3.ArithRef,
) -> bool:
    bounds = [upper_bound, *_equality_aliases(upper_bound, constraints)]
    return any(
        _constraint_implies_lt(constraint, index_expr, bound)
        for bound in bounds
        for constraint in constraints
    )


def _has_lower_bound(
    constraints: list[z3.BoolRef],
    index_expr: z3.ArithRef,
    lower_bound: z3.ArithRef,
) -> bool:
    return any(
        _constraint_implies_ge(constraint, index_expr, lower_bound) for constraint in constraints
    )


def _constraint_implies_lt(
    constraint: z3.BoolRef,
    left_expr: z3.ArithRef,
    right_expr: z3.ArithRef,
) -> bool:
    simplified = z3.simplify(constraint)
    if _comparison_matches(simplified, z3.Z3_OP_LT, left_expr, right_expr):
        return True
    if _comparison_matches(simplified, z3.Z3_OP_GT, right_expr, left_expr):
        return True
    if z3.is_not(simplified) and simplified.num_args() == 1:
        child = z3.simplify(simplified.arg(0))
        return _comparison_matches(child, z3.Z3_OP_LE, right_expr, left_expr) or (
            _comparison_matches(child, z3.Z3_OP_GE, left_expr, right_expr)
        )
    return False


def _constraint_implies_ge(
    constraint: z3.BoolRef,
    left_expr: z3.ArithRef,
    right_expr: z3.ArithRef,
) -> bool:
    simplified = z3.simplify(constraint)
    if _comparison_matches(simplified, z3.Z3_OP_GE, left_expr, right_expr):
        return True
    if _comparison_matches(simplified, z3.Z3_OP_LE, right_expr, left_expr):
        return True
    if z3.is_not(simplified) and simplified.num_args() == 1:
        child = z3.simplify(simplified.arg(0))
        return _comparison_matches(child, z3.Z3_OP_LT, left_expr, right_expr) or (
            _comparison_matches(child, z3.Z3_OP_GT, right_expr, left_expr)
        )
    return False


def _comparison_matches(
    expression: z3.ExprRef,
    comparison_kind: int,
    left_expr: z3.ArithRef,
    right_expr: z3.ArithRef,
) -> bool:
    if expression.decl().kind() != comparison_kind or expression.num_args() != 2:
        return False
    return safe_z3_eq(expression.arg(0), left_expr) and safe_z3_eq(expression.arg(1), right_expr)


def _is_negative_of(left_expr: z3.ArithRef, right_expr: z3.ArithRef) -> bool:
    simplified = z3.simplify(left_expr + right_expr)
    return z3.is_int_value(simplified) and simplified.as_long() == 0


def _expr_known_nonnegative(
    expression: z3.ArithRef,
    constraints: list[z3.BoolRef],
) -> bool:
    if _expr_is_sequence_length(expression):
        return True
    if _has_lower_bound(constraints, expression, get_int_val(0)):
        return True
    for alias in _equality_aliases(expression, constraints):
        if _expr_is_sequence_length(alias) or _has_lower_bound(constraints, alias, get_int_val(0)):
            return True
    return False


def _expr_is_sequence_length(expression: z3.ArithRef) -> bool:
    try:
        return expression.decl().kind() == z3.Z3_OP_SEQ_LENGTH
    except z3.Z3Exception:
        return False


def _equality_aliases(
    expression: z3.ArithRef,
    constraints: list[z3.BoolRef],
) -> list[z3.ArithRef]:
    aliases: list[z3.ArithRef] = []
    for constraint in constraints:
        simplified = z3.simplify(constraint)
        if not z3.is_eq(simplified) or simplified.num_args() != 2:
            continue
        left = simplified.arg(0)
        right = simplified.arg(1)
        if isinstance(left, z3.ArithRef) and safe_z3_eq(right, expression):
            aliases.append(left)
        elif isinstance(right, z3.ArithRef) and safe_z3_eq(left, expression):
            aliases.append(right)
    return aliases


def _symbolic_value_int(value: SymbolicValue) -> int | None:
    """Return a concrete integer payload or simplified integer channel."""
    concrete = value.value
    if isinstance(concrete, int) and not isinstance(concrete, bool):
        return concrete
    if z3.is_int_value(value.z3_int):
        return value.z3_int.as_long()
    simplified_index = z3.simplify(value.z3_int)
    if not z3.is_int_value(simplified_index):
        return None
    return simplified_index.as_long()


def _concrete_int_value(expr: z3.ArithRef) -> int | None:
    """Return the concrete integer value of *expr*, if Z3 can simplify it to one."""
    if z3.is_int_value(expr):
        return expr.as_long()
    simplified = z3.simplify(expr)
    if not z3.is_int_value(simplified):
        return None
    return simplified.as_long()


__all__ = [
    "IndexBoundsCheckResult",
    "IndexBoundsCheckStatus",
    "_unwrap_symbolic_sequence",
    "pure_check_index_bounds",
    "pure_check_index_bounds_result",
]
