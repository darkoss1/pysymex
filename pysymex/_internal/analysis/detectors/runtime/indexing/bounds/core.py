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

"""Public Z3-backed index bounds checks for sequence accesses.

Provides :func:`pure_check_index_bounds`, the stateless SAT-checked primitive
for ``IndexError`` detection, and :func:`pure_check_index_bounds_result`, which
preserves unsupported and inconclusive states for detector/reporting callers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.analysis.detectors.detector.issue_evidence import (
    constraints_extend_inconclusive_path,
    issue_from_feasibility_evidence,
)
from pysymex._internal.analysis.detectors.feasibility import get_model_if_satisfiable_result
from pysymex._internal.analysis.detectors.runtime.indexing.bounds.evidence import (
    IndexBoundsEvidence,
    index_bounds_evidence,
    unwrap_symbolic_sequence,
)
from pysymex._internal.analysis.detectors.runtime.indexing.bounds.proofs import (
    definitely_in_bounds,
    path_constraints_prove_in_bounds,
)
from pysymex._internal.analysis.detectors.runtime.indexing.bounds.types import (
    IndexBoundsCheckResult,
)
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.engine.policies import path_may_be_feasible
from pysymex._internal.core.solver.engine.queries import (
    check_sat_result_with_dependency_slice,
    get_model,
)
from pysymex._internal.core.types.checks import is_type_subscription
from pysymex._internal.core.types.containers.slices import extract_slice_bounds
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex._internal.analysis.detectors.detector.types import GetModelFn, IsSatFn, Issue

_unwrap_symbolic_sequence = unwrap_symbolic_sequence


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
    Supports symbolic lists, tuples, strings, concrete sequences, and
    concrete sequence payloads stored in symbolic values.

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
    container = unwrap_symbolic_sequence(container)

    evidence = index_bounds_evidence(container, index)
    if evidence is None:
        return IndexBoundsCheckResult.unsupported("unsupported_container")

    if definitely_in_bounds(index, evidence.lower_bound, evidence.upper_bound):
        return IndexBoundsCheckResult.in_bounds("definitely_in_bounds")
    if path_constraints_prove_in_bounds(
        index.z3_int,
        evidence.lower_bound,
        evidence.upper_bound,
        path_constraints,
    ):
        return IndexBoundsCheckResult.in_bounds("path_constraints_prove_in_bounds")

    return _index_bounds_result_from_evidence(
        index=index,
        evidence=evidence,
        path_constraints=path_constraints,
        pc=pc,
        is_satisfiable_fn=is_satisfiable_fn,
        get_model_fn=get_model_fn,
        last_inconclusive_feasibility_len=last_inconclusive_feasibility_len,
    )


def _index_bounds_result_from_evidence(
    *,
    index: SymbolicValue,
    evidence: IndexBoundsEvidence,
    path_constraints: list[z3.BoolRef],
    pc: int,
    is_satisfiable_fn: IsSatFn,
    get_model_fn: GetModelFn,
    last_inconclusive_feasibility_len: int,
) -> IndexBoundsCheckResult:
    """Convert bounds evidence and solver outcome into a structured result."""
    oob_local = z3.And(
        index.is_int,
        z3.Or(
            index.z3_int < evidence.lower_bound,
            index.z3_int >= evidence.upper_bound,
        ),
    )
    local_feasibility = check_sat_result_with_dependency_slice(
        path_constraints,
        oob_local,
    )
    if local_feasibility.is_unsat:
        return IndexBoundsCheckResult.no_evidence("dependency_slice_proves_in_bounds")

    oob_constraint = [*path_constraints, oob_local]
    model_result = get_model_if_satisfiable_result(
        oob_constraint,
        is_satisfiable_fn,
        get_model_fn,
        allow_witness_model=True,
    )
    issue = issue_from_feasibility_evidence(
        result=model_result,
        kind=IssueKind.INDEX_ERROR,
        message=f"Possible index out of bounds: {evidence.container_name}[{index.name}]",
        constraints=oob_constraint,
        pc=pc,
        confidence=evidence.confidence,
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
