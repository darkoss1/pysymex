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

"""Top-level structured solver query helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.config.defaults import DEFAULT_ENGINE_SOLVER_TIMEOUT_MS
from pysymex._internal.core.cache.control import is_process_cache_disabled
from pysymex._internal.core.solver.constraints.chain import ConstraintChain
from pysymex._internal.core.solver.engine.constraints import normalize_constraint_iterable
from pysymex._internal.core.solver.engine.context import SolverContext, thread_local_solver
from pysymex._internal.core.solver.engine.results import SolverResult

if TYPE_CHECKING:
    from collections.abc import Iterable


def check_sat_result(
    constraints: Iterable[object] | z3.BoolRef,
    *,
    known_sat_prefix_len: int | None = None,
) -> SolverResult:
    """Check satisfiability without collapsing SAT/UNSAT/UNKNOWN.

    Detector, proof, and reporting code should use this API when ``unknown``
    must not be treated as a definite SAT or UNSAT result.

    Args:
        constraints: One Boolean constraint or an iterable of constraint
            candidates accepted by the normalization boundary.
        known_sat_prefix_len: Optional prefix length already established SAT
            by the owning caller.

    Returns:
        A structured solver outcome. Malformed constraint candidates and
        inconclusive engine checks yield ``UNKNOWN``.

    """
    from pysymex._internal.core.solver.engine.incremental import IncrementalSolver

    if isinstance(constraints, ConstraintChain):
        constraints = constraints.to_list()

    if isinstance(constraints, z3.BoolRef):
        typed_constraints = [constraints]
    else:
        raw_constraints = list(constraints)
        typed_constraints = normalize_constraint_iterable(raw_constraints)
        if len(typed_constraints) != len(raw_constraints):
            return SolverResult.unknown()

    solver = SolverContext.active.get()
    if solver is not None:
        return solver.check_sat_result(
            typed_constraints,
            known_sat_prefix_len=known_sat_prefix_len,
        )

    cached_solver = thread_local_solver.solver
    if cached_solver is None:
        cached_solver = IncrementalSolver(
            timeout_ms=DEFAULT_ENGINE_SOLVER_TIMEOUT_MS,
            use_cache=True,
        )
        thread_local_solver.solver = cached_solver
    return cached_solver.check_sat_result(
        typed_constraints,
        known_sat_prefix_len=known_sat_prefix_len,
    )


def check_sat_result_with_dependency_slice(
    path_constraints: Iterable[object],
    query: object | z3.BoolRef,
    *,
    known_sat_prefix_len: int | None = None,
) -> SolverResult:
    """Check ``path_constraints + query`` with an UNKNOWN-only dependency-slice retry.

    This helper is for local feasibility questions such as subscript bounds,
    exception edges, detector sinks, and mutation success/error forks. Those
    queries frequently append one local predicate to a large path prefix. If the
    full query returns ``UNKNOWN``, retry against only the constraints connected
    to the local predicate through shared Z3 symbols.

    The retry never converts a definitive full SAT/UNSAT result. It only
    replaces UNKNOWN with UNSAT from a dependency-linked subset. SAT from a
    subset is only a local witness, not a proof that the full ambient path is
    feasible, so it deliberately preserves the original UNKNOWN.
    """
    raw_prefix = list(path_constraints)
    raw_query = query if isinstance(query, z3.BoolRef) else None
    if raw_query is None:
        return SolverResult.unknown()

    raw_constraints = [*raw_prefix, raw_query]
    prefix_len = len(raw_prefix) if known_sat_prefix_len is None else known_sat_prefix_len
    full = check_sat_result(raw_constraints, known_sat_prefix_len=prefix_len)
    if not full.is_unknown or not raw_prefix:
        return full

    typed_prefix = normalize_constraint_iterable(raw_prefix)
    typed_query = normalize_constraint_iterable([raw_query])
    if len(typed_prefix) != len(raw_prefix) or len(typed_query) != 1:
        return full

    solver = SolverContext.active.get() or thread_local_solver.solver
    if solver is None:
        return full

    from pysymex._internal.core.solver.engine.incremental import IncrementalSolver

    if not isinstance(solver, IncrementalSolver):
        return full

    try:
        sliced_prefix = solver.slice_prefix_for_query(typed_prefix, typed_query[0])
    except (z3.Z3Exception, OSError, RuntimeError, ValueError):
        return full
    if len(sliced_prefix) >= len(typed_prefix):
        return full

    retry = solver.check_sat_result(
        [*sliced_prefix, typed_query[0]],
        known_sat_prefix_len=len(sliced_prefix),
    )
    if retry.is_unsat:
        return retry
    return full


def get_model(constraints: Iterable[object] | z3.BoolRef) -> z3.ModelRef | None:
    """Return a Z3 model only when encoded constraints are established SAT.

    Returns:
        A model for a SAT result, or ``None`` for UNSAT, UNKNOWN, or malformed
        constraint input.

    """
    result = get_model_result(constraints)
    return result.model if result.is_sat else None


def get_model_result(constraints: Iterable[object] | z3.BoolRef) -> SolverResult:
    """Return structured SAT/UNSAT/UNKNOWN evidence for model extraction.

    Args:
        constraints: One Boolean constraint or an iterable of constraint
            candidates accepted by the normalization boundary.

    Returns:
        A structured solver result. SAT includes a model; malformed input
        yields UNKNOWN.

    """
    if isinstance(constraints, ConstraintChain):
        constraints = constraints.to_list()

    if isinstance(constraints, z3.BoolRef):
        typed_constraints = [constraints]
    else:
        raw_constraints = list(constraints)
        typed_constraints = normalize_constraint_iterable(raw_constraints)
        if len(typed_constraints) != len(raw_constraints):
            return SolverResult.unknown()

    solver = SolverContext.active.get()
    if solver is not None:
        return solver.check_sat_cached(typed_constraints)
    return get_model_cached_result(typed_constraints)


def get_model_cached_result(constraints: Iterable[object] | z3.BoolRef) -> SolverResult:
    """Return standalone structured evidence for model extraction.

    Returns:
        SAT with a model, UNSAT, or UNKNOWN for malformed/inconclusive checks.

    """
    from pysymex._internal.core.solver.engine.incremental import IncrementalSolver

    if isinstance(constraints, ConstraintChain):
        constraints = constraints.to_list()

    if isinstance(constraints, z3.BoolRef):
        typed_constraints = [constraints]
    else:
        raw_constraints = list(constraints)
        typed_constraints = normalize_constraint_iterable(raw_constraints)
        if len(typed_constraints) != len(raw_constraints):
            return SolverResult.unknown()
    if is_process_cache_disabled():
        solver = IncrementalSolver(timeout_ms=DEFAULT_ENGINE_SOLVER_TIMEOUT_MS, use_cache=False)
        return solver.check_sat_cached(typed_constraints)

    solver = thread_local_solver.model_solver
    if solver is None:
        solver = IncrementalSolver(timeout_ms=DEFAULT_ENGINE_SOLVER_TIMEOUT_MS, use_cache=True)
        thread_local_solver.model_solver = solver
    return solver.check_sat_cached(typed_constraints)
