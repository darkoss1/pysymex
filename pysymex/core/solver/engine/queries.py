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

from collections.abc import Iterable

import z3

from pysymex.core.cache.control import register_process_cache_clearer
from pysymex.core.solver.constraints.chain import ConstraintChain
from pysymex.core.solver.engine.configuration import create_configured_solver
from pysymex.core.solver.engine.caches import ClearableCache, StructuralCache
from pysymex.core.solver.engine.constraints import normalize_constraint_iterable
from pysymex.core.solver.engine.context import active_incremental_solver, thread_local_solver
from pysymex.core.solver.engine.results import SolverResult

DEFAULT_SOLVER_TIMEOUT_MS: int = 5000

_SOLVER_CACHES: list[ClearableCache] = []

_IS_SAT_CACHE = StructuralCache(maxsize=512)
_MODEL_CACHE = StructuralCache(maxsize=512)
_PROVE_CACHE = StructuralCache(maxsize=512)

_SOLVER_CACHES.extend([_IS_SAT_CACHE, _MODEL_CACHE, _PROVE_CACHE])


def create_solver(timeout_ms: int = DEFAULT_SOLVER_TIMEOUT_MS) -> z3.Solver:
    """Create a standalone Z3 solver configured with a query timeout.

    Args:
        timeout_ms: Timeout in milliseconds. Defaults to 5 000 ms.

    Returns:
        A configured ``z3.Solver`` ready for use.

    Notes:
        Other owner-specific solver components may create and configure their
        own Z3 solver instances directly.
    """
    return create_configured_solver(timeout_ms)


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
    from pysymex.core.solver.engine.incremental import IncrementalSolver

    if isinstance(constraints, ConstraintChain):
        constraints = constraints.to_list()

    if isinstance(constraints, z3.BoolRef):
        typed_constraints = [constraints]
    else:
        raw_constraints = list(constraints)
        typed_constraints = normalize_constraint_iterable(raw_constraints)
        if len(typed_constraints) != len(raw_constraints):
            return SolverResult.unknown()

    solver = active_incremental_solver.get()
    if solver is not None:
        return solver.check_sat_result(
            typed_constraints,
            known_sat_prefix_len=known_sat_prefix_len,
        )

    cached_solver = thread_local_solver.solver
    if cached_solver is None:
        cached_solver = IncrementalSolver(timeout_ms=DEFAULT_SOLVER_TIMEOUT_MS, use_cache=True)
        thread_local_solver.solver = cached_solver
    return cached_solver.check_sat_result(
        typed_constraints,
        known_sat_prefix_len=known_sat_prefix_len,
    )


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

    solver = active_incremental_solver.get()
    if solver is not None:
        return solver.check_sat_cached(typed_constraints)
    return get_model_cached_result(typed_constraints)


def get_model_cached(constraints: Iterable[object] | z3.BoolRef) -> z3.ModelRef | None:
    """Return a standalone SAT model through the incremental solver owner.

    Returns:
        A model for a SAT result, or ``None`` when a model is not established.
    """
    result = get_model_cached_result(constraints)
    return result.model if result.is_sat else None


def get_model_cached_result(constraints: Iterable[object] | z3.BoolRef) -> SolverResult:
    """Return standalone structured evidence for model extraction.

    Returns:
        SAT with a model, UNSAT, or UNKNOWN for malformed/inconclusive checks.
    """
    from pysymex.core.solver.engine.incremental import IncrementalSolver

    if isinstance(constraints, ConstraintChain):
        constraints = constraints.to_list()

    if isinstance(constraints, z3.BoolRef):
        typed_constraints = [constraints]
    else:
        raw_constraints = list(constraints)
        typed_constraints = normalize_constraint_iterable(raw_constraints)
        if len(typed_constraints) != len(raw_constraints):
            return SolverResult.unknown()
    solver = IncrementalSolver(timeout_ms=5000, use_cache=False)
    return solver.check_sat_cached(typed_constraints)


def get_model_string(constraints: list[z3.BoolRef]) -> str | None:
    """Return string form of an established SAT model, if one is available."""
    model = get_model(constraints)
    return str(model) if model else None


def prove_result(claim: object) -> SolverResult:
    """Return the structured solver result for proving ``claim``.

    A claim is proved exactly when the encoded negation is UNSAT. Refutable
    claims therefore return SAT with a counterexample model, and malformed or
    inconclusive claims return UNKNOWN.

    Args:
        claim: Boolean constraint candidate to prove.

    Returns:
        Structured solver result for ``Not(claim)``.
    """
    typed_claims = normalize_constraint_iterable([claim])
    if len(typed_claims) != 1:
        return SolverResult.unknown()
    return _prove_normalized_claim(typed_claims[0])


def _prove_normalized_claim(claim: z3.BoolRef) -> SolverResult:
    """Check the negated proof obligation with the standalone proof solver."""
    from pysymex.core.solver.engine.incremental import IncrementalSolver

    solver = IncrementalSolver(timeout_ms=5000, use_cache=False)
    return solver.check_sat_cached([z3.Not(claim)])


def prove(claim: z3.BoolRef) -> bool:
    """Return whether the encoded negation of ``claim`` is established UNSAT.

    Notes:
        ``False`` includes inconclusive and satisfiable-negation outcomes; it
        is not evidence that the claim is false.
    """
    return _prove_normalized_claim(claim).is_unsat


def clear_solver_caches() -> None:
    """Clear standalone API caches that retain Z3-associated values.

    Side Effects:
        Empties the caches registered by this module. Per-instance
        ``IncrementalSolver`` caches are reset by their owning instance.
    """
    for cached_fn in _SOLVER_CACHES:
        cached_fn.clear()


register_process_cache_clearer("core.solver_query_caches", clear_solver_caches)


__all__ = [
    "DEFAULT_SOLVER_TIMEOUT_MS",
    "check_sat_result",
    "clear_solver_caches",
    "create_solver",
    "get_model",
    "get_model_cached",
    "get_model_cached_result",
    "get_model_result",
    "get_model_string",
    "prove",
    "prove_result",
]
