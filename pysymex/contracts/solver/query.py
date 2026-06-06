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

"""Contract solver query records and execution policy."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

import z3

from pysymex.config.defaults import DEFAULT_VERIFIED_SOLVER_TIMEOUT_MS
from pysymex.contracts.ir.evidence import TheoryFeature
from pysymex.contracts.ir.obligations import QueryKind
from pysymex.core.solver.engine.context import active_incremental_solver
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.results import SolverResult
from pysymex.core.state.record import known_sat_prefix_len_for_state


def _empty_constraints() -> tuple[z3.BoolRef, ...]:
    """Return an empty immutable constraint tuple."""
    return ()


def _empty_theory_profile() -> tuple[TheoryFeature, ...]:
    """Return an empty theory-profile tuple."""
    return ()


@dataclass(frozen=True, slots=True)
class ContractQuery:
    """A solver query issued for one contract obligation.

    The query carries solver policy separately from runtime hook control flow.
    Runtime hooks decide when to create an obligation; this module decides how
    the active incremental solver is selected and called.
    """

    query_kind: QueryKind
    constraints: tuple[z3.BoolRef, ...] = field(default_factory=_empty_constraints)
    known_sat_prefix_len: int = 0
    timeout_ms: int = DEFAULT_VERIFIED_SOLVER_TIMEOUT_MS
    use_cache: bool = False
    need_model: bool = False
    theory_profile: tuple[TheoryFeature, ...] = field(default_factory=_empty_theory_profile)

    @staticmethod
    def from_constraints(
        constraints: Iterable[z3.BoolRef],
        *,
        query_kind: QueryKind,
        known_sat_prefix_len: int = 0,
        timeout_ms: int = DEFAULT_VERIFIED_SOLVER_TIMEOUT_MS,
        use_cache: bool = False,
        need_model: bool = False,
        theory_profile: tuple[TheoryFeature, ...] | None = None,
    ) -> ContractQuery:
        """Materialize constraints into a deterministic query record."""
        materialized_constraints = tuple(constraints)
        return ContractQuery(
            query_kind=query_kind,
            constraints=materialized_constraints,
            known_sat_prefix_len=known_sat_prefix_len,
            timeout_ms=timeout_ms,
            use_cache=use_cache,
            need_model=need_model,
            theory_profile=(
                theory_profile
                if theory_profile is not None
                else theory_profile_for_constraints(materialized_constraints)
            ),
        )


def check_contract_query(query: ContractQuery) -> SolverResult:
    """Check a contract query using the active incremental solver when present."""
    solver = active_incremental_solver.get()
    if solver is None:
        solver = IncrementalSolver(timeout_ms=query.timeout_ms, use_cache=query.use_cache)
    result = solver.check_sat_result(
        list(query.constraints),
        known_sat_prefix_len=query.known_sat_prefix_len,
    )
    if query.need_model and result.is_sat and result.model is None:
        model_result = _check_contract_query_model(query)
        if model_result.is_sat and model_result.model is not None:
            return model_result
    return result


def _check_contract_query_model(query: ContractQuery) -> SolverResult:
    """Run a fresh model-producing check for a SAT contract query."""
    solver = IncrementalSolver(timeout_ms=query.timeout_ms, use_cache=False)
    return solver.check_sat_cached(list(query.constraints))


def theory_profile_for_constraints(
    constraints: Iterable[z3.BoolRef],
) -> tuple[TheoryFeature, ...]:
    """Infer a conservative SMT theory profile from Z3 constraints."""
    features: set[TheoryFeature] = set()
    seen: set[int] = set()
    for constraint in constraints:
        _collect_theory_features(constraint, features, seen)
    return tuple(sorted(features, key=lambda feature: feature.value))


def _collect_theory_features(
    expr: z3.ExprRef,
    features: set[TheoryFeature],
    seen: set[int],
) -> None:
    """Collect theory features from one Z3 expression tree."""
    expr_id = expr.get_id()
    if expr_id in seen:
        return
    seen.add(expr_id)

    if isinstance(expr, z3.QuantifierRef):
        features.add(TheoryFeature.QUANTIFIER)
        _collect_theory_features(expr.body(), features, seen)
        return

    sort = expr.sort()
    sort_kind = sort.kind()
    float_sort_kind = getattr(z3, "Z3_FLOATING_POINT_SORT", None)
    sequence_sort_kind = getattr(z3, "Z3_SEQ_SORT", None)
    if sort_kind == z3.Z3_BOOL_SORT:
        features.add(TheoryFeature.BOOL)
    elif sort_kind == z3.Z3_INT_SORT:
        features.add(TheoryFeature.INTEGER)
    elif sort_kind == z3.Z3_REAL_SORT:
        features.add(TheoryFeature.REAL)
    elif sort_kind == z3.Z3_BV_SORT:
        features.add(TheoryFeature.BIT_VECTOR)
    elif sort_kind == z3.Z3_ARRAY_SORT:
        features.add(TheoryFeature.ARRAY)
    elif sequence_sort_kind is not None and sort_kind == sequence_sort_kind:
        features.add(TheoryFeature.STRING)
    elif float_sort_kind is not None and sort_kind == float_sort_kind:
        features.add(TheoryFeature.FLOATING_POINT)
    elif sort_kind == z3.Z3_UNINTERPRETED_SORT:
        features.add(TheoryFeature.UNINTERPRETED)
    else:
        features.add(TheoryFeature.UNKNOWN)

    if not z3.is_app(expr):
        return
    for index in range(expr.num_args()):
        _collect_theory_features(expr.arg(index), features, seen)


__all__ = [
    "ContractQuery",
    "check_contract_query",
    "known_sat_prefix_len_for_state",
    "theory_profile_for_constraints",
]
