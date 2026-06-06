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

"""High-level SAT query operations for IncrementalSolver."""

from __future__ import annotations

from collections.abc import Iterable
from pysymex.logger import get_logger

import z3

from pysymex.core.solver.constraints.literals import exact_bool_literal
from pysymex.core.solver.engine.types import SolverMixinContract
from pysymex.core.solver.engine.results import SolverResult

logger = get_logger(__name__)
_SOLVER_QUERY_ERRORS = (z3.Z3Exception, OSError, RuntimeError, ValueError)
_MIN_PREFIX_CONSTRAINTS_FOR_INDEPENDENCE_SLICE = 64
_MAX_WARM_MODEL_CONSTRAINTS = 96
_MIN_PREFIX_ASSUMPTION_CHECK_CONSTRAINTS = 16


def _drop_exact_literals(
    constraints: list[z3.BoolRef],
    *,
    filter_known_sat_prefix: bool,
    known_sat_prefix_len: int | None = None,
) -> tuple[list[z3.BoolRef], int | None] | None:
    """Drop exact truths and return ``None`` when an exact falsehood is present."""
    prefix_boundary = (
        known_sat_prefix_len
        if filter_known_sat_prefix
        and known_sat_prefix_len is not None
        and 0 <= known_sat_prefix_len <= len(constraints)
        else None
    )
    adjusted_prefix_len = 0
    filtered: list[z3.BoolRef] = []
    for index, constraint in enumerate(constraints):
        literal = exact_bool_literal(constraint)
        if literal is False:
            return None
        if literal is True:
            continue
        if prefix_boundary is not None and index < prefix_boundary:
            adjusted_prefix_len += 1
        filtered.append(constraint)
    return filtered, adjusted_prefix_len if prefix_boundary is not None else None


class SolverSatMixin(SolverMixinContract):
    """Run high-level SAT queries while preserving solver uncertainty.

    This mixin normalizes constraints, consults definitive caches, optionally
    slices an aligned prefix, and returns :class:`SolverResult` so callers can
    keep ``UNKNOWN`` distinct from SAT and UNSAT.
    """

    def check_sat_result(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        """Check encoded constraints while preserving inconclusive outcomes.

        May use constraint independence optimization to reduce the retained
        prefix for the current suffix.

        Args:
            constraints: Boolean Z3 constraints to check.
            known_sat_prefix_len: Optional prefix length supplied as already
                SAT by the caller; the suffix remains subject to this query.

        Returns:
            A SAT/UNSAT/UNKNOWN result. Unsupported constraint values, Z3
            query failures, and scope synchronization failures produce
            ``UNKNOWN``.

        Notes:
            ``UNKNOWN`` results are time/resource-sensitive and are not
            memoized or retained in the definitive result cache.
        """
        import z3

        raw_list = constraints if isinstance(constraints, list) else list(constraints)
        constraint_list = self._normalize_bool_constraints(raw_list)
        if len(constraint_list) != len(raw_list):
            logger.debug("Solver query received non-boolean or unsupported constraints")
            return SolverResult.unknown()

        if not constraint_list:
            return SolverResult.sat(None)

        effective_timeout_ms = self._effective_timeout_ms()
        if effective_timeout_ms <= 0:
            return SolverResult.unknown()

        literal_filter = _drop_exact_literals(
            constraint_list,
            filter_known_sat_prefix=True,
            known_sat_prefix_len=known_sat_prefix_len,
        )
        if literal_filter is None:
            return SolverResult.unsat()
        constraint_list, known_sat_prefix_len = literal_filter
        if not constraint_list:
            return SolverResult.sat(None)

        cached_unsat_subset = self._lookup_unsat_subset_cache(constraint_list)
        if cached_unsat_subset is not None:
            return cached_unsat_subset

        from pysymex.core.solver.constraints.hashing import structural_hash

        cache_hv = structural_hash(constraint_list, self._hasher)
        cache_key = self._mix_cache_context(0, cache_hv)

        bucket = self._cache_index.get(cache_key)
        cache_disc = (
            ()
            if bucket is None
            else self._constraints_discriminator_for_constraints(constraints, constraint_list)
        )

        cached = self._cache_lookup(cache_key, cache_disc)
        if cached is not None:
            return cached

        if known_sat_prefix_len is not None and 0 <= known_sat_prefix_len <= len(constraint_list):
            prefix = constraint_list[:known_sat_prefix_len]
            suffix = constraint_list[known_sat_prefix_len:]
        else:
            prefix = []
            suffix = constraint_list

        is_aligned = known_sat_prefix_len is not None and known_sat_prefix_len == len(
            self.active_path
        )
        if is_aligned:
            sliced_prefix = prefix
        elif not prefix or not suffix:
            sliced_prefix = prefix
        elif len(prefix) < _MIN_PREFIX_CONSTRAINTS_FOR_INDEPENDENCE_SLICE:
            sliced_prefix = prefix
        else:
            sliced_prefix = self._slice_prefix_for_suffix(prefix, suffix)

        if len(sliced_prefix) >= _MIN_PREFIX_ASSUMPTION_CHECK_CONSTRAINTS:
            suffix = [*sliced_prefix, *suffix]
            sliced_prefix = []

        try:
            self._sync_path(sliced_prefix)
        except _SOLVER_QUERY_ERRORS:
            result = SolverResult.unknown()
            self._cache_store(cache_key, cache_disc, result)
            return result

        if not suffix:
            result = SolverResult.sat(None)
            self._cache_store(cache_key, cache_disc, result)
            return result

        if self._warm_start and self._last_models:
            latest_model = self._last_models[-1]
            try:
                if len(suffix) <= 20 and all(
                    z3.is_true(latest_model.eval(c, model_completion=True)) for c in suffix
                ):
                    result = SolverResult.sat(latest_model)
                    self._cache_store(cache_key, cache_disc, result)
                    return result
            except (z3.Z3Exception, OSError, RuntimeError, ValueError, AttributeError):
                logger.debug("Solver warm-start model check failed", exc_info=True)

        try:
            result = self.check(*suffix, need_model=False)
        except _SOLVER_QUERY_ERRORS:
            result = SolverResult.unknown()
            logger.debug("Solver query failed; preserving path as UNKNOWN", exc_info=True)

        self._cache_store(cache_key, cache_disc, result)
        self._store_unsat_subset_cache(constraint_list, result)
        return result

    def path_may_be_feasible(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        """Return whether constraints are not established UNSAT.

        UNKNOWN is treated as feasible for path exploration. Use
        :meth:`check_sat_result` for detector feasibility and reporting.
        """
        result = self.check_sat_result(
            constraints,
            known_sat_prefix_len=known_sat_prefix_len,
        )
        return not result.is_unsat

    def check_sat_cached(self, constraints: list[z3.BoolRef]) -> SolverResult:
        """Check constraints and cache only definitive results.

        Args:
            constraints: List of Z3 boolean constraints.

        Returns:
            A SAT/UNSAT/UNKNOWN result; SAT includes a model when established.

        Notes:
            Malformed input and scoped Z3 failures return ``UNKNOWN``.
            ``UNKNOWN`` is never cached as reusable evidence.
        """
        translated_constraints = self._normalize_bool_constraints(constraints)
        if len(translated_constraints) != len(constraints):
            logger.debug("Cached solver query received non-boolean or unsupported constraints")
            return SolverResult.unknown()
        nontrivial_constraints_reversed: list[z3.BoolRef] = []
        for constraint in reversed(translated_constraints):
            literal = exact_bool_literal(constraint)
            if literal is False:
                return SolverResult.unsat()
            if literal is not True:
                nontrivial_constraints_reversed.append(constraint)
        if not nontrivial_constraints_reversed:
            return SolverResult.sat(None)
        nontrivial_constraints_reversed.reverse()
        translated_constraints = nontrivial_constraints_reversed

        cache_key = self._make_cache_key(translated_constraints)
        bucket = self._cache_index.get(cache_key)
        cache_disc: tuple[str, ...] | None = None
        if bucket is not None:
            cache_disc = self._constraints_discriminator(translated_constraints)
            cached = self._cache_lookup(cache_key, cache_disc)
            if cached is not None and (not cached.is_sat or cached.model is not None):
                return cached

        cached_unsat_subset = self._lookup_unsat_subset_cache(translated_constraints)
        if cached_unsat_subset is not None:
            return cached_unsat_subset

        warm_model_result = self._warm_model_result_for_constraints(translated_constraints)
        if warm_model_result is not None:
            if cache_disc is None:
                cache_disc = self._constraints_discriminator(translated_constraints)
            self._cache_store(cache_key, cache_disc, warm_model_result)
            return warm_model_result

        result_obj = SolverResult.unknown()
        pushed = False
        try:
            self.solver.push()
            pushed = True
            self.solver.add(translated_constraints)
            result_obj = self.check(need_model=True)
        except _SOLVER_QUERY_ERRORS:
            logger.debug("Cached solver query failed; preserving result as UNKNOWN", exc_info=True)
        finally:
            if pushed:
                try:
                    self.solver.pop()
                except _SOLVER_QUERY_ERRORS:
                    logger.debug(
                        "Cached solver scope pop failed after UNKNOWN query", exc_info=True
                    )
                    self.reset()
                    result_obj = SolverResult.unknown()

        if not result_obj.is_unknown:
            if cache_disc is None:
                cache_disc = self._constraints_discriminator(translated_constraints)
            self._cache_store(cache_key, cache_disc, result_obj)
            self._store_unsat_subset_cache(translated_constraints, result_obj)
        return result_obj

    def _warm_model_result_for_constraints(
        self, constraints: list[z3.BoolRef]
    ) -> SolverResult | None:
        """Return a retained SAT model only when it satisfies every constraint."""
        if not self._warm_start or not self._last_models:
            return None
        if len(constraints) > _MAX_WARM_MODEL_CONSTRAINTS:
            return None

        model = self._last_models[-1]
        try:
            for constraint in constraints:
                if not z3.is_true(model.eval(constraint, model_completion=True)):
                    return None
        except _SOLVER_QUERY_ERRORS:
            logger.debug("Warm-start model validation failed", exc_info=True)
            return None

        return SolverResult.sat(model)
