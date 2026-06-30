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

"""Model-producing cached SAT queries for the incremental solver."""

from __future__ import annotations

from collections import OrderedDict

import z3

from pysymex._internal.core.solver.constraints.literals import exact_bool_literal
from pysymex._internal.core.solver.engine.results import SolverResult
from pysymex._internal.core.solver.engine.types import SolverMixinContract
from pysymex._internal.core.solver.facts import PathFactDecision, PathFactPolicy
from pysymex._internal.logging.root import get_logger

logger = get_logger(__name__)

_SOLVER_QUERY_ERRORS = (z3.Z3Exception, OSError, RuntimeError, ValueError)
_MAX_WARM_MODEL_CONSTRAINTS = 96
_MAX_QUICK_SAT_CACHE_SIZE = 4096


def _drop_exact_literals_for_model_query(
    constraints: list[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None,
) -> tuple[list[z3.BoolRef], int | None] | None:
    """Drop exact truths and preserve the known-prefix boundary for model queries."""
    prefix_boundary = (
        known_sat_prefix_len
        if known_sat_prefix_len is not None and 0 <= known_sat_prefix_len <= len(constraints)
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


class SolverSatCacheMixin(SolverMixinContract):
    """Run model-producing cached SAT queries while preserving UNKNOWN."""

    def check_sat_cached(
        self,
        constraints: list[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        """Check constraints and cache only definitive results.

        Args:
            constraints: List of Z3 boolean constraints.
            known_sat_prefix_len: Optional prefix length already established
                SAT by the owning caller.

        Returns:
            A SAT/UNSAT/UNKNOWN result; SAT includes a model when established.

        Notes:
            Malformed input and scoped Z3 failures return ``UNKNOWN``.
            ``UNKNOWN`` is never cached as reusable evidence.

        """
        ctx_id = self._current_cache_context()
        constraints_tuple = tuple(constraints)
        quick_key = (ctx_id, tuple(id(c) for c in constraints_tuple))
        cached: (
            OrderedDict[
                tuple[int, tuple[int, ...]],
                tuple[SolverResult, tuple[z3.BoolRef, ...]],
            ]
            | None
        ) = getattr(self, "_quick_sat_cache", None)
        if cached is None:
            self._quick_sat_cache = cached = OrderedDict()
        else:
            result = cached.get(quick_key)
            if result is not None:
                cached.move_to_end(quick_key)
                self._cache_hits += 1
                return result[0]

        result_obj = self._check_sat_cached_impl(constraints, known_sat_prefix_len)
        if not result_obj.is_unknown:
            cached[quick_key] = (result_obj, constraints_tuple)
            cached.move_to_end(quick_key)
            while len(cached) > _MAX_QUICK_SAT_CACHE_SIZE:
                cached.popitem(last=False)
        return result_obj

    def _check_sat_cached_impl(
        self,
        constraints: list[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        translated_constraints = self._normalize_bool_constraints(constraints)
        if len(translated_constraints) != len(constraints):
            logger.debug("Cached solver query received non-boolean or unsupported constraints")
            return SolverResult.unknown()
        literal_filter = _drop_exact_literals_for_model_query(
            translated_constraints,
            known_sat_prefix_len=known_sat_prefix_len,
        )
        if literal_filter is None:
            return SolverResult.unsat()
        translated_constraints, known_sat_prefix_len = literal_filter
        if not translated_constraints:
            return SolverResult.sat(None)

        cache_key = self._make_cache_key(translated_constraints)
        cache_disc = self._constraints_identity_discriminator(translated_constraints)
        cache_identity_constraints: tuple[z3.BoolRef, ...] | None = tuple(
            translated_constraints,
        )
        bucket = self._cache_index.get(cache_key)
        if bucket is not None:
            cached = self._cache_lookup(cache_key, cache_disc)
            if cached is not None and (not cached.is_sat or cached.model is not None):
                return cached
            cache_disc = self._constraints_discriminator(translated_constraints)
            cache_identity_constraints = None
            cached = self._cache_lookup(cache_key, cache_disc)
            if cached is not None and (not cached.is_sat or cached.model is not None):
                return cached

        cached_unsat_subset = self._lookup_unsat_subset_cache(translated_constraints)
        if cached_unsat_subset is not None:
            return cached_unsat_subset

        if (
            PathFactPolicy.classify(
                translated_constraints,
                known_sat_prefix_len=known_sat_prefix_len,
                allow_entailed=False,
            )
            is PathFactDecision.UNSAT
        ):
            return SolverResult.unsat()

        warm_model_result = self._warm_model_result_for_constraints(translated_constraints)
        if warm_model_result is not None:
            self._cache_store(
                cache_key,
                cache_disc,
                warm_model_result,
                identity_constraints=cache_identity_constraints,
            )
            return warm_model_result

        if known_sat_prefix_len is not None and 0 <= known_sat_prefix_len <= len(
            translated_constraints,
        ):
            result_obj = self._check_sat_cached_with_known_prefix(
                constraints=translated_constraints,
                known_sat_prefix_len=known_sat_prefix_len,
            )
            if not result_obj.is_unknown:
                self._cache_store(
                    cache_key,
                    cache_disc,
                    result_obj,
                    identity_constraints=cache_identity_constraints,
                )
                self._store_unsat_subset_cache(translated_constraints, result_obj)
            return result_obj

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
                        "Cached solver scope pop failed after UNKNOWN query",
                        exc_info=True,
                    )
                    self.reset()
                    result_obj = SolverResult.unknown()

        if not result_obj.is_unknown:
            self._cache_store(
                cache_key,
                cache_disc,
                result_obj,
                identity_constraints=cache_identity_constraints,
            )
            self._store_unsat_subset_cache(translated_constraints, result_obj)
        return result_obj

    def _check_sat_cached_with_known_prefix(
        self,
        *,
        constraints: list[z3.BoolRef],
        known_sat_prefix_len: int,
    ) -> SolverResult:
        """Check a model query by asserting the known-SAT prefix once."""
        prefix = constraints[:known_sat_prefix_len]
        suffix = constraints[known_sat_prefix_len:]
        try:
            self._sync_path(prefix)
            return self.check(*suffix, need_model=True)
        except _SOLVER_QUERY_ERRORS:
            logger.debug("Known-prefix cached solver query failed", exc_info=True)
            return SolverResult.unknown()

    def _warm_model_result_for_constraints(
        self,
        constraints: list[z3.BoolRef],
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
