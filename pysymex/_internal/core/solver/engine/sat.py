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

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.solver.constraints.literals import exact_bool_literal
from pysymex._internal.core.solver.engine.cache.sat import SolverSatCacheMixin
from pysymex._internal.core.solver.engine.results import SolverResult
from pysymex._internal.core.solver.facts import PathFactDecision, PathFactPolicy
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = get_logger(__name__)
_SOLVER_QUERY_ERRORS = (z3.Z3Exception, OSError, RuntimeError, ValueError)
_MIN_PREFIX_CONSTRAINTS_FOR_INDEPENDENCE_SLICE = 64
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


class SolverSatMixin(SolverSatCacheMixin):
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

        fact_decision = PathFactPolicy.classify(
            constraint_list,
            known_sat_prefix_len=known_sat_prefix_len,
            allow_entailed=True,
            allow_supported_sat=known_sat_prefix_len is None,
        )
        if fact_decision is PathFactDecision.UNSAT:
            return SolverResult.unsat()
        if fact_decision is PathFactDecision.ENTAILED or fact_decision is PathFactDecision.SAT:
            return SolverResult.sat(None)

        from pysymex._internal.core.solver.constraints.hashing import structural_hash

        cache_hv = structural_hash(constraint_list, self._hasher)
        cache_key = self._mix_cache_context(0, cache_hv)

        cache_disc = self._constraints_identity_discriminator_for_constraints(
            constraints,
            constraint_list,
        )
        cache_identity_constraints: tuple[z3.BoolRef, ...] | None = tuple(constraint_list)
        bucket = self._cache_index.get(cache_key)
        if bucket is not None:
            cached = self._cache_lookup(cache_key, cache_disc)
            if cached is not None:
                return cached
            cache_disc = self._constraints_discriminator_for_constraints(
                constraints,
                constraint_list,
            )
            cache_identity_constraints = None
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
            self.active_path,
        )
        if (
            is_aligned
            or not prefix
            or not suffix
            or len(prefix) < _MIN_PREFIX_CONSTRAINTS_FOR_INDEPENDENCE_SLICE
        ):
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
            self._cache_store(
                cache_key,
                cache_disc,
                result,
                identity_constraints=cache_identity_constraints,
            )
            return result

        if not suffix:
            result = SolverResult.sat(None)
            self._cache_store(
                cache_key,
                cache_disc,
                result,
                identity_constraints=cache_identity_constraints,
            )
            return result

        if self._warm_start and self._last_models:
            latest_model = self._last_models[-1]
            try:
                if len(suffix) <= 20 and all(
                    z3.is_true(latest_model.eval(c, model_completion=True)) for c in suffix
                ):
                    result = SolverResult.sat(latest_model)
                    self._cache_store(
                        cache_key,
                        cache_disc,
                        result,
                        identity_constraints=cache_identity_constraints,
                    )
                    return result
            except (z3.Z3Exception, OSError, RuntimeError, ValueError, AttributeError):
                logger.debug("Solver warm-start model check failed", exc_info=True)

        try:
            result = self.check(*suffix, need_model=False)
        except _SOLVER_QUERY_ERRORS:
            result = SolverResult.unknown()
            logger.debug("Solver query failed; preserving path as UNKNOWN", exc_info=True)

        if result.is_unknown and prefix and suffix:
            result = self._retry_unknown_with_dependency_slice(
                result,
                prefix=prefix,
                suffix=suffix,
            )

        self._cache_store(
            cache_key,
            cache_disc,
            result,
            identity_constraints=cache_identity_constraints,
        )
        self._store_unsat_subset_cache(constraint_list, result)
        return result

    def _retry_unknown_with_dependency_slice(
        self,
        original: SolverResult,
        *,
        prefix: list[z3.BoolRef],
        suffix: list[z3.BoolRef],
    ) -> SolverResult:
        """Retry an UNKNOWN query against only dependency-linked path facts.

        The common hot path keeps the solver synchronized to the full active
        path and checks a small suffix as assumptions. That is fast when Z3 can
        decide the whole ambient context, but it is fragile for detector and
        collection-feasibility queries: unrelated bitwise/arithmetic path facts
        can make a local bounds or exception query return ``unknown``.

        On ``UNKNOWN`` only, rebuild the ambient solver prefix from the
        constraint-independence slice selected for the suffix. This preserves
        soundness because the slice is a subset of the already-SAT path prefix:
        UNSAT remains a local proof for the queried dependency component, while
        SAT from the subset deliberately preserves the original UNKNOWN because
        it is not a full-path feasibility proof. The solver is allowed to remain
        synchronized to the sliced prefix; later queries call ``_sync_path``
        before checking.
        """
        try:
            sliced_prefix = self._slice_prefix_for_suffix(prefix, suffix)
        except _SOLVER_QUERY_ERRORS:
            logger.debug("Solver dependency-slice selection failed", exc_info=True)
            return original

        if len(sliced_prefix) >= len(prefix):
            return original

        try:
            self._sync_path(sliced_prefix)
            retry = self.check(*suffix, need_model=False)
        except _SOLVER_QUERY_ERRORS:
            logger.debug("Solver dependency-sliced retry failed", exc_info=True)
            return original

        if retry.is_unsat:
            return retry
        return original

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
