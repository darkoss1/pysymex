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

"""Low-level exact check-cache helpers for IncrementalSolver."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.solver.constraints.hashing import ConstraintHasher, structural_hash
from pysymex._internal.core.solver.engine.caches import CheckCacheEntry
from pysymex._internal.core.solver.engine.types import SolverMixinContract
from pysymex._internal.core.z3.expression_ops import Z3ExpressionOps
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections import OrderedDict

    import z3

    from pysymex._internal.core.solver.engine.results import SolverResult

logger = get_logger(__name__)


class SolverCheckCacheMixin(SolverMixinContract):
    """Cache low-level scoped solver checks after collision-safe validation.

    The cache records structured definitive results only; inconclusive
    ``UNKNOWN`` checks are deliberately excluded from storage.
    """

    if TYPE_CHECKING:
        _cache_hits: int
        _cache_size: int
        _check_cache: OrderedDict[int, list[CheckCacheEntry]]
        _constraint_scope_stack: list[list[z3.BoolRef]]
        _hasher: ConstraintHasher
        _use_cache: bool

        def _current_cache_context(self) -> int:
            """Return the owning solver's ambient cache context."""
            ...

        @staticmethod
        def _mix_cache_context(seed: int, value: int) -> int:
            """Combine cache-context components deterministically."""
            ...

    def _current_constraint_context(self) -> tuple[z3.BoolRef, ...]:
        """Return the currently asserted constraints in chronological scope order."""
        constraints: list[z3.BoolRef] = []
        for scope_constraints in self._constraint_scope_stack:
            constraints.extend(scope_constraints)
        return tuple(constraints)

    def _same_constraint_sequence(
        self,
        left: tuple[z3.BoolRef, ...],
        right: tuple[z3.BoolRef, ...],
    ) -> bool:
        """Return whether two cached constraint sequences are structurally identical."""
        if len(left) != len(right):
            return False
        for left_constraint, right_constraint in zip(left, right, strict=True):
            if left_constraint is right_constraint:
                continue
            if self._hasher.hash_expr(left_constraint) != self._hasher.hash_expr(right_constraint):
                return False
            if not Z3ExpressionOps.safe_eq(left_constraint, right_constraint):
                return False
        return True

    def _make_check_cache_key(self, assumptions: tuple[z3.BoolRef, ...]) -> int:
        """Create a cache key for the active asserted context plus assumptions."""
        assumption_hash = structural_hash(list(assumptions), self._hasher)
        return self._mix_cache_context(
            self._current_cache_context(),
            self._mix_cache_context(len(assumptions), assumption_hash),
        )

    def _check_cache_lookup(
        self,
        primary: int,
        context: tuple[z3.BoolRef, ...],
        assumptions: tuple[z3.BoolRef, ...],
    ) -> SolverResult | None:
        """Lookup a low-level check result after exact collision validation."""
        if not self._use_cache:
            return None
        entries = self._check_cache.get(primary)
        if entries is None:
            return None
        for entry in entries:
            if self._same_constraint_sequence(
                entry.context,
                context,
            ) and self._same_constraint_sequence(entry.assumptions, assumptions):
                self._cache_hits += 1
                self._check_cache.move_to_end(primary)
                if logger.state.trace_enabled:
                    logger.trace(
                        "solver check cache hit primary=%d assumptions=%d",
                        primary,
                        len(assumptions),
                    )
                return entry.result
        if logger.state.debug_enabled:
            logger.debug("check() cache collision detected")
        return None

    def _check_cache_store(
        self,
        primary: int,
        context: tuple[z3.BoolRef, ...],
        assumptions: tuple[z3.BoolRef, ...],
        result: SolverResult,
    ) -> None:
        """Store a low-level check result without caching UNKNOWN answers."""
        if not self._use_cache or result.is_unknown:
            return
        entry = CheckCacheEntry(context=context, assumptions=assumptions, result=result)
        entries = self._check_cache.get(primary)
        if entries is None:
            self._check_cache[primary] = [entry]
        else:
            entries.append(entry)
            self._check_cache.move_to_end(primary)
        if logger.state.trace_enabled:
            logger.trace(
                "solver check cache stored primary=%d assumptions=%d size=%d",
                primary,
                len(assumptions),
                len(self._check_cache),
            )
        while len(self._check_cache) > self._cache_size:
            self._check_cache.popitem(last=False)
