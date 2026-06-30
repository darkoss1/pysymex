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

"""Constraint-independence optimizer owner.

The optimizer tracks shared-variable clusters across path constraints and can
return a reduced constraint prefix for a query. Slicing is an optimization only;
solver SAT/UNSAT/UNKNOWN evidence remains owned by the solver engine.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING

from pysymex._internal.core.solver.independence.cache import IndependenceCacheMixin
from pysymex._internal.core.solver.independence.lifecycle import (
    IndependenceLifecycleMixin,
)
from pysymex._internal.core.solver.independence.slicing import IndependenceSlicingMixin
from pysymex._internal.core.solver.independence.union.find import ConstraintUnionFind

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.solver.independence.slice.cache import SliceCache


class IndependenceOptimizer(
    IndependenceLifecycleMixin,
    IndependenceCacheMixin,
    IndependenceSlicingMixin,
):
    """Track shared-variable constraint clusters for optional query slicing.

    Instead of always sending all registered path constraints to Z3, the
    optimizer may select the constraints linked to the query through recorded
    variables while preserving conservative constraints required by its
    slicing implementation.

    The optimizer maintains internal state (Union-Find, variable caches) and
    is designed to be re-used across the lifetime of a single symbolic
    execution. Call ``reset()`` between functions or files.

    Limitations:
        This class never proves feasibility or infeasibility by itself. It only
        chooses a prefix for the owning solver to query.
    """

    __slots__ = (
        "_adaptive_disable_min_queries",
        "_adaptive_disable_min_reduction",
        "_extract_cached",
        "_extract_full",
        "_registered_path_ids",
        "_slice_cache",
        "_slice_cache_disable_max_hit_rate",
        "_slice_cache_disable_min_attempts",
        "_slice_cache_disabled_count",
        "_slice_cache_enabled",
        "_slice_cache_hits",
        "_slice_cache_max_size",
        "_slice_cache_misses",
        "_slicing_disabled",
        "_slicing_disabled_count",
        "_uf",
        "_var_cache",
        "constraint_index",
        "sliced_queries",
        "total_constraints_after",
        "total_constraints_before",
        "total_queries",
        "var_to_constraint_indices",
    )

    def __init__(
        self,
        slice_cache_size: int = 1024,
        adaptive_disable_min_queries: int = 32,
        adaptive_disable_min_reduction: float = 0.02,
        slice_cache_disable_min_attempts: int = 512,
        slice_cache_disable_max_hit_rate: float = 0.01,
    ) -> None:
        """Initialize empty dependency, cache, and reduction-statistic state.

        Args:
            slice_cache_size: Maximum number of slice-cache buckets retained.
            adaptive_disable_min_queries: Minimum number of measured queries
                before low-value slicing may be disabled.
            adaptive_disable_min_reduction: Minimum measured reduction ratio
                required to keep slicing enabled after that threshold.
            slice_cache_disable_min_attempts: Minimum slice-cache lookups
                before no-reuse cache overhead may be disabled.
            slice_cache_disable_max_hit_rate: Maximum observed hit rate that
                disables slice result caching while retaining slicing itself.

        """
        self._uf = ConstraintUnionFind()
        self._var_cache: dict[int, tuple[z3.ExprRef, frozenset[str]]] = {}
        self._registered_path_ids: tuple[int, ...] = ()
        self._slice_cache: SliceCache = OrderedDict()
        self.constraint_index = 0
        self.var_to_constraint_indices: dict[str, list[int]] = {}
        self._slice_cache_max_size = max(1, slice_cache_size)
        self._adaptive_disable_min_queries = max(1, adaptive_disable_min_queries)
        self._adaptive_disable_min_reduction = max(0.0, adaptive_disable_min_reduction)
        self._slice_cache_disable_min_attempts = max(1, slice_cache_disable_min_attempts)
        self._slice_cache_disable_max_hit_rate = max(0.0, slice_cache_disable_max_hit_rate)
        self._slice_cache_enabled = True
        self._slice_cache_disabled_count = 0
        self._extract_full = 0
        self._extract_cached = 0
        self._slice_cache_hits = 0
        self._slice_cache_misses = 0
        self._slicing_disabled = False
        self._slicing_disabled_count = 0
        self.sliced_queries = 0
        self.total_queries = 0
        self.total_constraints_before = 0
        self.total_constraints_after = 0
