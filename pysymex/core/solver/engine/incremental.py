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

"""Incremental Z3 solver owner."""

from __future__ import annotations

from collections import OrderedDict, deque

import z3

from pysymex.core.solver.constraints.hashing import ConstraintHasher
from pysymex.core.solver.engine.configuration import (
    configure_process_z3,
    create_configured_solver,
)
from pysymex.core.solver.engine.result_cache import SolverCacheMixin
from pysymex.core.solver.engine.caches import (
    AstTranslationCacheEntry,
    CheckCacheEntry,
    CONSTRAINT_FINGERPRINT_CACHE_MAX_ENTRIES,
    UNSAT_SUBSET_CACHE_MAX_ENTRIES,
    UnsatSubsetCacheEntry,
)
from pysymex.core.solver.engine.lifecycle import SolverLifecycleMixin
from pysymex.core.solver.engine.models import SolverModelMixin
from pysymex.core.solver.engine.results import SolverResult
from pysymex.core.solver.engine.sat import SolverSatMixin
from pysymex.core.solver.engine.scopes import SolverScopeMixin
from pysymex.core.solver.engine.translation import SolverTranslationMixin
from pysymex.core.solver.independence.optimizer import ConstraintIndependenceOptimizer
from pysymex.logger import get_logger

logger = get_logger(__name__)


class IncrementalSolver(
    SolverLifecycleMixin,
    SolverTranslationMixin,
    SolverCacheMixin,
    SolverScopeMixin,
    SolverSatMixin,
    SolverModelMixin,
):
    """Incremental Z3 query engine with structural caches and explicit uncertainty.

    The engine owns scoped assertions, translation into its Z3 context,
    optional query slicing, and structured SAT/UNSAT/UNKNOWN results.
    Cached definitive results remain tied to validated constraint contexts.
    """

    def __init__(
        self,
        timeout_ms: int = 10000,
        cache_size: int = 50000,
        warm_start: bool = True,
        use_cache: bool = True,
    ) -> None:
        """Initialize the incremental solver.

        Args:
            timeout_ms: Configured Z3 timeout per query, before any active
                absolute deadline further reduces it.
            cache_size: Maximum number of entries in the structural cache.
            warm_start: Whether a previously retained SAT model may be reused
                when it satisfies the checked suffix under the synchronized
                prefix.
            use_cache: Master toggle for the internal structural-hash cache.
        """
        configure_process_z3(timeout_ms)
        self.solver = create_configured_solver(timeout_ms)
        self._timeout_ms = timeout_ms
        self._scope_depth = 0
        self.cache: OrderedDict[tuple[int, tuple[str, ...]], SolverResult] = OrderedDict()
        self._cache_index: dict[int, set[tuple[str, ...]]] = {}
        self._check_cache: OrderedDict[int, list[CheckCacheEntry]] = OrderedDict()
        self._constraint_fingerprint_cache: OrderedDict[int, list[tuple[z3.ExprRef, str]]] = (
            OrderedDict()
        )
        self._constraint_fingerprint_cache_max_size = CONSTRAINT_FINGERPRINT_CACHE_MAX_ENTRIES
        self._unsat_subset_cache: deque[UnsatSubsetCacheEntry] = deque(
            maxlen=UNSAT_SUBSET_CACHE_MAX_ENTRIES
        )
        self._z3_ast_cache: OrderedDict[int, list[AstTranslationCacheEntry]] = OrderedDict()
        self._z3_ast_cache_hits = 0
        self._z3_ast_cache_misses = 0
        self._cache_context_stack: list[int] = [0]
        self._constraint_scope_stack: list[list[z3.BoolRef]] = [[]]
        self.pending_constraint_scope_stack: list[list[z3.BoolRef]] = [[]]
        self._cache_size = cache_size
        self._query_count = 0
        self._sat_result_count = 0
        self._unsat_result_count = 0
        self._unknown_result_count = 0
        self._cache_hits = 0
        self._solver_time_ms = 0.0
        self._warm_start = warm_start
        self._last_models: deque[z3.ModelRef] = deque(maxlen=10)
        self._optimizer = ConstraintIndependenceOptimizer()
        self._use_cache = use_cache
        self._is_unsat_context: set[int] = set()
        self._deadline_time: float | None = None

        self.active_path: list[z3.BoolRef] = []
        self._hasher = ConstraintHasher()
        self._last_set_timeout_ms: int | None = None
        self._last_set_rlimit: int | None = None


__all__ = ["IncrementalSolver"]
