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

"""IncrementalSolver lifecycle and deadline helpers."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from pysymex._internal.core.solver.constraints.hashing import ConstraintHasher
from pysymex._internal.core.solver.engine.configuration import create_configured_solver
from pysymex._internal.core.solver.engine.types import SolverMixinContract
from pysymex._internal.core.z3.expression_ops import Z3ExpressionOps
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    import z3

logger = get_logger(__name__)


class SolverLifecycleMixin(SolverMixinContract):
    """Manage solver reset, deadlines, and structural expression equality."""

    def set_deadline(self, deadline_time: float | None) -> None:
        """Set an absolute wall-clock deadline for subsequent solver queries.

        ``deadline_time`` uses ``time.perf_counter()`` units. A ``None`` value
        clears the deadline and restores the configured per-query timeout.
        """
        self._deadline_time = deadline_time

    def _effective_timeout_ms(self) -> int:
        """Return the solver timeout clamped to the active wall-clock deadline."""
        if self._deadline_time is None:
            return self._timeout_ms
        remaining_ms = int((self._deadline_time - time.perf_counter()) * 1000)
        if remaining_ms <= 0:
            return 0
        return max(1, min(self._timeout_ms, remaining_ms))

    def reset(self) -> None:
        """Replace the Z3 solver and clear per-instance query state.

        Side Effects:
            Clears scopes, active-path tracking, retained models, translation
            and result caches, optimizer state, and any active deadline.
        """
        self.solver = create_configured_solver(self._timeout_ms)

        self._scope_depth = 0
        self.cache.clear()
        self._cache_index.clear()
        self._cache_identity_constraints.clear()
        self._quick_sat_cache.clear()
        self._check_cache.clear()
        self._constraint_fingerprint_cache.clear()
        self._unsat_subset_cache.clear()
        self._z3_ast_cache.clear()
        self._z3_ast_cache_hits = 0
        self._z3_ast_cache_misses = 0
        self._cache_context_stack = [0]
        self._constraint_scope_stack = [[]]
        self.pending_constraint_scope_stack = [[]]
        self._last_models.clear()
        self._query_count = 0
        self._z3_check_count = 0
        self._sat_result_count = 0
        self._unsat_result_count = 0
        self._unknown_result_count = 0
        self._cache_hits = 0
        self._solver_time_ms = 0.0
        self._optimizer.reset()
        self._is_unsat_context.clear()
        self.active_path.clear()
        self._hasher = ConstraintHasher()
        self._deadline_time = None
        self._last_set_timeout_ms = None
        self._last_set_rlimit = None

    def expr_equal(self, a: z3.BoolRef, b: z3.BoolRef) -> bool:
        """Return whether two constraints match the engine's identity predicate.

        Notes:
            The fallback comparison uses cached hashes and rendered forms; it
            does not invoke Z3 to prove logical equivalence.

        """
        if a is b:
            return True
        if Z3ExpressionOps.safe_eq(a, b):
            return True
        if self._hasher.hash_expr(a) != self._hasher.hash_expr(b):
            return False
        ctx_a = a.ctx
        ctx_b = b.ctx
        if (ctx_a() if callable(ctx_a) else ctx_a) is (ctx_b() if callable(ctx_b) else ctx_b):
            return False
        return str(a) == str(b)
