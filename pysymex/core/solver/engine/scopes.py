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

"""Scope, assertion, and low-level check operations for IncrementalSolver."""

from __future__ import annotations

from collections.abc import Iterable
from pysymex.logger import get_logger
import time

import z3

from pysymex.core.solver.constraints.theory import constraints_include_bitvector_smt_theory
from pysymex.core.solver.engine.configuration import rlimit_for_timeout_ms
from pysymex.core.solver.engine.events import emit_event
from pysymex.core.solver.engine.types import SolverMixinContract
from pysymex.core.solver.engine.results import SolverResult
from pysymex.core.solver.independence.optimizer import ConstraintIndependenceOptimizer
from pysymex.stats.types import EventType

logger = get_logger(__name__)


class SolverScopeMixin(SolverMixinContract):
    """Own incremental Z3 scopes and convert checks into structured results.

    Query exceptions and elapsed deadlines yield ``SolverResult.unknown()``
    rather than a SAT or UNSAT claim.
    """

    def constraint_optimizer(self) -> ConstraintIndependenceOptimizer:
        """Expose the shared constraint optimizer for graph-based analyses."""
        return self._optimizer

    def push(self) -> None:
        """Push a new constraint scope."""
        self.solver.push()
        self._scope_depth += 1
        self._cache_context_stack.append(self._current_cache_context())
        self._constraint_scope_stack.append([])
        self.pending_constraint_scope_stack.append([])

    def pop(self) -> None:
        """Pop the current constraint scope."""
        if self._scope_depth > 0:
            try:
                self.solver.pop()
            except (z3.Z3Exception, OSError, RuntimeError) as exc:
                logger.debug("Solver pop failed at depth %d: %s", self._scope_depth, exc)
                self.reset()
                return

            self._scope_depth -= 1
            self._cache_context_stack.pop()
            self._constraint_scope_stack.pop()
            self.pending_constraint_scope_stack.pop()

    def add(self, *constraints: z3.BoolRef) -> None:
        """Normalize and add supported Boolean constraints at the current scope.

        Notes:
            Inputs that cannot be normalized to a Boolean Z3 constraint are
            omitted here. Structured query entrypoints detect malformed
            complete inputs before relying on SAT/UNSAT results.
        """
        from pysymex.core.constants import Z3_FALSE, Z3_TRUE

        processed_constraints: list[z3.BoolRef] = []

        for c in constraints:
            if c is Z3_TRUE:
                continue
            if c is Z3_FALSE:
                processed_constraints.append(c)
                continue

            normalized = self._normalize_bool_constraint(c)
            if normalized is not None:
                processed_constraints.append(normalized)

        if not processed_constraints:
            return

        self._constraint_scope_stack[-1].extend(processed_constraints)
        if self._use_cache:
            updated_context = self._current_cache_context()
            for c in processed_constraints:
                updated_context = self._mix_cache_context(updated_context, c.hash())
            self._cache_context_stack[-1] = updated_context
        self.pending_constraint_scope_stack[-1].extend(processed_constraints)
        self.solver.add(*processed_constraints)

    def extend_path(self, constraints: Iterable[z3.BoolRef]) -> None:
        """Permanently extend the ambient path with new constraints.

        Adds constraints at the current scope and updates active_path.
        Used by the symbolic executor to commit path segments it has chosen
        to retain; this method does not itself establish feasibility.
        """
        c_list = list(constraints)
        for c in c_list:
            self.push()
            self.add(c)
            self.active_path.append(c)

    def check(self, *assumptions: z3.BoolRef, need_model: bool = False) -> SolverResult:
        """Check the current encoded scope with optional temporary assumptions.

        Args:
            assumptions: Additional assumptions for this check only.
            need_model: Whether to materialize and return a model for SAT results.
                       Defaults to False for performance.

        Returns:
            A structured result for the encoded query, with an optional model
            only when SAT is established and requested.

        Notes:
            Expired deadlines, solver exceptions, and Z3 ``unknown`` results
            are represented as ``SolverResult.unknown()``.
        """
        self._query_count += 1

        num_clauses = len(self.active_path) + len(assumptions)
        emit_event(EventType.SOLVER_QUERY, 0.0, {"clauses": num_clauses})

        effective_timeout_ms = self._effective_timeout_ms()
        if effective_timeout_ms <= 0:
            emit_event(EventType.SOLVER_UNKNOWN, 1.0)
            self._unknown_result_count += 1
            return SolverResult.unknown()

        assumption_tuple = tuple(assumptions)
        check_cache_key: int | None = None
        check_context: tuple[z3.BoolRef, ...] | None = None
        should_store_check_cache = False
        if (
            self._use_cache
            and not need_model
            and not constraints_include_bitvector_smt_theory(assumption_tuple)
        ):
            check_cache_key = self._make_check_cache_key(assumption_tuple)
            if check_cache_key in self._check_cache:
                check_context = self._current_constraint_context()
                cached = self._check_cache_lookup(
                    check_cache_key,
                    check_context,
                    assumption_tuple,
                )
                if cached is not None:
                    if cached.is_sat:
                        self._sat_result_count += 1
                        emit_event(EventType.SOLVER_SAT, 1.0)
                    elif cached.is_unsat:
                        self._unsat_result_count += 1
                        emit_event(EventType.SOLVER_UNSAT, 1.0)
                    else:
                        self._unknown_result_count += 1
                        emit_event(EventType.SOLVER_UNKNOWN, 1.0)
                    return cached
            should_store_check_cache = True

        if effective_timeout_ms != self._last_set_timeout_ms:
            self.solver.set("timeout", effective_timeout_ms)
            self._last_set_timeout_ms = effective_timeout_ms

        rlimit = rlimit_for_timeout_ms(effective_timeout_ms)
        if rlimit != self._last_set_rlimit:
            self.solver.set("rlimit", rlimit)
            self._last_set_rlimit = rlimit
        start = time.perf_counter()

        try:
            self._flush_pending_constraints()
            result = self.solver.check(*assumption_tuple)
        except (z3.Z3Exception, OSError, RuntimeError, ValueError):
            logger.debug("Solver check failed; preserving result as UNKNOWN", exc_info=True)
            result = z3.unknown

        elapsed_ms = (time.perf_counter() - start) * 1000
        self._solver_time_ms += elapsed_ms

        if result == z3.sat:
            if need_model:
                try:
                    model = self.solver.model()
                except (z3.Z3Exception, OSError, RuntimeError, ValueError):
                    logger.debug(
                        "Solver model extraction failed; preserving result as UNKNOWN",
                        exc_info=True,
                    )
                    emit_event(EventType.SOLVER_UNKNOWN, 1.0)
                    self._unknown_result_count += 1
                    return SolverResult.unknown()
                emit_event(EventType.SOLVER_SAT, 1.0)
                self._sat_result_count += 1
                if self._warm_start:
                    self._last_models.append(model)
                return SolverResult.sat(model)
            emit_event(EventType.SOLVER_SAT, 1.0)
            self._sat_result_count += 1
            result_obj = SolverResult.sat(None)
        elif result == z3.unsat:
            emit_event(EventType.SOLVER_UNSAT, 1.0)
            self._unsat_result_count += 1
            result_obj = SolverResult.unsat()
        else:
            emit_event(EventType.SOLVER_UNKNOWN, 1.0)
            self._unknown_result_count += 1
            result_obj = SolverResult.unknown()

        if check_cache_key is not None and should_store_check_cache:
            if check_context is None:
                check_context = self._current_constraint_context()
            self._check_cache_store(check_cache_key, check_context, assumption_tuple, result_obj)
        return result_obj
