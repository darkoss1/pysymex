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

"""Typing-only protocol declarations shared by incremental solver mixins.

Concrete cache, translation, scope, SAT, model, and lifecycle behavior is
owned and documented by the executable mixin modules in this package.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections import OrderedDict, deque
    from collections.abc import Iterable

    import z3

    from pysymex._internal.core.solver.constraints.hashing import ConstraintHasher
    from pysymex._internal.core.solver.engine.caches import (
        AstTranslationCacheEntry,
        CheckCacheEntry,
        UnsatSubsetCacheEntry,
    )
    from pysymex._internal.core.solver.engine.results import SolverResult
    from pysymex._internal.core.solver.independence.optimizer import IndependenceOptimizer

    class SolverMixinContract:
        """Static attribute and method surface shared by solver engine mixins.

        Limitations:
            This protocol is evaluated only for type checking. Declarations
            here do not establish executable solver behavior or a
            SAT/UNSAT/UNKNOWN handling guarantee without a concrete mixin
            implementation.
        """

        active_path: list[z3.BoolRef]
        cache: OrderedDict[tuple[int, tuple[str | int, ...]], SolverResult]
        pending_constraint_scope_stack: list[list[z3.BoolRef]]
        solver: z3.Solver
        _cache_context_stack: list[int]
        _cache_hits: int
        _cache_identity_constraints: dict[
            tuple[int, tuple[str | int, ...]],
            tuple[z3.BoolRef, ...],
        ]
        _cache_index: dict[int, set[tuple[str | int, ...]]]
        _cache_size: int
        _check_cache: OrderedDict[int, list[CheckCacheEntry]]
        _constraint_fingerprint_cache: OrderedDict[int, list[tuple[z3.ExprRef, str]]]
        _constraint_fingerprint_cache_max_size: int
        _constraint_scope_stack: list[list[z3.BoolRef]]
        _deadline_time: float | None
        _hasher: ConstraintHasher
        _is_unsat_context: set[int]
        _last_models: deque[z3.ModelRef]
        _last_set_rlimit: int | None
        _last_set_timeout_ms: int | None
        _optimizer: IndependenceOptimizer
        _query_count: int
        _quick_sat_cache: OrderedDict[
            tuple[int, tuple[int, ...]],
            tuple[SolverResult, tuple[z3.BoolRef, ...]],
        ]
        _sat_result_count: int
        _scope_depth: int
        _solver_time_ms: float
        _timeout_ms: int
        _unknown_result_count: int
        _unsat_result_count: int
        _unsat_subset_cache: deque[UnsatSubsetCacheEntry]
        _use_cache: bool
        _warm_start: bool
        _z3_check_count: int
        _z3_ast_cache: OrderedDict[int, list[AstTranslationCacheEntry]]
        _z3_ast_cache_hits: int
        _z3_ast_cache_misses: int

        def _constraints_discriminator(self, constraints: list[z3.BoolRef]) -> tuple[str, ...]:
            """Require a stable cache collision discriminator."""
            ...

        def _constraints_discriminator_for_constraints(
            self,
            constraints_obj: Iterable[z3.BoolRef],
            constraints: list[z3.BoolRef],
        ) -> tuple[str, ...]:
            """Require a discriminator for an input constraint collection."""
            ...

        def _constraints_identity_discriminator(
            self,
            constraints: list[z3.BoolRef],
        ) -> tuple[str | int, ...]:
            """Require a cheap identity discriminator for normalized constraints."""
            ...

        def _constraints_identity_discriminator_for_constraints(
            self,
            constraints_obj: Iterable[z3.BoolRef],
            constraints: list[z3.BoolRef],
        ) -> tuple[str | int, ...]:
            """Require a cheap identity discriminator for an input collection."""
            ...

        def _current_cache_context(self) -> int:
            """Require the active cache-context identifier."""
            ...

        def _current_constraint_context(self) -> tuple[z3.BoolRef, ...]:
            """Require the currently asserted constraint context."""
            ...

        def _effective_timeout_ms(self) -> int:
            """Require the effective timeout for the current query."""
            ...

        def _flush_pending_constraints(self) -> None:
            """Require removal of constraints already asserted to the solver."""
            ...

        def _make_cache_key(self, constraints: list[z3.BoolRef]) -> int:
            """Require a cache key for normalized constraints."""
            ...

        def _make_check_cache_key(self, assumptions: tuple[z3.BoolRef, ...]) -> int:
            """Require a check-cache key for query assumptions."""
            ...

        def _lookup_unsat_subset_cache(
            self,
            constraints: list[z3.BoolRef],
        ) -> SolverResult | None:
            """Require exact UNSAT-subset cache lookup."""
            ...

        def _store_unsat_subset_cache(
            self,
            constraints: list[z3.BoolRef],
            result: SolverResult,
        ) -> None:
            """Require exact UNSAT-subset cache storage."""
            ...

        def _check_cache_lookup(
            self,
            primary: int,
            context: tuple[z3.BoolRef, ...],
            assumptions: tuple[z3.BoolRef, ...],
        ) -> SolverResult | None:
            """Require lookup of a structurally matched check result."""
            ...

        @staticmethod
        def _mix_cache_context(seed: int, value: int) -> int:
            """Require deterministic combination of cache contexts."""
            ...

        def _normalize_bool_constraint(self, value: object) -> z3.BoolRef | None:
            """Require normalization of one Boolean constraint candidate."""
            ...

        def _normalize_bool_constraints(self, values: Iterable[object]) -> list[z3.BoolRef]:
            """Require normalization of Boolean constraint candidates."""
            ...

        def _cache_lookup(
            self,
            primary: int,
            discriminator: tuple[str | int, ...],
        ) -> SolverResult | None:
            """Require lookup of a discriminator-verified cache result."""
            ...

        def _cache_store(
            self,
            primary: int,
            discriminator: tuple[str | int, ...],
            result: SolverResult,
            identity_constraints: tuple[z3.BoolRef, ...] | None = None,
        ) -> None:
            """Require storage of a structured query result."""
            ...

        def _check_cache_store(
            self,
            primary: int,
            context: tuple[z3.BoolRef, ...],
            assumptions: tuple[z3.BoolRef, ...],
            result: SolverResult,
        ) -> None:
            """Require storage of a contextual check result."""
            ...

        def _same_constraint_sequence(
            self,
            left: tuple[z3.BoolRef, ...],
            right: tuple[z3.BoolRef, ...],
        ) -> bool:
            """Require structural comparison of constraint sequences."""
            ...

        def _slice_prefix_for_suffix(
            self,
            prefix: list[z3.BoolRef],
            query: Iterable[z3.BoolRef] | z3.BoolRef,
        ) -> list[z3.BoolRef]:
            """Require dependency-based prefix selection for a query."""
            ...

        def _sync_path(self, target_prefix: list[z3.BoolRef]) -> None:
            """Require synchronization of asserted path constraints."""
            ...

        def add(self, *constraints: z3.BoolRef) -> None:
            """Require assertion of constraints through the solver owner."""
            ...

        def check(self, *assumptions: z3.BoolRef, need_model: bool = False) -> SolverResult:
            """Require a structured check operation over assumptions."""
            ...

        def check_sat_result(
            self,
            constraints: Iterable[z3.BoolRef],
            known_sat_prefix_len: int | None = None,
        ) -> SolverResult:
            """Require a structured satisfiability result for constraints."""
            ...

        def expr_equal(self, a: z3.BoolRef, b: z3.BoolRef) -> bool:
            """Require structural expression equality checking."""
            ...

        def get_model(self, constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
            """Require a model query for supplied constraints."""
            ...

        def check_sat_cached(
            self,
            constraints: list[z3.BoolRef],
            known_sat_prefix_len: int | None = None,
        ) -> SolverResult:
            """Require a cache-aware structured satisfiability query."""
            ...

        def path_may_be_feasible(
            self,
            constraints: Iterable[z3.BoolRef],
            known_sat_prefix_len: int | None = None,
        ) -> bool:
            """Require the optimistic path-feasibility predicate."""
            ...

        def pop(self) -> None:
            """Require removal of one asserted solver scope."""
            ...

        def push(self) -> None:
            """Require creation of one asserted solver scope."""
            ...

        def reset(self) -> None:
            """Require restoration of initial solver and cache state."""
            ...

else:

    class SolverMixinContract:
        """Runtime placeholder for the type-checking-only solver mixin surface."""
