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

"""Cache helpers for constraint independence slicing."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.solver.independence.slice.cache import (
    SliceCache,
    lookup_slice_cache,
    slice_cache_key,
    store_slice_cache,
)
from pysymex._internal.core.solver.independence.z3_ops import IndependenceZ3Ops
from pysymex._internal.logging.root import get_logger

logger = get_logger(__name__)


class IndependenceCacheMixin:
    """Cache variable extraction and validated slices.

    Cache keys are only prefilters; stored expressions are compared before a
    cached slice is reused.
    """

    if TYPE_CHECKING:
        _adaptive_disable_min_queries: int
        _adaptive_disable_min_reduction: float
        _extract_cached: int
        _extract_full: int
        _slice_cache: SliceCache
        _slice_cache_disable_max_hit_rate: float
        _slice_cache_disable_min_attempts: int
        _slice_cache_disabled_count: int
        _slice_cache_enabled: bool
        _slice_cache_hits: int
        _slice_cache_max_size: int
        _slice_cache_misses: int
        _slicing_disabled: bool
        _slicing_disabled_count: int
        _var_cache: dict[int, tuple[z3.ExprRef, frozenset[str]]]
        total_constraints_after: int
        total_constraints_before: int
        total_queries: int

    def _extract_variables(self, expr: z3.ExprRef) -> frozenset[str]:
        """Extract free variables from Z3 expression, with caching."""
        z3_expr = IndependenceZ3Ops.as_z3_expr(expr)
        if z3_expr is None:
            return frozenset()

        key = z3_expr.get_id()
        cached = self._var_cache.get(key)
        if cached is not None:
            self._extract_cached += 1
            if logger.state.trace_enabled:
                logger.trace("Constraint independence variable cache hit key=%d", key)
            return cached[1]

        self._extract_full += 1

        names: set[str] = set()
        worklist: list[z3.ExprRef] = [z3_expr]
        seen_ids: set[int] = {key}

        keepalive: list[z3.ExprRef] = []

        while worklist:
            node = worklist.pop()
            if z3.is_quantifier(node):
                body = node.body()
                keepalive.append(body)
                body_id = body.get_id()
                if body_id not in seen_ids:
                    seen_ids.add(body_id)
                    worklist.append(body)
                continue
            if not z3.is_app(node):
                continue
            decl = node.decl()
            kind = decl.kind()

            if kind == z3.Z3_OP_UNINTERPRETED:
                if decl.arity() == 0:
                    names.add(decl.name())
                    continue
                names.add(IndependenceZ3Ops.decl_dependency_token(decl))

            children = node.children()
            if children:
                keepalive.extend(children)
            for child in children:
                child_id = child.get_id()
                if child_id not in seen_ids:
                    seen_ids.add(child_id)
                    worklist.append(child)

        result = frozenset(names)
        self._var_cache[key] = (z3_expr, result)
        return result

    def _slice_cache_key(
        self,
        path_constraints: list[z3.BoolRef],
        query: z3.BoolRef,
        query_vars: frozenset[str],
    ) -> int:
        """Return a cheap prefilter key for the validated slice cache."""
        return slice_cache_key(path_constraints, query, query_vars)

    def _lookup_slice_cache(
        self,
        cache_key: int,
        path_constraints: list[z3.BoolRef],
        query: z3.BoolRef,
    ) -> list[z3.BoolRef] | None:
        """Return a validated cached slice and update cache hit/miss counters."""
        cached = lookup_slice_cache(self._slice_cache, cache_key, path_constraints, query)
        if cached is None:
            self._slice_cache_misses += 1
            return None

        self._slice_cache_hits += 1
        return cached

    def _store_slice_cache(
        self,
        cache_key: int,
        path_constraints: list[z3.BoolRef],
        query: z3.BoolRef,
        relevant_indices: tuple[int, ...],
    ) -> None:
        """Store weak references and retained indices in the bounded slice cache."""
        store_slice_cache(
            self._slice_cache,
            cache_key,
            path_constraints,
            query,
            relevant_indices,
            max_size=self._slice_cache_max_size,
        )

    def _maybe_disable_slicing(self) -> None:
        """Disable slicing after measured reduction and reuse both remain low."""
        if self._slicing_disabled or self.total_queries < self._adaptive_disable_min_queries:
            return
        if self.total_constraints_before <= 0:
            return

        reduction_ratio = 1.0 - (self.total_constraints_after / self.total_constraints_before)
        cache_attempts = self._slice_cache_hits + self._slice_cache_misses
        cache_hit_rate = self._slice_cache_hits / cache_attempts if cache_attempts else 0.0

        if reduction_ratio < self._adaptive_disable_min_reduction and cache_hit_rate < 0.70:
            self._slicing_disabled = True
            self._slicing_disabled_count += 1
            logger.verbose(
                "Disabled constraint slicing reduction=%.3f cache_hit_rate=%.3f",
                reduction_ratio,
                cache_hit_rate,
            )

    def _maybe_disable_slice_cache(self) -> None:
        """Disable slice-result caching when measured reuse does not justify its cost."""
        if not self._slice_cache_enabled:
            return

        cache_attempts = self._slice_cache_hits + self._slice_cache_misses
        if cache_attempts < self._slice_cache_disable_min_attempts:
            return

        cache_hit_rate = self._slice_cache_hits / cache_attempts if cache_attempts else 0.0
        if cache_hit_rate > self._slice_cache_disable_max_hit_rate:
            return

        self._slice_cache_enabled = False
        self._slice_cache_disabled_count += 1
        self._slice_cache.clear()
        logger.verbose("Disabled constraint slice cache hit_rate=%.3f", cache_hit_rate)
