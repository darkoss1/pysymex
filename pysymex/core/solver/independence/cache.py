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

from collections import OrderedDict
from typing import TYPE_CHECKING
import weakref

import z3

from pysymex.core.solver.independence.helpers import (
    as_z3_expr,
    decl_dependency_token,
    expr_theory_signature,
)
from pysymex.core.z3_utils import safe_z3_eq
from pysymex.logger import get_logger

logger = get_logger(__name__)


class ConstraintIndependenceCacheMixin:
    """Cache variable extraction, theory signatures, and validated slices.

    Cache keys are only prefilters; stored expressions are compared before a
    cached slice is reused.
    """

    if TYPE_CHECKING:
        _adaptive_disable_min_queries: int
        _adaptive_disable_min_reduction: float
        _extract_cached: int
        _extract_full: int
        _prefix_theory_signature_cache: dict[tuple[int, ...], frozenset[str]]
        _slice_cache: OrderedDict[
            int,
            list[
                tuple[
                    tuple[weakref.ReferenceType[z3.BoolRef], ...],
                    weakref.ReferenceType[z3.BoolRef],
                    tuple[int, ...],
                ]
            ],
        ]
        _slice_cache_disable_max_hit_rate: float
        _slice_cache_disable_min_attempts: int
        _slice_cache_disabled_count: int
        _slice_cache_enabled: bool
        _slice_cache_hits: int
        _slice_cache_max_size: int
        _slice_cache_misses: int
        _slicing_disabled: bool
        _slicing_disabled_count: int
        _theory_signature_cache: dict[int, tuple[z3.ExprRef, tuple[str, ...]]]
        _theory_signature_cached: int
        _theory_signature_full: int
        _var_cache: dict[int, tuple[z3.ExprRef, frozenset[str]]]
        total_constraints_after: int
        total_constraints_before: int
        total_queries: int

    def _extract_variables(self, expr: z3.ExprRef) -> frozenset[str]:
        """Extract free variables from Z3 expression, with caching."""
        z3_expr = as_z3_expr(expr)
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
                names.add(decl_dependency_token(decl))

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

    def _get_theory_signature(self, expr: z3.ExprRef) -> tuple[str, ...]:
        """Return cached theory/sort signature for a verified Z3 AST."""
        key = expr.get_id()
        cached = self._theory_signature_cache.get(key)
        if cached is not None:
            self._theory_signature_cached += 1
            if logger.state.trace_enabled:
                logger.trace("Theory signature cache hit key=%d", key)
            return cached[1]

        self._theory_signature_full += 1
        signature = expr_theory_signature(expr)
        self._theory_signature_cache[key] = (expr, signature)
        return signature

    def _slice_cache_key(
        self,
        path_constraints: list[z3.BoolRef],
        query: z3.BoolRef,
        query_vars: frozenset[str],
    ) -> int:
        """Build a cheap prefilter key from path, query, and variable hashes.

        Slice-cache keys are not proof evidence. Cache lookup validates the live
        path and query expressions before reuse, so the key should stay cheap
        enough not to dominate one-off slicing attempts.
        """
        path_hashes = tuple(c.hash() for c in path_constraints)

        return hash(
            (
                len(path_constraints),
                path_hashes,
                query.hash(),
                tuple(sorted(query_vars)),
            )
        )

    def _lookup_slice_cache(
        self,
        cache_key: int,
        path_constraints: list[z3.BoolRef],
        query: z3.BoolRef,
    ) -> list[z3.BoolRef] | None:
        """Return a cached slice only after validating live path and query ASTs."""
        bucket = self._slice_cache.get(cache_key)
        if bucket is None:
            self._slice_cache_misses += 1
            return None

        self._slice_cache.move_to_end(cache_key)
        stale_entries: list[
            tuple[
                tuple[weakref.ReferenceType[z3.BoolRef], ...],
                weakref.ReferenceType[z3.BoolRef],
                tuple[int, ...],
            ]
        ] = []
        for entry in list(bucket):
            cached_path_refs, cached_query_ref, cached_indices = entry
            cached_query = cached_query_ref()
            if cached_query is None:
                stale_entries.append(entry)
                continue
            cached_path: list[z3.BoolRef] = []
            stale_path = False
            for cached_ref in cached_path_refs:
                cached_constraint = cached_ref()
                if cached_constraint is None:
                    stale_path = True
                    break
                cached_path.append(cached_constraint)
            if stale_path:
                stale_entries.append(entry)
                continue
            if len(cached_path) != len(path_constraints):
                continue
            try:
                if cached_query is not query and not safe_z3_eq(cached_query, query):
                    continue
                if not all(
                    cached is current or safe_z3_eq(cached, current)
                    for cached, current in zip(cached_path, path_constraints, strict=True)
                ):
                    continue
            except z3.Z3Exception:
                if logger.state.debug_enabled:
                    logger.debug("Slice cache validation failed", exc_info=True)
                continue
            self._slice_cache_hits += 1
            if logger.state.trace_enabled:
                logger.trace("Constraint slice cache hit key=%d", cache_key)
            if len(cached_indices) == len(path_constraints):
                return path_constraints
            return [path_constraints[index] for index in cached_indices]

        for stale_entry in stale_entries:
            bucket.remove(stale_entry)
        if not bucket:
            del self._slice_cache[cache_key]

        self._slice_cache_misses += 1
        return None

    def _store_slice_cache(
        self,
        cache_key: int,
        path_constraints: list[z3.BoolRef],
        query: z3.BoolRef,
        relevant_indices: tuple[int, ...],
    ) -> None:
        """Store weak references and retained indices in the bounded slice cache."""
        entry = (
            tuple(weakref.ref(constraint) for constraint in path_constraints),
            weakref.ref(query),
            relevant_indices,
        )
        bucket = self._slice_cache.get(cache_key)
        if bucket is None:
            self._slice_cache[cache_key] = [entry]
        else:
            bucket.append(entry)
            self._slice_cache.move_to_end(cache_key)
        while len(self._slice_cache) > self._slice_cache_max_size:
            self._slice_cache.popitem(last=False)

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


__all__ = ["ConstraintIndependenceCacheMixin"]
