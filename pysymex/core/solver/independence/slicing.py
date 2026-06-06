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

"""Constraint slicing and diagnostics for independence optimization."""

from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING
import weakref

import z3

from pysymex.core.solver.independence.union_find import UnionFind


class ConstraintIndependenceSlicingMixin:
    """Select dependency-linked prefixes without itself proving feasibility."""

    if TYPE_CHECKING:
        _extract_cached: int
        _extract_full: int
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
        _slice_cache_disabled_count: int
        _slice_cache_enabled: bool
        _slice_cache_hits: int
        _slice_cache_misses: int
        _slicing_disabled: bool
        _slicing_disabled_count: int
        _theory_signature_cache: dict[int, tuple[z3.ExprRef, tuple[str, ...]]]
        _theory_signature_cached: int
        _theory_signature_full: int
        _uf: UnionFind
        _var_cache: dict[int, tuple[z3.ExprRef, frozenset[str]]]
        sliced_queries: int
        total_constraints_after: int
        total_constraints_before: int
        total_queries: int

        def _lookup_slice_cache(
            self,
            cache_key: int,
            path_constraints: list[z3.BoolRef],
            query: z3.BoolRef,
        ) -> list[z3.BoolRef] | None:
            """Return a structurally matched cached slice, when available."""
            ...

        def _maybe_disable_slicing(self) -> None:
            """Disable slicing when retained-prefix evidence warrants it."""
            ...

        def _maybe_disable_slice_cache(self) -> None:
            """Disable slice-result cache when measured reuse is too low."""
            ...

        def _slice_cache_key(
            self,
            path_constraints: list[z3.BoolRef],
            query: z3.BoolRef,
            query_vars: frozenset[str],
        ) -> int:
            """Return a cache key for a path, query, and query variables."""
            ...

        def _store_slice_cache(
            self,
            cache_key: int,
            path_constraints: list[z3.BoolRef],
            query: z3.BoolRef,
            relevant_indices: tuple[int, ...],
        ) -> None:
            """Store retained constraint indices for a structurally matched query."""
            ...

        def get_variables(self, constraint: z3.BoolRef) -> frozenset[str]:
            """Return extracted variables without registering dependencies."""
            ...

    def slice_for_query(
        self,
        path_constraints: list[z3.BoolRef],
        query: z3.BoolRef,
    ) -> list[z3.BoolRef]:
        """Return the conservatively retained prefix for one query expression.

        Constraints linked by registered shared variables are retained, as
        are variable-free constraints encountered while filtering. The
        original list is returned when slicing is disabled or removes no
        constraints.

        A query without extracted variables returns an empty sliced prefix;
        this method itself does not decide whether any path is feasible.

        Limitations:
            In that constant-query fast path, variable-free constraints from
            ``path_constraints`` are not retained in the returned prefix.

        Args:
            path_constraints: The full list of accumulated path constraints.
            query: The branch condition (or negation) being checked.

        Returns:
            Retained path constraints, possibly the original list instance.
        """
        self.total_queries += 1
        n_input = len(path_constraints)
        self.total_constraints_before += n_input

        if n_input == 0:
            self.total_constraints_after += 0
            self._maybe_disable_slicing()
            return []

        if self._slicing_disabled:
            self.total_constraints_after += n_input
            return path_constraints

        query_vars = self.get_variables(query)
        cache_key: int | None = None
        if self._slice_cache_enabled:
            cache_key = self._slice_cache_key(path_constraints, query, query_vars)
            cached = self._lookup_slice_cache(cache_key, path_constraints, query)
            self._maybe_disable_slice_cache()
            if cached is not None:
                n_cached = len(cached)
                self.total_constraints_after += n_cached
                if n_cached < n_input:
                    self.sliced_queries += 1
                self._maybe_disable_slicing()
                return cached

        if not query_vars:
            self.total_constraints_after += 0
            self.sliced_queries += 1
            if cache_key is not None and self._slice_cache_enabled:
                self._store_slice_cache(cache_key, path_constraints, query, ())
            self._maybe_disable_slicing()
            return []

        query_roots: set[str] = set()
        uf_find = self._uf.find
        for v in query_vars:
            query_roots.add(uf_find(v))

        relevant_indices: list[int] = []
        root_cache: dict[str, str] = {}
        for index, constraint in enumerate(path_constraints):
            c_vars = self.get_variables(constraint)
            if not c_vars:
                relevant_indices.append(index)
                continue

            for v in c_vars:
                root = root_cache.get(v)
                if root is None:
                    root = uf_find(v)
                    root_cache[v] = root
                if root in query_roots:
                    relevant_indices.append(index)
                    break

        n_output = len(relevant_indices)
        self.total_constraints_after += n_output

        if n_output < n_input:
            self.sliced_queries += 1

        relevant_indices_tuple = tuple(relevant_indices)
        if cache_key is not None and self._slice_cache_enabled:
            self._store_slice_cache(cache_key, path_constraints, query, relevant_indices_tuple)
        self._maybe_disable_slicing()

        if n_output == n_input:
            return path_constraints

        return [path_constraints[index] for index in relevant_indices]

    def get_stats(self) -> dict[str, object]:
        """Return optimizer statistics for diagnostics.

        Returns:
            Dictionary with query counts, constraint reduction ratios, and
            cache statistics.
        """
        if self.total_constraints_before > 0:
            reduction_ratio = 1.0 - (self.total_constraints_after / self.total_constraints_before)
        else:
            reduction_ratio = 0.0
        slice_cache_attempts = self._slice_cache_hits + self._slice_cache_misses
        slice_cache_hit_rate = (
            self._slice_cache_hits / slice_cache_attempts if slice_cache_attempts else 0.0
        )

        return {
            "total_queries": self.total_queries,
            "sliced_queries": self.sliced_queries,
            "total_constraints_before": self.total_constraints_before,
            "total_constraints_after": self.total_constraints_after,
            "reduction_ratio": round(reduction_ratio, 4),
            "slice_cache_hits": self._slice_cache_hits,
            "slice_cache_misses": self._slice_cache_misses,
            "slice_cache_hit_rate": round(slice_cache_hit_rate, 4),
            "slice_cache_size": len(self._slice_cache),
            "slice_cache_enabled": self._slice_cache_enabled,
            "slice_cache_disabled_count": self._slice_cache_disabled_count,
            "slicing_disabled": self._slicing_disabled,
            "slicing_disabled_count": self._slicing_disabled_count,
            "registered_constraints": len(self._var_cache),
            "var_cache_size": len(self._var_cache),
            "full_extractions": self._extract_full,
            "cached_extractions": self._extract_cached,
            "theory_signature_cache_size": len(self._theory_signature_cache),
            "theory_signature_full": self._theory_signature_full,
            "theory_signature_cached": self._theory_signature_cached,
        }


__all__ = ["ConstraintIndependenceSlicingMixin"]
