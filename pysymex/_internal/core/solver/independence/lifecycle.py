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

"""Lifecycle and registration methods for constraint independence."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.solver.independence.union.find import ConstraintUnionFind
from pysymex._internal.core.solver.independence.z3_ops import IndependenceZ3Ops

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.solver.independence.slice.cache import SliceCache


class IndependenceLifecycleMixin:
    """Maintain registered constraint dependencies and resettable cache state."""

    if TYPE_CHECKING:
        _extract_cached: int
        _extract_full: int
        _registered_path_ids: tuple[int, ...]
        _slice_cache: SliceCache
        _slice_cache_disabled_count: int
        _slice_cache_enabled: bool
        _slice_cache_hits: int
        _slice_cache_misses: int
        _slicing_disabled: bool
        _slicing_disabled_count: int
        _uf: ConstraintUnionFind
        _var_cache: dict[int, tuple[z3.ExprRef, frozenset[str]]]
        constraint_index: int
        sliced_queries: int
        total_constraints_after: int
        total_constraints_before: int
        total_queries: int
        var_to_constraint_indices: dict[str, list[int]]

        def _extract_variables(self, expr: z3.ExprRef) -> frozenset[str]:
            """Return dependency tokens extracted from one Z3 expression."""
            ...

    def reset(self) -> None:
        """Clear registered dependencies, caches, and reduction statistics."""
        self._uf = ConstraintUnionFind()
        self._var_cache.clear()
        self._registered_path_ids = ()
        self._slice_cache.clear()
        self._slice_cache_enabled = True
        self._slice_cache_disabled_count = 0
        self.constraint_index = 0
        self.var_to_constraint_indices.clear()
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

    def reset_path_state(self) -> None:
        """Clear registered path dependencies while preserving extraction caches."""
        self._uf = ConstraintUnionFind()
        self.constraint_index = 0
        self.var_to_constraint_indices.clear()
        self._registered_path_ids = ()

    def sync_registered_path(self, path_constraints: list[z3.BoolRef]) -> None:
        """Make registered dependencies match ``path_constraints`` exactly.

        Reuses existing registrations only when the current registered prefix
        is identical to, or a strict prefix of, the requested path. Path
        switches rebuild from scratch so stale dependency edges cannot affect
        later slice selection.
        """
        path_ids = tuple(constraint.get_id() for constraint in path_constraints)
        if path_ids == self._registered_path_ids:
            return

        registered_count = len(self._registered_path_ids)
        if path_ids[:registered_count] != self._registered_path_ids:
            self.reset_path_state()
            registered_count = 0

        for constraint in path_constraints[registered_count:]:
            self.register_constraint(constraint)
        self._registered_path_ids = path_ids

    def register_constraint(self, constraint: z3.BoolRef) -> frozenset[str]:
        """Record dependency tokens and union those shared by one constraint.

        All extracted variables in the constraint are unioned so subsequent
        slicing retains transitive dependency closure.

        Args:
            constraint: A Z3 boolean constraint.

        Returns:
            The frozenset of variable names in the constraint.

        """
        z3_c = IndependenceZ3Ops.as_z3_expr(constraint)
        if z3_c is None:
            self.constraint_index += 1
            return frozenset()

        var_names = self._extract_variables(z3_c)

        it = iter(var_names)
        first = next(it, None)
        if first is not None:
            self._uf.find(first)

            current_idx = self.constraint_index
            for v in var_names:
                self.var_to_constraint_indices.setdefault(v, []).append(current_idx)

            for v in it:
                self._uf.union(first, v)

        self.constraint_index += 1
        if len(self._registered_path_ids) + 1 == self.constraint_index:
            self._registered_path_ids = (*self._registered_path_ids, z3_c.get_id())
        return var_names

    def get_variables(self, constraint: z3.BoolRef) -> frozenset[str]:
        """Return dependency tokens for a constraint without registering it.

        If the constraint hasn't been registered yet, extracts and caches
        the variables but does NOT update the Union-Find structure (use
        ``register_constraint`` for that).

        Args:
            constraint: A Z3 expression.

        Returns:
            Frozenset of variable names.

        """
        z3_c = IndependenceZ3Ops.as_z3_expr(constraint)
        if z3_c is None:
            return frozenset()
        return self._extract_variables(z3_c)
