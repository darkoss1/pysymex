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

"""Z3 context translation and constraint normalization for IncrementalSolver."""

from __future__ import annotations

from collections.abc import Iterable
from typing import cast

import z3

from pysymex.core.solver.engine.caches import (
    AstTranslationCacheEntry,
    TranslatableZ3Expr,
)
from pysymex.core.solver.engine.constraints import as_bool_constraint
from pysymex.core.solver.engine.types import SolverMixinContract
from pysymex.logger import get_logger

logger = get_logger(__name__)


class SolverTranslationMixin(SolverMixinContract):
    """Normalize Boolean constraints and cache cross-context Z3 translations.

    Translation failures retain the original expression as implemented here;
    a later query may therefore fail and become ``UNKNOWN``. This mixin
    performs normalization and caching, not a satisfiability check.
    """

    def _ast_signature_key(self, expr: z3.BoolRef, target_ctx: object) -> int:
        """Return a safe prefilter key for the per-solver Z3 AST translation cache."""
        source_ctx: object = getattr(expr, "ctx", None)
        stack: list[z3.ExprRef] = [expr]
        seen: set[int] = set()
        decl_kinds: list[int] = []
        sort_kinds: list[int] = []

        while stack:
            current = stack.pop()
            current_id = current.get_id()
            if current_id in seen:
                continue
            seen.add(current_id)

            try:
                sort_kinds.append(current.sort().kind())
            except z3.Z3Exception:
                if logger.state.debug_enabled:
                    logger.debug(
                        "Failed to read Z3 AST sort during translation signature", exc_info=True
                    )
                sort_kinds.append(-1)

            if z3.is_app(current):
                try:
                    decl_kinds.append(current.decl().kind())
                except z3.Z3Exception:
                    if logger.state.debug_enabled:
                        logger.debug(
                            "Failed to read Z3 AST declaration during translation signature",
                            exc_info=True,
                        )
                    decl_kinds.append(-1)
                for index in range(current.num_args()):
                    stack.append(current.arg(index))
            elif z3.is_quantifier(current):
                quantifier = current
                decl_kinds.append(1 if quantifier.is_forall() else 2)
                for index in range(quantifier.num_vars()):
                    try:
                        sort_kinds.append(quantifier.var_sort(index).kind())
                    except z3.Z3Exception:
                        if logger.state.debug_enabled:
                            logger.debug(
                                "Failed to read Z3 quantifier sort during translation signature",
                                exc_info=True,
                            )
                        sort_kinds.append(-1)
                stack.append(quantifier.body())

        return hash(
            (
                self._hasher.hash_expr(expr),
                id(source_ctx),
                id(target_ctx),
                tuple(sorted(decl_kinds)),
                tuple(sorted(sort_kinds)),
            )
        )

    def _lookup_translated_ast(
        self,
        cache_key: int,
        source: z3.BoolRef,
    ) -> z3.BoolRef | None:
        """Lookup a translated BoolRef after collision validation against the source AST."""
        bucket = self._z3_ast_cache.get(cache_key)
        if bucket is None:
            self._z3_ast_cache_misses += 1
            return None

        self._z3_ast_cache.move_to_end(cache_key)
        for entry in bucket:
            try:
                if z3.eq(entry.source, source):
                    self._z3_ast_cache_hits += 1
                    if logger.state.trace_enabled:
                        logger.trace("Z3 AST translation cache hit key=%d", cache_key)
                    return entry.translated
            except z3.Z3Exception:
                if logger.state.debug_enabled:
                    logger.debug("Z3 AST translation cache validation failed", exc_info=True)
                continue

        self._z3_ast_cache_misses += 1
        if logger.state.trace_enabled:
            logger.trace("Z3 AST translation cache miss key=%d", cache_key)
        return None

    def _store_translated_ast(
        self,
        cache_key: int,
        source: z3.BoolRef,
        translated: z3.BoolRef,
    ) -> None:
        """Store a translated BoolRef in the per-solver LRU cache."""
        entry = AstTranslationCacheEntry(source=source, translated=translated)
        bucket = self._z3_ast_cache.get(cache_key)
        if bucket is None:
            self._z3_ast_cache[cache_key] = [entry]
        else:
            bucket.append(entry)
            self._z3_ast_cache.move_to_end(cache_key)
        while len(self._z3_ast_cache) > self._cache_size:
            self._z3_ast_cache.popitem(last=False)

    def _translate_bool_constraint(self, constraint: z3.BoolRef) -> z3.BoolRef:
        """Translate a BoolRef into this solver's Z3 context with validated cache reuse."""
        target_ctx = z3.main_ctx()
        source_ctx: object = getattr(constraint, "ctx", None)
        if source_ctx == target_ctx:
            return constraint
        cache_key: int | None = None
        if self._use_cache:
            cache_key = self._ast_signature_key(constraint, target_ctx)
            cached = self._lookup_translated_ast(cache_key, constraint)
            if cached is not None:
                return cached

        try:
            raw_translated = cast("TranslatableZ3Expr", constraint).translate(target_ctx)
            if not isinstance(raw_translated, z3.BoolRef):
                logger.warning("Z3 AST translation produced non-boolean constraint")
                return constraint
            translated = raw_translated
        except z3.Z3Exception:
            logger.warning(
                "Z3 AST translation failed; retaining original constraint", exc_info=True
            )
            return constraint

        if self._use_cache and cache_key is not None:
            self._store_translated_ast(cache_key, constraint, translated)
        return translated

    def _normalize_bool_constraint(self, value: object) -> z3.BoolRef | None:
        """Normalize and context-translate a solver constraint candidate."""
        normalized = as_bool_constraint(value)
        if normalized is None:
            return None
        return self._translate_bool_constraint(normalized)

    def _normalize_bool_constraints(self, values: Iterable[object]) -> list[z3.BoolRef]:
        """Return normalizable Boolean constraints, omitting unsupported inputs."""
        constraints: list[z3.BoolRef] = []
        for value in values:
            normalized = self._normalize_bool_constraint(value)
            if normalized is not None:
                constraints.append(normalized)
        return constraints
