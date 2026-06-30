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

"""Structural metadata for Z3 formulae shared by solver layers."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.cache.control import (
    is_process_cache_disabled,
    register_process_cache_clearer,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

_FORMULA_META_CACHE_MAX_ENTRIES = 262144
_FORMULA_META_CACHE: OrderedDict[tuple[int, int], tuple[z3.ExprRef, FormulaMeta]] = OrderedDict()
_formula_meta_hits = 0
_formula_meta_misses = 0


@dataclass(frozen=True, slots=True)
class FormulaMeta:
    """Cached structural metadata for a Z3 formula or term."""

    node_count: int
    max_depth: int
    contains_bitvector: bool
    contains_float: bool
    contains_array: bool
    contains_sequence: bool
    contains_modulo: bool
    contains_division: bool
    contains_nonlinear_mul: bool
    contains_uninterpreted: bool

    @property
    def contains_hard_witness_theory(self) -> bool:
        """Return whether the expression uses theory fragments suited for witnesses."""
        return self.contains_sequence or self.contains_float or self.contains_array

    @property
    def contains_complex_theory(self) -> bool:
        """Return whether the expression is likely to be solver-expensive."""
        return (
            self.contains_bitvector
            or self.contains_float
            or self.contains_array
            or self.contains_sequence
            or self.contains_modulo
            or self.contains_division
            or self.contains_nonlinear_mul
        )


@dataclass(frozen=True, slots=True)
class FormulaMetaCacheStats:
    """Snapshot of process-local formula metadata cache activity."""

    hits: int
    misses: int


def formula_meta(expr: z3.ExprRef) -> FormulaMeta:
    """Return cached structural metadata for one Z3 expression."""
    global _formula_meta_hits, _formula_meta_misses
    if is_process_cache_disabled():
        return _uncached_formula_meta(expr)

    key = _expr_identity(expr)
    cached = _FORMULA_META_CACHE.get(key)
    if cached is not None:
        _formula_meta_hits += 1
        _FORMULA_META_CACHE.move_to_end(key)
        return cached[1]

    _formula_meta_misses += 1
    meta = _uncached_formula_meta(expr)
    _FORMULA_META_CACHE[key] = (expr, meta)
    _FORMULA_META_CACHE.move_to_end(key)
    _trim_formula_meta_cache()
    return meta


def formula_meta_cache_stats() -> FormulaMetaCacheStats:
    """Return formula metadata cache hit and miss counters."""
    return FormulaMetaCacheStats(
        hits=_formula_meta_hits,
        misses=_formula_meta_misses,
    )


def clear_formula_meta_cache() -> None:
    """Clear process-local formula metadata cache entries and counters."""
    global _formula_meta_hits, _formula_meta_misses
    _FORMULA_META_CACHE.clear()
    _formula_meta_hits = 0
    _formula_meta_misses = 0


register_process_cache_clearer(
    "core.formula_meta_cache",
    clear_formula_meta_cache,
)


def _uncached_formula_meta(expr: z3.ExprRef) -> FormulaMeta:
    post_order: list[z3.ExprRef] = []
    visited: set[tuple[int, int]] = set()
    stack: list[tuple[z3.ExprRef, bool]] = [(expr, False)]

    use_global = not is_process_cache_disabled()

    while stack:
        node, processed = stack.pop()
        node_key = _expr_identity(node)
        if node_key in visited:
            continue
        if processed:
            visited.add(node_key)
            post_order.append(node)
        else:
            if use_global and node_key in _FORMULA_META_CACHE:
                continue

            stack.append((node, True))
            for child in _expr_children(node):
                stack.append((child, False))

    local_cache: dict[tuple[int, int], FormulaMeta] = {}

    for node in post_order:
        node_key = _expr_identity(node)
        contains_bitvector = isinstance(node, z3.BitVecRef)
        contains_float = isinstance(node, z3.FPRef)
        contains_array = isinstance(node, z3.ArrayRef)
        contains_sequence = isinstance(node, z3.SeqRef)
        contains_modulo = False
        contains_division = False
        contains_nonlinear_mul = False
        contains_uninterpreted = False

        try:
            kind: int | None = node.decl().kind()
        except (AttributeError, z3.Z3Exception):
            kind = None

        if kind == z3.Z3_OP_UNINTERPRETED:
            contains_uninterpreted = True
        elif kind == z3.Z3_OP_MOD:
            contains_modulo = True
        elif kind == z3.Z3_OP_DIV:
            contains_division = True
        elif kind == z3.Z3_OP_MUL:
            non_const_children = 0
            try:
                for child in _expr_children(node):
                    if not isinstance(child, (z3.IntNumRef, z3.RatNumRef)):
                        non_const_children += 1
                if non_const_children > 1:
                    contains_nonlinear_mul = True
            except (AttributeError, z3.Z3Exception):
                pass

        node_count = 1
        max_depth = 1
        for child in _expr_children(node):
            child_key = _expr_identity(child)
            child_meta = None
            if use_global:
                cached_child = _FORMULA_META_CACHE.get(child_key)
                if cached_child is not None:
                    child_meta = cached_child[1]
            if child_meta is None:
                child_meta = local_cache.get(child_key)

            if child_meta is not None:
                node_count += child_meta.node_count
                max_depth = max(max_depth, 1 + child_meta.max_depth)
                contains_bitvector = contains_bitvector or child_meta.contains_bitvector
                contains_float = contains_float or child_meta.contains_float
                contains_array = contains_array or child_meta.contains_array
                contains_sequence = contains_sequence or child_meta.contains_sequence
                contains_modulo = contains_modulo or child_meta.contains_modulo
                contains_division = contains_division or child_meta.contains_division
                contains_nonlinear_mul = contains_nonlinear_mul or child_meta.contains_nonlinear_mul
                contains_uninterpreted = contains_uninterpreted or child_meta.contains_uninterpreted

        meta = FormulaMeta(
            node_count=node_count,
            max_depth=max_depth,
            contains_bitvector=contains_bitvector,
            contains_float=contains_float,
            contains_array=contains_array,
            contains_sequence=contains_sequence,
            contains_modulo=contains_modulo,
            contains_division=contains_division,
            contains_nonlinear_mul=contains_nonlinear_mul,
            contains_uninterpreted=contains_uninterpreted,
        )
        if use_global:
            _FORMULA_META_CACHE[node_key] = (node, meta)
        else:
            local_cache[node_key] = meta

    expr_key = _expr_identity(expr)
    if use_global:
        _trim_formula_meta_cache()
        return _FORMULA_META_CACHE[expr_key][1]
    return local_cache[expr_key]


def _expr_children(expression: z3.ExprRef) -> list[z3.ExprRef]:
    try:
        return list(cast("Iterable[z3.ExprRef]", expression.children()))
    except (AttributeError, z3.Z3Exception):
        return []


def _expr_identity(expression: z3.ExprRef) -> tuple[int, int]:
    ast_id = getattr(expression, "_symex_id", None)
    if ast_id is None:
        ast_id = expression.get_id()
        try:
            setattr(expression, "_symex_id", ast_id)
        except AttributeError:
            pass
    ctx = expression.ctx
    ctx_id = id(ctx() if callable(ctx) else ctx)
    return (ctx_id, ast_id)


def _trim_formula_meta_cache() -> None:
    while len(_FORMULA_META_CACHE) > _FORMULA_META_CACHE_MAX_ENTRIES:
        _FORMULA_META_CACHE.popitem(last=False)
