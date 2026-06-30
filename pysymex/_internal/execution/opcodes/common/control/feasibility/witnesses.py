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

"""String-witness term caches used by branch ordering."""

from __future__ import annotations

from collections import OrderedDict

import z3

from pysymex._internal.core.cache.control import (
    is_process_cache_disabled,
    register_process_cache_clearer,
)

_StringWitnessTermsCacheKey = tuple[tuple[int, int], ...]
_StringWitnessExprCacheKey = tuple[int, int]
_STRING_WITNESS_TERMS_CACHE_MAX_SIZE = 8192
_STRING_WITNESS_TERMS_CACHE: OrderedDict[
    _StringWitnessTermsCacheKey,
    tuple[tuple[z3.ExprRef, ...], bool],
] = OrderedDict()
_STRING_WITNESS_EXPR_CACHE_MAX_SIZE = 8192
_STRING_WITNESS_EXPR_CACHE: OrderedDict[
    _StringWitnessExprCacheKey,
    tuple[z3.ExprRef, bool],
] = OrderedDict()

STRING_WITNESS_TERMS_CACHE = _STRING_WITNESS_TERMS_CACHE
STRING_WITNESS_EXPR_CACHE = _STRING_WITNESS_EXPR_CACHE


def has_string_witness_terms(expressions: tuple[z3.ExprRef, ...]) -> bool:
    """Return whether expressions contain string/integer witness helper terms."""
    return _has_string_witness_terms(expressions)


def uncached_has_string_witness_terms(expressions: tuple[z3.ExprRef, ...]) -> bool:
    """Return string-witness term presence without the outer expression tuple cache."""
    return _uncached_has_string_witness_terms(expressions)


def string_witness_terms_cache_key(
    expressions: tuple[z3.ExprRef, ...],
) -> _StringWitnessTermsCacheKey:
    """Return the cache key for a tuple of branch-order expressions."""
    return _string_witness_terms_cache_key(expressions)


def string_witness_expr_cache_lookup(expression: z3.ExprRef) -> bool | None:
    """Return a cached per-expression string-witness result when available."""
    return _string_witness_expr_cache_lookup(expression)


def string_witness_expr_cache_store(expression: z3.ExprRef, result: bool) -> None:
    """Store a per-expression string-witness result."""
    _string_witness_expr_cache_store(expression, result)


def string_witness_expr_cache_key(expression: z3.ExprRef) -> _StringWitnessExprCacheKey:
    """Return the cache key for one branch-order expression."""
    return _string_witness_expr_cache_key(expression)


def is_string_witness_term(expression: z3.ExprRef) -> bool:
    """Return whether an expression is a string/integer witness helper term."""
    return _is_string_witness_term(expression)


def _has_string_witness_terms(expressions: tuple[z3.ExprRef, ...]) -> bool:
    if is_process_cache_disabled():
        return _uncached_has_string_witness_terms(expressions)

    cache_key = _string_witness_terms_cache_key(expressions)
    cached = _STRING_WITNESS_TERMS_CACHE.get(cache_key)
    if cached is not None:
        _cached_expressions, cached_result = cached
        _STRING_WITNESS_TERMS_CACHE.move_to_end(cache_key)
        return cached_result

    result = _uncached_has_string_witness_terms(expressions)
    _STRING_WITNESS_TERMS_CACHE[cache_key] = (expressions, result)
    if len(_STRING_WITNESS_TERMS_CACHE) > _STRING_WITNESS_TERMS_CACHE_MAX_SIZE:
        _STRING_WITNESS_TERMS_CACHE.popitem(last=False)
    return result


def _string_witness_terms_cache_key(
    expressions: tuple[z3.ExprRef, ...],
) -> _StringWitnessTermsCacheKey:
    return tuple((id(expr.ctx_ref()), expr.get_id()) for expr in expressions)


def _uncached_has_string_witness_terms(expressions: tuple[z3.ExprRef, ...]) -> bool:
    pending: list[z3.ExprRef] = list(expressions)
    visited: set[int] = set()
    cacheable_misses: list[z3.ExprRef] = []
    while pending:
        if len(visited) > 256:
            return False
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        cached = _string_witness_expr_cache_lookup(expression)
        if cached is True:
            return True
        if cached is False:
            continue
        cacheable_misses.append(expression)
        if _is_string_witness_term(expression):
            _string_witness_expr_cache_store(expression, True)
            return True
        pending.extend(expression.children())
    for expression in cacheable_misses:
        _string_witness_expr_cache_store(expression, False)
    return False


def _string_witness_expr_cache_lookup(expression: z3.ExprRef) -> bool | None:
    if is_process_cache_disabled():
        return None

    cache_key = _string_witness_expr_cache_key(expression)
    cached = _STRING_WITNESS_EXPR_CACHE.get(cache_key)
    if cached is None:
        return None
    _cached_expression, cached_result = cached
    _STRING_WITNESS_EXPR_CACHE.move_to_end(cache_key)
    return cached_result


def _string_witness_expr_cache_store(expression: z3.ExprRef, result: bool) -> None:
    if is_process_cache_disabled():
        return

    cache_key = _string_witness_expr_cache_key(expression)
    _STRING_WITNESS_EXPR_CACHE[cache_key] = (expression, result)
    if len(_STRING_WITNESS_EXPR_CACHE) > _STRING_WITNESS_EXPR_CACHE_MAX_SIZE:
        _STRING_WITNESS_EXPR_CACHE.popitem(last=False)


def _string_witness_expr_cache_key(expression: z3.ExprRef) -> _StringWitnessExprCacheKey:
    return (id(expression.ctx_ref()), expression.get_id())


def _is_string_witness_term(expression: z3.ExprRef) -> bool:
    try:
        decl = expression.decl()
    except (AttributeError, z3.Z3Exception):
        return False
    if decl.kind() != z3.Z3_OP_UNINTERPRETED:
        return False
    name = str(decl.name())
    return name.startswith(("ord_", "bin_")) or "count" in name


def clear_string_witness_caches() -> None:
    """Clear process-local branch string-witness probe caches."""
    _STRING_WITNESS_TERMS_CACHE.clear()
    _STRING_WITNESS_EXPR_CACHE.clear()


register_process_cache_clearer(
    "execution.string_witness_caches",
    clear_string_witness_caches,
)
