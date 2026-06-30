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

"""Cache reuse for exact syntactic Boolean literal classification."""

from __future__ import annotations

from collections import OrderedDict
from typing import Final

import z3

from pysymex._internal.core.cache.control import register_process_cache_clearer

_EXACT_BOOL_LITERAL_ATTR: Final = "_symex_exact_bool_literal"
MISSING_EXACT_BOOL_LITERAL: Final = object()
_EXACT_BOOL_LITERAL_CACHE_MAX_SIZE: Final = 8192
_EXACT_BOOL_LITERAL_CACHE: OrderedDict[tuple[int, int], tuple[z3.BoolRef, bool | None]] = (
    OrderedDict()
)


def attached_exact_bool_literal(expr: z3.BoolRef) -> object:
    """Return a wrapper-local literal classification or the missing sentinel."""
    return getattr(expr, _EXACT_BOOL_LITERAL_ATTR, MISSING_EXACT_BOOL_LITERAL)


def lookup_exact_bool_literal_cache(expr: z3.BoolRef) -> tuple[bool, bool | None]:
    """Return a cached AST-id literal classification after expression validation."""
    key = _exact_bool_literal_cache_key(expr)
    cached = _EXACT_BOOL_LITERAL_CACHE.get(key)
    if cached is None:
        return False, None
    cached_expr, cached_literal = cached
    if cached_expr is expr or _same_bool_expr(cached_expr, expr):
        _EXACT_BOOL_LITERAL_CACHE.move_to_end(key)
        return True, cached_literal
    del _EXACT_BOOL_LITERAL_CACHE[key]
    return False, None


def store_exact_bool_literal_cache(expr: z3.BoolRef, literal: bool | None) -> None:
    """Store a bounded exact-literal classification for wrapper-independent reuse."""
    key = _exact_bool_literal_cache_key(expr)
    _EXACT_BOOL_LITERAL_CACHE[key] = (expr, literal)
    _EXACT_BOOL_LITERAL_CACHE.move_to_end(key)
    if len(_EXACT_BOOL_LITERAL_CACHE) > _EXACT_BOOL_LITERAL_CACHE_MAX_SIZE:
        _EXACT_BOOL_LITERAL_CACHE.popitem(last=False)


def _exact_bool_literal_cache_key(expr: z3.BoolRef) -> tuple[int, int]:
    """Return a process-local key for a Z3 Boolean AST within its context."""
    ast_id = getattr(expr, "_symex_id", None)
    if ast_id is None:
        ast_id = expr.get_id()
        try:
            setattr(expr, "_symex_id", ast_id)
        except AttributeError:
            pass
    ctx = expr.ctx
    ctx_id = id(ctx() if callable(ctx) else ctx)
    return (ctx_id, ast_id)


def _same_bool_expr(left: z3.BoolRef, right: z3.BoolRef) -> bool:
    """Return whether two BoolRef wrappers point at the same Z3 AST."""
    left_id = getattr(left, "_symex_id", None) or left.get_id()
    right_id = getattr(right, "_symex_id", None) or right.get_id()
    if left_id != right_id:
        return False
    left_ctx = left.ctx
    right_ctx = right.ctx
    left_ctx_id = id(left_ctx() if callable(left_ctx) else left_ctx)
    right_ctx_id = id(right_ctx() if callable(right_ctx) else right_ctx)
    return left_ctx_id == right_ctx_id


def try_attach_exact_bool_literal(expr: z3.BoolRef, literal: bool | None) -> None:
    """Attach a local-classification result to a Z3 wrapper when supported."""
    try:
        setattr(expr, _EXACT_BOOL_LITERAL_ATTR, literal)
    except AttributeError:
        return


def clear_exact_bool_literal_cache() -> None:
    """Clear wrapper-independent exact-literal classification entries."""
    _EXACT_BOOL_LITERAL_CACHE.clear()


register_process_cache_clearer(
    "core.exact_bool_literal_cache",
    clear_exact_bool_literal_cache,
)
