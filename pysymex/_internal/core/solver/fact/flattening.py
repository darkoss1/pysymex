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

"""Exact conjunction flattening for path-fact classification."""

from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING, Final

import z3

from pysymex._internal.core.cache.control import is_process_cache_disabled
from pysymex._internal.core.solver.constraints.literals import exact_bool_literal
from pysymex._internal.core.solver.fact.atoms import expr_key

if TYPE_CHECKING:
    from collections.abc import Sequence

_FLATTEN_CACHE_MAX_SIZE: Final = 16384
_FLATTEN_ID_CACHE_MAX_SIZE: Final = 16384
_FLATTEN_CACHE: OrderedDict[tuple[int, int], tuple[z3.BoolRef, tuple[z3.BoolRef, ...]]] = (
    OrderedDict()
)
_FLATTEN_ID_CACHE: OrderedDict[int, tuple[z3.BoolRef, tuple[z3.BoolRef, ...]]] = OrderedDict()


def flatten_constraints(
    constraints: Sequence[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None,
) -> tuple[tuple[z3.BoolRef, ...], int | None]:
    """Return exact flattened constraints and the adjusted known-SAT prefix length."""
    flattened: list[z3.BoolRef] = []
    adjusted_prefix_len = 0
    prefix_len = known_sat_prefix_len
    if prefix_len is not None and not (0 <= prefix_len <= len(constraints)):
        prefix_len = None

    for index, constraint in enumerate(constraints):
        literal = exact_bool_literal(constraint)
        if literal is True:
            continue
        items = (constraint,) if literal is False else _flatten_bool_constraint(constraint)
        flattened.extend(items)
        if prefix_len is not None and index < prefix_len:
            adjusted_prefix_len += len(items)

    return tuple(flattened), adjusted_prefix_len if prefix_len is not None else None


def clear_path_fact_flatten_cache() -> None:
    """Clear process-local path-fact conjunction flattening entries."""
    _FLATTEN_CACHE.clear()
    _FLATTEN_ID_CACHE.clear()


def _flatten_bool_constraint(expr: z3.BoolRef) -> tuple[z3.BoolRef, ...]:
    if is_process_cache_disabled():
        return _uncached_flatten_bool_constraint(expr)

    identity_key = id(expr)
    identity_cached = _FLATTEN_ID_CACHE.get(identity_key)
    if identity_cached is not None:
        cached_expr, cached_items = identity_cached
        if cached_expr is expr:
            _FLATTEN_ID_CACHE.move_to_end(identity_key)
            return cached_items
        del _FLATTEN_ID_CACHE[identity_key]

    key = expr_key(expr)
    cached = _FLATTEN_CACHE.get(key)
    if cached is not None:
        _, cached_items = cached
        _FLATTEN_CACHE.move_to_end(key)
        _store_flatten_identity_cache(identity_key, expr, cached_items)
        return cached_items

    items = _uncached_flatten_bool_constraint(expr)
    _FLATTEN_CACHE[key] = (expr, items)
    _FLATTEN_CACHE.move_to_end(key)
    if len(_FLATTEN_CACHE) > _FLATTEN_CACHE_MAX_SIZE:
        _FLATTEN_CACHE.popitem(last=False)
    _store_flatten_identity_cache(identity_key, expr, items)
    return items


def _store_flatten_identity_cache(
    key: int,
    expr: z3.BoolRef,
    items: tuple[z3.BoolRef, ...],
) -> None:
    _FLATTEN_ID_CACHE[key] = (expr, items)
    _FLATTEN_ID_CACHE.move_to_end(key)
    if len(_FLATTEN_ID_CACHE) > _FLATTEN_ID_CACHE_MAX_SIZE:
        _FLATTEN_ID_CACHE.popitem(last=False)


def _uncached_flatten_bool_constraint(expr: z3.BoolRef) -> tuple[z3.BoolRef, ...]:
    if z3.is_and(expr):
        flattened: list[z3.BoolRef] = []
        for child in expr.children():
            if isinstance(child, z3.BoolRef):
                flattened.extend(_flatten_bool_constraint(child))
            else:
                return (expr,)
        return tuple(flattened)
    return (expr,)
