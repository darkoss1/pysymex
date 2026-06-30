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

"""Concrete-backed lookup helpers for symbolic dictionaries."""

from __future__ import annotations

from collections.abc import Hashable

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.containers.dict.keys import (
    UNRESOLVED_KEY,
    concrete_lookup_key,
    symbolic_key_equals_concrete,
)


def copy_concrete_items(
    concrete_items: dict[object, object] | None,
) -> dict[object, object] | None:
    """Return a shallow copy of retained concrete items."""
    if concrete_items is None:
        return None
    return dict(concrete_items)


def concrete_key_presence(
    concrete_items: dict[object, object] | None,
    key: object,
) -> z3.BoolRef | None:
    """Return a path predicate for membership in concrete-backed dictionaries."""
    value_conditions = concrete_value_conditions(concrete_items, key)
    if value_conditions is None:
        return None
    if not value_conditions:
        return Z3_FALSE
    return simplify_expr(z3.Or(*(condition for condition, _value in value_conditions)))


def concrete_value_conditions(
    concrete_items: dict[object, object] | None,
    key: object,
) -> tuple[tuple[z3.BoolRef, object], ...] | None:
    """Return retained values paired with path predicates for a lookup key."""
    if concrete_items is None:
        return None

    concrete_key = concrete_lookup_key(key)
    if concrete_key is not UNRESOLVED_KEY:
        if not isinstance(concrete_key, Hashable):
            return None
        if concrete_key not in concrete_items:
            return ()
        return ((Z3_TRUE, concrete_items[concrete_key]),)

    value_conditions: list[tuple[z3.BoolRef, object]] = []
    for candidate, value in concrete_items.items():
        condition = symbolic_key_equals_concrete(key, candidate)
        if condition is not None:
            value_conditions.append((simplify_expr(condition), value))
    if not value_conditions:
        return None
    return tuple(value_conditions)


def concrete_value(
    concrete_items: dict[object, object] | None,
    key: object,
) -> tuple[bool, object | None]:
    """Return whether a concrete-backed value is known and the value itself."""
    if concrete_items is None:
        return False, None
    concrete_key = concrete_lookup_key(key)
    if concrete_key is UNRESOLVED_KEY or not isinstance(concrete_key, Hashable):
        return False, None
    if concrete_key not in concrete_items:
        return False, None
    return True, concrete_items[concrete_key]


def contains_concrete_key(concrete_items: dict[object, object] | None, key: object) -> bool:
    """Return ``True`` only for definitely present concrete-backed keys."""
    presence = concrete_key_presence(concrete_items, key)
    if presence is None:
        return False
    simplified = simplify_expr(presence)
    if z3.is_true(simplified):
        return True
    if z3.is_false(simplified):
        return False
    return False
