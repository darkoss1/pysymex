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

"""Concrete item retention policy for symbolic dictionary mutations."""

from __future__ import annotations

import dataclasses
from collections.abc import Hashable
from typing import cast

from pysymex._internal.core.types.containers.dict.keys import (
    UNRESOLVED_KEY,
    concrete_lookup_key,
    retained_lookup_key,
)
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue


def retained_concrete_item(parent_name: str, value: object) -> object:
    """Return a retained dict item with parent-relative modeled roots."""
    from pysymex._internal.core.types.containers.dicts import SymbolicDict

    if isinstance(value, SymbolicList):
        return dataclasses.replace(value, _name=parent_name)
    if isinstance(value, SymbolicDict):
        return dataclasses.replace(value, _name=parent_name)
    if isinstance(value, list):
        return dataclasses.replace(
            SymbolicList.from_const(cast("list[object]", value)),
            _name=parent_name,
        )
    if isinstance(value, dict):
        return SymbolicDict.from_const_named(parent_name, cast("dict[object, object]", value))
    if isinstance(value, set):
        return dataclasses.replace(
            SymbolicValue.from_const(cast("set[object]", value)),
            _name=parent_name,
        )
    return value


def concrete_items_after_set(
    concrete_items: dict[object, object] | None,
    key: object,
    value: object,
    *,
    parent_name: str,
) -> dict[object, object] | None:
    """Return retained concrete items after a resolvable dict assignment."""
    if concrete_items is None:
        return None

    concrete_key = retained_lookup_key(key)
    if concrete_key is UNRESOLVED_KEY or not isinstance(concrete_key, Hashable):
        return None

    updated = dict(concrete_items)
    updated[concrete_key] = retained_concrete_item(parent_name, value)
    return updated


def concrete_items_after_delete(
    concrete_items: dict[object, object] | None,
    key: object,
) -> dict[object, object] | None:
    """Return retained concrete items after a resolvable dict deletion."""
    if concrete_items is None:
        return None

    concrete_key = concrete_lookup_key(key)
    if concrete_key is UNRESOLVED_KEY or not isinstance(concrete_key, Hashable):
        return None

    updated = dict(concrete_items)
    updated.pop(concrete_key, None)
    return updated
