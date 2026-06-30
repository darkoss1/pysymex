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

"""Named stack-value conversion for concrete call defaults."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.value.coercion import coerce_call_stack_value

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.typing.protocols import StackValue


def as_named_stack_value(name: str, value: object) -> StackValue:
    """Convert a value to stack form while preserving a source-root name."""
    if isinstance(value, dict):
        return SymbolicDict.from_const_named(name, cast("dict[object, object]", value))
    if isinstance(value, set):
        return dataclasses.replace(SymbolicValue.from_const(cast("set[object]", value)), _name=name)
    stack_value = coerce_call_stack_value(value)
    if isinstance(stack_value, SymbolicList):
        return dataclasses.replace(stack_value, _name=name)
    return stack_value


def as_named_default_stack_values(defaults: Mapping[str, object]) -> dict[str, StackValue]:
    """Convert default values while preserving repeated mutable-default aliases."""
    converted: dict[str, StackValue] = {}
    mutable_defaults: dict[int, StackValue] = {}
    for name, value in defaults.items():
        item_value: object = value
        mutable_value: object | None = None
        if isinstance(item_value, dict):
            mutable_value = cast("dict[object, object]", item_value)
        elif isinstance(item_value, list):
            mutable_value = cast("list[object]", item_value)
        elif isinstance(item_value, set):
            mutable_value = cast("set[object]", item_value)

        if mutable_value is not None:
            key = id(mutable_value)
            cached = mutable_defaults.get(key)
            if cached is None:
                cached = as_named_stack_value(name, mutable_value)
                mutable_defaults[key] = cached
            converted[name] = cached
        else:
            converted[name] = as_named_stack_value(name, cast("object", item_value))
    return converted
