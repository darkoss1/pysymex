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

"""Descriptor-free object attribute capture for call default materialization."""

from __future__ import annotations

import types
from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

from pysymex._internal.execution.calls.default.materialization.values import as_named_stack_value
from pysymex._internal.execution.calls.value.coercion import coerce_call_stack_value

if TYPE_CHECKING:
    from pysymex._internal.typing.protocols import StackValue


def safe_object_attrs(value: object) -> dict[object, object] | None:
    """Return a shallow ``__dict__`` copy without invoking user descriptors."""
    try:
        raw_attrs = object.__getattribute__(value, "__dict__")
    except AttributeError:
        return None
    if not isinstance(raw_attrs, dict):
        return None
    return dict(cast("dict[object, object]", raw_attrs))


def receiver_method_attrs(
    receiver: object,
    instance_attrs: Mapping[str, StackValue],
) -> dict[str, StackValue]:
    """Return heap-modeled ordinary methods visible from a safe concrete receiver."""
    from pysymex._internal.core.classes.types import SymbolicMethod

    methods: dict[str, StackValue] = {}
    for cls in reversed(type(receiver).__mro__):
        raw_namespace = getattr(cls, "__dict__", {})
        if not isinstance(raw_namespace, Mapping):
            continue
        namespace = cast("Mapping[object, object]", raw_namespace)
        for attr_name, attr_value in namespace.items():
            if not isinstance(attr_name, str) or attr_name in instance_attrs:
                continue
            if not isinstance(attr_value, types.FunctionType):
                continue
            methods[attr_name] = coerce_call_stack_value(
                SymbolicMethod(name=attr_name, func=attr_value),
            )
    return methods


def named_attribute_stack_value(root_name: str, attr_name: str, value: object) -> StackValue:
    """Return a stack value rooted at ``root.attr`` when the value is mutable."""
    if isinstance(value, list):
        return as_named_stack_value(f"{root_name}.{attr_name}", cast("list[object]", value))
    if isinstance(value, dict):
        return as_named_stack_value(f"{root_name}.{attr_name}", cast("dict[object, object]", value))
    if isinstance(value, set):
        return as_named_stack_value(f"{root_name}.{attr_name}", cast("set[object]", value))
    return coerce_call_stack_value(value)
