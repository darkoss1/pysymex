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

"""Concrete-literal bridge shared by parser and serialization models."""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.types.base import SymbolicNoneType, SymbolicType
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.sets import SymbolicSet
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.results import ModelResult, SideEffects

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.typing.protocols import StackValue


UNRESOLVED = object()


def concrete_value(value: object) -> object:
    """Return a recursively concrete payload or :data:`UNRESOLVED`."""
    if isinstance(value, SymbolicNoneType):
        return None
    if isinstance(value, SymbolicString):
        return value.z3_str.as_string() if z3.is_string_value(value.z3_str) else UNRESOLVED
    if isinstance(value, SymbolicBytes):
        payload = value.concrete_value
        return payload if payload is not None else UNRESOLVED
    if isinstance(value, SymbolicValue):
        payload = value.value
        if payload is None:
            return None if z3.is_true(value.is_none) else UNRESOLVED
        return concrete_value(payload)
    if isinstance(value, SymbolicList):
        items = value.concrete_items
        return _concrete_sequence(items, list) if items is not None else UNRESOLVED
    if isinstance(value, SymbolicTuple):
        return _concrete_sequence(value.elements, tuple)
    if isinstance(value, SymbolicDict):
        items = value.concrete_items
        return _concrete_mapping(items) if items is not None else UNRESOLVED
    if isinstance(value, SymbolicSet):
        items = value.concrete_items
        return set(items) if items is not None else UNRESOLVED
    if isinstance(value, SymbolicType):
        return UNRESOLVED
    if isinstance(value, list):
        return _concrete_sequence(cast("list[object]", value), list)
    if isinstance(value, tuple):
        return _concrete_sequence(cast("tuple[object, ...]", value), tuple)
    if isinstance(value, dict):
        return _concrete_mapping(cast("dict[object, object]", value))
    if isinstance(value, set):
        converted = _concrete_sequence(tuple(cast("set[object]", value)), tuple)
        return (
            set(cast("tuple[object, ...]", converted))
            if converted is not UNRESOLVED
            else UNRESOLVED
        )
    if isinstance(value, frozenset):
        converted = _concrete_sequence(tuple(cast("frozenset[object]", value)), tuple)
        return (
            frozenset(cast("tuple[object, ...]", converted))
            if converted is not UNRESOLVED
            else UNRESOLVED
        )
    if value is None or isinstance(value, (bool, int, float, str, bytes)):
        return value
    return UNRESOLVED


def concrete_call(
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> tuple[list[object], dict[str, object]] | None:
    """Concretize a complete call without executing user callbacks."""
    concrete_args = concrete_value(args)
    concrete_kwargs = concrete_value(kwargs)
    if concrete_args is UNRESOLVED or concrete_kwargs is UNRESOLVED:
        return None
    return cast("list[object]", concrete_args), cast("dict[str, object]", concrete_kwargs)


def binding_error(
    function: Callable[..., object],
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    source: str,
) -> ModelResult | None:
    """Return the CPython call-binding ``TypeError`` for an invalid call shape."""
    try:
        inspect.signature(function).bind(*args, **kwargs)
    except TypeError as exc:
        return raised_exception(source, exc)
    return None


def raised_exception(source: str, exc: BaseException) -> ModelResult:
    """Translate an exact host exception into a modeled raised exception."""
    return ModelResult.none(SideEffects.from_native_exception(source, exc))


def stack_value(value: object) -> StackValue:
    """Convert a concrete literal tree into the most precise symbolic carrier."""
    if value is None:
        return SymbolicNoneType()
    if isinstance(value, str):
        return SymbolicString.from_const(value)
    if isinstance(value, bytes):
        return SymbolicBytes.concrete(value)
    if isinstance(value, list):
        return SymbolicList.from_const([stack_value(item) for item in cast("list[object]", value)])
    if isinstance(value, tuple):
        return SymbolicTuple(tuple(stack_value(item) for item in cast("tuple[object, ...]", value)))
    if isinstance(value, dict):
        mapping = cast("dict[object, object]", value)
        return SymbolicDict.from_const({key: stack_value(item) for key, item in mapping.items()})
    return SymbolicValue.from_const(value)


def _concrete_sequence(
    values: list[object] | tuple[object, ...],
    factory: type[list[object] | tuple[object, ...]],
) -> object:
    converted = [concrete_value(item) for item in values]
    if any(item is UNRESOLVED for item in converted):
        return UNRESOLVED
    return converted if factory is list else tuple(converted)


def _concrete_mapping(values: dict[object, object]) -> object:
    converted: dict[object, object] = {}
    for key, item in values.items():
        concrete_key = concrete_value(key)
        concrete_item = concrete_value(item)
        if concrete_key is UNRESOLVED or concrete_item is UNRESOLVED:
            return UNRESOLVED
        try:
            converted[concrete_key] = concrete_item
        except TypeError:
            return UNRESOLVED
    return converted
