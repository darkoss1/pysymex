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

"""Mapping-like object protocols used by call and attribute execution."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, TypeGuard

from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.execution.calls.value.coercion import coerce_call_stack_value

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class ObjectMapProtocol(Protocol):
    """Mapping-like runtime protocol used for strict key/value narrowing."""

    def __contains__(self, key: object, /) -> bool:
        """Return whether *key* is present in the mapping."""
        ...

    def __getitem__(self, key: object, /) -> object:
        """Return the value stored under *key*."""
        ...

    def __setitem__(self, key: object, value: object, /) -> None:
        """Store *value* under *key* in the mapping."""
        ...

    def items(self) -> Iterable[tuple[object, object]]:
        """Iterate key/value pairs for strict mapping narrowing."""
        ...


def is_object_map(value: object) -> TypeGuard[ObjectMapProtocol]:
    """Return ``True`` when *value* behaves like a mutable mapping."""
    return (
        hasattr(value, "items")
        and callable(getattr(value, "items", None))
        and hasattr(value, "__contains__")
        and hasattr(value, "__getitem__")
        and hasattr(value, "__setitem__")
    )


def is_symbolic_module_receiver(value: object, state: VMState) -> bool:
    """Return whether a call receiver is a symbolic imported module object."""
    if not isinstance(value, SymbolicObject) or value.address == -1:
        return False
    heap_value = state.load_heap(value.address)
    return is_object_map(heap_value) and "__module_name__" in heap_value


def as_mapping(value: object) -> dict[str, object] | None:
    """Return a concrete ``dict[str, object]`` for mapping-like values."""
    if is_object_map(value):
        return {k: v for k, v in value.items() if isinstance(k, str)}
    return None


def bind_heap_modeled_method(value: object, receiver: StackValue) -> object:
    """Bind unbound modeled methods to the current call receiver when needed."""
    try:
        from pysymex._internal.core.classes.types import SymbolicMethod
    except ImportError:
        return value
    if isinstance(value, SymbolicMethod) and not value.is_bound:
        return value.bind_to_instance(receiver)
    return value


def map_get(value: ObjectMapProtocol, key: str) -> tuple[bool, object | None]:
    """Read a mapping entry while preserving existence vs None values."""
    if key in value:
        return True, value[key]
    return False, None


def map_set(value: ObjectMapProtocol, key: str, item: StackValue) -> None:
    """Store a value in a mapping-like object."""
    value[key] = item


def map_to_stack_dict(value: ObjectMapProtocol) -> dict[str, StackValue]:
    """Convert a mutable mapping-like object to ``dict[str, StackValue]``."""
    return {k: coerce_call_stack_value(v) for k, v in value.items() if isinstance(k, str)}
