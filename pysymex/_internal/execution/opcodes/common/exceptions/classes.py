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

"""Exception class, payload, and handler-target normalization helpers."""

from __future__ import annotations

import builtins
from typing import TypeGuard, cast

from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.types.scalars.values import SymbolicValue

_MISSING_ITEMS = object()


def concrete_exception_match(exc: object, exc_types: list[object]) -> bool | None:
    """Return a precise CPython-style subclass match when all classes are known."""
    raised_type = raised_exception_class(exc)
    if raised_type is None:
        return None

    handler_types: list[type[BaseException]] = []
    for exc_type in exc_types:
        handler_type = _handler_exception_class(exc_type)
        if handler_type is None:
            return None
        handler_types.append(handler_type)

    return any(issubclass(raised_type, handler_type) for handler_type in handler_types)


def has_definite_invalid_exception_handler(exc_types: list[object]) -> bool:
    """Return true when a handler target is definitely invalid for ``except``."""
    return any(_is_definite_invalid_exception_handler(exc_type) for exc_type in exc_types)


def _is_definite_invalid_exception_handler(value: object) -> bool:
    """Return whether ``value`` is known not to be a valid exception handler target."""
    if _handler_exception_class(value) is not None:
        return False
    if _symbolic_exception_payload(value) is not None:
        return False
    return not isinstance(value, SymbolicValue)


def raised_exception_class(value: object) -> type[BaseException] | None:
    """Resolve the concrete class of a raised exception value when available."""
    payload = _symbolic_exception_payload(value)
    if payload is not None:
        exc_type = payload.exc_type
        if isinstance(exc_type, type):
            return exc_type
        return _builtin_exception_class(exc_type)
    if isinstance(value, BaseException):
        return type(value)
    if _is_base_exception_class(value):
        return value
    return None


def _handler_exception_class(value: object) -> type[BaseException] | None:
    """Resolve a concrete exception handler class without accepting instances."""
    if _is_base_exception_class(value):
        return value
    payload = _symbolic_exception_payload(value)
    if payload is None:
        return None
    exc_type = payload.exc_type
    if isinstance(exc_type, type):
        return exc_type
    return _builtin_exception_class(exc_type)


def _is_base_exception_class(value: object) -> TypeGuard[type[BaseException]]:
    """Return whether ``value`` is a concrete ``BaseException`` subclass."""
    return isinstance(value, type) and issubclass(value, BaseException)


def _builtin_exception_class(name: str) -> type[BaseException] | None:
    """Return the built-in exception class named by *name*, when known."""
    candidate = getattr(builtins, name, None)
    if _is_base_exception_class(candidate):
        return candidate
    return None


def _symbolic_exception_payload(value: object) -> SymbolicException | None:
    """Extract a symbolic exception from a direct value or modeled wrapper."""
    if isinstance(value, SymbolicException):
        return value
    modeled_value = getattr(value, "_modeled_object", None)
    return modeled_value if isinstance(modeled_value, SymbolicException) else None


def realize_exception_items(exc_types_obj: object) -> list[object]:
    """Normalize exception type payloads to a plain list."""
    raw_items_attr = getattr(exc_types_obj, "_concrete_items", _MISSING_ITEMS)
    if raw_items_attr is not _MISSING_ITEMS:
        if raw_items_attr is None:
            return []
        if isinstance(raw_items_attr, tuple):
            return list(cast("tuple[object, ...]", raw_items_attr))
        if isinstance(raw_items_attr, list):
            return list(cast("list[object]", raw_items_attr))
        return [raw_items_attr]

    raw_items_obj: object = exc_types_obj
    if raw_items_obj is None:
        return []
    if isinstance(raw_items_obj, tuple):
        return list(cast("tuple[object, ...]", raw_items_obj))
    return [raw_items_obj]
