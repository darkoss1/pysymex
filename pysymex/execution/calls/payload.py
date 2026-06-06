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

"""Symbolic function payload metadata for MAKE_FUNCTION and call entry."""

from __future__ import annotations

import types
from dataclasses import dataclass, replace
from typing import cast

from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.sequences import SymbolicTuple
from pysymex.core.types.scalars.values import SymbolicValue


@dataclass(frozen=True, slots=True)
class SymbolicFunctionPayload:
    """Immutable metadata attached to symbolic ``MAKE_FUNCTION`` results."""

    code: types.CodeType
    closure: tuple[object, ...] = ()
    annotations: object | None = None
    defaults: tuple[object, ...] = ()
    kwdefaults: object | None = None


def function_payload(value: object) -> SymbolicFunctionPayload | None:
    """Return an existing payload or wrap a bare ``types.CodeType``."""
    if isinstance(value, SymbolicFunctionPayload):
        return value
    if isinstance(value, types.CodeType):
        return SymbolicFunctionPayload(code=value)
    return None


def with_closure(
    payload: SymbolicFunctionPayload, closure_value: object
) -> SymbolicFunctionPayload:
    """Attach closure cells decoded from stack values."""
    if isinstance(closure_value, SymbolicList) and closure_value.concrete_items is not None:
        concrete_items = closure_value.concrete_items
        closure = tuple(concrete_items)
    elif isinstance(closure_value, tuple):
        closure = cast("tuple[object, ...]", closure_value)
    elif isinstance(closure_value, list):
        closure = tuple(cast("list[object]", closure_value))
    else:
        closure = (closure_value,)
    return replace(payload, closure=closure)


def with_annotations(
    payload: SymbolicFunctionPayload, annotations: object
) -> SymbolicFunctionPayload:
    """Record function annotations from ``MAKE_FUNCTION`` flags."""
    return replace(payload, annotations=annotations)


def with_defaults(
    payload: SymbolicFunctionPayload, defaults_value: object
) -> SymbolicFunctionPayload:
    """Decode positional default arguments from stack tuples or lists."""
    constant_value: object = (
        defaults_value.value if isinstance(defaults_value, SymbolicValue) else None
    )
    if isinstance(constant_value, tuple):
        defaults = cast("tuple[object, ...]", constant_value)
    elif isinstance(defaults_value, SymbolicTuple):
        defaults = defaults_value.elements
    elif isinstance(defaults_value, SymbolicList) and defaults_value.concrete_items is not None:
        defaults = tuple(defaults_value.concrete_items)
    elif isinstance(defaults_value, tuple):
        defaults = cast("tuple[object, ...]", defaults_value)
    elif isinstance(defaults_value, list):
        defaults = tuple(cast("list[object]", defaults_value))
    else:
        defaults = ()
    return replace(payload, defaults=defaults)


def with_kwdefaults(
    payload: SymbolicFunctionPayload, kwdefaults_value: object
) -> SymbolicFunctionPayload:
    """Attach keyword-only defaults from ``MAKE_FUNCTION``."""
    return replace(payload, kwdefaults=kwdefaults_value)
