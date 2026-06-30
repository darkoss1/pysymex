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

"""Bound-method receiver seeding for function initial states."""

from __future__ import annotations

import types
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.identity.addressing import next_address
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.execution.calls.default.materialization.attributes import (
    receiver_method_attrs,
)
from pysymex._internal.execution.calls.value.coercion import coerce_call_stack_value

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def bound_receiver_local_name(func: Callable[..., object], params: list[str]) -> str | None:
    """Return the hidden receiver local for a bound method root call, if any."""
    receiver = getattr(func, "__self__", None)
    if receiver is None:
        return None
    code = getattr(func, "__code__", None)
    if not isinstance(code, types.CodeType) or code.co_argcount <= 0:
        return None
    receiver_name = str(code.co_varnames[0])
    if receiver_name in params:
        return None
    return receiver_name


def bound_receiver_object(func: Callable[..., object]) -> object | None:
    """Return the bound receiver object for method roots, when present."""
    return getattr(func, "__self__", None)


def bind_bound_receiver(state: VMState, name: str, receiver: object) -> VMState:
    """Bind a bound-method receiver into a heap-backed root local."""
    if isinstance(receiver, type):
        return state.set_local(name, cast("StackValue", receiver))
    attrs = _safe_receiver_attrs(receiver)
    if attrs is None:
        return state.set_local(name, coerce_call_stack_value(receiver))

    address = next_address()
    symbolic_receiver = SymbolicObject(name, address, ConstraintValues.int(address), {address})
    modeled_attrs = {
        str(attr_name): coerce_call_stack_value(attr_value)
        for attr_name, attr_value in attrs.items()
        if isinstance(attr_name, str)
    }
    modeled_attrs.update(receiver_method_attrs(receiver, modeled_attrs))
    state = state.store_heap(address, modeled_attrs)
    return state.set_local(name, symbolic_receiver)


def _safe_receiver_attrs(receiver: object) -> dict[object, object] | None:
    """Return a shallow receiver ``__dict__`` copy without invoking user descriptors."""
    try:
        raw_attrs = object.__getattribute__(receiver, "__dict__")
    except AttributeError:
        return None
    if not isinstance(raw_attrs, dict):
        return None
    return dict(cast("dict[object, object]", raw_attrs))
