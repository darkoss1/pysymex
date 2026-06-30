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

"""Lower ``CALL_FUNCTION_EX`` / ``KW_NAMES`` call patterns to resolved call dispatch.

Unpacks the variable positional tuple and keyword mapping from the stack, binds them to a
target callable, and forwards expanded call targets to
:mod:`pysymex._internal.execution.calls.target.dispatch`.

Limitations:
    Star-args spreading of symbolic tuples with unknown arity may degrade before call setup.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.guards.stack import is_call_null_marker
from pysymex._internal.execution.calls.object.maps import is_object_map
from pysymex._internal.execution.calls.value.coercion import coerce_call_stack_value
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.exceptions.type_errors import type_error_result
from pysymex._internal.execution.opcodes.common.symbolic_types import definite_symbolic_type_name

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def _expand_positional_args(args_val: StackValue) -> list[StackValue]:
    """Expand concrete ``*args`` payloads while preserving symbolic unknowns."""
    raw_value = _call_function_ex_payload(args_val)
    if isinstance(raw_value, SymbolicList):
        concrete_items = raw_value.concrete_items
        if concrete_items is not None:
            return [coerce_call_stack_value(value) for value in concrete_items]
        return [args_val]
    if isinstance(raw_value, SymbolicDict):
        concrete_items = raw_value.concrete_items
        if concrete_items is not None:
            return [coerce_call_stack_value(key) for key in concrete_items]
        return [args_val]
    if isinstance(raw_value, Iterable) and not isinstance(raw_value, SymbolicValue):
        iterable_values = cast("Iterable[object]", raw_value)
        return [coerce_call_stack_value(value) for value in iterable_values]
    return [args_val]


def _call_function_ex_payload(value: StackValue) -> object:
    """Return a concrete payload carried by a stack value when one is known."""
    if isinstance(value, SymbolicValue) and value.value is not None:
        return value.value
    return value


def _callable_name(func_obj: object) -> str:
    """Return a readable callable name for CPython-style call errors."""
    qualname = getattr(func_obj, "__qualname__", None)
    if isinstance(qualname, str) and qualname:
        return qualname
    name = getattr(func_obj, "__name__", None)
    if isinstance(name, str) and name:
        return name
    return type(func_obj).__name__


def _call_function_ex_type_name(value: object) -> str:
    """Return a CPython-style type name for star-unpacking errors."""
    if value is None or isinstance(value, SymbolicNoneType):
        return "NoneType"
    if isinstance(value, SymbolicValue):
        if value.value is not None:
            return type(value.value).__name__
        symbolic_type = definite_symbolic_type_name(value)
        if symbolic_type is not None:
            return symbolic_type
    return type(value).__name__


def _positional_unpack_type_error(func_obj: object, args_val: StackValue) -> str | None:
    """Return the ``*args`` TypeError message when the payload is definitely invalid."""
    raw_value = _call_function_ex_payload(args_val)
    if isinstance(raw_value, SymbolicValue):
        if _definite_non_iterable_symbolic_type(raw_value) is not None:
            return (
                f"{_callable_name(func_obj)}() argument after * must be an iterable, "
                f"not {_call_function_ex_type_name(raw_value)}"
            )
        return None
    if isinstance(raw_value, SymbolicList):
        return None
    if isinstance(raw_value, SymbolicDict):
        return None
    if isinstance(raw_value, Iterable):
        return None
    return (
        f"{_callable_name(func_obj)}() argument after * must be an iterable, "
        f"not {_call_function_ex_type_name(raw_value)}"
    )


def _keyword_unpack_type_error(func_obj: object, kwargs_val: StackValue) -> str | None:
    """Return the ``**kwargs`` TypeError message when the payload is definitely invalid."""
    if isinstance(kwargs_val, SymbolicDict):
        concrete_items = kwargs_val.concrete_items
        if concrete_items is not None and any(not isinstance(key, str) for key in concrete_items):
            return "keywords must be strings"
        return None

    raw_value = _call_function_ex_payload(kwargs_val)
    if isinstance(raw_value, SymbolicValue):
        if _definite_non_mapping_symbolic_type(raw_value) is not None:
            return (
                f"{_callable_name(func_obj)}() argument after ** must be a mapping, "
                f"not {_call_function_ex_type_name(raw_value)}"
            )
        return None

    if isinstance(raw_value, Mapping):
        mapping = cast("Mapping[object, object]", raw_value)
        if any(not isinstance(key, str) for key in mapping):
            return "keywords must be strings"
        return None

    if is_object_map(raw_value):
        if any(not isinstance(key, str) for key, _ in raw_value.items()):
            return "keywords must be strings"
        return None

    return (
        f"{_callable_name(func_obj)}() argument after ** must be a mapping, "
        f"not {_call_function_ex_type_name(raw_value)}"
    )


def _definite_non_iterable_symbolic_type(value: SymbolicValue) -> str | None:
    """Return a type name when a symbolic value is definitely invalid for ``*args``."""
    type_name = definite_symbolic_type_name(value)
    if type_name in {"NoneType", "bool", "float", "int"}:
        return type_name
    return None


def _definite_non_mapping_symbolic_type(value: SymbolicValue) -> str | None:
    """Return a type name when a symbolic value is definitely invalid for ``**kwargs``."""
    type_name = definite_symbolic_type_name(value)
    if type_name in {"NoneType", "bool", "bytes", "float", "int", "list", "str", "tuple"}:
        return type_name
    return None


def _expand_keyword_args(kwargs_val: StackValue) -> dict[str, StackValue]:
    """Expand a concrete ``**kwargs`` payload after validation."""
    if isinstance(kwargs_val, SymbolicDict):
        concrete_items = kwargs_val.concrete_items
        if concrete_items is not None:
            return {
                key: coerce_call_stack_value(value)
                for key, value in concrete_items.items()
                if isinstance(key, str)
            }
        return {"**kwargs": kwargs_val}

    raw_value = _call_function_ex_payload(kwargs_val)
    if isinstance(raw_value, Mapping):
        mapping = cast("Mapping[object, object]", raw_value)
        return {
            key: coerce_call_stack_value(value)
            for key, value in mapping.items()
            if isinstance(key, str)
        }
    if is_object_map(raw_value):
        return {
            key: coerce_call_stack_value(value)
            for key, value in raw_value.items()
            if isinstance(key, str)
        }
    return {}


def handle_common_call_function_ex(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Handle CALL_FUNCTION_EX (Python 3.11+)."""
    from pysymex._internal.execution.calls.target.dispatch.expanded import (
        dispatch_expanded_call_target,
    )

    has_kwargs = False
    if instr.arg is not None:
        has_kwargs = (instr.arg & 1) == 1

    required_items = 3 if has_kwargs else 2
    if len(state.stack) < required_items:
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    empty_kwargs: dict[str, StackValue] = {}
    kwargs_val: StackValue = state.pop() if has_kwargs else empty_kwargs
    args_val = state.pop()
    if len(state.stack) >= 2 and is_call_null_marker(state.peek()):
        state.pop()
    func_obj: StackValue = state.pop() if state.stack else None

    positional_error = _positional_unpack_type_error(func_obj, args_val)
    if positional_error is not None:
        return type_error_result(state, ctx, instr.offset, positional_error)

    if has_kwargs:
        keyword_error = _keyword_unpack_type_error(func_obj, kwargs_val)
        if keyword_error is not None:
            return type_error_result(state, ctx, instr.offset, keyword_error)

    args = _expand_positional_args(args_val)
    kwargs = _expand_keyword_args(kwargs_val) if has_kwargs else {}

    return dispatch_expanded_call_target(instr, state, ctx, func_obj, args, kwargs)
