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

"""Symbolic function payload metadata shared by model and execution layers."""

from __future__ import annotations

import inspect
import types
from dataclasses import dataclass, replace
from typing import Literal, cast

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.scalars.values import SymbolicValue


@dataclass(frozen=True, slots=True)
class SymbolicFunctionPayload:
    """Immutable metadata attached to symbolic ``MAKE_FUNCTION`` results."""

    code: types.CodeType
    closure: tuple[object, ...] = ()
    annotations: object | None = None
    defaults: tuple[object, ...] = ()
    kwdefaults: object | None = None
    contract: object | None = None

    @property
    def __name__(self) -> str:
        """Expose code-object name for contract diagnostics and summaries."""
        return self.code.co_name

    @property
    def __contract__(self) -> object | None:
        """Expose statically retained contract metadata without a wrapper frame."""
        return self.contract

    @property
    def __signature__(self) -> inspect.Signature:
        """Return a Python-call-compatible signature reconstructed from code metadata."""
        return _payload_signature(self)

    def __call__(self, *args: object, **kwargs: object) -> object:
        """Prevent accidental host execution of symbolic payloads."""
        msg = "symbolic function payloads cannot be executed concretely"
        raise TypeError(msg)


MethodDescriptorKind = Literal["class", "static"]


@dataclass(frozen=True, slots=True)
class MethodDescriptorPayload:
    """Runtime ``classmethod``/``staticmethod`` metadata for modeled class writes."""

    payload: SymbolicFunctionPayload
    kind: MethodDescriptorKind


def function_payload(value: object) -> SymbolicFunctionPayload | None:
    """Return an existing payload or wrap a bare ``types.CodeType``."""
    if isinstance(value, SymbolicFunctionPayload):
        return value
    if isinstance(value, types.CodeType):
        return SymbolicFunctionPayload(code=value)
    return None


def method_descriptor_payload(value: object) -> MethodDescriptorPayload | None:
    """Return runtime method-descriptor metadata when present."""
    if isinstance(value, MethodDescriptorPayload):
        return value
    return None


def with_closure(
    payload: SymbolicFunctionPayload,
    closure_value: object,
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
    payload: SymbolicFunctionPayload,
    annotations: object,
) -> SymbolicFunctionPayload:
    """Record function annotations from ``MAKE_FUNCTION`` flags."""
    return replace(payload, annotations=annotations)


def with_defaults(
    payload: SymbolicFunctionPayload,
    defaults_value: object,
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
    payload: SymbolicFunctionPayload,
    kwdefaults_value: object,
) -> SymbolicFunctionPayload:
    """Attach keyword-only defaults from ``MAKE_FUNCTION``."""
    return replace(payload, kwdefaults=kwdefaults_value)


def with_contract(payload: SymbolicFunctionPayload, contract: object) -> SymbolicFunctionPayload:
    """Attach statically retained contract metadata to a symbolic payload."""
    return replace(payload, contract=contract)


def _payload_signature(payload: SymbolicFunctionPayload) -> inspect.Signature:
    """Build an ``inspect.Signature`` for a symbolic function payload."""
    code = payload.code
    parameters: list[inspect.Parameter] = []

    posonly_count = getattr(code, "co_posonlyargcount", 0)
    arg_count = code.co_argcount
    positional_names = code.co_varnames[:arg_count]
    default_offset = arg_count - len(payload.defaults)
    defaults_by_name = {
        positional_names[index]: payload.defaults[index - default_offset]
        for index in range(default_offset, arg_count)
        if 0 <= index - default_offset < len(payload.defaults)
    }

    for index, name in enumerate(positional_names):
        kind = (
            inspect.Parameter.POSITIONAL_ONLY
            if index < posonly_count
            else inspect.Parameter.POSITIONAL_OR_KEYWORD
        )
        default = defaults_by_name.get(name, inspect.Parameter.empty)
        parameters.append(inspect.Parameter(name, kind, default=default))

    kwonly_count = code.co_kwonlyargcount
    kwonly_names = code.co_varnames[arg_count : arg_count + kwonly_count]
    trailing_index = arg_count + kwonly_count
    if code.co_flags & 0x04:
        parameters.append(
            inspect.Parameter(
                code.co_varnames[trailing_index],
                inspect.Parameter.VAR_POSITIONAL,
            ),
        )
        trailing_index += 1

    typed_kwdefaults: dict[str, object] = {}
    kwdefaults_obj: object | None = payload.kwdefaults
    if isinstance(kwdefaults_obj, dict):
        raw_kwdefaults = cast("dict[object, object]", kwdefaults_obj)
        typed_kwdefaults = {
            name: value for name, value in raw_kwdefaults.items() if isinstance(name, str)
        }
    for name in kwonly_names:
        default = typed_kwdefaults.get(name, inspect.Parameter.empty)
        parameters.append(inspect.Parameter(name, inspect.Parameter.KEYWORD_ONLY, default=default))

    if code.co_flags & 0x08:
        parameters.append(
            inspect.Parameter(
                code.co_varnames[trailing_index],
                inspect.Parameter.VAR_KEYWORD,
            ),
        )

    return inspect.Signature(parameters)
