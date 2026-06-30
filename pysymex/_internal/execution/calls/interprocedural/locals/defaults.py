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

"""Default-value preparation for interprocedural call binding."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.calls.payload import SymbolicFunctionPayload
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.execution.calls.default.materialization.objects import (
    realize_named_default_objects,
)
from pysymex._internal.execution.calls.default.materialization.values import (
    as_named_default_stack_values,
)

if TYPE_CHECKING:
    import types
    from collections.abc import Sequence

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


@dataclass(frozen=True, slots=True)
class CalleeDefaultBindings:
    """Default values prepared for CPython-style function binding."""

    state: VMState
    positional_defaults: dict[str, StackValue]
    keyword_defaults: dict[str, StackValue]


def prepare_callee_default_bindings(
    state: VMState,
    func_obj: object,
    func_code: types.CodeType,
    pos_arg_names: Sequence[str],
    kwonly_arg_names: Sequence[str],
    arg_count: int,
) -> CalleeDefaultBindings:
    """Materialize positional and keyword defaults for callee binding."""
    defaults_obj = getattr(func_obj, "__defaults__", None)
    if defaults_obj is None and isinstance(func_obj, SymbolicFunctionPayload):
        defaults_obj = func_obj.defaults
    if isinstance(defaults_obj, tuple):
        defaults_tuple = cast("tuple[object, ...]", defaults_obj)
        defaults_count = len(defaults_tuple)
    else:
        defaults_tuple = ()
        defaults_count = 0
    default_offset = arg_count - defaults_count
    default_values = {
        name: defaults_tuple[index - default_offset]
        for index, name in enumerate(pos_arg_names)
        if index >= default_offset
    }

    kwdefaults_obj = getattr(func_obj, "__kwdefaults__", None)
    if kwdefaults_obj is None and isinstance(func_obj, SymbolicFunctionPayload):
        kwdefaults_obj = func_obj.kwdefaults
    if isinstance(kwdefaults_obj, dict):
        default_values.update(cast("dict[str, object]", kwdefaults_obj))
    elif isinstance(kwdefaults_obj, SymbolicDict):
        for name in kwonly_arg_names:
            found, value = kwdefaults_obj.concrete_value_for_key(name)
            if found:
                default_values[name] = value

    converted_defaults = as_named_default_stack_values(default_values)
    state, converted_defaults = realize_named_default_objects(
        state,
        default_values,
        converted_defaults,
    )
    positional_defaults = {
        name: converted_defaults[name]
        for index, name in enumerate(pos_arg_names)
        if index >= default_offset
    }
    keyword_defaults = {
        name: converted_defaults[name] for name in kwonly_arg_names if name in converted_defaults
    }
    return CalleeDefaultBindings(
        state=state,
        positional_defaults=positional_defaults,
        keyword_defaults=keyword_defaults,
    )
