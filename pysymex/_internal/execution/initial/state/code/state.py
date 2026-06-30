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

"""Initial VM-state construction for direct code-object execution."""

from __future__ import annotations

import types
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.builtins import get_all_builtins
from pysymex._internal.core.memory.cow.dicts import CowDict
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.calls.default.materialization.objects import (
    realize_named_default_objects,
)
from pysymex._internal.execution.calls.default.materialization.values import (
    as_named_default_stack_values,
    as_named_stack_value,
)
from pysymex._internal.execution.initial.state.factory.core import SymbolicInputFactory

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.typing.protocols import StackValue


def create_code_initial_state(
    code: types.CodeType,
    symbolic_vars: Mapping[str, str] | None = None,
    initial_globals: Mapping[str, object] | None = None,
    *,
    symbolic_vars_are_inferred: bool = False,
) -> VMState:
    """Build the starting state for ``execute_code`` targets.

    Module/``exec`` code uses a shared root namespace. Symbolic inputs for that
    surface must therefore be visible both to root ``LOAD_NAME`` users and to
    nested functions that resolve the same name through ``LOAD_GLOBAL``. Builtin
    names are seeded into globals so ``LOAD_NAME``/``LOAD_GLOBAL`` can resolve
    concrete builtin functions and exception classes before falling back to
    symbolic unknowns.
    """
    factory = SymbolicInputFactory()
    initial_state = VMState()
    mirror_symbolic_inputs_to_globals = code.co_name == "<module>"
    builtin_globals = {
        name: cast("StackValue", value) for name, value in get_all_builtins().items()
    }
    initial_state.global_vars = CowDict(builtin_globals)
    if initial_globals:
        for name, value in initial_globals.items():
            initial_state.global_vars[name] = _code_initial_global_stack_value(name, value)
    default_values = _code_object_default_values(code, initial_globals)
    symbolic_var_map = dict(symbolic_vars or {})
    if symbolic_vars_are_inferred and default_values:
        for name in default_values:
            symbolic_var_map.pop(name, None)
    default_stack_values = as_named_default_stack_values(default_values)
    initial_state, default_stack_values = realize_named_default_objects(
        initial_state,
        default_values,
        default_stack_values,
    )

    argcount = code.co_argcount + code.co_kwonlyargcount
    varargs_name = None
    varkw_name = None
    if code.co_flags & 0x04:
        varargs_name = code.co_varnames[argcount]
        argcount += 1
    if code.co_flags & 0x08:
        varkw_name = code.co_varnames[argcount]
        argcount += 1

    for param in code.co_varnames[:argcount]:
        if param not in symbolic_var_map and param in default_stack_values:
            initial_state = initial_state.set_local(param, default_stack_values[param])
            continue
        if param not in symbolic_var_map:
            if param == varargs_name:
                symbolic_var_map[param] = "tuple"
            elif param == varkw_name:
                symbolic_var_map[param] = "dict"
            else:
                symbolic_var_map[param] = "any"

    for name, type_hint in symbolic_var_map.items():
        sym_val, constraint = factory.create_symbolic_for_context_type(
            name,
            type_hint,
            initial_globals,
        )
        initial_state = initial_state.set_local(name, sym_val)
        if mirror_symbolic_inputs_to_globals:
            initial_state = initial_state.set_global(name, sym_val)
        initial_state = initial_state.add_constraint(constraint)

    return factory.flush_temp_memory(initial_state)


def _code_object_default_values(
    code: types.CodeType,
    initial_globals: Mapping[str, object] | None,
) -> dict[str, object]:
    """Return function defaults for direct code-object execution when available."""
    if initial_globals is None:
        return {}
    func_obj = initial_globals.get(code.co_name)
    if not isinstance(func_obj, types.FunctionType) or func_obj.__code__ is not code:
        return {}

    positional_names = code.co_varnames[: code.co_argcount]
    default_values: dict[str, object] = {}
    defaults = func_obj.__defaults__ or ()
    default_offset = len(positional_names) - len(defaults)
    for index, value in enumerate(defaults):
        name_index = default_offset + index
        if 0 <= name_index < len(positional_names):
            default_values[positional_names[name_index]] = value

    kwonly_start = code.co_argcount
    kwonly_end = kwonly_start + code.co_kwonlyargcount
    kwonly_names = set(code.co_varnames[kwonly_start:kwonly_end])
    for name, value in (func_obj.__kwdefaults__ or {}).items():
        if name in kwonly_names:
            default_values[name] = value
    return default_values


def _code_initial_global_stack_value(name: str, value: object) -> StackValue:
    """Return the VM carrier for a caller-supplied code-object global."""
    if isinstance(value, list):
        return as_named_stack_value(name, cast("list[object]", value))
    if isinstance(value, dict):
        return as_named_stack_value(name, cast("dict[object, object]", value))
    if isinstance(value, set):
        return as_named_stack_value(name, cast("set[object]", value))
    return cast("StackValue", value)
