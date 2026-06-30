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

"""Local-variable assembly after interprocedural call binding."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.execution.calls.interprocedural.locals.closures import copy_closure_cells

if TYPE_CHECKING:
    import types
    from collections.abc import Mapping, Sequence

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def build_callee_local_vars(
    state: VMState,
    func_obj: object,
    func_code: types.CodeType,
    func_name: object,
    symbolic_closure: tuple[object, ...],
    args: Sequence[StackValue],
    kwargs: Mapping[str, StackValue],
    pos_arg_names: Sequence[str],
    kwonly_arg_names: Sequence[str],
    arg_count: int,
    positional_defaults: Mapping[str, StackValue],
    keyword_defaults: Mapping[str, StackValue],
) -> tuple[VMState, dict[str, StackValue]]:
    """Build the callee locals mapping after call binding has been validated."""
    new_locals: dict[str, StackValue] = {}
    state = copy_closure_cells(
        state,
        func_obj,
        func_code,
        func_name,
        symbolic_closure,
        new_locals,
    )

    for index, name in enumerate(pos_arg_names):
        if index < len(args):
            new_locals[name] = args[index]
        elif name in kwargs:
            new_locals[name] = kwargs[name]
        else:
            new_locals[name] = positional_defaults[name]

    for name in kwonly_arg_names:
        if name in kwargs:
            new_locals[name] = kwargs[name]
        else:
            new_locals[name] = keyword_defaults[name]

    trailing_arg_index = arg_count + len(kwonly_arg_names)
    if func_code.co_flags & 0x04:
        vararg_name = func_code.co_varnames[trailing_arg_index]
        extra_pos: Sequence[StackValue] = args[arg_count:] if len(args) > arg_count else ()
        vararg_items = cast("list[object]", list(extra_pos))
        vararg_list = SymbolicList.empty(vararg_name).extend(vararg_items)
        new_locals[vararg_name] = vararg_list
        trailing_arg_index += 1

    if func_code.co_flags & 0x08:
        kwarg_name = func_code.co_varnames[trailing_arg_index]
        unused_kwargs: dict[str, StackValue] = {
            k: v for k, v in kwargs.items() if k not in pos_arg_names and k not in kwonly_arg_names
        }
        new_locals[kwarg_name] = unused_kwargs

    return state, new_locals
