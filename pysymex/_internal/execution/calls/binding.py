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

"""Validate Python function argument binding before interprocedural entry.

Owns CPython-compatible binding TypeError detection for user-defined callables
after CALL/CALL_KW stack lowering and before callee frame construction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.execution.opcodes.common.exceptions.type_errors import type_error_result

if TYPE_CHECKING:
    import types
    from collections.abc import Mapping, Sequence

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult


@dataclass(frozen=True, slots=True)
class BindingTypeError:
    """Describe a CPython call-binding TypeError before entering the callee."""

    message: str


def validate_python_function_binding(
    func_name: str,
    func_code: types.CodeType,
    args: Sequence[object],
    kwargs: Mapping[str, object],
    positional_defaults: Mapping[str, object],
    keyword_defaults: Mapping[str, object],
) -> BindingTypeError | None:
    """Return a binding error when Python would reject the call."""
    posonly_count = func_code.co_posonlyargcount
    arg_count = func_code.co_argcount
    pos_arg_names = tuple(func_code.co_varnames[:arg_count])
    kwonly_count = func_code.co_kwonlyargcount
    kwonly_arg_names = tuple(func_code.co_varnames[arg_count : arg_count + kwonly_count])
    has_varargs = bool(func_code.co_flags & 0x04)
    has_varkw = bool(func_code.co_flags & 0x08)

    if len(args) > arg_count and not has_varargs:
        return BindingTypeError(
            f"{func_name}() takes {_plural(arg_count, 'positional argument')} "
            f"but {len(args)} {_was_or_were(len(args))} given",
        )

    keyword_names = tuple(kwargs)
    posonly_keyword_names = [name for name in pos_arg_names[:posonly_count] if name in kwargs]
    if posonly_keyword_names and not has_varkw:
        return BindingTypeError(
            f"{func_name}() got some positional-only arguments passed as keyword "
            f"arguments: {_quote_join(posonly_keyword_names)}",
        )

    duplicate_names = [
        name
        for index, name in enumerate(pos_arg_names[posonly_count:], start=posonly_count)
        if index < len(args) and name in kwargs
    ]
    if duplicate_names:
        return BindingTypeError(
            f"{func_name}() got multiple values for argument '{duplicate_names[0]}'",
        )

    accepted_keywords = set(pos_arg_names[posonly_count:])
    accepted_keywords.update(kwonly_arg_names)
    unexpected_keywords = [
        name for name in keyword_names if name not in accepted_keywords and not has_varkw
    ]
    if unexpected_keywords:
        return BindingTypeError(
            f"{func_name}() got an unexpected keyword argument '{unexpected_keywords[0]}'",
        )

    required_positional_count = max(0, arg_count - len(positional_defaults))
    for index, name in enumerate(pos_arg_names[:required_positional_count]):
        if index < len(args):
            continue
        if index >= posonly_count and name in kwargs:
            continue
        return BindingTypeError(f"{func_name}() missing required argument '{name}'")

    for name in kwonly_arg_names:
        if name not in kwargs and name not in keyword_defaults:
            return BindingTypeError(f"{func_name}() missing required argument '{name}'")

    return None


def binding_type_error_result(
    state: VMState,
    ctx: OpcodeDispatcher,
    caller_offset: int,
    message: str,
) -> OpcodeResult:
    """Route or report a call-binding TypeError at the caller CALL offset."""
    return type_error_result(state, ctx, caller_offset, message)


def _plural(count: int, singular: str) -> str:
    """Return CPython-style count and noun text."""
    return f"{count} {singular if count == 1 else singular + 's'}"


def _was_or_were(count: int) -> str:
    """Return the CPython-style verb for an argument count."""
    return "was" if count == 1 else "were"


def _quote_join(names: Sequence[str]) -> str:
    """Return CPython's quoted comma-separated name group."""
    return f"'{', '.join(names)}'"
