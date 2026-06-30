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

"""Ordered special call-target dispatch before generic model/call handling."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.calls.target.specials.context.managers import (
    dispatch_context_manager_call,
)
from pysymex._internal.execution.calls.target.specials.exit.stacks import dispatch_exit_stack_call
from pysymex._internal.execution.calls.target.specials.functional import (
    dispatch_supported_suppress_call,
    dispatch_transparent_decorator_call,
)
from pysymex._internal.execution.calls.target.specials.operator.accessors import (
    dispatch_operator_accessor_call,
)
from pysymex._internal.execution.calls.target.specials.slices import dispatch_slice_indices_call

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult
    from pysymex._internal.typing.protocols import StackValue


def dispatch_special_call_target(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: StackValue,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult | None:
    """Apply ordered special adapters for call targets with trusted local semantics."""
    from pysymex._internal.execution.opcodes.common.coroutines.dispatch import (
        try_dispatch_coroutine_call,
    )

    coroutine_result = try_dispatch_coroutine_call(state, func_obj, args, kwargs, ctx, instr)
    if coroutine_result is not None:
        return coroutine_result

    context_manager_result = dispatch_context_manager_call(
        instr,
        state,
        ctx,
        func_obj,
        args,
        kwargs,
    )
    if context_manager_result is not None:
        return context_manager_result

    exit_stack_result = dispatch_exit_stack_call(instr, state, ctx, func_obj, args, kwargs)
    if exit_stack_result is not None:
        return exit_stack_result

    suppress_result = dispatch_supported_suppress_call(state, func_obj, args, kwargs)
    if suppress_result is not None:
        return suppress_result

    decorator_result = dispatch_transparent_decorator_call(state, func_obj, args, kwargs)
    if decorator_result is not None:
        return decorator_result

    accessor_result = dispatch_operator_accessor_call(instr, state, ctx, func_obj, args, kwargs)
    if accessor_result is not None:
        return accessor_result

    from pysymex._internal.execution.calls.object.attribute.descriptors import (
        try_object_descriptor_call,
    )

    object_attribute_result = try_object_descriptor_call(
        instr,
        state,
        ctx,
        func_obj,
        args,
        kwargs,
    )
    if object_attribute_result is not None:
        return object_attribute_result

    return dispatch_slice_indices_call(state, func_obj, args, kwargs)
