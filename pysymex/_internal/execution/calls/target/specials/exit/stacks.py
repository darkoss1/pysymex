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

"""Trusted ``contextlib.ExitStack`` call adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.interprocedural.entry import (
    perform_interprocedural_call_impl,
)
from pysymex._internal.execution.calls.value.coercion import coerce_call_stack_value
from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def dispatch_exit_stack_call(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult | None:
    """Apply trusted ``ExitStack`` methods without analyzing model internals as target code."""
    if kwargs:
        return None

    from pysymex._internal.models.stdlib.contextlib.stacks import ExitStackModel

    receiver = getattr(func_obj, "__self__", None)
    if not isinstance(receiver, ExitStackModel):
        return None

    method_name = getattr(func_obj, "__name__", "")
    if method_name == "__exit__":
        exit_args = list(args)
        while len(exit_args) < 3:
            exit_args.append(None)
        raw_exc_type = exit_args[0]
        raw_exc_val = exit_args[1]
        exc_type = (
            raw_exc_type
            if isinstance(raw_exc_type, type) and issubclass(raw_exc_type, BaseException)
            else None
        )
        exc_val = raw_exc_val if isinstance(raw_exc_val, BaseException) else None
        result = receiver.__exit__(exc_type, exc_val, None)
        state = state.push(result)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    if method_name != "enter_context" or len(args) != 1:
        return None

    manager = args[0]
    from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

    exit_method = lookup_modeled_method(manager, "__exit__")
    if exit_method is not None:
        receiver.register_exit_callback(exit_method)

    enter_method = lookup_modeled_method(manager, "__enter__")
    if enter_method is not None:
        return perform_interprocedural_call_impl(
            state,
            ctx,
            enter_method,
            [],
            {},
            protocol_method="__enter__",
        )

    manager_obj = manager.value if isinstance(manager, SymbolicValue) else manager
    enter = getattr(manager_obj, "__enter__", None)
    exit_ = getattr(manager_obj, "__exit__", None)
    if callable(enter) and callable(exit_):
        receiver.register_exit_callback(exit_)
        state = state.push(coerce_call_stack_value(enter()))
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    return None
