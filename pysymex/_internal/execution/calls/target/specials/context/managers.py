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

"""Trusted ``contextlib.contextmanager`` call adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.execution.calls.model.dispatch import apply_model
from pysymex._internal.execution.calls.value.coercion import coerce_call_stack_value
from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def dispatch_context_manager_call(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult | None:
    """Apply trusted ``contextlib.contextmanager`` factory and normal exit calls."""
    from pysymex._internal.models.stdlib.contextlib.managers import (
        ContextManager,
        ContextManagerFactory,
    )

    if isinstance(func_obj, ContextManagerFactory):
        manager = func_obj(*args, **kwargs)
        state = state.push(coerce_call_stack_value(manager)).advance_pc()
        return OpcodeResult.continue_with(state)

    receiver = getattr(func_obj, "__self__", None)
    if not isinstance(receiver, ContextManager):
        return None

    method_name = getattr(func_obj, "__name__", "")
    if method_name != "__exit__":
        return None

    if not context_manager_normal_exit(args):
        from pysymex._internal.execution.opcodes.common.control.fallbacks import (
            UNSUPPORTED_GENERATOR,
            flag_unsupported_generator,
        )

        fallback_event = flag_unsupported_generator(
            state=state,
            reason="contextlib.contextmanager exception throw is not modeled precisely",
        )
        state = state.push(False).advance_pc()
        return OpcodeResult.continue_with(
            state,
            degraded_passes=[UNSUPPORTED_GENERATOR],
            fallback_events=[fallback_event],
        )

    generator = receiver.generator
    if generator is None:
        state = state.push(SymbolicNoneType()).advance_pc()
        return OpcodeResult.continue_with(state)

    return apply_model(state, next, [cast("StackValue", generator), None], {}, ctx, instr)


def context_manager_normal_exit(args: list[StackValue]) -> bool:
    """Return whether ``__exit__`` arguments represent a no-exception with exit."""
    return all(arg is None or isinstance(arg, SymbolicNoneType) for arg in args)
