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

"""Retained modeled ``__iter__`` protocol support for UNPACK_SEQUENCE."""

from __future__ import annotations

import dis
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.collections.stack_ops import CollectionStackOps

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue

UNPACK_ITER_PROTOCOL = "__iter_unpack_sequence__"


@dataclass(frozen=True, slots=True)
class UnpackStep:
    """Retained caller state for unpacking through a modeled ``__iter__`` call."""

    count: int
    unpack_pc: int
    continue_pc: int


def route_modeled_unpack_iter(
    state: VMState,
    ctx: OpcodeDispatcher,
    container: StackValue,
    *,
    count: int,
) -> OpcodeResult | None:
    """Enter a modeled ``__iter__`` for native unpacking when the source defines one."""
    if not isinstance(container, SymbolicValue):
        return None
    from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

    iter_method = lookup_modeled_method(container, "__iter__")
    if iter_method is None:
        return None
    from pysymex._internal.execution.calls.interprocedural.entry import (
        perform_interprocedural_call_impl,
    )

    return perform_interprocedural_call_impl(
        state,
        ctx,
        iter_method,
        [],
        {},
        protocol_method=UNPACK_ITER_PROTOCOL,
        resume_pc=state.pc,
        protocol_retained_operand=cast(
            "StackValue",
            UnpackStep(
                count=count,
                unpack_pc=state.pc,
                continue_pc=state.pc + 1,
            ),
        ),
    )


def complete_retained_unpack_iter(
    frame: CallFrame,
    return_value: StackValue | None,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult | None:
    """Complete an unpack suspended around a modeled ``__iter__`` return."""
    retained = _retained_unpack_iter(frame)
    if retained is None:
        return None
    state.depth -= 1
    if return_value is None:
        state = state.push(cast("StackValue", None)).set_pc(retained.unpack_pc)
        return OpcodeResult.continue_with(state)

    items = _exact_unpack_iter_items(return_value, state)
    if items is None:
        state = state.push(return_value).set_pc(retained.unpack_pc)
        return OpcodeResult.continue_with(state)

    actual = len(items)
    if actual != retained.count:
        instr = ctx.get_instruction(retained.unpack_pc)
        if not isinstance(instr, dis.Instruction):
            return OpcodeResult.terminate()
        return CollectionStackOps.unpack_arity_error(
            instr,
            state,
            ctx,
            expected=retained.count,
            actual=actual,
        )

    for item in reversed(items):
        state = state.push(item)
    return OpcodeResult.continue_with(state.set_pc(retained.continue_pc))


def _retained_unpack_iter(frame: CallFrame) -> UnpackStep | None:
    """Return retained unpack state when this frame owns an unpack ``__iter__`` call."""
    if frame.protocol_method != UNPACK_ITER_PROTOCOL:
        return None
    retained = frame.protocol_retained_operand
    if isinstance(retained, UnpackStep):
        return retained
    return None


def _exact_unpack_iter_items(
    return_value: StackValue,
    state: VMState,
) -> list[StackValue] | None:
    """Return exact finite items from an unpack ``__iter__`` return, if known."""
    from pysymex._internal.models.builtins.iteration.sources import IterationSources

    if isinstance(return_value, SymbolicIterator):
        return IterationSources.iterable_items(return_value, state)
    return IterationSources.iterable_items(return_value, state)
