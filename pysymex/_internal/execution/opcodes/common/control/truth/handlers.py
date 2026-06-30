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

"""Modeled truth protocol dispatch for control-flow opcodes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.capabilities import length_expr
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.protocol.fallbacks import (
    MEMBERSHIP_CALL_UNAVAILABLE_REASON,
    TRUTH_CALL_UNAVAILABLE_REASON,
    UNSUPPORTED_MEMBERSHIP_PROTOCOL,
    UNSUPPORTED_TRUTH_PROTOCOL,
    flag_unsupported_membership,
    unsupported_truth_event,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def try_dispatch_modeled_truth_protocol(
    value: object,
    state: VMState,
    ctx: OpcodeDispatcher,
    *,
    resume_pc: int | None = None,
    retained_operand: StackValue | None = None,
    membership_operation: str | None = None,
) -> OpcodeResult | None:
    """Execute a modeled ``__bool__`` or fallback ``__len__`` truth method."""
    if not isinstance(value, SymbolicValue):
        return None
    from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

    protocol_method = "__bool__"
    truth_method = lookup_modeled_method(value, protocol_method)
    if truth_method is None:
        protocol_method = "__len__"
        truth_method = lookup_modeled_method(value, protocol_method)
        if truth_method is None:
            return None
    frame_protocol_method = protocol_method
    if membership_operation is not None:
        suffix = "bool" if protocol_method == "__bool__" else "len"
        frame_protocol_method = f"{membership_operation}_truth_{suffix}__"

    from pysymex._internal.execution.calls.interprocedural.entry import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        truth_method,
        [],
        {},
        protocol_method=frame_protocol_method,
        resume_pc=resume_pc,
        protocol_retained_operand=retained_operand,
    )
    if result is not None:
        return result
    if membership_operation is not None:
        degraded_pass = UNSUPPORTED_MEMBERSHIP_PROTOCOL
        fallback_event = flag_unsupported_membership(
            state=state,
            reason=MEMBERSHIP_CALL_UNAVAILABLE_REASON,
        )
    else:
        degraded_pass = UNSUPPORTED_TRUTH_PROTOCOL
        fallback_event = unsupported_truth_event(
            state=state,
            reason=TRUTH_CALL_UNAVAILABLE_REASON,
        )
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[degraded_pass],
        fallback_events=[fallback_event],
        terminal=True,
    )


def resolve_heap_backed_truth_operand(value: object, state: VMState) -> object:
    """Return builtin container storage for object handles whose truth is length-based."""
    from pysymex._internal.core.types.containers.objects import SymbolicObject

    if not isinstance(value, SymbolicObject) or value.address == -1:
        return value

    stored = state.memory.get(value.address)
    if stored is not None and length_expr(stored) is not None:
        return stored
    return value
