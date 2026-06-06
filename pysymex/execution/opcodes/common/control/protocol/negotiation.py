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

"""Try fallback modeled candidates when a dunder returns ``NotImplemented``.

CPython may delegate to a base implementation; this module walks
``CallFrame.protocol_fallbacks`` and issues the next interprocedural call with the same
``protocol_method`` and resume PC. Marks unsupported when no further candidate exists.

Limitations:
    Only handles explicit fallback lists recorded at suspension time; dynamic MRO changes
    at runtime are not re-derived.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.control.protocol.fallbacks import (
    PROTOCOL_FALLBACK_UNAVAILABLE_REASON,
    UNSUPPORTED_COMPARISON_PROTOCOL,
    unsupported_comparison_event,
)
from pysymex.execution.opcodes.common.numeric.fallbacks import unsupported_numeric_event
from pysymex.execution.opcodes.common.numeric.labels import UNSUPPORTED_NUMERIC_ABSTRACTION

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.types import CallFrame
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def is_not_implemented_return(return_value: StackValue | None) -> bool:
    """Return whether a modeled protocol delegated through ``NotImplemented``."""
    return return_value is NotImplemented or (
        isinstance(return_value, SymbolicValue) and return_value.value is NotImplemented
    )


def continue_deferred_protocol_call(
    frame: CallFrame,
    return_value: StackValue | None,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult | None:
    """Invoke the next modeled candidate after a delegating protocol return."""
    if not frame.protocol_fallbacks or not is_not_implemented_return(return_value):
        return None
    candidate = frame.protocol_fallbacks[0]
    from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

    method = lookup_modeled_method(candidate.owner, candidate.method_name)
    if method is None:
        return _unsupported_negotiation_result(frame.protocol_method, state)
    from pysymex.execution.calls.interprocedural import (
        perform_interprocedural_call_impl,
    )

    state.depth -= 1
    result = perform_interprocedural_call_impl(
        state,
        ctx,
        method,
        [candidate.owner, candidate.argument],
        {},
        protocol_method=frame.protocol_method,
        resume_pc=frame.return_pc,
        protocol_retained_operand=frame.protocol_retained_operand,
        protocol_fallbacks=frame.protocol_fallbacks[1:],
    )
    if result is not None:
        return result
    return _unsupported_negotiation_result(frame.protocol_method, state)


def _unsupported_negotiation_result(protocol_method: str | None, state: VMState) -> OpcodeResult:
    """Terminate when no further modeled protocol fallback can run."""
    marker = (
        UNSUPPORTED_NUMERIC_ABSTRACTION
        if protocol_method == "__numeric__"
        else UNSUPPORTED_COMPARISON_PROTOCOL
    )
    fallback_events = (
        [
            unsupported_numeric_event(
                state=state,
                reason=PROTOCOL_FALLBACK_UNAVAILABLE_REASON,
                unsupported_protocol=True,
            )
        ]
        if marker == UNSUPPORTED_NUMERIC_ABSTRACTION
        else [
            unsupported_comparison_event(
                state=state,
                reason=PROTOCOL_FALLBACK_UNAVAILABLE_REASON,
            )
        ]
    )
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[marker],
        fallback_events=fallback_events,
        terminal=True,
    )


__all__ = ["continue_deferred_protocol_call", "is_not_implemented_return"]
