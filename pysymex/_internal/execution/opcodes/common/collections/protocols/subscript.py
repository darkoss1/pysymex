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

"""Opcode-side dispatch to modeled ``__getitem__`` methods."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.collections.fallbacks import (
    CollectionFallbackEvents,
)
from pysymex._internal.execution.opcodes.common.lowering.types import (
    UNSUPPORTED_SUBSCRIPT_ABSTRACTION,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def route_modeled_subscript(
    state: VMState,
    ctx: OpcodeDispatcher,
    container: StackValue,
    method_name: str,
    args: list[StackValue],
) -> OpcodeResult | None:
    """Enter a custom subscript method when the container defines one."""
    if not isinstance(container, SymbolicValue):
        return None
    from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

    method = lookup_modeled_method(container, method_name)
    if method is None:
        return None
    from pysymex._internal.execution.calls.interprocedural.entry import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        method,
        [container, *args],
        {},
        protocol_method=method_name,
    )
    if result is not None:
        return result
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_SUBSCRIPT_ABSTRACTION],
        fallback_events=[
            CollectionFallbackEvents.unsupported_subscript(
                state=state,
                reason=f"modeled subscript method {method_name!r} could not be entered",
            ),
        ],
        terminal=True,
    )
