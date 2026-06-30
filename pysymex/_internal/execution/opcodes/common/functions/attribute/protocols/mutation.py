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

"""Opcode-side dispatch for dynamic attribute mutation hooks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.opcodes.common.functions.attribute.fallbacks import (
    unsupported_attribute_protocol,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.scalars.values import SymbolicValue
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult
    from pysymex._internal.typing.protocols import StackValue


def route_modeled_attribute_mutation(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    method_name: str,
    args: list[StackValue],
    *,
    protocol_method: str | None = None,
) -> OpcodeResult | None:
    """Execute a custom attribute mutation hook before ordinary storage."""
    from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

    method = lookup_modeled_method(receiver, method_name)
    if method is None:
        return None
    from pysymex._internal.execution.calls.interprocedural.entry import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        method,
        args,
        {},
        protocol_method=protocol_method or method_name,
    )
    if result is not None:
        return result
    return unsupported_attribute_protocol(
        state,
        reason=f"modeled attribute mutation {method_name!r} could not be entered",
    )
