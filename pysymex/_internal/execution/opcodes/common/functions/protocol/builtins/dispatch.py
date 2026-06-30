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

"""Intercept builtin calls that implement dunder protocols (``len``, ``iter``, conversions).

When bytecode calls a builtin wrapper around ``__len__``, ``__int__``, ``__iter__``, or
attribute mutation helpers, this module suspends into modeled user methods when the receiver
is a :class:`~pysymex._internal.core.classes.SymbolicInstance`.

Limitations:
    Only registered protocol/builtin pairings are handled; unknown builtins defer to generic calls.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.opcodes.common.functions.protocol.builtins.attribute import (
    route_attribute_builtin,
)
from pysymex._internal.execution.opcodes.common.functions.protocol.builtins.unary import (
    dispatch_unary_protocol_builtin,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult
    from pysymex._internal.typing.protocols import StackValue


def dispatch_modeled_protocol_builtin(
    state: VMState,
    func_obj: object,
    model_name: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    ctx: OpcodeDispatcher | None,
) -> OpcodeResult | None:
    """Execute object protocol methods required by protocol-aware builtins."""
    from pysymex._internal.execution.opcodes.common.functions.attribute.descriptors.hasattr import (
        dispatch_declared_descriptor_hasattr,
    )

    hasattr_result = dispatch_declared_descriptor_hasattr(
        state,
        func_obj,
        model_name,
        args,
        kwargs,
        ctx,
    )
    if hasattr_result is not None:
        return hasattr_result
    attribute_result = route_attribute_builtin(state, func_obj, model_name, args, kwargs, ctx)
    if attribute_result is not None:
        return attribute_result
    return dispatch_unary_protocol_builtin(state, func_obj, model_name, args, kwargs, ctx)
