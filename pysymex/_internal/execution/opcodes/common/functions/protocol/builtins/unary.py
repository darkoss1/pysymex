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

"""Unary protocol builtin dispatch for ``len``, conversions, and iteration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.functions.protocol.fallbacks import (
    UNSUPPORTED_CONVERSION_PROTOCOL,
    UNSUPPORTED_ITERATION_PROTOCOL,
    UNSUPPORTED_LENGTH_PROTOCOL,
    protocol_builtin_fallback_events,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def dispatch_unary_protocol_builtin(
    state: VMState,
    func_obj: object,
    model_name: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    ctx: OpcodeDispatcher | None,
) -> OpcodeResult | None:
    """Execute unary object protocol methods required by protocol-aware builtins."""
    if len(args) != 1 or kwargs or ctx is None:
        return None
    if model_name == "bool" or func_obj is bool:
        from pysymex._internal.execution.opcodes.common.control.truth.handlers import (
            try_dispatch_modeled_truth_protocol,
        )

        return try_dispatch_modeled_truth_protocol(args[0], state, ctx)
    if model_name == "len" or func_obj is len:
        return _dispatch_unary_protocol_method(
            state,
            ctx,
            args[0],
            "__len__",
            "__len_value__",
            UNSUPPORTED_LENGTH_PROTOCOL,
        )
    if model_name == "int" or func_obj is int:
        result = _dispatch_unary_protocol_method(
            state,
            ctx,
            args[0],
            "__int__",
            "__int_value__",
            UNSUPPORTED_CONVERSION_PROTOCOL,
        )
        if result is not None:
            return result
        return _dispatch_unary_protocol_method(
            state,
            ctx,
            args[0],
            "__index__",
            "__index_value__",
            UNSUPPORTED_CONVERSION_PROTOCOL,
        )
    if model_name == "float" or func_obj is float:
        return _dispatch_unary_protocol_method(
            state,
            ctx,
            args[0],
            "__float__",
            "__float_value__",
            UNSUPPORTED_CONVERSION_PROTOCOL,
        )
    if model_name == "iter" or func_obj is iter:
        return _dispatch_unary_protocol_method(
            state,
            ctx,
            args[0],
            "__iter__",
            "__iter__",
            UNSUPPORTED_ITERATION_PROTOCOL,
        )
    if model_name == "next" or func_obj is next:
        return _dispatch_unary_protocol_method(
            state,
            ctx,
            args[0],
            "__next__",
            "__next_value__",
            UNSUPPORTED_ITERATION_PROTOCOL,
        )
    if model_name == "reversed" or func_obj is reversed:
        return _dispatch_unary_protocol_method(
            state,
            ctx,
            args[0],
            "__reversed__",
            "__reversed__",
            UNSUPPORTED_ITERATION_PROTOCOL,
        )
    return None


def _dispatch_unary_protocol_method(
    state: VMState,
    ctx: OpcodeDispatcher,
    value: StackValue,
    method_name: str,
    protocol_method: str,
    unsupported_marker: str,
) -> OpcodeResult | None:
    """Call a modeled unary dunder for protocol builtins such as ``len`` or ``iter``."""
    from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

    method = lookup_modeled_method(value, method_name)
    if method is None:
        return None
    from pysymex._internal.execution.calls.interprocedural.entry import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        method,
        [],
        {},
        protocol_method=protocol_method,
    )
    if result is not None:
        return result
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[unsupported_marker],
        fallback_events=protocol_builtin_fallback_events(
            state=state,
            degraded_pass=unsupported_marker,
        ),
        terminal=True,
    )
