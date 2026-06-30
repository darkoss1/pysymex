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

"""Opcode-side dispatch for retained modeled property accessors."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.classes.types import MethodType, SymbolicMethod
from pysymex._internal.execution.opcodes.common.functions.attribute.fallbacks import (
    unsupported_descriptor_protocol,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import ProtocolCallCandidate
    from pysymex._internal.core.types.scalars.values import SymbolicValue
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult
    from pysymex._internal.typing.protocols import StackValue


def dispatch_modeled_property_getter(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
    *,
    protocol_method: str = "__descriptor_get__",
    protocol_retained_operand: StackValue | None = None,
    protocol_fallbacks: tuple[ProtocolCallCandidate, ...] = (),
    resume_pc: int | None = None,
) -> OpcodeResult | None:
    """Execute a retained property getter body when available."""
    modeled_object = getattr(receiver, "_modeled_object", None)
    modeled_class = getattr(modeled_object, "cls", None)
    properties = getattr(modeled_class, "properties", None)
    if not isinstance(properties, dict) or attr_name not in properties:
        return None
    descriptor = cast("dict[str, object]", properties)[attr_name]
    getter_func = getattr(descriptor, "getter_func", None)
    getter_code = getattr(descriptor, "getter_code", None)
    from pysymex._internal.core.calls.payload import function_payload

    getter_payload = function_payload(getter_code)
    if not callable(getter_func) and getter_payload is None:
        return unsupported_descriptor_protocol(
            state,
            reason=f"property {attr_name!r} has no retained getter code",
        )
    from pysymex._internal.execution.calls.interprocedural.entry import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        SymbolicMethod(
            attr_name,
            getter_func if callable(getter_func) else getter_payload,
            method_type=MethodType.INSTANCE,
        ).bind_to_instance(receiver),
        [],
        {},
        protocol_method=protocol_method,
        protocol_retained_operand=protocol_retained_operand,
        protocol_fallbacks=protocol_fallbacks,
        resume_pc=resume_pc,
    )
    if result is not None:
        return result
    return unsupported_descriptor_protocol(
        state,
        reason=f"property getter {attr_name!r} could not be entered",
    )


def dispatch_modeled_property_mutation(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
    method_name: str,
    args: list[StackValue],
    *,
    protocol_method: str | None = None,
) -> OpcodeResult | None:
    """Execute a retained property setter or deleter body."""
    modeled_object = getattr(receiver, "_modeled_object", None)
    modeled_class = getattr(modeled_object, "cls", None)
    properties = getattr(modeled_class, "properties", None)
    if not isinstance(properties, dict) or attr_name not in properties:
        return None
    descriptor = cast("dict[str, object]", properties)[attr_name]
    code_name = "setter_code" if method_name == "__descriptor_set__" else "deleter_code"
    func_name = "setter_func" if method_name == "__descriptor_set__" else "deleter_func"
    method_func = getattr(descriptor, func_name, None)
    method_code = getattr(descriptor, code_name, None)
    from pysymex._internal.core.calls.payload import function_payload

    method_payload = function_payload(method_code)
    if not callable(method_func) and method_payload is None:
        return None
    from pysymex._internal.execution.calls.interprocedural.entry import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        SymbolicMethod(
            attr_name,
            method_func if callable(method_func) else method_payload,
            method_type=MethodType.INSTANCE,
        ).bind_to_instance(receiver),
        args,
        {},
        protocol_method=protocol_method or method_name,
    )
    if result is not None:
        return result
    return unsupported_descriptor_protocol(
        state,
        reason=f"property {method_name!r} for {attr_name!r} could not be entered",
    )
