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

"""Dispatch ``__get__`` for descriptors declared in analyzed class bodies.

Uses :class:`~pysymex._internal.execution.opcodes.common.functions.classes.descriptor.bindings.DeclaredDescriptorBinding`
records collected at class creation time. Data vs non-data descriptors follow different call
scheduling rules before interprocedural entry.

Limitations:
    Descriptors installed dynamically at runtime are not retained and will not match here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.execution.opcodes.common.functions.attribute.fallbacks import (
    unsupported_descriptor_protocol,
)
from pysymex._internal.execution.opcodes.common.functions.classes.descriptor.bindings import (
    DescriptorBinding,
    find_declared_class_descriptor_binding,
    find_declared_descriptor_binding,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import ProtocolCallCandidate
    from pysymex._internal.core.types.scalars.values import SymbolicValue
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult
    from pysymex._internal.typing.protocols import StackValue


def get_declared_data_descriptor(
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
    """Execute data-descriptor reads before ordinary instance storage."""
    binding = find_declared_descriptor_binding(receiver, attr_name)
    if binding is None or not binding.is_data:
        return None
    return _dispatch_descriptor_method(
        state,
        ctx,
        binding,
        "__get__",
        [receiver, binding.owner],
        protocol_method=protocol_method,
        protocol_retained_operand=protocol_retained_operand,
        protocol_fallbacks=protocol_fallbacks,
        resume_pc=resume_pc,
    )


def get_declared_non_data_descriptor(
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
    """Execute non-data descriptor reads only after instance lookup misses."""
    binding = find_declared_descriptor_binding(receiver, attr_name)
    if binding is None or binding.is_data:
        return None
    return _dispatch_descriptor_method(
        state,
        ctx,
        binding,
        "__get__",
        [receiver, binding.owner],
        protocol_method=protocol_method,
        protocol_retained_operand=protocol_retained_operand,
        protocol_fallbacks=protocol_fallbacks,
        resume_pc=resume_pc,
    )


def get_declared_class_descriptor(
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
    """Execute descriptor reads on symbolic class operands."""
    binding = find_declared_class_descriptor_binding(receiver, attr_name)
    if binding is None or not binding.has_getter:
        return None
    return _dispatch_descriptor_method(
        state,
        ctx,
        binding,
        "__get__",
        [SymbolicNoneType(), receiver],
        protocol_method=protocol_method,
        protocol_retained_operand=protocol_retained_operand,
        protocol_fallbacks=protocol_fallbacks,
        resume_pc=resume_pc,
    )


def set_declared_descriptor(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
    method_name: str,
    args: list[StackValue],
    *,
    protocol_method: str | None = None,
    resume_pc: int | None = None,
) -> OpcodeResult | None:
    """Execute a general data descriptor mutation before instance storage."""
    binding = find_declared_descriptor_binding(receiver, attr_name)
    if binding is None or not binding.is_data:
        return None
    return _dispatch_descriptor_method(
        state,
        ctx,
        binding,
        method_name,
        [receiver, *args],
        protocol_method=protocol_method,
        resume_pc=resume_pc,
    )


def _dispatch_descriptor_method(
    state: VMState,
    ctx: OpcodeDispatcher,
    binding: DescriptorBinding,
    method_name: str,
    args: list[StackValue],
    *,
    protocol_method: str | None = None,
    protocol_retained_operand: StackValue | None = None,
    protocol_fallbacks: tuple[ProtocolCallCandidate, ...] = (),
    resume_pc: int | None = None,
) -> OpcodeResult:
    """Invoke a retained descriptor dunder via interprocedural dispatch."""
    if binding.descriptor is None or (method_name == "__get__" and not binding.has_getter):
        return unsupported_descriptor_protocol(
            state,
            reason=f"declared descriptor {method_name!r} is missing retained protocol data",
        )
    from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

    method = lookup_modeled_method(binding.descriptor, method_name)
    if method is None:
        return unsupported_descriptor_protocol(
            state,
            reason=f"declared descriptor {method_name!r} has no modeled method",
        )
    from pysymex._internal.execution.calls.interprocedural.entry import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        method,
        args,
        {},
        protocol_method=protocol_method
        or {
            "__get__": "__descriptor_get__",
            "__set__": "__descriptor_set__",
            "__delete__": "__descriptor_delete__",
        }[method_name],
        protocol_retained_operand=protocol_retained_operand,
        protocol_fallbacks=protocol_fallbacks,
        resume_pc=resume_pc,
    )
    if result is not None:
        return result
    return unsupported_descriptor_protocol(
        state,
        reason=f"declared descriptor {method_name!r} could not be entered",
    )
