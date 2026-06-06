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

"""Resolve ``LOAD_SUPER_ATTR`` for modeled classes with a complete MRO snapshot.

Recovers the defining class from the active method body when possible, then binds ``super()``
calls to the next modeled base implementation. Documents CPython 3.12+ stack layout in handler
docstrings.

Limitations:
    Fails closed with ``UNSUPPORTED_SUPER_PROTOCOL`` when the defining class cell cannot be
    recovered or the MRO is incomplete.
"""

from __future__ import annotations

import dis
import types
from typing import TYPE_CHECKING, cast

from pysymex.core.cache.code_objects import get_instructions as cached_get_instructions
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.calls.payload import function_payload
from pysymex.execution.calls.type_call import BoundTypeCall
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.calls.model_dispatch import require_stack_depth
from pysymex.execution.fallback import FallbackEvent, FallbackKind, RiskLevel, SoundnessTag
from pysymex.models.objects import MethodType, SymbolicClass, SymbolicInstance, SymbolicMethod

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher

UNSUPPORTED_SUPER_PROTOCOL = "unsupported_super_protocol"


def handle_common_load_super_attr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Resolve zero-argument ``super().method`` for a complete modeled MRO.

    CPython 3.12+ places ``super``, the defining class cell, and ``self`` on
    the stack before ``LOAD_SUPER_ATTR``. The scanner cannot retain the
    concrete ``__class__`` cell for modeled class bodies, so the defining
    class is recovered only when the active method body is uniquely present
    in the receiver's complete local-class MRO. Other super lookups remain
    explicit precision losses.
    """
    require_stack_depth(state, instr, 3, "LOAD_SUPER_ATTR operands")
    receiver = state.pop()
    state.pop()
    state.pop()

    method_lookup = instr.arg is not None and bool(instr.arg & 1)
    if method_lookup and isinstance(receiver, SymbolicValue):
        method = _resolve_super_method(receiver, str(instr.argval), ctx)
        if method is None:
            method = _resolve_super_type_method(receiver, str(instr.argval), ctx)
        if method is not None:
            state = state.push(cast("StackValue", method))
            state = state.push(receiver)
            return OpcodeResult.continue_with(state.advance_pc())
    attr_name = str(instr.argval)
    return _unsupported_super_result(
        state,
        attr_name,
        reason=f"super attribute {attr_name!r} could not be resolved with a complete modeled MRO",
    )


def handle_common_load_super_variants(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Retain explicit degradation for unvalidated super opcode variants."""
    _ = ctx
    require_stack_depth(state, instr, 2, "super opcode operands")
    state.pop()
    state.pop()
    attr_name = str(instr.argval)
    return _unsupported_super_result(
        state,
        attr_name,
        reason=f"super opcode variant for {attr_name!r} is unsupported",
    )


def handle_modeled_super_proxy_attr(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    proxy: object,
    *,
    push_null: bool,
) -> OpcodeResult:
    """Resolve py311 ``super().attr`` after ``super()`` returned a modeled proxy."""
    receiver = getattr(proxy, "receiver", None)
    attr_name = str(instr.argval)
    if not isinstance(receiver, SymbolicValue):
        return _unsupported_super_result(
            state,
            attr_name,
            reason=(
                f"zero-argument super attribute {attr_name!r} has a receiver outside "
                "the modeled symbolic MRO"
            ),
        )
    method = _resolve_super_method(receiver, attr_name, ctx)
    if method is None:
        method = _resolve_super_type_method(receiver, attr_name, ctx)
    if method is None:
        return _unsupported_super_result(
            state,
            attr_name,
            reason=(
                f"zero-argument super attribute {attr_name!r} could not be resolved "
                "with a complete modeled MRO"
            ),
        )
    state = state.push(cast("StackValue", method))
    if push_null:
        state = state.push(receiver)
    return OpcodeResult.continue_with(state.advance_pc())


def _resolve_super_method(
    receiver: SymbolicValue, attr_name: str, ctx: OpcodeDispatcher
) -> SymbolicMethod | None:
    """Bind ``super().attr`` to the next instance method after the active owner class."""
    instance = getattr(receiver, "_modeled_object", None)
    if not isinstance(instance, SymbolicInstance):
        return None
    if not bool(getattr(instance.cls, "_pysymex_bases_complete", False)):
        return None
    owner_index = _active_owner_index(instance.cls, ctx)
    if owner_index is None:
        return None
    for cls in instance.cls.mro[owner_index + 1 :]:
        method = cls.methods.get(attr_name)
        if method is not None:
            if method.method_type != MethodType.INSTANCE:
                return None
            return method.bind_to_instance(receiver)
    return None


def _resolve_super_type_method(
    receiver: SymbolicValue, attr_name: str, ctx: OpcodeDispatcher
) -> SymbolicMethod | BoundTypeCall | None:
    """Bind metaclass ``super().__call__`` to parent metaclass construction behavior."""
    if attr_name != "__call__":
        return None
    from pysymex.execution.opcodes.common.functions.classes import modeled_class_from_value

    receiver_cls = modeled_class_from_value(receiver)
    if receiver_cls is None:
        return None
    metaclass = receiver_cls.metaclass
    if metaclass is None or not bool(getattr(metaclass, "_pysymex_bases_complete", False)):
        return None
    owner_index = _active_owner_index(metaclass, ctx)
    if owner_index is None:
        return None
    for cls in metaclass.mro[owner_index + 1 :]:
        if cls.module == "builtins" and cls.name == "type":
            return BoundTypeCall(receiver)
        method = cls.methods.get(attr_name)
        if method is not None:
            if method.method_type != MethodType.INSTANCE:
                return None
            return method.bind_to_class(receiver)
    return None


def _active_owner_index(modeled_cls: SymbolicClass, ctx: OpcodeDispatcher) -> int | None:
    """Return the MRO index of the class whose method matches the active bytecode."""
    active_instructions = list(ctx.instructions)
    for index, cls in enumerate(modeled_cls.mro):
        for method in cls.methods.values():
            payload = function_payload(method.func)
            method_code = payload.code if payload is not None else method.func
            if isinstance(method_code, types.CodeType) and (
                list(cached_get_instructions(method_code)) == active_instructions
            ):
                return index
    return None


def _unsupported_super_result(state: VMState, attr_name: str, *, reason: str) -> OpcodeResult:
    """Push a symbolic super attribute and record unsupported super protocol degradation."""
    fallback_event = unsupported_super_event(state=state, reason=reason)
    value, constraint = SymbolicValue.symbolic(f"super_{attr_name}")
    state = state.push(value)
    state = state.add_constraint(constraint)
    return OpcodeResult.continue_with(
        state.advance_pc(),
        degraded_passes=[UNSUPPORTED_SUPER_PROTOCOL],
        fallback_events=[fallback_event],
    )


def unsupported_super_event(*, state: VMState, reason: str) -> FallbackEvent:
    """Build a fallback event for unsupported ``super`` protocol resolution."""
    return FallbackEvent(
        kind=FallbackKind.UNSUPPORTED,
        label=UNSUPPORTED_SUPER_PROTOCOL,
        owner="execution.opcodes.super",
        reason=reason,
        pc=state.pc,
        soundness=SoundnessTag.UNSUPPORTED,
        false_positive_risk=RiskLevel.MEDIUM,
        false_negative_risk=RiskLevel.HIGH,
    )


__all__ = [
    "UNSUPPORTED_SUPER_PROTOCOL",
    "handle_common_load_super_attr",
    "handle_common_load_super_variants",
    "handle_modeled_super_proxy_attr",
]
