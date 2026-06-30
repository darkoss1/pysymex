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

"""Normalize ``__new__`` and ``__init__`` protocol returns for modeled classes.

Ensures foreign-instance ``__new__`` results match the requested class when bases are
complete, and coordinates with return opcodes so ``__init__`` on impossible instances is
classified as unsupported rather than silently accepted.

Limitations:
    Incomplete MRO metadata or ambiguous ``SymbolicValue.is_obj`` may yield
    ``unsupported_construction_protocol`` degradation instead of a definite issue.
"""

from __future__ import annotations

import types
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.construction_fallbacks import (
    CONSTRUCTOR_INIT_UNAVAILABLE_REASON,
    UNSUPPORTED_CONSTRUCTION_PROTOCOL,
    flag_unsupported_construction,
)
from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.core.classes.classes import SymbolicClass
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def normalize_construction(
    frame: CallFrame,
    return_value: StackValue | None,
) -> tuple[StackValue | None, Issue | None, str | None] | None:
    """Complete definite foreign-instance ``__new__`` returns without ``__init__``."""
    if frame.protocol_method != "__new__":
        return None
    if not isinstance(return_value, SymbolicValue):
        return return_value, None, None
    modeled_object = getattr(return_value, "_modeled_object", None)
    may_be_object = modeled_object is not None or not z3.is_false(
        simplify_expr(return_value.is_obj),
    )
    if not may_be_object:
        return return_value, None, None

    from pysymex._internal.core.classes.instances import SymbolicInstance

    target_class = _requested_class(frame.protocol_retained_operand)
    if isinstance(modeled_object, SymbolicInstance) and z3.is_true(
        simplify_expr(return_value.is_obj),
    ):
        if target_class is not None and modeled_object.isinstance_of(target_class):
            return return_value, None, None
        if (
            target_class is not None
            and getattr(modeled_object.cls, "_pysymex_bases_complete", True)
            and not modeled_object.isinstance_of(target_class)
        ):
            return return_value, None, None
    return return_value, None, UNSUPPORTED_CONSTRUCTION_PROTOCOL


def _requested_class(target: StackValue | None) -> SymbolicClass | None:
    """Resolve the definite class whose call invoked ``__new__``."""
    from pysymex._internal.core.classes.registry import class_registry

    target, _, _ = _constructor_call(target)
    if isinstance(target, SymbolicValue):
        class_body = getattr(target, "_modeled_object", None)
        if isinstance(class_body, types.CodeType):
            return class_registry.get_by_code_object(class_body)
    if isinstance(target, type):
        return class_registry.get_class(target.__name__)
    return None


def continue_modeled_instance_initialization(
    frame: CallFrame,
    return_value: StackValue | None,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult | None:
    """Run the effective ``__init__`` for a definite valid ``__new__`` result."""
    if frame.protocol_method != "__new__" or not isinstance(return_value, SymbolicValue):
        return None
    from pysymex._internal.core.classes.instances import SymbolicInstance

    instance = getattr(return_value, "_modeled_object", None)
    target_class = _requested_class(frame.protocol_retained_operand)
    if (
        not isinstance(instance, SymbolicInstance)
        or not z3.is_true(simplify_expr(return_value.is_obj))
        or target_class is None
        or not instance.isinstance_of(target_class)
    ):
        return None
    _, args, kwargs = _constructor_call(frame.protocol_retained_operand)
    effective_class = instance.cls
    init_method = effective_class.lookup_method("__init__")
    if init_method is None:
        return None
    from pysymex._internal.execution.opcodes.common.functions.classes.init import (
        apply_straight_line_init_assignments,
    )

    init_callable = getattr(init_method, "func", None)
    from pysymex._internal.execution.calls.contract_obligations import (
        has_enabled_runtime_contract_obligations,
    )

    can_summarize_init = not (
        callable(init_callable)
        and has_enabled_runtime_contract_obligations(init_callable, getattr(ctx, "config", None))
    )
    if can_summarize_init and apply_straight_line_init_assignments(
        effective_class,
        instance,
        list(args),
        kwargs,
    ):
        return None
    from pysymex._internal.execution.calls.interprocedural.entry import (
        perform_interprocedural_call_impl,
    )

    init_result = perform_interprocedural_call_impl(
        state,
        ctx,
        init_method,
        [return_value, *args],
        kwargs,
        is_init=True,
        init_instance=return_value,
        resume_pc=state.pc,
    )
    if init_result is not None:
        state.depth -= 1
        return init_result
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_CONSTRUCTION_PROTOCOL],
        fallback_events=[
            flag_unsupported_construction(
                state=state,
                reason=CONSTRUCTOR_INIT_UNAVAILABLE_REASON,
            ),
        ],
        terminal=True,
    )


def _constructor_call(
    retained: StackValue | None,
) -> tuple[StackValue | None, tuple[StackValue, ...], dict[str, StackValue]]:
    """Unpack the retained constructor target, args, and kwargs from a protocol frame."""
    payload = cast("tuple[object, ...]", retained) if isinstance(retained, tuple) else ()
    if len(payload) == 3:
        target, args, kwargs = payload
        if isinstance(args, tuple) and isinstance(kwargs, dict):
            return (
                cast("StackValue", target),
                cast("tuple[StackValue, ...]", args),
                cast("dict[str, StackValue]", kwargs),
            )
    return cast("StackValue | None", retained), (), {}
