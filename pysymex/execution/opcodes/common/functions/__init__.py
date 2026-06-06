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

"""CALL and related function opcode dispatch for the common handler layer.

Resolves call layout, applies stdlib and builtin models, forks ``None``-callable
error paths, and falls back to havoc for unmodeled targets. Delegates attribute,
import, and ``MAKE_FUNCTION`` opcodes to sibling modules under this package.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

import z3

from pysymex.core.state.types import VMStateError
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.lowering import CallLowerer
from pysymex.execution.opcodes.common.functions.misc import (
    handle_common_call_intrinsic_2 as handle_common_call_intrinsic_2,
    handle_common_import_from as handle_common_import_from,
    handle_common_import_name as handle_common_import_name,
    handle_common_import_star as handle_common_import_star,
    handle_common_kw_names as handle_common_kw_names,
    handle_common_load_build_class as handle_common_load_build_class,
    handle_common_make_function as handle_common_make_function,
    handle_common_precall as handle_common_precall,
    handle_common_set_function_attribute as handle_common_set_function_attribute,
)
from pysymex.execution.opcodes.common.functions.super import (
    handle_common_load_super_attr as handle_common_load_super_attr,
    handle_common_load_super_variants as handle_common_load_super_variants,
)
from pysymex.execution.opcodes.common.functions.attribute.load import (
    handle_common_load_method as handle_common_load_method,
)
from pysymex.execution.opcodes.common.functions.attribute.store import (
    handle_common_delete_attr as handle_common_delete_attr,
    handle_common_store_attr as handle_common_store_attr,
)
from pysymex.execution.opcodes.common.functions.call_ex import (
    handle_common_call_function_ex as handle_common_call_function_ex,
)
from pysymex.execution.calls.helpers import (
    coerce_kw_names as _coerce_kw_names,
    coerce_kw_names as coerce_kw_names,
    is_symbolic_module_receiver as _is_symbolic_module_receiver,
)
from pysymex.execution.calls.model_dispatch import (
    handle_definite_non_callable_call as _handle_definite_non_callable_call,
    is_call_null_marker as _is_call_null_marker,
    is_uninterpreted_bool_const as _is_uninterpreted_bool_const,
    path_is_sat as _path_is_sat,
    require_stack_depth as _require_stack_depth,
)
from pysymex.execution.calls.target_dispatch import (
    dispatch_resolved_call as _dispatch_resolved_call,
)


if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def _is_modeled_context_exit(value: object) -> bool:
    """Return whether *value* represents a modeled context manager ``__exit__``."""
    method = getattr(value, "method", None)
    return getattr(value, "name", "") == "__exit__" or getattr(method, "name", "") == "__exit__"


def handle_common_call(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle function calls, applying models if available."""
    argc = int(instr.argval) if instr.argval else 0
    _require_stack_depth(state, instr, argc + 1, "CALL arguments plus callable")

    args: list[StackValue] = []
    for _ in range(argc):
        args.append(state.pop())
    if len(args) > 1:
        args.reverse()

    kwargs: dict[str, StackValue] = {}
    kw_names_raw = state.pending_kw_names
    if kw_names_raw is not None:
        kw_names = _coerce_kw_names(kw_names_raw)
        kw_count = len(kw_names)
        if len(args) >= kw_count:
            kw_vals = args[-kw_count:]
            args = args[:-kw_count]
            kwargs = dict(zip(kw_names, kw_vals, strict=False))
        state.pending_kw_names = None

    _require_stack_depth(state, instr, 1, "callable after argument pop")

    lowerer = CallLowerer(state.pc)
    top_value = state.pop()

    receiver_or_null: StackValue = SymbolicNone()
    receiver_is_argument = False
    if state.stack:
        peeked = state.peek()
        if _is_call_null_marker(peeked) and lowerer.is_likely_callable(top_value):
            state.pop()
            func_obj = top_value
        elif lowerer.is_likely_callable(top_value) and lowerer.is_likely_callable(peeked):
            receiver_or_null = top_value
            func_obj = state.pop()
        elif not lowerer.is_likely_callable(top_value):
            receiver_or_null = top_value
            func_obj = state.pop()
            receiver_is_argument = _is_modeled_context_exit(func_obj)
        else:
            func_obj = top_value
            receiver_or_null = state.pop()
    else:
        func_obj = top_value

    if func_obj is None:
        if not isinstance(receiver_or_null, SymbolicNone) and receiver_or_null is not None:
            raise VMStateError("CALL stack is malformed: callable slot is NULL")
        non_callable_result = _handle_definite_non_callable_call(instr, state, ctx, func_obj)
        if non_callable_result is not None:
            return non_callable_result
        return OpcodeResult.terminate()

    if _is_symbolic_module_receiver(receiver_or_null, state):
        receiver_or_null = SymbolicNone()
    layout = lowerer.resolve_layout(
        func_obj,
        receiver_or_null,
        args,
        kwargs,
        receiver_is_argument=receiver_is_argument,
    )

    non_callable_result = _handle_definite_non_callable_call(instr, state, ctx, layout.func_obj)
    if non_callable_result is not None:
        return non_callable_result

    if isinstance(layout.func_obj, SymbolicValue):
        is_none = lowerer.emit_none_check(layout.func_obj)
        handler_pc = ctx.find_exception_handler(instr.offset)
        non_none_constraint = z3.Not(is_none)
        if (
            handler_pc is None
            and _is_uninterpreted_bool_const(is_none)
            and _path_is_sat([*state.path_constraints, non_none_constraint])
        ):
            state = state.add_constraint(non_none_constraint)
            return _dispatch_resolved_call(
                instr, state, ctx, layout.func_obj, layout.args, layout.kwargs
            )
        can_succeed = _path_is_sat([*state.path_constraints, non_none_constraint])
        can_raise = _path_is_sat([*state.path_constraints, is_none])
        if can_raise and not can_succeed:
            error_state = state.fork().add_constraint(is_none)
            non_callable_result = _handle_definite_non_callable_call(instr, error_state, ctx, None)
            if non_callable_result is not None:
                return non_callable_result
            return OpcodeResult.terminate()
        if can_raise and handler_pc is not None:
            error_result = _handle_definite_non_callable_call(
                instr, state.fork().add_constraint(is_none), ctx, None
            )
            state = state.fork().add_constraint(z3.Not(is_none))
            result = _dispatch_resolved_call(
                instr, state, ctx, layout.func_obj, layout.args, layout.kwargs
            )
            error_states = error_result.new_states if error_result is not None else []
            error_issues = error_result.issues if error_result is not None else []
            if result.new_states:
                return OpcodeResult.branch(
                    [*result.new_states, *error_states],
                    [*result.issues, *error_issues],
                    result.degraded_passes,
                    result.fallback_events,
                )
            return OpcodeResult.branch(
                error_states,
                [*result.issues, *error_issues],
                result.degraded_passes,
                result.fallback_events,
            )
        if can_raise:
            state = state.add_constraint(z3.Not(is_none))

    return _dispatch_resolved_call(instr, state, ctx, layout.func_obj, layout.args, layout.kwargs)
