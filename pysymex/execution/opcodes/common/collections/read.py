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

"""``BINARY_SUBSCR`` read paths for containers, slices, and modeled protocols.

Pops index then container, tries ``__getitem__``/slice protocol dispatch, and falls
back to :class:`~pysymex.execution.opcodes.common.lowering.CollectionLowerer` or
havoc with explicit degradation tags. Store/delete live in
:mod:`pysymex.execution.opcodes.common.collections.subscript`.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.solver.constraints.literals import exact_bool_literal
from pysymex.core.solver.engine.queries import check_sat_result, get_model
from pysymex.core.solver.engine.results import SolverResult
from pysymex.core.state.record import known_sat_prefix_len_for_state
from pysymex.core.types.base import safe_z3_eq
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.checks import is_type_subscription
from pysymex.core.types.havoc import HavocValue
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.collections.helpers import (
    add_lowered_constraints,
    apply_heap_updates,
    branch_or_terminate_exception,
    path_is_sat,
    require_stack_depth,
    resolve_runtime_container,
)
from pysymex.execution.opcodes.common.collections.fallbacks import (
    collection_fallback_events,
    unsupported_slice_event,
    unsupported_subscript_event,
)
from pysymex.execution.opcodes.common.collections.protocols import (
    dispatch_built_slice_index_protocol,
    dispatch_modeled_index_protocol,
    dispatch_modeled_subscript_protocol,
    dispatch_retained_slice_zero_step,
)
from pysymex.execution.opcodes.common.exceptions.helpers import jump_to_exception_handler
from pysymex.core.types.containers.slices import (
    UNSUPPORTED_SLICE_ABSTRACTION,
    extract_slice_bounds,
)
from pysymex.core.solver.slices import materialize_concrete_slice
from pysymex.execution.opcodes.common.lowering import CollectionLowerer
from pysymex.execution.opcodes.common.lowering.concrete_subscript import (
    concrete_int_index,
    to_stack_value,
)
from pysymex.execution.opcodes.common.lowering.types import (
    UNSUPPORTED_SUBSCRIPT_ABSTRACTION,
    LoweredValue,
)
from pysymex.models.containers.sequence_precision import slice_concrete_backed_sequence

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
    from pysymex.typing import StackValue


def handle_common_binary_subscr(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    *,
    report_mixed_list_error: bool = False,
) -> OpcodeResult:
    """Read ``obj[key]`` (``BINARY_SUBSCR``) with protocol, concrete, and havoc paths.

    CPython stack effect: pops index and container, pushes the loaded value. May fork
    on ``TypeError``/``IndexError`` when exception handlers exist; records issue kinds
    for mixed list/``None`` index when ``report_mixed_list_error`` is enabled.

    Limitations:
        Unsupported containers use havoc or symbolic fallbacks rather than full
        buffer/memory models.
    """
    require_stack_depth(state, instr, 2, "BINARY_SUBSCR container and index")
    index = state.pop()
    container = state.pop()

    modeled_result = dispatch_modeled_subscript_protocol(
        state, ctx, container, "__getitem__", [index]
    )
    if modeled_result is not None:
        return modeled_result

    if isinstance(container, HavocValue):
        fallback_event = unsupported_subscript_event(
            state=state,
            reason="havoc container subscript produces an unconstrained value",
        )
        ret, tc = HavocValue.havoc(f"{getattr(container, 'name', 'havoc')}[{state.pc}]")
        state = state.push(ret)
        state = state.add_constraint(tc)
        state = state.advance_pc()
        return OpcodeResult.continue_with(
            state,
            degraded_passes=[UNSUPPORTED_SUBSCRIPT_ABSTRACTION],
            fallback_events=[fallback_event],
        )

    if is_type_subscription(container):
        result, constraint = SymbolicValue.symbolic(f"generic_{state.pc}")
        state = state.add_constraint(constraint)
        state = state.push(result)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    real_container = resolve_runtime_container(container, state)
    if isinstance(index, SymbolicNone) and isinstance(real_container, (SymbolicList, list)):
        return _none_list_index_type_error(instr, state, ctx)
    if isinstance(real_container, (SymbolicList, SymbolicString, list, tuple, str, bytes)):
        sequence_container = cast(
            "SymbolicList | SymbolicString | list[object] | tuple[object, ...] | str | bytes",
            real_container,
        )
        if isinstance(index, SymbolicValue):
            slice_result = dispatch_built_slice_index_protocol(state, ctx, [container], index)
            if slice_result is not None:
                return slice_result
            if extract_slice_bounds(index) is not None:
                zero_step_result = dispatch_retained_slice_zero_step(instr, state, ctx, index)
                if zero_step_result is not None:
                    return zero_step_result
                lowered = _lower_concrete_built_slice(
                    sequence_container, index, state.path_constraints.to_list(), state.pc
                )
                if lowered is None:
                    return OpcodeResult(
                        new_states=[],
                        issues=[],
                        degraded_passes=[UNSUPPORTED_SLICE_ABSTRACTION],
                        fallback_events=[
                            unsupported_slice_event(
                                state=state,
                                reason="retained slice bounds could not be concretely lowered",
                            )
                        ],
                        terminal=True,
                    )
                state = apply_heap_updates(state, lowered.heap_updates)
                state = state.push(lowered.value)
                state = state.advance_pc()
                return OpcodeResult.continue_with(state)
        index_result = dispatch_modeled_index_protocol(state, ctx, [container], index)
        if index_result is not None:
            return index_result
    real_container = cast("object", real_container)
    precise_concrete = _single_feasible_concrete_list_item(real_container, index, state)
    if precise_concrete is not None:
        lowered = precise_concrete
    else:
        lowerer = CollectionLowerer(state.pc)
        lowered = lowerer.lower_subscript(real_container, index)

    exc_cond = lowered.exception_condition

    exc_literal = exact_bool_literal(exc_cond)
    if exc_literal is not False:
        path_constraints = state.path_constraints.to_list()
        known_prefix_len = known_sat_prefix_len_for_state(state)
        exc_constraints = [*path_constraints, exc_cond]
        if exc_literal is True and _path_already_inconclusive(state, path_constraints):
            exc_result = SolverResult.unknown()
        else:
            exc_result = check_sat_result(
                exc_constraints,
                known_sat_prefix_len=known_prefix_len,
            )
        if exc_result.is_unsat and exc_literal is True:
            return OpcodeResult.terminate()
        if not exc_result.is_unsat:
            not_exc = z3.Not(exc_cond)
            not_exc_literal = exact_bool_literal(not_exc)
            if not_exc_literal is True or (
                not_exc_literal is None
                and path_is_sat([*path_constraints, not_exc], known_sat_prefix_len=known_prefix_len)
            ):
                handler_pc = ctx.find_exception_handler(instr.offset)
                success_state = state.fork().add_constraint(not_exc)
                success_state = add_lowered_constraints(success_state, lowered.constraints)
                success_state = apply_heap_updates(success_state, lowered.heap_updates)
                success_state = success_state.push(lowered.value)
                success_state = success_state.advance_pc()
                if handler_pc is None:
                    issues = _possible_uncaught_subscript_errors(
                        state,
                        real_container,
                        exc_cond,
                        exc_result,
                        report_list_index_error=(
                            report_mixed_list_error or _is_certified_mixed_list_index(index)
                        ),
                    )
                    return OpcodeResult(
                        new_states=[success_state],
                        issues=issues,
                        degraded_passes=lowered.degraded_passes,
                        fallback_events=collection_fallback_events(
                            state=state,
                            degraded_passes=lowered.degraded_passes,
                            reason="subscript lowering required a collection abstraction",
                        ),
                    )
                error_state = state.fork().add_constraint(exc_cond).set_pc(handler_pc)
                return OpcodeResult.branch(
                    [success_state, error_state],
                    degraded_passes=lowered.degraded_passes,
                    fallback_events=collection_fallback_events(
                        state=state,
                        degraded_passes=lowered.degraded_passes,
                        reason="subscript lowering required a collection abstraction",
                    ),
                )

            handler_pc = ctx.find_exception_handler(instr.offset)
            if handler_pc is None:
                issues = _possible_uncaught_subscript_errors(
                    state,
                    real_container,
                    exc_cond,
                    exc_result,
                    report_list_index_error=True,
                )
                if issues:
                    return OpcodeResult.error(
                        issues[0],
                        degraded_passes=lowered.degraded_passes,
                        fallback_events=collection_fallback_events(
                            state=state,
                            degraded_passes=lowered.degraded_passes,
                            reason="subscript lowering required a collection abstraction",
                        ),
                    )
            return branch_or_terminate_exception(instr, state, ctx, exc_cond)

    fallback_events = collection_fallback_events(
        state=state,
        degraded_passes=lowered.degraded_passes,
        reason="subscript lowering required a collection abstraction",
    )
    state = add_lowered_constraints(state, lowered.constraints)
    state = apply_heap_updates(state, lowered.heap_updates)
    state = state.push(lowered.value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(
        state,
        degraded_passes=lowered.degraded_passes,
        fallback_events=fallback_events,
    )


def _none_list_index_type_error(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Route ``None`` list indexing to a handler or ``TypeError`` issue."""
    message = "list indices must be integers or slices, not NoneType"
    exc = SymbolicException.concrete(TypeError, message, raised_at=state.pc)
    handler_state = jump_to_exception_handler(state, ctx, instr.offset, exc)
    if handler_state is not None:
        return OpcodeResult.continue_with(handler_state)
    issue = Issue(
        kind=IssueKind.TYPE_ERROR,
        message=f"Possible TypeError: {message}",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)


def _lower_concrete_built_slice(
    container: object,
    carrier: SymbolicValue,
    constraints: list[z3.BoolRef],
    pc: int,
) -> LoweredValue | None:
    """Lower a subscript read when slice bounds are concrete on this path."""
    concrete_slice = materialize_concrete_slice(carrier, constraints)
    if concrete_slice is None:
        return None
    if isinstance(container, SymbolicList):
        retained = slice_concrete_backed_sequence(container, concrete_slice)
        if retained is None:
            return None
        if getattr(retained, "_type", None) == "tuple":
            return LoweredValue(retained)
        concrete_items = retained.concrete_items
        if concrete_items is None:
            return None
        items = cast("list[StackValue]", concrete_items)
        built = CollectionLowerer(pc).build_list(items)
        return LoweredValue(
            built.handle,
            heap_updates=[*built.heap_updates, (built.handle.address, built.storage)],
        )
    if isinstance(container, (list, tuple, str, bytes)):
        concrete_container = cast("list[object] | tuple[object, ...] | str | bytes", container)
        return LoweredValue(to_stack_value(concrete_container[concrete_slice]))
    return None


def _is_certified_mixed_list_index(index: StackValue) -> bool:
    """Return whether the index is a retained native slice stop component."""
    return isinstance(index, SymbolicValue) and index.model_name == "slice.indices.stop"


def _path_already_inconclusive(state: VMState, constraints: list[z3.BoolRef]) -> bool:
    """Return whether the current path prefix is already marked solver-inconclusive."""
    return (
        state.last_inconclusive_feasibility_len >= 0
        and state.last_inconclusive_feasibility_len == len(constraints)
    )


def _possible_uncaught_subscript_errors(
    state: VMState,
    real_container: object,
    exception_condition: z3.BoolRef,
    feasibility_result: SolverResult,
    *,
    report_list_index_error: bool,
) -> list[Issue]:
    """Emit possible uncaught subscript issues only after SAT feasibility proof."""
    if not feasibility_result.is_sat:
        return []
    constraints = [*state.path_constraints, exception_condition]
    if isinstance(real_container, (SymbolicDict, dict)):
        return [
            Issue(
                kind=IssueKind.KEY_ERROR,
                message="Possible KeyError: subscript key may be missing",
                constraints=constraints,
                model=get_model(constraints),
                pc=state.pc,
            )
        ]
    if not report_list_index_error or not isinstance(real_container, SymbolicList):
        return []
    return [
        Issue(
            kind=IssueKind.INDEX_ERROR,
            message="Possible IndexError: list index out of range",
            constraints=constraints,
            model=get_model(constraints),
            pc=state.pc,
        )
    ]


def _single_feasible_concrete_list_item(
    container: object,
    index: StackValue,
    state: VMState,
) -> LoweredValue | None:
    """Return a lowered item when exactly one concrete list index is feasible."""
    if not isinstance(container, SymbolicList) or not isinstance(index, SymbolicValue):
        return None
    concrete_items = container.concrete_items
    if not concrete_items:
        return None

    concrete_index = concrete_int_index(index)
    if concrete_index is not None:
        try:
            return LoweredValue(to_stack_value(concrete_items[concrete_index]))
        except IndexError:
            return None

    constraints = state.path_constraints.to_list()
    known_prefix_len = known_sat_prefix_len_for_state(state)
    idx = index.z3_int
    length = len(concrete_items)
    item_index = _fixed_index_from_exact_constraints(idx, length, constraints)
    if item_index is not None:
        if check_sat_result(constraints, known_sat_prefix_len=known_prefix_len).is_sat:
            return LoweredValue(to_stack_value(concrete_items[item_index]))
        return None

    out_of_bounds = z3.Or(idx < -length, idx >= length)
    out_of_bounds_literal = exact_bool_literal(out_of_bounds)
    if out_of_bounds_literal is True or (
        out_of_bounds_literal is None
        and path_is_sat([*constraints, out_of_bounds], known_sat_prefix_len=known_prefix_len)
    ):
        return None

    if length == 1:
        return LoweredValue(to_stack_value(concrete_items[0]))

    in_bounds_constraints = [*constraints, idx >= -length, idx < length]
    if item_index is None:
        if _concrete_items_have_precise_integer_channel(concrete_items):
            return None
        model = get_model(in_bounds_constraints)
        if model is None:
            return None

        modeled_index = _model_int(model, idx)
        if modeled_index is None:
            return None

        item_index = _normalize_concrete_index(modeled_index, length)
        if item_index is None:
            return None

    other_item_possible = z3.And(
        idx >= -length,
        idx < length,
        z3.Not(_normalized_index_alias(idx, item_index, length)),
    )
    other_item_literal = exact_bool_literal(other_item_possible)
    if other_item_literal is True or (
        other_item_literal is None
        and path_is_sat([*constraints, other_item_possible], known_sat_prefix_len=known_prefix_len)
    ):
        return None

    return LoweredValue(to_stack_value(concrete_items[item_index]))


def _concrete_items_have_precise_integer_channel(concrete_items: list[object]) -> bool:
    """Return whether symbolic array fallback preserves all retained item payloads."""
    for item in concrete_items:
        if isinstance(item, bool | int):
            continue
        if isinstance(item, SymbolicValue) and item.affinity_type in {"int", "bool"}:
            continue
        return False
    return True


def _fixed_index_from_exact_constraints(
    index: z3.ArithRef, length: int, constraints: list[z3.BoolRef]
) -> int | None:
    """Return an exact constrained item index without model extraction."""
    candidates: set[int] = set()
    for constraint in reversed(constraints):
        candidate = _exact_index_equality_candidate(index, constraint, length)
        if candidate is not None:
            candidates.add(candidate)
            if len(candidates) > 1:
                return None
    if len(candidates) == 1:
        return candidates.pop()
    return None


def _exact_index_equality_candidate(
    index: z3.ArithRef, constraint: z3.BoolRef, length: int
) -> int | None:
    """Extract an item index from constraints shaped exactly like ``index == k``."""
    if not z3.is_eq(constraint) or constraint.num_args() != 2:
        return None
    left = constraint.arg(0)
    right = constraint.arg(1)
    if safe_z3_eq(left, index) and z3.is_int_value(right):
        return _normalize_concrete_index(right.as_long(), length)
    if safe_z3_eq(right, index) and z3.is_int_value(left):
        return _normalize_concrete_index(left.as_long(), length)
    return None


def _model_int(model: z3.ModelRef, expr: z3.ArithRef) -> int | None:
    """Extract an integer witness from a model without treating failure as proof."""
    try:
        value = model.eval(expr, model_completion=True)
    except z3.Z3Exception:
        return None
    if not z3.is_int_value(value):
        return None
    return value.as_long()


def _normalize_concrete_index(index: int, length: int) -> int | None:
    """Normalize a concrete CPython list index or return ``None`` out of bounds."""
    normalized = index if index >= 0 else index + length
    if 0 <= normalized < length:
        return normalized
    return None


def _normalized_index_alias(index: z3.ArithRef, item_index: int, length: int) -> z3.BoolRef:
    """Return the raw index values that select one normalized list item."""
    negative_index = item_index - length
    if negative_index < 0:
        return z3.Or(index == item_index, index == negative_index)
    return index == item_index
