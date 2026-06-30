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
back to :class:`~pysymex._internal.execution.opcodes.common.lowering.CollectionLowerer` or
havoc with explicit degradation tags. Store/delete live in
:mod:`pysymex._internal.execution.opcodes.common.collections.subscript`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.constraints.literals import exact_bool_literal
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.engine.queries import (
    check_sat_result,
    check_sat_result_with_dependency_slice,
    get_model,
)
from pysymex._internal.core.solver.engine.results import SolverResult
from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.checks import is_type_subscription
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.slices import (
    UNSUPPORTED_SLICE_ABSTRACTION,
    extract_slice_bounds,
)
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.generic_aliases import modeled_runtime_generic_alias
from pysymex._internal.core.types.havoc import HavocValue
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.feasibility.unknowns import (
    FeasibilityBranch,
    UnknownFeasibilitySpec,
    may_be_feasible,
    merge_degraded_passes,
    terminal_result_with_events,
    unknown_feasibility_events,
)
from pysymex._internal.execution.opcodes.common.collections.fallbacks import (
    CollectionFallbackEvents,
)
from pysymex._internal.execution.opcodes.common.collections.hashability import (
    concrete_unhashable_type_error,
    requires_symbolic_object_hashing,
)
from pysymex._internal.execution.opcodes.common.collections.protocols.index import (
    dispatch_built_slice_index_protocol,
    route_modeled_index,
)
from pysymex._internal.execution.opcodes.common.collections.protocols.slices import (
    dispatch_retained_slice_zero_step,
)
from pysymex._internal.execution.opcodes.common.collections.protocols.subscript import (
    route_modeled_subscript,
)
from pysymex._internal.execution.opcodes.common.collections.read.errors import (
    is_certified_mixed_list_index,
    none_list_index_type_error,
    path_already_inconclusive,
    possible_uncaught_subscript_errors,
    subscript_read_exception_handler_state,
    unsupported_dict_key_hashing,
)
from pysymex._internal.execution.opcodes.common.collections.read.lists import (
    single_feasible_concrete_list_item,
)
from pysymex._internal.execution.opcodes.common.collections.read.slices import (
    lower_concrete_built_slice,
)
from pysymex._internal.execution.opcodes.common.collections.stack_ops import CollectionStackOps
from pysymex._internal.execution.opcodes.common.collections.subscript.shared import (
    subscript_exception_result,
)
from pysymex._internal.execution.opcodes.common.lowering.collections.lowerer import (
    CollectionLowerer,
)
from pysymex._internal.execution.opcodes.common.lowering.types import (
    UNSUPPORTED_SUBSCRIPT_ABSTRACTION,
    LoweredValue,
)
from pysymex._internal.execution.opcodes.common.satisfiability import PathSatisfiability

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.fallback.types import FallbackEvent
    from pysymex._internal.typing.protocols import StackValue

SUBSCRIPT_READ_FEASIBILITY_UNKNOWN = "subscript_read_feasibility_unknown"
path_is_sat = PathSatisfiability.is_sat
_SUBSCRIPT_READ_FEASIBILITY_SPEC = UnknownFeasibilitySpec(
    label=SUBSCRIPT_READ_FEASIBILITY_UNKNOWN,
    owner="execution.opcodes.collections",
    subject="subscript read exception",
)


def _possible_havoc_mapping_key_errors(state: VMState, container: HavocValue) -> list[Issue]:
    """Return possible ``KeyError`` evidence for subscript reads on havoc mappings.

    A havoc container means the producer lost precise provenance, not that mapping
    lookup is safe. If the current path still permits the havoc value to be a
    dictionary, preserve the missing-key bug path instead of silently turning
    ``obj[key]`` into an unconstrained success value.
    """
    constraints = [*state.path_constraints.to_list(), container.is_dict]
    if not check_sat_result(constraints).is_sat:
        return []
    return [
        Issue(
            kind=IssueKind.KEY_ERROR,
            message="Possible KeyError: subscript key may be missing",
            constraints=constraints,
            model=get_model(constraints),
            pc=state.pc,
            confidence=0.1,
        ),
    ]


def _handle_havoc_subscript(state: VMState, container: HavocValue) -> OpcodeResult:
    """Return the degraded fallback for subscripting an imprecise havoc container."""
    fallback_event = CollectionFallbackEvents.unsupported_subscript(
        state=state,
        reason="havoc container subscript produces an unconstrained value",
    )
    issues = _possible_havoc_mapping_key_errors(state, container)
    ret, tc = HavocValue.havoc(f"{getattr(container, 'name', 'havoc')}[{state.pc}]")
    state = state.push(ret)
    state = state.add_constraint(tc)
    state = state.advance_pc()
    return OpcodeResult(
        new_states=[state],
        issues=issues,
        degraded_passes=[UNSUPPORTED_SUBSCRIPT_ABSTRACTION],
        fallback_events=[fallback_event],
    )


def _handle_early_subscript_dispatch(
    state: VMState,
    ctx: OpcodeDispatcher,
    container: StackValue,
    index: StackValue,
) -> OpcodeResult | None:
    """Handle protocol, havoc, and generic-alias subscript paths before lowering."""
    modeled_result = route_modeled_subscript(state, ctx, container, "__getitem__", [index])
    if modeled_result is not None:
        return modeled_result

    if isinstance(container, HavocValue):
        return _handle_havoc_subscript(state, container)

    runtime_generic_alias = modeled_runtime_generic_alias(container, index, state.pc)
    if runtime_generic_alias is not None:
        state = state.push(runtime_generic_alias)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    if is_type_subscription(container):
        result, constraint = SymbolicValue.symbolic(f"generic_{state.pc}")
        state = state.add_constraint(constraint)
        state = state.push(result)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    return None


def _resolve_subscript_container(
    container: StackValue,
    index: StackValue,
    state: VMState,
) -> object:
    """Resolve runtime wrapper objects and promote retained string slices."""
    real_container = SymbolicObject.resolve_runtime_container(container, state)
    if isinstance(real_container, SymbolicValue) and extract_slice_bounds(index) is not None:
        if (
            z3.is_true(simplify_expr(real_container.is_str))
            or real_container.affinity_type == "str"
        ):
            return SymbolicString(_name=real_container.name, _unified=real_container)
    return real_container


def _validate_subscript_key(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    real_container: object,
    index: StackValue,
) -> OpcodeResult | None:
    """Reject definite key/index errors before generic collection lowering."""
    if isinstance(index, SymbolicNoneType) and isinstance(real_container, (SymbolicList, list)):
        return none_list_index_type_error(instr, state, ctx)
    if not isinstance(real_container, (SymbolicDict, dict)):
        return None

    type_error_message = concrete_unhashable_type_error(index)
    if type_error_message is not None:
        return subscript_exception_result(
            instr,
            state,
            ctx,
            IssueKind.TYPE_ERROR,
            TypeError(type_error_message),
        )
    if requires_symbolic_object_hashing(index):
        return unsupported_dict_key_hashing(
            state,
            reason="BINARY_SUBSCR dict key requires symbolic or modeled object hashing",
        )
    return None


def _handle_sequence_protocol_subscript(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    container: StackValue,
    real_container: object,
    index: StackValue,
) -> OpcodeResult | None:
    """Handle sequence slice and index protocols that bypass generic lowering."""
    if not isinstance(
        real_container,
        (SymbolicList, SymbolicTuple, SymbolicString, SymbolicBytes, list, tuple, str, bytes),
    ):
        return None

    sequence_container = cast(
        "SymbolicList | SymbolicTuple | SymbolicString | SymbolicBytes | list[object] | tuple[object, ...] | str | bytes",
        real_container,
    )
    if isinstance(index, SymbolicValue):
        slice_result = dispatch_built_slice_index_protocol(state, ctx, [container], index)
        if slice_result is not None:
            return slice_result
        if extract_slice_bounds(index) is not None:
            return _handle_retained_slice_subscript(instr, state, ctx, sequence_container, index)
    return route_modeled_index(state, ctx, [container], index)


def _handle_retained_slice_subscript(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    sequence_container: (
        SymbolicList
        | SymbolicTuple
        | SymbolicString
        | SymbolicBytes
        | list[object]
        | tuple[object, ...]
        | str
        | bytes
    ),
    index: SymbolicValue,
) -> OpcodeResult:
    """Lower a retained built-slice value against a concrete or symbolic sequence."""
    zero_step_result = dispatch_retained_slice_zero_step(instr, state, ctx, index)
    if zero_step_result is not None:
        return zero_step_result
    lowered = lower_concrete_built_slice(
        sequence_container,
        index,
        state.path_constraints.to_list(),
        state.pc,
    )
    if lowered is None:
        return OpcodeResult(
            new_states=[],
            issues=[],
            degraded_passes=[UNSUPPORTED_SLICE_ABSTRACTION],
            fallback_events=[
                CollectionFallbackEvents.unsupported_slice(
                    state=state,
                    reason="retained slice bounds could not be concretely lowered",
                ),
            ],
            terminal=True,
        )
    state = CollectionStackOps.apply_heap_updates(state, lowered.heap_updates)
    state = state.push(lowered.value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _lower_subscript(real_container: object, index: StackValue, state: VMState) -> LoweredValue:
    """Produce a lowered value, preferring exact concrete-list fast paths."""
    precise_concrete = single_feasible_concrete_list_item(
        real_container,
        index,
        state,
        path_is_sat_fn=path_is_sat,
        check_sat_result_fn=check_sat_result,
        get_model_fn=get_model,
    )
    if precise_concrete is not None:
        return precise_concrete
    return CollectionLowerer(state.pc).lower_subscript(real_container, index)


def _check_subscript_exception_feasibility(
    state: VMState,
    exc_cond: z3.BoolRef,
    exc_literal: bool | None,
) -> SolverResult:
    """Query whether the lowered subscript exception branch is feasible."""
    path_constraints = state.path_constraints.to_list()
    if exc_literal is True and path_already_inconclusive(state, path_constraints):
        return SolverResult.unknown()
    return check_sat_result_with_dependency_slice(
        path_constraints,
        exc_cond,
        known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
    )


def _check_subscript_success_feasibility(
    state: VMState,
    not_exc: z3.BoolRef,
) -> SolverResult:
    """Query whether the lowered subscript success branch is feasible."""
    not_exc_literal = exact_bool_literal(not_exc)
    if not_exc_literal is True:
        return SolverResult.sat(None)
    if not_exc_literal is False:
        return SolverResult.unsat()
    return check_sat_result_with_dependency_slice(
        state.path_constraints.to_list(),
        not_exc,
        known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
    )


def _fallback_events_for_lowered_exception(
    state: VMState,
    lowered: LoweredValue,
    exc_result: SolverResult,
    success_result: SolverResult,
) -> tuple[list[FallbackEvent], list[str]]:
    """Build degradation metadata for a lowered subscript with feasibility evidence."""
    fallback_events = [
        *CollectionFallbackEvents.for_degraded_passes(
            state=state,
            degraded_passes=lowered.degraded_passes,
            reason="subscript lowering required a collection abstraction",
        ),
        *unknown_feasibility_events(
            state=state,
            spec=_SUBSCRIPT_READ_FEASIBILITY_SPEC,
            branches=[
                FeasibilityBranch("exception", exc_result),
                FeasibilityBranch("success", success_result),
            ],
        ),
    ]
    return fallback_events, merge_degraded_passes(lowered.degraded_passes, fallback_events)


def _success_state_for_lowered_value(
    state: VMState,
    lowered: LoweredValue,
    not_exc: z3.BoolRef | None = None,
) -> VMState:
    """Apply lowered constraints, heap updates, stack push, and PC advance."""
    if not_exc is not None:
        state = state.add_constraint(not_exc)
    state = CollectionStackOps.add_lowered_constraints(state, lowered.constraints)
    state = CollectionStackOps.apply_heap_updates(state, lowered.heap_updates)
    state = state.push(lowered.value)
    return state.advance_pc()


def _result_with_successful_lowered_subscript(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    real_container: object,
    index: StackValue,
    lowered: LoweredValue,
    exc_cond: z3.BoolRef,
    exc_result: SolverResult,
    fallback_events: list[FallbackEvent],
    degraded_passes: list[str],
    report_mixed_list_error: bool,
) -> OpcodeResult:
    """Return a result when the success side of a lowered subscript may run."""
    handler_pc = ctx.find_exception_handler(instr.offset)
    success_state = _success_state_for_lowered_value(state.fork(), lowered, z3.Not(exc_cond))
    if handler_pc is None:
        issues = possible_uncaught_subscript_errors(
            state,
            real_container,
            exc_cond,
            exc_result,
            report_list_index_error=(
                isinstance(real_container, SymbolicTuple)
                or report_mixed_list_error
                or is_certified_mixed_list_index(index)
            ),
            get_model_fn=get_model,
        )
        return OpcodeResult(
            new_states=[success_state],
            issues=issues,
            degraded_passes=degraded_passes,
            fallback_events=fallback_events,
        )

    error_state = subscript_read_exception_handler_state(
        instr,
        state.fork().add_constraint(exc_cond),
        ctx,
        real_container,
    )
    if error_state is None:
        return OpcodeResult.continue_with(
            success_state,
            degraded_passes=degraded_passes,
            fallback_events=fallback_events,
        )
    return OpcodeResult.branch(
        [success_state, error_state],
        degraded_passes=degraded_passes,
        fallback_events=fallback_events,
    )


def _result_without_successful_lowered_subscript(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    real_container: object,
    exc_cond: z3.BoolRef,
    exc_result: SolverResult,
    fallback_events: list[FallbackEvent],
    degraded_passes: list[str],
) -> OpcodeResult:
    """Return an exception-only lowered subscript result."""
    handler_pc = ctx.find_exception_handler(instr.offset)
    if handler_pc is None:
        issues = possible_uncaught_subscript_errors(
            state,
            real_container,
            exc_cond,
            exc_result,
            report_list_index_error=True,
            get_model_fn=get_model,
        )
        if issues:
            return OpcodeResult.error(
                issues[0],
                degraded_passes=degraded_passes,
                fallback_events=fallback_events,
            )
    handler_state = subscript_read_exception_handler_state(
        instr,
        state.add_constraint(exc_cond),
        ctx,
        real_container,
    )
    if handler_state is None:
        return terminal_result_with_events(fallback_events)
    return OpcodeResult.continue_with(
        handler_state,
        degraded_passes=degraded_passes,
        fallback_events=fallback_events,
    )


def _handle_lowered_exception_condition(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    real_container: object,
    index: StackValue,
    lowered: LoweredValue,
    report_mixed_list_error: bool,
) -> OpcodeResult | None:
    """Branch or report errors for a lowered subscript exception condition."""
    exc_cond = lowered.exception_condition
    exc_literal = exact_bool_literal(exc_cond)
    if exc_literal is False:
        return None

    exc_result = _check_subscript_exception_feasibility(state, exc_cond, exc_literal)
    if exc_result.is_unsat:
        return OpcodeResult.terminate() if exc_literal is True else None

    not_exc = z3.Not(exc_cond)
    success_result = _check_subscript_success_feasibility(state, not_exc)
    fallback_events, degraded_passes = _fallback_events_for_lowered_exception(
        state,
        lowered,
        exc_result,
        success_result,
    )
    if may_be_feasible(success_result):
        return _result_with_successful_lowered_subscript(
            instr,
            state,
            ctx,
            real_container,
            index,
            lowered,
            exc_cond,
            exc_result,
            fallback_events,
            degraded_passes,
            report_mixed_list_error,
        )
    return _result_without_successful_lowered_subscript(
        instr,
        state,
        ctx,
        real_container,
        exc_cond,
        exc_result,
        fallback_events,
        degraded_passes,
    )


def _continue_with_lowered_subscript(state: VMState, lowered: LoweredValue) -> OpcodeResult:
    """Continue after a lowered subscript whose exception condition is impossible."""
    fallback_events = CollectionFallbackEvents.for_degraded_passes(
        state=state,
        degraded_passes=lowered.degraded_passes,
        reason="subscript lowering required a collection abstraction",
    )
    state = _success_state_for_lowered_value(state, lowered)
    return OpcodeResult.continue_with(
        state,
        degraded_passes=lowered.degraded_passes,
        fallback_events=fallback_events,
    )


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
    CollectionStackOps.require_depth(state, instr, 2, "BINARY_SUBSCR container and index")
    index = state.pop()
    container = state.pop()

    early_result = _handle_early_subscript_dispatch(state, ctx, container, index)
    if early_result is not None:
        return early_result

    real_container = _resolve_subscript_container(container, index, state)
    validation_result = _validate_subscript_key(instr, state, ctx, real_container, index)
    if validation_result is not None:
        return validation_result

    sequence_result = _handle_sequence_protocol_subscript(
        instr,
        state,
        ctx,
        container,
        real_container,
        index,
    )
    if sequence_result is not None:
        return sequence_result

    lowered = _lower_subscript(real_container, index, state)
    exception_result = _handle_lowered_exception_condition(
        instr,
        state,
        ctx,
        real_container,
        index,
        lowered,
        report_mixed_list_error,
    )
    if exception_result is not None:
        return exception_result
    return _continue_with_lowered_subscript(state, lowered)
