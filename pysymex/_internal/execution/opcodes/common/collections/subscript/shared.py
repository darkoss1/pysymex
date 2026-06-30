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

"""Shared helpers for ``STORE_SUBSCR`` and ``DELETE_SUBSCR`` mutation paths."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.effects.events import WriteEvent, WriteKind
from pysymex._internal.core.exceptions.policy import from_native_exception, index_error
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.engine.queries import check_sat_result_with_dependency_slice
from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.types.containers.dict.keys import symbolic_storage_key
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.feasibility.unknowns import (
    FeasibilityBranch,
    UnknownFeasibilitySpec,
    degraded_passes_from_events,
    may_be_feasible,
    terminal_result_with_events,
    unknown_feasibility_events,
)
from pysymex._internal.execution.opcodes.common.collections.fallbacks import (
    CollectionFallbackEvents,
)
from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow

if TYPE_CHECKING:
    import dis
    from collections.abc import Callable

    from pysymex._internal.core.effects.locations import WriteLocation
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.containers.lists import SymbolicList
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue

SYMBOLIC_LIST_MUTATION_FEASIBILITY_UNKNOWN = "symbolic_list_mutation_feasibility_unknown"
_SYMBOLIC_LIST_MUTATION_FEASIBILITY_SPEC = UnknownFeasibilitySpec(
    label=SYMBOLIC_LIST_MUTATION_FEASIBILITY_UNKNOWN,
    owner="execution.opcodes.collections",
    subject="symbolic list mutation",
)


def replace_direct_container_aliases(
    state: VMState,
    old_container: object,
    new_container: StackValue,
) -> VMState:
    """Refresh symbolic container aliases and source carriers after mutation."""
    from pysymex._internal.execution.opcodes.common.functions.classes.instances.aliases import (
        propagate_container_mutation_reference,
    )

    return propagate_container_mutation_reference(state, old_container, new_container)


def record_item_write(state: VMState, location: WriteLocation, instr: dis.Instruction) -> VMState:
    """Record a successful modeled item write or deletion."""
    return state.record_write_event(
        WriteEvent(WriteKind.ITEM, location.name, state.pc, location.precise, instr.opname),
    )


def subscript_exception_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    kind: IssueKind,
    exc: Exception,
) -> OpcodeResult:
    """Route a subscript exception to a handler or emit a possible-issue report."""
    modeled_exc = from_native_exception(exc, state=state, instr=instr)
    handler_state = ExceptionFlow.jump_to_handler(state, ctx, instr.offset, modeled_exc)
    if handler_state is not None:
        return OpcodeResult.continue_with(handler_state)

    issue = Issue(
        kind=kind,
        message=f"Possible {type(exc).__name__}: {exc}",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)


def concrete_dict_key(key: StackValue) -> object:
    """Return a concrete hash key for definite symbolic scalar keys."""
    if isinstance(key, SymbolicString) and z3.is_string_value(key.z3_str):
        return key.z3_str.as_string()
    if isinstance(key, SymbolicValue):
        if key.value is not None:
            return key.value
        if z3.is_true(simplify_expr(key.is_none)):
            return None
        if z3.is_string_value(key.z3_str):
            return key.z3_str.as_string()
        if z3.is_int_value(key.z3_int):
            return key.z3_int.as_long()
    return key


def symbolic_dict_subscript_keys(key: StackValue) -> tuple[object, SymbolicString]:
    """Return mutation and storage keys for modeled dictionary subscript operations."""
    if isinstance(key, SymbolicString):
        return key, key
    if isinstance(key, SymbolicValue) and key.value is None:
        storage_key = SymbolicString(_name=key.name, _unified=key)
        return storage_key, storage_key
    return key, symbolic_storage_key(key)


def unsupported_dict_hashing(state: VMState, *, reason: str) -> OpcodeResult:
    """Advance with explicit degradation for unsupported modeled dict key hashing."""
    fallback_events = CollectionFallbackEvents.for_degraded_passes(
        state=state,
        degraded_passes=[CollectionFallbackEvents.UNSUPPORTED_HASHED_COLLECTION_PROTOCOL],
        reason=reason,
    )
    state = state.advance_pc()
    return OpcodeResult.continue_with(
        state,
        degraded_passes=[CollectionFallbackEvents.UNSUPPORTED_HASHED_COLLECTION_PROTOCOL],
        fallback_events=fallback_events,
    )


def symbolic_list_mutation_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    container: SymbolicList,
    index: SymbolicValue,
    apply_success: Callable[[VMState], VMState],
) -> OpcodeResult:
    """Fork symbolic list mutation into in-bounds success and out-of-bounds error paths."""
    in_bounds = _symbolic_list_index_in_bounds(container, index)
    out_of_bounds = _symbolic_list_index_out_of_bounds(container, index)
    base_constraints = state.path_constraints.to_list()
    known_prefix = StateConstraints.known_sat_prefix_len(state)
    in_bounds_result = check_sat_result_with_dependency_slice(
        base_constraints,
        in_bounds,
        known_sat_prefix_len=known_prefix,
    )
    out_of_bounds_result = check_sat_result_with_dependency_slice(
        base_constraints,
        out_of_bounds,
        known_sat_prefix_len=known_prefix,
    )
    fallback_events = unknown_feasibility_events(
        state=state,
        spec=_SYMBOLIC_LIST_MUTATION_FEASIBILITY_SPEC,
        branches=[
            FeasibilityBranch("in_bounds", in_bounds_result),
            FeasibilityBranch("out_of_bounds", out_of_bounds_result),
        ],
    )
    degraded_passes = degraded_passes_from_events(fallback_events)

    success_state: VMState | None = None
    if may_be_feasible(in_bounds_result):
        success_state = apply_success(state.fork().add_constraint(in_bounds)).advance_pc()

    if may_be_feasible(out_of_bounds_result):
        error_state = _symbolic_list_mutation_error_handler_state(
            instr,
            state.fork().add_constraint(out_of_bounds),
            ctx,
        )
        if error_state is not None:
            if success_state is not None:
                return OpcodeResult.branch(
                    [success_state, error_state],
                    degraded_passes=degraded_passes,
                    fallback_events=fallback_events,
                )
            return OpcodeResult.continue_with(
                error_state,
                degraded_passes=degraded_passes,
                fallback_events=fallback_events,
            )
        if out_of_bounds_result.is_sat:
            issue = Issue(
                kind=IssueKind.INDEX_ERROR,
                message="Possible IndexError: list assignment index out of range",
                constraints=[*base_constraints, out_of_bounds],
                model=out_of_bounds_result.model,
                pc=state.pc,
            )
            if success_state is not None:
                return OpcodeResult(
                    new_states=[success_state],
                    issues=[issue],
                    degraded_passes=degraded_passes,
                    fallback_events=fallback_events,
                )
            return OpcodeResult.error(
                issue,
                degraded_passes=degraded_passes,
                fallback_events=fallback_events,
            )

    if success_state is not None:
        return OpcodeResult.continue_with(
            success_state,
            degraded_passes=degraded_passes,
            fallback_events=fallback_events,
        )
    return terminal_result_with_events(fallback_events)


def _symbolic_list_index_in_bounds(
    container: SymbolicList,
    index: SymbolicValue,
) -> z3.BoolRef:
    """Return the CPython valid-index condition for list mutation."""
    return z3.And(
        index.is_int,
        index.z3_int >= -container.z3_len,
        index.z3_int < container.z3_len,
    )


def _symbolic_list_index_out_of_bounds(
    container: SymbolicList,
    index: SymbolicValue,
) -> z3.BoolRef:
    """Return the CPython out-of-range condition for list mutation."""
    return z3.And(
        index.is_int,
        z3.Or(
            index.z3_int < -container.z3_len,
            index.z3_int >= container.z3_len,
        ),
    )


def _symbolic_list_mutation_error_handler_state(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> VMState | None:
    """Route symbolic list mutation ``IndexError`` through an exception handler."""
    exc = index_error("list assignment index out of range", state=state, instr=instr)
    return ExceptionFlow.jump_to_handler(state, ctx, instr.offset, exc)
