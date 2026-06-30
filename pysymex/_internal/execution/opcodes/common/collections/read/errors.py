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

"""Subscript read exception routing and issue construction."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.exceptions.policy import concrete_exception
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.collections.fallbacks import (
    CollectionFallbackEvents,
)
from pysymex._internal.execution.opcodes.common.collections.subscript.shared import (
    subscript_exception_result,
)
from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow

if TYPE_CHECKING:
    import dis
    from collections.abc import Callable

    import z3

    from pysymex._internal.core.solver.engine.results import SolverResult
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def none_list_index_type_error(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Route ``None`` list indexing to a handler or ``TypeError`` issue."""
    return subscript_exception_result(
        instr,
        state,
        ctx,
        IssueKind.TYPE_ERROR,
        TypeError("list indices must be integers or slices, not NoneType"),
    )


def unsupported_dict_key_hashing(state: VMState, *, reason: str) -> OpcodeResult:
    """Advance with explicit degradation for unsupported dict read key hashing."""
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


def subscript_read_exception_handler_state(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    real_container: object,
) -> VMState | None:
    """Return a CPython-shaped handler state for a possible read-side subscript error."""
    exc_type: type[BaseException]
    message: str
    if isinstance(real_container, (SymbolicDict, dict)):
        exc_type = KeyError
        message = "subscript key may be missing"
    elif isinstance(real_container, (SymbolicList, SymbolicTuple, list, tuple, str, bytes)):
        exc_type = IndexError
        message = "subscript index may be out of range"
    else:
        exc_type = TypeError
        message = f"{type(real_container).__name__!s} is not subscriptable"
    exc = concrete_exception(exc_type, message, state=state, instr=instr)
    return ExceptionFlow.jump_to_handler(state, ctx, instr.offset, exc)


def is_certified_mixed_list_index(index: StackValue) -> bool:
    """Return whether the index is a retained native slice stop component."""
    return isinstance(index, SymbolicValue) and index.model_name == "slice.indices.stop"


def path_already_inconclusive(state: VMState, constraints: list[z3.BoolRef]) -> bool:
    """Return whether the current path prefix is already marked solver-inconclusive."""
    return (
        state.last_inconclusive_feasibility_len >= 0
        and state.last_inconclusive_feasibility_len == len(constraints)
    )


def possible_uncaught_subscript_errors(
    state: VMState,
    real_container: object,
    exception_condition: z3.BoolRef,
    feasibility_result: SolverResult,
    *,
    report_list_index_error: bool,
    get_model_fn: Callable[..., z3.ModelRef | None],
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
                model=get_model_fn(constraints),
                pc=state.pc,
            ),
        ]
    if not report_list_index_error or not isinstance(real_container, (SymbolicList, SymbolicTuple)):
        return []
    container_name = "tuple" if isinstance(real_container, SymbolicTuple) else "list"
    return [
        Issue(
            kind=IssueKind.INDEX_ERROR,
            message=f"Possible IndexError: {container_name} index out of range",
            constraints=constraints,
            model=get_model_fn(constraints),
            pc=state.pc,
        ),
    ]
