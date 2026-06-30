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

"""Continuation support for ``iter(callable, sentinel)`` loops."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.feasibility.branching import branch_feasible
from pysymex._internal.execution.opcodes.common.control.iteration.exit import (
    push_for_iter_exit_sentinel,
)
from pysymex._internal.execution.opcodes.common.functions.protocol.fallbacks import (
    ITERATION_PROTOCOL_UNAVAILABLE_REASON,
    UNSUPPORTED_ITERATION_PROTOCOL,
    flag_unsupported_iteration,
)
from pysymex._internal.execution.opcodes.common.lowering.comparison import ComparisonLowerer

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.core.types.containers.callable_iterators import CallableSentinelIterator
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue

CALLABLE_SENTINEL_ITER_PROTOCOL = "__callable_sentinel_iter__"


@dataclass(frozen=True, slots=True)
class CallableSentinelStep:
    """Caller-loop state retained while the producer callable executes."""

    iterator: CallableSentinelIterator
    target_index: int
    continue_pc: int
    push_exit_sentinel: bool = True
    pop_exit_iterator: bool = False


def dispatch_callable_sentinel_iteration(
    state: VMState,
    ctx: OpcodeDispatcher,
    iterator: CallableSentinelIterator,
    *,
    target_index: int,
    push_exit_sentinel: bool = True,
    pop_exit_iterator: bool = False,
) -> OpcodeResult | None:
    """Enter the callable producer for one ``FOR_ITER`` step."""
    from pysymex._internal.execution.calls.interprocedural.entry import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        iterator.producer,
        [],
        {},
        protocol_method=CALLABLE_SENTINEL_ITER_PROTOCOL,
        resume_pc=state.pc,
        protocol_retained_operand=cast(
            "StackValue",
            CallableSentinelStep(
                iterator=iterator,
                target_index=target_index,
                continue_pc=state.pc + 1,
                push_exit_sentinel=push_exit_sentinel,
                pop_exit_iterator=pop_exit_iterator,
            ),
        ),
    )
    if result is not None:
        return result
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_ITERATION_PROTOCOL],
        fallback_events=[
            flag_unsupported_iteration(
                state=state,
                reason=ITERATION_PROTOCOL_UNAVAILABLE_REASON,
            ),
        ],
        terminal=True,
    )


def finish_callable_sentinel_return(
    frame: CallFrame,
    return_value: StackValue | None,
    state: VMState,
) -> OpcodeResult | None:
    """Route producer return to either loop exit or the next loop body item."""
    retained = _retain_callable_sentinel(frame)
    if retained is None:
        return None
    item = return_value if return_value is not None else SymbolicNoneType("callable_iter_None")
    comparison, type_error_cond = ComparisonLowerer(state.pc).lower(
        item,
        retained.iterator.sentinel,
        "==",
    )
    if not z3.is_false(simplify_expr(type_error_cond)):
        return _unsupported_iteration(state)

    equal = simplify_expr(comparison.z3_bool)
    not_equal = z3.Not(equal)
    branches: list[VMState] = []
    known_prefix = StateConstraints.known_sat_prefix_len(state)

    if branch_feasible(
        state.path_constraints,
        not_equal,
        known_sat_prefix_len=known_prefix,
    ):
        continue_state = state.fork().add_constraint(not_equal)
        if continue_state.stack:
            continue_state.pop()
        continue_state = continue_state.push(retained.iterator.advance())
        continue_state = continue_state.push(item)
        continue_state.depth = max(0, continue_state.depth - 1)
        branches.append(continue_state.set_pc(retained.continue_pc))

    if branch_feasible(
        state.path_constraints,
        equal,
        known_sat_prefix_len=known_prefix,
    ):
        exit_state = state.fork().add_constraint(equal)
        exit_state = push_for_iter_exit_sentinel(
            exit_state,
            name="callable_iter_exhausted",
            push_sentinel=retained.push_exit_sentinel,
            pop_iterator=retained.pop_exit_iterator,
        )
        exit_state.depth = max(0, exit_state.depth - 1)
        branches.append(exit_state.set_pc(retained.target_index))

    if not branches:
        return OpcodeResult.terminate()
    return OpcodeResult.branch(branches)


def finish_callable_sentinel_stop(
    frame: CallFrame,
    state: VMState,
    exc: StackValue,
) -> VMState | None:
    """Convert producer ``StopIteration`` into normal loop exhaustion."""
    retained = _retain_callable_sentinel(frame)
    if retained is None or not _is_stop_iteration(exc):
        return None
    return push_for_iter_exit_sentinel(
        state,
        name="callable_iter_exhausted",
        push_sentinel=retained.push_exit_sentinel,
        pop_iterator=retained.pop_exit_iterator,
    ).set_pc(retained.target_index)


def handle_callable_sentinel_exception(
    state: VMState,
    exception_name: str,
) -> bool:
    """Return whether an active callable-sentinel iterator consumes the exception."""
    if _normalize_exception_name(exception_name) != "StopIteration":
        return False
    return any(_retain_callable_sentinel(frame) is not None for frame in state.call_stack)


def _retain_callable_sentinel(
    frame: CallFrame,
) -> CallableSentinelStep | None:
    if frame.protocol_method != CALLABLE_SENTINEL_ITER_PROTOCOL:
        return None
    retained = frame.protocol_retained_operand
    if isinstance(retained, CallableSentinelStep):
        return retained
    return None


def _unsupported_iteration(state: VMState) -> OpcodeResult:
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_ITERATION_PROTOCOL],
        fallback_events=[
            flag_unsupported_iteration(
                state=state,
                reason="callable-sentinel equality protocol could not be modeled",
            ),
        ],
        terminal=True,
    )


def _is_stop_iteration(exc: object) -> bool:
    if isinstance(exc, SymbolicException):
        exc_type = exc.exc_type
        return exc_type is StopIteration or exc_type == "StopIteration"
    payload = getattr(exc, "_modeled_object", None)
    if isinstance(payload, SymbolicException):
        return _is_stop_iteration(payload)
    if isinstance(exc, StopIteration):
        return True
    if isinstance(exc, type):
        return issubclass(exc, StopIteration)
    return _normalize_exception_name(str(getattr(exc, "name", ""))) == "StopIteration"


def _normalize_exception_name(name: str) -> str:
    if name.startswith("global_"):
        return name.removeprefix("global_")
    return name
