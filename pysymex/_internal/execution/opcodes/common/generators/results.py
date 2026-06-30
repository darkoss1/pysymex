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

"""Result construction for modeled generator completion and fallback paths."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.exceptions.policy import stop_iteration, type_error
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.types import CallFrame
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.havoc import HavocValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.fallbacks import (
    UNSUPPORTED_GENERATOR,
    flag_unsupported_generator,
)
from pysymex._internal.execution.opcodes.common.control.iteration.exit import (
    push_for_iter_exit_sentinel,
)
from pysymex._internal.execution.opcodes.common.generators.aliases import replace_generator_aliases

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.containers.generators import ModeledGenerator
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.opcodes.common.generators.requests import ResumeRequest


def complete_closed_call(
    state: VMState,
    ctx: OpcodeDispatcher,
    instr: dis.Instruction,
    request: ResumeRequest,
) -> OpcodeResult:
    """Finish ``next``/``send`` on a closed generator with default or ``StopIteration``."""
    if request.has_default:
        value = request.default if request.default is not None else SymbolicNoneType()
        return OpcodeResult.continue_with(state.push(value).advance_pc())
    frame = CallFrame(
        "",
        state.pc + 1,
        state.local_vars,
        len(state.stack),
        caller_offset=instr.offset,
    )
    return raise_stop_iteration(state, ctx, frame)


def complete_closed_for_iter(
    state: VMState,
    target_index: int,
    *,
    push_exit_sentinel: bool = True,
    pop_exit_iterator: bool = False,
) -> OpcodeResult:
    """Exit a ``FOR_ITER`` loop over a generator known to be closed."""
    exit_state = push_for_iter_exit_sentinel(
        state,
        name="generator_iter_exhausted",
        push_sentinel=push_exit_sentinel,
        pop_iterator=pop_exit_iterator,
    )
    return OpcodeResult.continue_with(exit_state.set_pc(target_index))


def close_generator_call(state: VMState, generator: ModeledGenerator) -> OpcodeResult:
    """Close a generator without modeling ``GeneratorExit``/``finally`` execution."""
    fallback_event = flag_unsupported_generator(
        state=state,
        reason="generator close finalization is not modeled precisely",
    )
    closed = dataclasses.replace(generator, closed=True)
    replace_generator_aliases(state, generator, closed)
    state = state.push(SymbolicNoneType()).advance_pc()
    return OpcodeResult.continue_with(
        state,
        degraded_passes=[UNSUPPORTED_GENERATOR],
        fallback_events=[fallback_event],
    )


def raise_stop_iteration(
    state: VMState,
    ctx: OpcodeDispatcher,
    frame: CallFrame,
    return_value: object | None = None,
) -> OpcodeResult:
    """Route or report ``StopIteration`` when a generator is exhausted."""
    from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow

    exc = stop_iteration(
        None
        if return_value is None or isinstance(return_value, SymbolicNoneType)
        else return_value,
        state=state,
    )
    if frame.caller_offset is not None:
        handled = ExceptionFlow.jump_to_handler(state, ctx, frame.caller_offset, exc)
        if handled is not None:
            return OpcodeResult.continue_with(handled)
    issue = Issue(
        kind=IssueKind.UNHANDLED_EXCEPTION,
        message="Possible unhandled exception: StopIteration",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)


def type_error_result(
    state: VMState,
    ctx: OpcodeDispatcher,
    instr: dis.Instruction,
    message: str,
) -> OpcodeResult:
    """Jump to a ``TypeError`` handler or emit a definite type-error issue."""
    from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow

    exc = type_error(message, state=state, instr=instr)
    handled = ExceptionFlow.jump_to_handler(state, ctx, instr.offset, exc)
    if handled is not None:
        return OpcodeResult.continue_with(handled)
    issue = Issue(
        kind=IssueKind.TYPE_ERROR,
        message=f"Possible TypeError: {message}",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)


def abstract_generator_call(state: VMState) -> OpcodeResult:
    """Havoc a generator resume result when precise continuation is unsupported."""
    fallback_event = flag_unsupported_generator(
        state=state,
        reason="generator resume could not be modeled precisely",
    )
    value, constraint = HavocValue.havoc(f"havoc_generator_next_{state.pc}")
    state = state.push(value).add_constraint(constraint).advance_pc()
    return OpcodeResult.continue_with(
        state,
        degraded_passes=[UNSUPPORTED_GENERATOR],
        fallback_events=[fallback_event],
    )
