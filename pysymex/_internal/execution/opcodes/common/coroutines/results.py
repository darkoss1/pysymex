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

"""Result construction for modeled coroutine protocol paths."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.exceptions.policy import concrete_exception, stop_iteration, type_error
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.havoc import HavocValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.fallbacks import (
    UNSUPPORTED_GENERATOR,
    flag_unsupported_generator,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def raise_stop_iteration(
    state: VMState,
    ctx: OpcodeDispatcher,
    frame: CallFrame,
    return_value: object | None = None,
) -> OpcodeResult:
    """Route or report ``StopIteration`` for ``coroutine.send(None)`` completion."""
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


def runtime_error_result(
    state: VMState,
    ctx: OpcodeDispatcher,
    instr: dis.Instruction,
    message: str,
) -> OpcodeResult:
    """Jump to a ``RuntimeError`` handler or emit an unhandled exception issue."""
    from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow

    exc = concrete_exception(RuntimeError, message, state=state, instr=instr)
    handled = ExceptionFlow.jump_to_handler(state, ctx, instr.offset, exc)
    if handled is not None:
        return OpcodeResult.continue_with(handled)
    issue = Issue(
        kind=IssueKind.UNHANDLED_EXCEPTION,
        message="Possible unhandled exception: RuntimeError",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)


def unsupported_coroutine(state: VMState, reason: str) -> OpcodeResult:
    """Havoc a coroutine protocol result when precise resume is unsupported."""
    fallback_event = flag_unsupported_generator(state=state, reason=reason)
    value, constraint = HavocValue.havoc(f"havoc_coroutine_send_{state.pc}")
    state = state.push(value).add_constraint(constraint).advance_pc()
    return OpcodeResult.continue_with(
        state,
        degraded_passes=[UNSUPPORTED_GENERATOR],
        fallback_events=[fallback_event],
    )


def exception_from_throw_args(args: list[StackValue]) -> SymbolicException | None:
    """Return the exception injected by supported ``coroutine.throw`` forms."""
    if not args:
        return None
    first = args[0]
    if isinstance(first, SymbolicException):
        return first
    if isinstance(first, type) and issubclass(first, BaseException):
        return concrete_exception(first)
    if isinstance(first, BaseException):
        return concrete_exception(type(first), *first.args)
    return None
