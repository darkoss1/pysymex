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

"""``RAISE_VARARGS`` and ``RERAISE`` exception propagation semantics."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.exceptions.policy import issue_kind_for_exception
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.engine.queries import get_model_cached_result
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def handle_common_cleanup_throw(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Clean up after generator.throw()."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _extract_symbolic_exception(value: object) -> SymbolicException | None:
    """Return a direct or modeled exception payload from a VM stack value."""
    if isinstance(value, SymbolicException):
        return value
    modeled_value = getattr(value, "_modeled_object", None)
    return modeled_value if isinstance(modeled_value, SymbolicException) else None


def handle_common_reraise(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Re-raise the current exception."""
    oparg = instr.argval
    if not state.stack:
        return OpcodeResult.terminate()
    exc = state.pop()
    modeled_exc = _extract_symbolic_exception(exc)
    if modeled_exc is not None:
        exc = modeled_exc
    elif (
        (pending_exc := _extract_symbolic_exception(state.pending_reraise_exception)) is not None
        and oparg is not None
        and int(oparg) > 0
    ):
        exc = pending_exc
        modeled_exc = pending_exc
    else:
        retained_exc = next(
            (
                candidate_exc
                for candidate in reversed(state.stack)
                if (candidate_exc := _extract_symbolic_exception(candidate)) is not None
            ),
            None,
        )
        if retained_exc is not None:
            exc = retained_exc
            modeled_exc = retained_exc
        else:
            pending_exc = _extract_symbolic_exception(state.pending_reraise_exception)
            if pending_exc is not None:
                exc = pending_exc
                modeled_exc = pending_exc
            elif (active_exc := _extract_symbolic_exception(state.active_exception)) is not None:
                exc = active_exc
                modeled_exc = active_exc

    if oparg is not None and int(oparg) > 0 and state.stack:
        state.pop()

    handler_state = ExceptionFlow.jump_to_handler(state, ctx, instr.offset, exc)
    if handler_state is not None:
        return OpcodeResult.continue_with(handler_state)

    block = state.current_block()
    if block and block.block_type in ("finally", "except", "cleanup"):
        if block.handler_pc is not None:
            state = state.set_pc(block.handler_pc)
            state.stack = type(state.stack)()
            state = state.push(exc)
            return OpcodeResult.continue_with(state)

    if modeled_exc is not None:
        return OpcodeResult.error(_escaping_modeled_exception_issue(modeled_exc, state, instr))
    return OpcodeResult.terminate()


def _escaping_modeled_exception_issue(
    exc: SymbolicException,
    state: VMState,
    instr: dis.Instruction,
) -> Issue:
    """Return the issue for a modeled exception that escaped all handlers."""
    constraints = list(state.path_constraints)
    model_result = get_model_cached_result(constraints)
    detail = exc.message
    issue_kind = issue_kind_for_exception(exc.exc_type, detail)
    if issue_kind is IssueKind.UNHANDLED_EXCEPTION:
        message = f"Path raises unhandled exception: {exc.type_name}"
        if detail:
            message = f"{message}: {detail}"
    else:
        message = f"Possible {exc.type_name}"
        if detail:
            message = f"{message}: {detail}"
    return Issue(
        kind=issue_kind,
        message=message,
        constraints=constraints,
        model=model_result.model if model_result.is_sat else None,
        pc=exc.raised_at if exc.raised_at > 0 else instr.offset,
        line_number=exc.line_number,
        column=exc.column,
        confidence=getattr(exc, "confidence", 1.0),
        likelihood=getattr(exc, "likelihood", 1.0),
    )


def handle_exception_raise_varargs(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Handle exception raising, distinguishing caught vs uncaught."""
    argc = int(instr.argval) if instr.argval is not None else 0
    ExceptionFlow.require_depth(state, instr, argc, "RAISE_VARARGS")
    exc = None
    for _ in range(argc):
        exc = state.pop()
    if argc == 0:
        exc = state.active_exception
        state.pending_reraise_exception = exc
        state.invalidate_cached_hash()

    if exc is not None:
        handler_state = ExceptionFlow.jump_to_handler(state, ctx, instr.offset, exc)
        if handler_state is not None:
            return OpcodeResult.continue_with(handler_state)

    block = state.current_block()
    if block and block.block_type in ("finally", "except", "cleanup"):
        if block.handler_pc is not None:
            state = state.set_pc(block.handler_pc)
            state.stack = type(state.stack)()
            if exc is not None:
                state = state.push(exc)
            return OpcodeResult.continue_with(state)

    return OpcodeResult.terminate()
