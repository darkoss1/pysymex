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

"""Exception setup, propagation, and async/with opcode handlers.

Owns ``SETUP_*``, ``POP_EXCEPT``, ``CHECK_EXC_MATCH``, ``RAISE_VARARGS``, and
related control transfers into block handlers. Re-exports async iterator helpers
from :mod:`pysymex.execution.opcodes.common.exceptions.async_flow`; does not
encode solver feasibility for match checks beyond path-local guards.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.exceptions.async_flow import (
    handle_common_before_async_with as handle_common_before_async_with,
    handle_common_before_with as handle_common_before_with,
    handle_common_check_eg_match as handle_common_check_eg_match,
    handle_common_end_async_for as handle_common_end_async_for,
    handle_common_end_send as handle_common_end_send,
    handle_common_get_aiter as handle_common_get_aiter,
    handle_common_get_anext as handle_common_get_anext,
    handle_common_get_awaitable as handle_common_get_awaitable,
    handle_common_get_yield_from_iter as handle_common_get_yield_from_iter,
    handle_common_interpreter_exit as handle_common_interpreter_exit,
    handle_common_return_generator as handle_common_return_generator,
    handle_common_send as handle_common_send,
    handle_common_with_except_start as handle_common_with_except_start,
    handle_common_yield_value as handle_common_yield_value,
)
from pysymex.execution.opcodes.common.exceptions.helpers import (
    concrete_exception_match,
    has_definite_invalid_exception_handler,
    is_exception_handler_target,
    jump_to_exception_handler,
    materialize_exception_items,
    require_stack_depth,
)

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher

_INVALID_EXCEPTION_HANDLER_MESSAGE = (
    "catching classes that do not inherit from BaseException is not allowed"
)


def handle_common_setup_finally(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Set up a try/finally block by pushing a handler onto the block stack."""
    from pysymex.core.state.types import BlockInfo

    handler_offset = instr.argval
    handler_pc = None
    if handler_offset is not None:
        handler_pc = ctx.offset_to_index(int(handler_offset))

    if handler_pc is not None:
        state.enter_block(
            BlockInfo(
                block_type="finally",
                start_pc=state.pc,
                end_pc=handler_pc,
                handler_pc=handler_pc,
            )
        )

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_pop_block(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Pop a block from the block stack."""
    state.exit_block()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_push_exc_info(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Push exception info onto the stack."""
    if not state.stack and is_exception_handler_target(ctx, instr.offset):
        return OpcodeResult.terminate()
    require_stack_depth(state, instr, 1, "PUSH_EXC_INFO")
    exc = state.pop()
    state.active_exception = exc
    state.pending_reraise_exception = None
    state.invalidate_cached_hash()
    state = state.push(SymbolicNone("old_exc"))
    state = state.push(exc)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_pop_except(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Pop exception handler block."""
    require_stack_depth(state, instr, 1, "POP_EXCEPT")
    state.pop()
    state.active_exception = None
    state.invalidate_cached_hash()
    next_instr = ctx.get_instruction(state.pc + 1)
    if state.deferred_detector_issues and (next_instr is None or next_instr.opname != "RERAISE"):
        state.deferred_detector_issues = []
        state.invalidate_cached_hash()

    block = state.current_block()
    if block and block.block_type in ("except", "finally"):
        state.exit_block()

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_check_exc_match(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check if exception matches."""
    require_stack_depth(state, instr, 2, "CHECK_EXC_MATCH")
    exc_types = state.pop()
    exc = state.stack[-1]

    if exc is not None and exc_types is not None:
        exc_name = str(getattr(exc, "type_name", "") or getattr(exc, "name", ""))

        def _matches(t: object) -> bool:
            """Return whether *t* matches the raised exception's type name."""
            t_name = t.__name__ if isinstance(t, type) else str(t)
            return (
                t_name in {"BaseException", "Exception"}
                or t_name == exc_name
                or (bool(exc_name) and (t_name in exc_name or exc_name in t_name))
            )

        match_found = False
        exc_types_obj: object = exc_types
        items = materialize_exception_items(exc_types_obj)
        if items:
            match_found = any(_matches(t) for t in items)
        else:
            match_found = _matches(exc_types)

        exc_types_name = exc_types_obj.__name__ if isinstance(exc_types_obj, type) else ""
        handler_items = items or [exc_types]
        if has_definite_invalid_exception_handler(handler_items):
            return _invalid_exception_handler_type_error(instr, state, ctx)
        concrete_match = concrete_exception_match(exc, handler_items)
        if concrete_match is not None:
            state = state.push(SymbolicValue.from_const(concrete_match))
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)
        if match_found or exc_types_name in {"BaseException", "Exception"}:
            state = state.push(SymbolicValue.from_const(True))
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

    result, constraint = SymbolicValue.symbolic(f"exc_match_{state.pc}")
    state = state.push(result)
    state = state.add_constraint(constraint)
    state = state.add_constraint(result.is_bool)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _invalid_exception_handler_type_error(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Route CPython's invalid exception-handler TypeError."""
    exc = SymbolicException.concrete(
        TypeError,
        _INVALID_EXCEPTION_HANDLER_MESSAGE,
        raised_at=state.pc,
    )
    handler_state = jump_to_exception_handler(state, ctx, instr.offset, exc)
    if handler_state is not None:
        return OpcodeResult.continue_with(handler_state)
    issue = Issue(
        kind=IssueKind.TYPE_ERROR,
        message=f"Possible TypeError: {_INVALID_EXCEPTION_HANDLER_MESSAGE}",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)


def handle_common_cleanup_throw(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
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
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Re-raise the current exception."""
    oparg = instr.argval
    if not state.stack:
        return OpcodeResult.terminate()
    exc = state.pop()
    modeled_exc = _extract_symbolic_exception(exc)
    if modeled_exc is not None:
        exc = modeled_exc
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

    if oparg is not None and int(oparg) > 0:
        if state.stack:
            state.pop()

    handler_state = jump_to_exception_handler(state, ctx, instr.offset, exc)
    if handler_state is not None:
        return OpcodeResult.continue_with(handler_state)

    block = state.current_block()
    if block and block.block_type in ("finally", "except", "cleanup"):
        if block.handler_pc is not None:
            state = state.set_pc(block.handler_pc)
            state.stack = type(state.stack)()
            state = state.push(exc)
            return OpcodeResult.continue_with(state)

    return OpcodeResult.terminate()


def handle_common_setup_cleanup(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Set up cleanup handler (Python 3.12+)."""
    from pysymex.core.state.types import BlockInfo

    handler_offset = instr.argval
    if handler_offset is not None:
        handler_pc = ctx.offset_to_index(int(handler_offset))
        if handler_pc is not None:
            state.enter_block(
                BlockInfo(
                    block_type="cleanup",
                    start_pc=state.pc,
                    end_pc=handler_pc,
                    handler_pc=handler_pc,
                )
            )
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_raise_varargs(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle exception raising, distinguishing caught vs uncaught."""
    argc = int(instr.argval) if instr.argval is not None else 0
    require_stack_depth(state, instr, argc, "RAISE_VARARGS")
    exc = None
    for _ in range(argc):
        exc = state.pop()
    if argc == 0:
        exc = state.active_exception
        state.pending_reraise_exception = exc
        state.invalidate_cached_hash()

    if exc is not None:
        handler_state = jump_to_exception_handler(state, ctx, instr.offset, exc)
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


def handle_common_setup_with(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``SETUP_WITH``: pop manager and push symbolic enter/exit callables.

    CPython stack effect: pops the context manager, pushes ``__exit__`` then ``__enter__``
    results with feasibility literals. Modern ``before/with`` lowering lives in
    :mod:`pysymex.execution.opcodes.common.exceptions.async_flow`.

    Limitations:
        Does not model real context-manager protocol dispatch or async variants.
    """
    require_stack_depth(state, instr, 1, "SETUP_WITH")
    state.pop()

    exit_val, tc1 = SymbolicValue.symbolic(f"exit_{state.pc}")
    enter_val, tc2 = SymbolicValue.symbolic(f"enter_{state.pc}")

    state = state.push(exit_val)
    state = state.push(enter_val)
    state = state.add_constraint(tc1)
    state = state.add_constraint(tc2)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
