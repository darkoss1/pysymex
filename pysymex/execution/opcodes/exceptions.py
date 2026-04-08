# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Exception handling opcodes."""

from __future__ import annotations

import dis
from collections.abc import Iterable
from typing import TYPE_CHECKING

from pysymex.core.types import SymbolicValue
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher

_RAISING_OPS = frozenset(
    {
        "CALL",
        "CALL_FUNCTION",
        "CALL_METHOD",
        "CALL_FUNCTION_EX",
        "CALL_KW",
        "BINARY_SUBSCR",
        "STORE_SUBSCR",
        "DELETE_SUBSCR",
        "BINARY_TRUE_DIVIDE",
        "BINARY_FLOOR_DIVIDE",
        "BINARY_MODULO",
        "LOAD_ATTR",
        "STORE_ATTR",
        "DELETE_ATTR",
        "IMPORT_NAME",
        "IMPORT_FROM",
        "RAISE_VARARGS",
        "RERAISE",
        "BINARY_OP",
        "LOAD_GLOBAL",
        "UNPACK_SEQUENCE",
        "FOR_ITER",
    }
)


def try_block_can_raise(instructions: list[dis.Instruction]) -> bool:
    """Return True if a try block contains potentially raising opcodes.

    This conservative helper is used by legacy tests and orchestration logic.
    """
    return any(instr.opname in _RAISING_OPS for instr in instructions)


_try_block_can_raise = try_block_can_raise


@opcode_handler("SETUP_FINALLY")
def handle_setup_finally(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Set up a try/finally block by pushing a handler onto the block stack.

    Does **not** eagerly fork execution paths.  The exception state will
    be forked lazily when a raising opcode (e.g. ``RAISE_VARARGS``,
    ``CALL``) is actually encountered, or when the executor's
    ``_fork_for_exception`` helper fires.

    This avoids the exponential path-explosion caused by forking at
    every ``try:`` entry, especially in code with deeply-nested or
    back-to-back exception handlers.
    """
    from pysymex.core.state import BlockInfo

    handler_offset = instr.argval
    handler_pc = None
    if handler_offset is not None:
        handler_pc = ctx.offset_to_index(handler_offset)

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


@opcode_handler("POP_BLOCK")
def handle_pop_block(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Pop a block from the block stack."""
    state.exit_block()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("PUSH_EXC_INFO")
def handle_push_exc_info(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Push exception info onto the stack (Python 3.11+)."""
    exc = state.pop() if state.stack else None
    from pysymex.core.types import SymbolicNone

    state = state.push(SymbolicNone("old_exc"))
    if exc is not None:
        state = state.push(exc)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("POP_EXCEPT")
def handle_pop_except(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Pop exception handler block."""
    if state.stack:
        state.pop()

    block = state.current_block()
    if block and block.block_type in ("except", "finally"):
        state.exit_block()

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("CHECK_EXC_MATCH")
def handle_check_exc_match(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check if exception matches (Python 3.11+)."""
    exc_types = None
    if len(state.stack) >= 2:
        exc_types = state.pop()

    exc = state.stack[-1] if state.stack else None

    if exc is not None and exc_types is not None:
        exc_name = str(getattr(exc, "name", ""))

        def _matches(t: object) -> bool:
            t_name = getattr(t, "__name__", str(t))
            return (
                ("ValueError" in t_name)
                or ("TypeError" in t_name)
                or (t_name in exc_name)
                or (exc_name in t_name)
            )

        match_found = False
        if hasattr(exc_types, "_concrete_items") or isinstance(exc_types, (tuple, list)):
            items = getattr(exc_types, "_concrete_items", exc_types)
            if items is not None:
                if not isinstance(items, (list, tuple)):
                    if isinstance(items, Iterable):
                        try:
                            items = list(items)
                        except TypeError:
                            items = [items]
                    else:
                        items = [items]
                match_found = any(_matches(t) for t in dict.fromkeys(items))
        else:
            match_found = _matches(exc_types)

        if match_found or getattr(exc_types, "__name__", "") in ["ValueError", "TypeError"]:
            from pysymex.core.types import SymbolicValue

            state = state.push(SymbolicValue.from_const(match_found))
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

    from pysymex.core.types import SymbolicValue

    result, constraint = SymbolicValue.symbolic(f"exc_match_{state.pc}")
    state = state.push(result)
    state = state.add_constraint(constraint)
    state = state.add_constraint(result.is_bool)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("CLEANUP_THROW")
def handle_cleanup_throw(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Clean up after generator.throw() (Python 3.12+)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("RERAISE")
def handle_reraise(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Re-raise the current exception."""
    oparg = instr.argval
    exc = state.pop() if state.stack else None

    if oparg is not None and int(oparg) > 0:
        if state.stack:
            state.pop()

    handler_pc = ctx.find_exception_handler(instr.offset)
    if handler_pc is not None:
        state = state.set_pc(handler_pc)
        if exc is not None:
            state = state.push(exc)
        return OpcodeResult.continue_with(state)

    block = state.current_block()
    if block and block.block_type in ("finally", "except", "cleanup"):
        if block.handler_pc is not None:
            state = state.set_pc(block.handler_pc)
            if exc is not None:
                state = state.push(exc)
            return OpcodeResult.continue_with(state)

    from pysymex.analysis.detectors import Issue, IssueKind
    from pysymex.core.solver import get_model

    issue = Issue(
        kind=IssueKind.EXCEPTION,
        message="Exception re-raised and escaped",
        constraints=list(state.path_constraints),
        model=get_model(list(state.path_constraints)),
        pc=state.pc,
    )
    return OpcodeResult.error(issue, state=state)


@opcode_handler("WITH_EXCEPT_START")
def handle_with_except_start(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Start of __exit__ call in with statement."""
    result, constraint = SymbolicValue.symbolic(f"with_exit_{state.pc}")
    state = state.push(result)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BEFORE_WITH")
def handle_before_with(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Prepare for with statement (Python 3.11+)."""
    if state.stack:
        _ = state.pop()
        exit_val, c1 = SymbolicValue.symbolic(f"exit_{state.pc}")
        state = state.push(exit_val)
        state = state.add_constraint(c1)
        enter_val, c2 = SymbolicValue.symbolic(f"enter_{state.pc}")
        state = state.push(enter_val)
        state = state.add_constraint(c2)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BEFORE_ASYNC_WITH")
def handle_before_async_with(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Prepare for async with statement."""
    if state.stack:
        state.pop()
    exit_val, c1 = SymbolicValue.symbolic(f"async_exit_{state.pc}")
    enter_val, c2 = SymbolicValue.symbolic(f"async_enter_{state.pc}")
    state = state.push(exit_val)
    state = state.push(enter_val)
    state = state.add_constraint(c1)
    state = state.add_constraint(c2)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("END_ASYNC_FOR")
def handle_end_async_for(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """End of async for loop — clean up exception info from stack."""
    # CPython pops the exhausted async iterator and exception info
    for _ in range(2):
        if state.stack:
            state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("GET_AITER")
def handle_get_aiter(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Get async iterator."""
    if state.stack:
        state.pop()
    iter_val, constraint = SymbolicValue.symbolic(f"aiter_{state.pc}")
    state = state.push(iter_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("GET_ANEXT")
def handle_get_anext(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Get next from async iterator."""
    next_val, constraint = SymbolicValue.symbolic(f"anext_{state.pc}")
    state = state.push(next_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("GET_AWAITABLE")
def handle_get_awaitable(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Get awaitable from object.

    Pops the coroutine/awaitable object, pushes a symbolic representing
    the iterator that ``__await__`` returns.  The result is constrained
    to be non-None since a valid awaitable always yields an iterator.
    Taint from the source awaitable is propagated.
    """
    source = state.pop() if state.stack else None
    source_taint = frozenset(getattr(source, "taint_labels", None) or ())
    awaitable, constraint = SymbolicValue.symbolic(f"awaitable_{state.pc}")
    if source_taint:
        awaitable = awaitable.with_taint(source_taint)
    state = state.push(awaitable)
    state = state.add_constraint(constraint)
    import z3 as _z3

    state = state.add_constraint(_z3.Not(awaitable.is_none))
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("SEND")
def handle_send(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Send value to generator/coroutine.

    Stack: TOS = value to send, TOS1 = generator/coroutine.
    Pushes the yielded result.  Taint from the sent value is propagated
    to the result since generator data-flow links send → yield.
    """
    sent_val = state.pop() if state.stack else None
    _gen_obj = state.pop() if state.stack else None
    sent_taint = frozenset(getattr(sent_val, "taint_labels", None) or ())
    result, constraint = SymbolicValue.symbolic(f"send_{state.pc}")
    if sent_taint:
        result = result.with_taint(sent_taint)
    state = state.push(result)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("YIELD_VALUE")
def handle_yield_value(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Yield a value from a generator.

    Pops the value to yield, then pushes a symbolic representing the
    value that will be sent back via ``generator.send()``.  Taint from
    the yielded value implicitly flows to the sent-back result because
    the caller observes the yielded data.
    """
    yielded = state.pop() if state.stack else None
    yielded_taint = frozenset(getattr(yielded, "taint_labels", None) or ())
    sent, constraint = SymbolicValue.symbolic(f"yield_sent_{state.pc}")
    if yielded_taint:
        sent = sent.with_taint(yielded_taint)
    state = state.push(sent)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("END_SEND")
def handle_end_send(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """End of generator send (Python 3.12+)."""
    if len(state.stack) >= 2:
        state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("GET_YIELD_FROM_ITER")
def handle_get_yield_from_iter(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Get iterator for yield from."""
    if state.stack:
        state.pop()
    iter_val, constraint = SymbolicValue.symbolic(f"yield_from_{state.pc}")
    state = state.push(iter_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("CHECK_EG_MATCH")
def handle_check_eg_match(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check ExceptionGroup match (Python 3.11+ except* syntax)."""
    if len(state.stack) >= 2:
        state.pop()
        state.pop()
    match_val, c1 = SymbolicValue.symbolic(f"eg_match_{state.pc}")
    rest_val, c2 = SymbolicValue.symbolic(f"eg_rest_{state.pc}")
    state = state.push(rest_val)
    state = state.push(match_val)
    state = state.add_constraint(c1)
    state = state.add_constraint(c2)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("EXIT_INIT_CHECK")
def handle_exit_init_check(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check __init__ returned None (Python 3.12+)."""
    if state.stack:
        state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("SETUP_CLEANUP")
def handle_setup_cleanup(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Set up cleanup handler (Python 3.12+)."""
    from pysymex.core.state import BlockInfo

    handler_offset = instr.argval
    if handler_offset is not None:
        handler_pc = ctx.offset_to_index(handler_offset)
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


@opcode_handler("INTERPRETER_EXIT")
def handle_interpreter_exit(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Exit the interpreter (Python 3.12+, for PEP 669 monitoring)."""
    return OpcodeResult.terminate()


@opcode_handler("RAISE_VARARGS")
def handle_raise_varargs(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle exception raising."""
    from pysymex.analysis.detectors import Issue, IssueKind
    from pysymex.core.solver import get_model

    argc = int(instr.argval) if instr.argval is not None else 0
    exc = None
    for _ in range(argc):
        if state.stack:
            exc = state.pop()

    handler_pc = ctx.find_exception_handler(instr.offset)
    if handler_pc is not None:
        state = state.set_pc(handler_pc)
        if exc is not None:
            state = state.push(exc)
        return OpcodeResult.continue_with(state)

    block = state.current_block()
    if block and block.block_type in ("finally", "except", "cleanup"):
        if block.handler_pc is not None:
            state = state.set_pc(block.handler_pc)
            return OpcodeResult.continue_with(state)

    msg = f"Exception raised: {getattr(exc, 'name', 'unknown')}"
    kind = IssueKind.EXCEPTION
    exc_name = str(getattr(exc, "name", ""))
    if "AssertionError" in exc_name:
        kind = IssueKind.ASSERTION_ERROR
    elif "ValueError" in exc_name:
        kind = IssueKind.VALUE_ERROR
    elif "TypeError" in exc_name:
        kind = IssueKind.TYPE_ERROR

    issue = Issue(
        kind=kind,
        message=msg,
        constraints=list(state.path_constraints),
        model=get_model(list(state.path_constraints)),
        pc=state.pc,
    )
    return OpcodeResult.error(issue, state=state)


@opcode_handler("RETURN_GENERATOR")
def handle_return_generator(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Return a generator object (generator function entry)."""
    gen_val, constraint = SymbolicValue.symbolic(f"generator_{state.pc}")
    state = state.push(gen_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
