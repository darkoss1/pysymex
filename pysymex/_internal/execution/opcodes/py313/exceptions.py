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

"""Exception, generator, and async control opcode wrappers for Python 3.13.

Registers block-stack setup, 3.12+ cleanup/monitoring opcodes, and shared
exception/generator handlers via :mod:`pysymex._internal.execution.opcodes.common.exceptions`.
Does not model sys.monitoring hooks or full async runtime scheduling.
.

Each ``@opcode_handler`` entry registers CPython opcode names for this interpreter version and delegates semantics to :mod:`pysymex._internal.execution.opcodes.common` (stack effects, forks, constraints, and limitations are documented on the common handlers).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.dispatch.dispatcher.decorators import opcode_handler
from pysymex._internal.execution.opcodes.common.exceptions.blocks import (
    handle_common_pop_block,
    handle_common_pop_except,
    handle_common_push_exc_info,
    handle_common_setup_cleanup,
    handle_common_setup_finally,
)
from pysymex._internal.execution.opcodes.common.exceptions.flow.awaiting import (
    handle_common_end_async_for,
    handle_common_end_send,
    handle_common_get_aiter,
    handle_common_get_anext,
    handle_common_get_awaitable,
    handle_common_get_yield_from_iter,
    handle_common_return_generator,
    handle_common_send,
    handle_common_yield_value,
)
from pysymex._internal.execution.opcodes.common.exceptions.flow.context import (
    handle_common_before_async_with,
    handle_common_before_with,
    handle_common_setup_with,
    handle_common_with_except_start,
)
from pysymex._internal.execution.opcodes.common.exceptions.flow.groups import (
    handle_common_check_eg_match,
    handle_common_interpreter_exit,
)
from pysymex._internal.execution.opcodes.common.exceptions.matching import (
    handle_common_check_exc_match,
)
from pysymex._internal.execution.opcodes.common.exceptions.raising import (
    handle_common_cleanup_throw,
    handle_common_reraise,
    handle_exception_raise_varargs,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult


@opcode_handler("SETUP_FINALLY")
def handle_py313_setup_finally(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Set up a try/finally block by pushing a handler onto the block stack."""
    return handle_common_setup_finally(instr, state, ctx)


@opcode_handler("SETUP_WITH")
def handle_py313_setup_with(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Set up a with block."""
    return handle_common_setup_with(instr, state, ctx)


@opcode_handler("POP_BLOCK")
def handle_py313_pop_block(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Pop a block from the block stack."""
    return handle_common_pop_block(instr, state, ctx)


@opcode_handler("PUSH_EXC_INFO")
def handle_py313_push_exc_info(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Push exception info onto the stack (Python 3.11+)."""
    return handle_common_push_exc_info(instr, state, ctx)


@opcode_handler("POP_EXCEPT")
def handle_py313_pop_except(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Pop exception handler block."""
    return handle_common_pop_except(instr, state, ctx)


@opcode_handler("CHECK_EXC_MATCH")
def handle_py313_check_exc_match(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Check if exception matches (Python 3.11+)."""
    return handle_common_check_exc_match(instr, state, ctx)


@opcode_handler("CLEANUP_THROW")
def handle_py313_cleanup_throw(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Clean up after generator.throw() (Python 3.12+)."""
    return handle_common_cleanup_throw(instr, state, ctx)


@opcode_handler("RERAISE")
def handle_py313_reraise(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Re-raise the current exception."""
    return handle_common_reraise(instr, state, ctx)


@opcode_handler("WITH_EXCEPT_START")
def handle_py313_with_except_start(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Start of __exit__ call in with statement."""
    return handle_common_with_except_start(instr, state, ctx)


@opcode_handler("BEFORE_WITH")
def handle_py313_before_with(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Prepare for with statement (Python 3.11+)."""
    return handle_common_before_with(instr, state, ctx)


@opcode_handler("BEFORE_ASYNC_WITH")
def handle_py313_before_async_with(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Prepare for async with statement."""
    return handle_common_before_async_with(instr, state, ctx)


@opcode_handler("END_ASYNC_FOR")
def handle_py313_end_async_for(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """End of async for loop — clean up exception info from stack."""
    return handle_common_end_async_for(instr, state, ctx)


@opcode_handler("GET_AITER")
def handle_py313_get_aiter(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Get async iterator."""
    return handle_common_get_aiter(instr, state, ctx)


@opcode_handler("GET_ANEXT")
def handle_py313_get_anext(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Get next from async iterator."""
    return handle_common_get_anext(instr, state, ctx)


@opcode_handler("GET_AWAITABLE")
def handle_py313_get_awaitable(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Get awaitable from object."""
    return handle_common_get_awaitable(instr, state, ctx)


@opcode_handler("SEND")
def handle_py313_send(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Send value to generator/coroutine."""
    return handle_common_send(instr, state, ctx)


@opcode_handler("YIELD_VALUE")
def handle_py313_yield_value(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Yield a value from a generator."""
    return handle_common_yield_value(instr, state, ctx)


@opcode_handler("END_SEND")
def handle_py313_end_send(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """End of generator send (Python 3.12+)."""
    return handle_common_end_send(instr, state, ctx)


@opcode_handler("GET_YIELD_FROM_ITER")
def handle_py313_get_yield_from_iter(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Get iterator for yield from."""
    return handle_common_get_yield_from_iter(instr, state, ctx)


@opcode_handler("CHECK_EG_MATCH")
def handle_py313_check_eg_match(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Check ExceptionGroup match (Python 3.11+ except* syntax)."""
    return handle_common_check_eg_match(instr, state, ctx)


@opcode_handler("SETUP_CLEANUP")
def handle_py313_setup_cleanup(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Set up cleanup handler (Python 3.12+)."""
    return handle_common_setup_cleanup(instr, state, ctx)


@opcode_handler("INTERPRETER_EXIT")
def handle_py313_interpreter_exit(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Exit the interpreter (Python 3.12+, for PEP 669 monitoring)."""
    return handle_common_interpreter_exit(instr, state, ctx)


@opcode_handler("RAISE_VARARGS")
def py313_raise_varargs(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Handle exception raising."""
    return handle_exception_raise_varargs(instr, state, ctx)


@opcode_handler("RETURN_GENERATOR")
def handle_py313_return_generator(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Return a generator object (generator function entry)."""
    return handle_common_return_generator(instr, state, ctx)


handle_setup_finally = handle_py313_setup_finally
handle_setup_with = handle_py313_setup_with
handle_pop_block = handle_py313_pop_block
handle_push_exc_info = handle_py313_push_exc_info
handle_pop_except = handle_py313_pop_except
handle_check_exc_match = handle_py313_check_exc_match
handle_cleanup_throw = handle_py313_cleanup_throw
handle_reraise = handle_py313_reraise
handle_with_except_start = handle_py313_with_except_start
handle_before_with = handle_py313_before_with
handle_before_async_with = handle_py313_before_async_with
handle_end_async_for = handle_py313_end_async_for
handle_get_aiter = handle_py313_get_aiter
handle_get_anext = handle_py313_get_anext
handle_get_awaitable = handle_py313_get_awaitable
handle_send = handle_py313_send
handle_yield_value = handle_py313_yield_value
handle_end_send = handle_py313_end_send
handle_get_yield_from_iter = handle_py313_get_yield_from_iter
handle_check_eg_match = handle_py313_check_eg_match
handle_setup_cleanup = handle_py313_setup_cleanup
handle_interpreter_exit = handle_py313_interpreter_exit
handle_raise_varargs = py313_raise_varargs
handle_return_generator = handle_py313_return_generator
