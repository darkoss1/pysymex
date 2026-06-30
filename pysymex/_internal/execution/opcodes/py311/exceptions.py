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

"""Exception, generator, and async control opcode wrappers for Python 3.11.

Registers handlers for the 3.11 exception stack (``PUSH_EXC_INFO``,
``CHECK_EXC_MATCH``, ``BEFORE_WITH``, etc.) and generator/async opcodes,
mostly delegating to :mod:`pysymex._internal.execution.opcodes.common.exceptions`. Owns
only the local ``PREP_RERAISE_STAR`` stack shuffle; does not implement full
``except*``/ExceptionGroup reraise semantics.
.

Each ``@opcode_handler`` entry registers CPython opcode names for this interpreter version and delegates semantics to :mod:`pysymex._internal.execution.opcodes.common` (stack effects, forks, constraints, and limitations are documented on the common handlers).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.execution.dispatch.dispatcher.decorators import opcode_handler
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.exceptions.blocks import (
    handle_common_pop_except,
    handle_common_push_exc_info,
)
from pysymex._internal.execution.opcodes.common.exceptions.flow.awaiting import (
    handle_common_end_async_for,
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
    handle_common_with_except_start,
)
from pysymex._internal.execution.opcodes.common.exceptions.flow.groups import (
    handle_common_check_eg_match,
)
from pysymex._internal.execution.opcodes.common.exceptions.matching import (
    handle_common_check_exc_match,
)
from pysymex._internal.execution.opcodes.common.exceptions.raising import (
    handle_common_reraise,
    handle_exception_raise_varargs,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


@opcode_handler("PUSH_EXC_INFO")
def handle_py311_push_exc_info(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Push exception info onto the stack (Python 3.11+)."""
    return handle_common_push_exc_info(instr, state, ctx)


@opcode_handler("POP_EXCEPT")
def handle_py311_pop_except(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Pop exception handler block."""
    return handle_common_pop_except(instr, state, ctx)


@opcode_handler("CHECK_EXC_MATCH")
def handle_py311_check_exc_match(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Check if exception matches (Python 3.11+)."""
    return handle_common_check_exc_match(instr, state, ctx)


@opcode_handler("RERAISE")
def handle_py311_reraise(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Re-raise the current exception."""
    return handle_common_reraise(instr, state, ctx)


@opcode_handler("WITH_EXCEPT_START")
def handle_py311_with_except_start(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Start of __exit__ call in with statement."""
    return handle_common_with_except_start(instr, state, ctx)


@opcode_handler("BEFORE_WITH")
def handle_py311_before_with(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Prepare for with statement (Python 3.11+)."""
    return handle_common_before_with(instr, state, ctx)


@opcode_handler("BEFORE_ASYNC_WITH")
def handle_py311_before_async_with(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Prepare for async with statement."""
    return handle_common_before_async_with(instr, state, ctx)


@opcode_handler("END_ASYNC_FOR")
def handle_py311_end_async_for(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """End of async for loop — clean up exception info from stack."""
    return handle_common_end_async_for(instr, state, ctx)


@opcode_handler("GET_AITER")
def handle_py311_get_aiter(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Get async iterator."""
    return handle_common_get_aiter(instr, state, ctx)


@opcode_handler("GET_ANEXT")
def handle_py311_get_anext(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Get next from async iterator."""
    return handle_common_get_anext(instr, state, ctx)


@opcode_handler("GET_AWAITABLE")
def handle_py311_get_awaitable(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Get awaitable from object."""
    return handle_common_get_awaitable(instr, state, ctx)


@opcode_handler("SEND")
def handle_py311_send(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Send value to generator/coroutine."""
    return handle_common_send(instr, state, ctx)


@opcode_handler("YIELD_VALUE")
def handle_py311_yield_value(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Yield a value from a generator."""
    return handle_common_yield_value(instr, state, ctx)


@opcode_handler("GET_YIELD_FROM_ITER")
def handle_py311_get_yield_from_iter(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Get iterator for yield from."""
    return handle_common_get_yield_from_iter(instr, state, ctx)


@opcode_handler("CHECK_EG_MATCH")
def handle_py311_check_eg_match(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Check ExceptionGroup match (Python 3.11+ except* syntax)."""
    return handle_common_check_eg_match(instr, state, ctx)


@opcode_handler("RAISE_VARARGS")
def handle_py311_exception_raise_varargs(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Handle exception raising."""
    return handle_exception_raise_varargs(instr, state, ctx)


@opcode_handler("RETURN_GENERATOR")
def handle_py311_return_generator(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Return a generator object (generator function entry)."""
    return handle_common_return_generator(instr, state, ctx)


@opcode_handler("PREP_RERAISE_STAR")
def handle_prep_reraise_star(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Prepare the retained ``except*`` remainder for a following ``RERAISE``."""
    del instr, ctx
    reraised = state.pop() if state.stack else None
    original = state.pop() if state.stack else None
    from pysymex._internal.execution.opcodes.common.control.intrinsics import (
        prep_reraise_star_result,
    )

    prepared = prep_reraise_star_result(state, original, reraised)
    if prepared is None:
        prepared = original
    if prepared is not None:
        state = state.push(cast("StackValue", prepared))
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


handle_push_exc_info = handle_py311_push_exc_info
handle_pop_except = handle_py311_pop_except
handle_check_exc_match = handle_py311_check_exc_match
handle_reraise = handle_py311_reraise
handle_with_except_start = handle_py311_with_except_start
handle_before_with = handle_py311_before_with
handle_before_async_with = handle_py311_before_async_with
handle_end_async_for = handle_py311_end_async_for
handle_get_aiter = handle_py311_get_aiter
handle_get_anext = handle_py311_get_anext
handle_get_awaitable = handle_py311_get_awaitable
handle_send = handle_py311_send
handle_yield_value = handle_py311_yield_value
handle_get_yield_from_iter = handle_py311_get_yield_from_iter
handle_check_eg_match = handle_py311_check_eg_match
handle_raise_varargs = handle_py311_exception_raise_varargs
handle_return_generator = handle_py311_return_generator
