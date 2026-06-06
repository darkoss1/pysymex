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

"""Async/Await and Coroutine opcodes for pysymex.
Adds support for:
- ASYNC_GEN_WRAP
- GEN_START
- EXTENDED_ARG_QUICK

Note: Most async opcodes (GET_AWAITABLE, SEND, YIELD_VALUE, GET_AITER,
GET_ANEXT, END_ASYNC_FOR, RETURN_GENERATOR, BEFORE_ASYNC_WITH,
CLEANUP_THROW, RESUME, CALL_INTRINSIC_1, CALL_INTRINSIC_2) are
registered in exceptions.py and control.py respectively.
.

Each ``@opcode_handler`` entry registers CPython opcode names for this interpreter version and delegates semantics to :mod:`pysymex.execution.opcodes.common` (stack effects, forks, constraints, and limitations are documented on the common handlers)."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.dispatcher import opcode_handler
from pysymex.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


@opcode_handler("ASYNC_GEN_WRAP")
def handle_async_gen_wrap(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """
    Wrap value for async generator.
    Used internally by async generators.
    """
    if state.stack:
        state.pop()
    wrapped, constraint = SymbolicValue.symbolic(f"async_wrapped_{state.pc}")
    state = state.push(wrapped)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
