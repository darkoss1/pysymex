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

"""Python 3.13 return, raise, and assertion marker wrappers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.constants import Z3_FALSE, Z3_ZERO
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.dispatcher.decorators import opcode_handler
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.raise_varargs import (
    handle_control_raise_varargs,
)
from pysymex._internal.execution.opcodes.common.control.returns.handlers import (
    handle_common_return_const,
    handle_common_return_value,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


@opcode_handler("RETURN_VALUE")
def handle_py313_return_value(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Return from function with inter-procedural support."""
    return handle_common_return_value(instr, state, ctx)


@opcode_handler("RETURN_CONST")
def handle_py313_return_const(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Return a constant (Python 3.13+) with inter-procedural support."""
    return handle_common_return_const(instr, state, ctx)


@opcode_handler("RAISE_VARARGS")
def py313_raise_varargs_control(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Raise an exception, unwinding the block stack to find a handler."""
    return handle_control_raise_varargs(instr, state, ctx)


@opcode_handler("LOAD_ASSERTION_ERROR")
def handle_py313_load_assertion_error(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Load AssertionError for assert statements."""
    marker = SymbolicValue(
        _name="AssertionError",
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
    )
    state = state.push(marker)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
