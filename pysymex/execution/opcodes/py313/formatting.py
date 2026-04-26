# pysymex: Python Symbolic Execution & Formal Verification
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

"""String formatting opcodes (Python 3.11+).

Handles FORMAT_SIMPLE and FORMAT_WITH_SPEC opcodes introduced in Python 3.11
for optimized f-string formatting.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.types.scalars import SymbolicString, SymbolicValue
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    import dis

    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher


@opcode_handler("FORMAT_SIMPLE")
def handle_format_simple(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """
    FORMAT_SIMPLE - Format a value using __format__ with an empty format spec.

    Introduced in Python 3.11 for optimized f-string formatting.
    Takes a value from the stack, formats it using value.__format__(''),
    and pushes the result back onto the stack.
    """
    value = state.pop()

    if isinstance(value, (SymbolicValue, SymbolicString)):
        result, constraint = SymbolicString.symbolic(f"formatted_{state.pc}")
        state = state.add_constraint(constraint)
        state = state.push(result)
    elif isinstance(value, (int, float, str, bool)):
        formatted = format(value, "")
        state = state.push(formatted)
    else:
        result, constraint = SymbolicString.symbolic(f"formatted_{state.pc}")
        state = state.add_constraint(constraint)
        state = state.push(result)

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("FORMAT_WITH_SPEC")
def handle_format_with_spec(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """
    FORMAT_WITH_SPEC - Format a value using __format__ with a format spec.

    Introduced in Python 3.11 for optimized f-string formatting.
    Takes a value and a format spec from the stack, formats the value using
    value.__format__(spec), and pushes the result back onto the stack.
    """
    spec = state.pop()
    value = state.pop()

    if isinstance(value, (SymbolicValue, SymbolicString)) or isinstance(
        spec, (SymbolicString, SymbolicValue)
    ):
        result, constraint = SymbolicString.symbolic(f"formatted_spec_{state.pc}")
        state = state.add_constraint(constraint)
        state = state.push(result)
    elif isinstance(value, (int, float, str, bool)) and isinstance(spec, str):
        try:
            formatted = format(value, spec)
            state = state.push(formatted)
        except (ValueError, TypeError):
            result, constraint = SymbolicString.symbolic(f"formatted_spec_{state.pc}")
            state = state.add_constraint(constraint)
            state = state.push(result)
    else:
        result, constraint = SymbolicString.symbolic(f"formatted_spec_{state.pc}")
        state = state.add_constraint(constraint)
        state = state.push(result)

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("CONVERT_VALUE")
def handle_convert_value(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """
    CONVERT_VALUE - Convert a value to a different type.

    Introduced in Python 3.11 for f-string conversion (!s, !r, !a).
    Takes a value and a conversion specifier from the stack, converts it,
    and pushes the result.
    """
    conversion = state.pop()
    value = state.pop()

    if isinstance(value, (SymbolicValue, SymbolicString)) or isinstance(
        conversion, (SymbolicValue, SymbolicString)
    ):
        result, constraint = SymbolicString.symbolic(f"converted_{state.pc}")
        state = state.add_constraint(constraint)
        state = state.push(result)
    elif isinstance(conversion, int):
        if conversion == 0:
            result = str(value)
        elif conversion == 1:
            result = repr(value)
        elif conversion == 2:
            result = ascii(value)
        else:
            result, constraint = SymbolicString.symbolic(f"converted_{state.pc}")
            state = state.add_constraint(constraint)
        state = state.push(result)
    else:
        result, constraint = SymbolicString.symbolic(f"converted_{state.pc}")
        state = state.add_constraint(constraint)
        state = state.push(result)

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
