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

"""``LOAD_CONST`` conversion into VM stack values."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def handle_common_load_const(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Load a constant onto the stack."""
    value = instr.argval
    sym_val: StackValue
    if value is None:
        sym_val = SymbolicNoneType("load_const_None")
    elif isinstance(value, str):
        sym_val = SymbolicString.from_const(value)
    elif isinstance(value, tuple):
        # Immutable literal tuples carry sequence and pattern metadata exactly.
        sym_val = cast("StackValue", value)
    else:
        sym_val = SymbolicValue.from_const(value)

    state = state.push(sym_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
