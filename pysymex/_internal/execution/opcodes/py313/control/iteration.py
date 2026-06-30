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

"""Python 3.13 iteration opcode wrappers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.dispatch.dispatcher.decorators import opcode_handler
from pysymex._internal.execution.opcodes.common.control.iteration.handlers import (
    handle_common_end_for,
    handle_common_for_iter,
    handle_common_get_iter,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult


@opcode_handler("FOR_ITER")
def handle_py313_for_iter(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Iterate over a sequence with symbolic index tracking."""
    return handle_common_for_iter(instr, state, ctx)


@opcode_handler("GET_ITER")
def handle_py313_get_iter(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Get iterator from iterable."""
    return handle_common_get_iter(instr, state, ctx)


@opcode_handler("END_FOR")
def handle_py313_end_for(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """End of for loop cleanup."""
    return handle_common_end_for(instr, state, ctx)
