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

"""Python 3.13 intrinsic and length opcode wrappers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.dispatch.dispatcher.decorators import opcode_handler
from pysymex._internal.execution.opcodes.common.control.intrinsics import (
    handle_common_call_intrinsic_1,
    handle_control_call_intrinsic_2,
)
from pysymex._internal.execution.opcodes.common.control.length import handle_common_get_len

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult


@opcode_handler("GET_LEN")
def handle_py313_get_len(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Get length of top of stack."""
    return handle_common_get_len(instr, state, ctx)


@opcode_handler("CALL_INTRINSIC_1")
def handle_py313_call_intrinsic_1(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Call single-argument intrinsic function."""
    return handle_common_call_intrinsic_1(instr, state, ctx)


@opcode_handler("CALL_INTRINSIC_2")
def handle_py313_call_intrinsic_2(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Call two-argument intrinsic function."""
    return handle_control_call_intrinsic_2(instr, state, ctx)
