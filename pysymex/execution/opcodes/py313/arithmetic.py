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

"""Arithmetic opcode wrappers for Python 3.13.

Each ``@opcode_handler`` entry registers CPython opcode names for this interpreter version and delegates semantics to :mod:`pysymex.execution.opcodes.common` (stack effects, forks, constraints, and limitations are documented on the common handlers)."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex.execution.dispatch.dispatcher import opcode_handler
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.numeric.ops import (
    handle_numeric_binary_op,
    handle_unary_invert as handle_common_unary_invert,
    handle_unary_negative as handle_common_unary_negative,
    handle_unary_not as handle_common_unary_not,
    handle_unary_positive as handle_common_unary_positive,
)

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


@opcode_handler("BINARY_OP")
def handle_binary_op(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Dispatch numeric ``BINARY_OP`` handling through shared Phase 1 semantics."""
    return handle_numeric_binary_op(instr, state, ctx)


def handle_unary_positive(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Apply Python unary ``+`` semantics.

    CPython raises ``TypeError`` for ``+`` on non-numeric types (e.g. ``str``).
    Symbolic strings therefore terminate this path rather than pass through silently.
    """
    return handle_common_unary_positive(instr, state, ctx)


@opcode_handler("UNARY_NEGATIVE")
def handle_unary_negative(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Apply Python unary ``-`` semantics."""
    _ = (instr, ctx)
    return handle_common_unary_negative(state)


@opcode_handler("UNARY_NOT")
def handle_unary_not(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Apply Python unary ``not`` semantics."""
    _ = (instr, ctx)
    return handle_common_unary_not(state)


@opcode_handler("UNARY_INVERT")
def handle_unary_invert(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Apply Python unary ``~`` semantics."""
    _ = (instr, ctx)
    return handle_common_unary_invert(state)


@opcode_handler("LOAD_ATTR")
def handle_load_attr(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Load an attribute, checking heap memory and modeled object state."""
    from pysymex.execution.opcodes.common.functions import handle_common_load_method

    return handle_common_load_method(instr, state, ctx)
