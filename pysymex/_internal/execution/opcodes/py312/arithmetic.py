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

"""Arithmetic opcode wrappers for Python 3.12.

Each ``@opcode_handler`` entry registers CPython opcode names for this interpreter version and delegates semantics to :mod:`pysymex._internal.execution.opcodes.common` (stack effects, forks, constraints, and limitations are documented on the common handlers).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.dispatch.dispatcher.decorators import opcode_handler
from pysymex._internal.execution.opcodes.common.numeric.ops.dispatch import (
    handle_numeric_binary_op,
    handle_numeric_unary_invert,
    handle_numeric_unary_negative,
    handle_numeric_unary_not,
    handle_numeric_unary_positive,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult


@opcode_handler("BINARY_OP")
def handle_py312_binary_op(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Dispatch numeric ``BINARY_OP`` handling through shared Phase 1 semantics."""
    return handle_numeric_binary_op(instr, state, ctx)


@opcode_handler("UNARY_POSITIVE")
def handle_py312_unary_positive(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Apply Python unary ``+`` semantics.

    CPython raises ``TypeError`` for ``+`` on non-numeric types (e.g. ``str``).
    Symbolic strings therefore terminate this path rather than pass through silently.
    """
    return handle_numeric_unary_positive(instr, state, ctx)


@opcode_handler("UNARY_NEGATIVE")
def handle_py312_unary_negative(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Apply Python unary ``-`` semantics."""
    _ = (instr, ctx)
    return handle_numeric_unary_negative(state)


@opcode_handler("UNARY_NOT")
def handle_py312_unary_not(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Apply Python unary ``not`` semantics."""
    _ = (instr, ctx)
    return handle_numeric_unary_not(state)


@opcode_handler("UNARY_INVERT")
def handle_py312_unary_invert(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Apply Python unary ``~`` semantics."""
    _ = (instr, ctx)
    return handle_numeric_unary_invert(state)


@opcode_handler("LOAD_ATTR")
def handle_py312_load_attr(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Load an attribute, checking heap memory and modeled object state."""
    from pysymex._internal.execution.opcodes.common.functions.attribute.load.handler import (
        handle_common_load_method,
    )

    return handle_common_load_method(instr, state, ctx)
