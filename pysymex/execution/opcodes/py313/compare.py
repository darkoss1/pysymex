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

"""Comparison opcode wrappers for Python 3.13.

Registers ``COMPARE_OP``, ``IS_OP``, and ``CONTAINS_OP`` handlers that delegate
to :mod:`pysymex.execution.opcodes.common.compare` for symbolic relational
constraints and static constraint elision. Does not own rich comparison
modeling, ``__contains__`` dispatch, or solver interaction.
.

Each ``@opcode_handler`` entry registers CPython opcode names for this interpreter version and delegates semantics to :mod:`pysymex.execution.opcodes.common` (stack effects, forks, constraints, and limitations are documented on the common handlers)."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex.execution.dispatch.dispatcher import opcode_handler
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.compare import (
    handle_common_compare_op,
    handle_common_contains_op,
    handle_common_is_op,
)

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


@opcode_handler("COMPARE_OP")
def handle_compare_op(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Comparison operation with Static Constraint Elision."""
    return handle_common_compare_op(instr, state, ctx)


@opcode_handler("IS_OP")
def handle_is_op(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Identity comparison (is / is not)."""
    return handle_common_is_op(instr, state, ctx)


@opcode_handler("CONTAINS_OP")
def handle_contains_op(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Membership test (in / not in)."""
    return handle_common_contains_op(instr, state, ctx)
