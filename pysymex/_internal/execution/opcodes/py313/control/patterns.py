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

"""Python 3.13 pattern-matching opcode wrappers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.dispatch.dispatcher.decorators import opcode_handler
from pysymex._internal.execution.opcodes.common.control.match.handlers import (
    handle_common_match_class,
    handle_common_match_keys,
    handle_common_match_mapping,
    handle_common_match_sequence,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult


@opcode_handler("MATCH_MAPPING")
def handle_py313_match_mapping(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Test whether the TOS match subject is a mapping.

    Delegates to :mod:`pysymex._internal.execution.opcodes.common.control.match`. Pushes a
    truthy :class:`~pysymex._internal.core.types.scalars.values.SymbolicValue` and leaves the
    subject on the stack.
    """
    return handle_common_match_mapping(instr, state, ctx)


@opcode_handler("MATCH_SEQUENCE")
def handle_py313_match_sequence(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Test whether the TOS match subject is a sequence.

    Delegates to :mod:`pysymex._internal.execution.opcodes.common.control.match`. Pushes a
    truthy :class:`~pysymex._internal.core.types.scalars.values.SymbolicValue` and leaves the
    subject on the stack.
    """
    return handle_common_match_sequence(instr, state, ctx)


@opcode_handler("MATCH_KEYS")
def handle_py313_match_keys(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Check if mapping has required keys for pattern matching."""
    return handle_common_match_keys(instr, state, ctx)


@opcode_handler("MATCH_CLASS")
def handle_py313_match_class(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Match a class pattern and push captured attribute values.

    Pops class, attribute-name tuple, and subject, then delegates to
    :mod:`pysymex._internal.execution.opcodes.common.control.match`. Pushes captured
    values on success or a no-match sentinel when the pattern cannot apply.

    Limitations:
        Symbolic subjects without a modeled ``isinstance`` path use conservative
        success expressions; custom classes may be approximated.
    """
    return handle_common_match_class(instr, state, ctx)
