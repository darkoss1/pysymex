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

"""Opcode metadata policy helpers.

Only opcodes in ``SAFE_METADATA_NOOPS`` may advance the program counter without
changing symbolic state. Internal/reserved and instrumented pseudo-opcodes are
rejected so they cannot be mistaken for Python-level semantics.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher

SAFE_METADATA_NOOPS = frozenset(("CACHE", "EXTENDED_ARG", "NOP", "PRECALL", "RESUME"))


def handle_common_metadata_noop(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Advance past a proven metadata no-op.

    This is deliberately allowlisted. A new opcode must not get silent no-op
    behavior merely because its handler is convenient to implement that way.
    """
    _ = ctx
    if instr.opname not in SAFE_METADATA_NOOPS:
        msg = f"Opcode is not an approved metadata no-op: {instr.opname}"
        raise RuntimeError(msg)
    return OpcodeResult.continue_with(state.advance_pc())


def handle_common_reserved_opcode(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Reject CPython reserved/internal opcode slots."""
    _ = state
    _ = ctx
    msg = f"Unsupported internal opcode: {instr.opname}"
    raise RuntimeError(msg)


def handle_common_instrumented_opcode(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Reject PEP 669 instrumented pseudo-opcodes unless explicitly lowered.

    Instrumented call, return, jump, and iteration opcodes carry real control or
    stack effects through their base opcode. Treating them as pass-through would
    silently skip user code, so the safe default is a hard failure.
    """
    _ = state
    _ = ctx
    msg = f"Unsupported instrumented pseudo-opcode: {instr.opname}"
    raise RuntimeError(msg)
