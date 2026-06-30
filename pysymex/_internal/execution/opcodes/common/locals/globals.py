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

"""Global namespace opcode handlers and global write-ledger events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.bytecode import global_name_from_argval
from pysymex._internal.core.effects.events import WriteEvent, WriteKind
from pysymex._internal.core.effects.locations import global_write_location
from pysymex._internal.core.exceptions.policy import name_error
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.locals.stack_ops import LocalStackOps

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def handle_common_load_global(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Load a global variable onto the stack."""
    from pysymex._internal.execution.opcodes.common.affinity import BUILTIN_TYPES

    name = global_name_from_argval(instr.argval)
    push_null = False
    if hasattr(instr, "arg") and instr.arg is not None and instr.arg & 1:
        push_null = True
    value = state.get_global(name)

    if value is None:
        if name in state.global_vars:
            value = SymbolicNoneType()
        else:
            if not _should_symbolize_missing_global(name, BUILTIN_TYPES):
                return _missing_global_result(instr, state, ctx, name)
            sym_val, type_constraint = SymbolicValue.symbolic(f"global_{name}")
            sym_val.model_name = name
            if name in BUILTIN_TYPES:
                sym_val.affinity_type = BUILTIN_TYPES[name]
            state = state.add_constraint(z3.Not(sym_val.is_none))

            state = state.set_global(name, sym_val)
            state = state.add_constraint(type_constraint)
            value = sym_val
    if push_null:
        state = state.push(SymbolicNoneType())
    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _missing_global_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    name: str,
) -> OpcodeResult:
    """Raise ``NameError`` for a missing user global without fabricating a value."""
    message = f"name '{name}' is not defined"
    from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow

    handled_state = ExceptionFlow.jump_to_handler(
        state,
        ctx,
        instr.offset,
        name_error(message, state=state, instr=instr),
    )
    if handled_state is not None:
        return OpcodeResult.continue_with(handled_state)
    return OpcodeResult.error(
        Issue(
            kind=IssueKind.NAME_ERROR,
            message=f"Variable '{name}' may be unbound (NameError)",
            constraints=list(state.path_constraints),
            pc=state.pc,
        ),
    )


def _should_symbolize_missing_global(name: str, builtin_types: dict[str, str]) -> bool:
    """Return whether a missing global is an intentional modeled symbolic binding."""
    return name in builtin_types


def handle_common_store_global(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Store top of stack into a global variable."""
    name = str(instr.argval)
    LocalStackOps.require_depth(state, instr, 1, "STORE_GLOBAL value")
    value = state.pop()
    state = state.set_global(name, value)
    location = global_write_location(name)
    state = state.record_write_event(
        WriteEvent(WriteKind.GLOBAL, location.name, state.pc, location.precise, instr.opname),
    )
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_delete_global(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Delete a global variable."""
    name = str(instr.argval)
    if name in state.global_vars:
        del state.global_vars[name]
        location = global_write_location(name)
        state = state.record_write_event(
            WriteEvent(WriteKind.GLOBAL, location.name, state.pc, location.precise, instr.opname),
        )
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
