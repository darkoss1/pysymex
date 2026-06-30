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

"""Fast-local load, store, delete, and maybe-null opcode handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.constants import Z3_TRUE
from pysymex._internal.core.exceptions.policy import unbound_local_error
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.types import UNBOUND, is_bound
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.locals.stack_ops import LocalStackOps

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def handle_common_load_fast(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Load a local variable onto the stack."""
    name = str(instr.argval)
    raw_value = state.get_local(name)
    if is_bound(raw_value):
        value = raw_value
    else:
        sym_val, type_constraint = SymbolicValue.symbolic(name)
        if any(
            s in name.lower()
            for s in ("substitutions", "config", "mapping", "settings", "options_map")
        ):
            sym_val.is_dict = Z3_TRUE

        state = state.set_local(name, sym_val)
        state = state.add_constraint(type_constraint)
        value = sym_val

    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_fast_check(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Load local variable with UnboundLocalError check."""
    name = str(instr.argval)
    raw_value = state.get_local(name)
    if is_bound(raw_value):
        value = raw_value
    else:
        return _unbound_fast_check_result(instr, state, ctx, name)
    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _unbound_fast_check_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    name: str,
) -> OpcodeResult:
    """Raise ``UnboundLocalError`` for checked fast-local reads without a value."""
    message = f"cannot access local variable '{name}' where it is not associated with a value"
    from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow

    handled_state = ExceptionFlow.jump_to_handler(
        state,
        ctx,
        instr.offset,
        unbound_local_error(message, state=state, instr=instr),
    )
    if handled_state is not None:
        return OpcodeResult.continue_with(handled_state)
    return OpcodeResult.error(
        Issue(
            kind=IssueKind.UNBOUND_VARIABLE,
            message=f"Variable '{name}' may be unbound (UnboundLocalError)",
            constraints=list(state.path_constraints),
            pc=state.pc,
        ),
    )


def handle_common_store_fast(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Store top of stack into local variable."""
    name = str(instr.argval)
    LocalStackOps.require_depth(state, instr, 1, "STORE_FAST value")
    value: StackValue = state.pop()
    state = state.set_local(name, value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_delete_fast(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``DELETE_FAST``: remove a fast-local binding when present.

    CPython stack effect: none (operand names the slot). No-op when the slot is unset.
    """
    name = str(instr.argval)
    state = state.set_local(name, UNBOUND)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_fast_and_clear(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Load local variable and set slot to NULL (list comprehension save/restore)."""
    name = str(instr.argval)
    raw_value = state.get_local(name)
    value = raw_value if is_bound(raw_value) else SymbolicNoneType()
    state = state.push(value)
    state = state.set_local(name, UNBOUND)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_store_fast_maybe_null(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Store to local that might be uninitialized (exception handling)."""
    name = str(instr.argval)
    LocalStackOps.require_depth(state, instr, 1, "STORE_FAST_MAYBE_NULL value")
    value = state.pop()
    state = state.set_local(name, value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
