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

"""ExceptionGroup match and interpreter-exit helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow
from pysymex._internal.execution.opcodes.common.exceptions.groups import split_known_exception_group

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def handle_common_check_eg_match(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Check ExceptionGroup match (Python 3.11+ except* syntax)."""
    ExceptionFlow.require_depth(state, instr, 2, "CHECK_EG_MATCH")
    requested_type = state.pop()
    group = state.pop()
    if group is None or isinstance(group, SymbolicNoneType):
        state = _push_check_eg_match_outputs(
            state,
            SymbolicNoneType("eg_rest"),
            SymbolicNoneType("eg_match"),
        )
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    known_split = split_known_exception_group(group, requested_type, state)
    if known_split is not None:
        rest, match = known_split
        state = _push_check_eg_match_outputs(state, rest, match)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    match_val, c1 = SymbolicValue.symbolic(f"eg_match_{state.pc}")
    rest_val, c2 = SymbolicValue.symbolic(f"eg_rest_{state.pc}")
    state = _push_check_eg_match_outputs(state, rest_val, match_val)
    state = state.add_constraint(c1)
    state = state.add_constraint(c2)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _push_check_eg_match_outputs(state: VMState, rest: StackValue, match: StackValue) -> VMState:
    """Push ``CHECK_EG_MATCH`` outputs while preserving CPython except* list layout."""
    if state.stack and isinstance(state.stack[-1], SymbolicList):
        exception_list = state.pop()
        state = state.push(rest)
        state = state.push(exception_list)
        return state.push(match)
    state = state.push(rest)
    return state.push(match)


def handle_common_interpreter_exit(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Exit the interpreter (Python 3.12+, for PEP 669 monitoring)."""
    return OpcodeResult.terminate()
