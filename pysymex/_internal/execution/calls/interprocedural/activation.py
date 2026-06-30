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

"""Callee frame and bytecode activation for interprocedural entry."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.state.types import wrap_cow_dict

if TYPE_CHECKING:
    import dis
    from collections.abc import Mapping, Sequence

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def push_interprocedural_frame(
    *,
    state: VMState,
    frame: CallFrame,
    new_locals: Mapping[str, StackValue],
) -> VMState:
    """Install callee locals and push the retained caller frame."""
    state.local_vars = wrap_cow_dict(dict(new_locals))
    return state.push_call(frame)


def activate_callee_bytecode(
    *,
    state: VMState,
    ctx: OpcodeDispatcher,
    new_locals: Mapping[str, StackValue],
    callee_instructions: Sequence[dis.Instruction],
    exception_entries: Sequence[object],
) -> VMState:
    """Switch VM and dispatcher instruction streams to the callee bytecode."""
    instructions = list(callee_instructions)
    state.local_vars = wrap_cow_dict(dict(new_locals))
    state.current_instructions = cast("list[object]", list(instructions))
    ctx.register_exception_entries(instructions, list(exception_entries))
    ctx.set_instructions(instructions)
    state = state.set_pc(0)
    state.depth += 1
    return state
