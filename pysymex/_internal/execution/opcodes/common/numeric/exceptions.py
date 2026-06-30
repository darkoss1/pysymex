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

"""Modeled exception routing used by numeric opcode handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.exceptions.policy import modeled_exception

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def jump_to_modeled_exception_handler(
    state: VMState,
    ctx: OpcodeDispatcher | None,
    instr: dis.Instruction,
    exception_name: str,
    message: str | None = None,
    confidence: float = 1.0,
    likelihood: float = 1.0,
) -> VMState | None:
    """Route a modeled exception through the current exception handler, if any."""
    if ctx is None:
        return None

    from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow

    exc: StackValue = modeled_exception(
        exception_name,
        message=message,
        state=state,
        instr=instr,
        confidence=confidence,
        likelihood=likelihood,
    )
    return ExceptionFlow.jump_to_handler(state, ctx, instr.offset, exc)
