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

"""Modeled ``TypeError`` routing for opcode handlers.

Centralizes the common CPython-compatible path: build a symbolic ``TypeError``,
enter an exception-table handler when available, or emit a deterministic
``TYPE_ERROR`` issue for an uncaught feasible runtime error.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.exceptions.helpers import jump_to_exception_handler

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def type_error_result(
    state: VMState,
    ctx: OpcodeDispatcher,
    caller_offset: int,
    message: str,
) -> OpcodeResult:
    """Route or report a concrete CPython ``TypeError`` at *caller_offset*."""
    modeled_exc = SymbolicException.concrete(TypeError, message, raised_at=state.pc)
    handler_state = jump_to_exception_handler(state, ctx, caller_offset, modeled_exc)
    if handler_state is not None:
        return OpcodeResult.continue_with(handler_state)

    issue = Issue(
        kind=IssueKind.TYPE_ERROR,
        message=f"Possible TypeError: {message}",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)


__all__ = ["type_error_result"]
