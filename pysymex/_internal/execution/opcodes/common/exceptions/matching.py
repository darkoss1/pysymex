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

"""``CHECK_EXC_MATCH`` exception-handler matching semantics."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.exceptions.policy import type_error
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.exceptions.classes import (
    concrete_exception_match,
    has_definite_invalid_exception_handler,
    realize_exception_items,
)
from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher

_INVALID_EXCEPTION_HANDLER_MESSAGE = (
    "catching classes that do not inherit from BaseException is not allowed"
)


def handle_common_check_exc_match(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Check if exception matches."""
    ExceptionFlow.require_depth(state, instr, 2, "CHECK_EXC_MATCH")
    exc_types = state.pop()
    exc = state.stack[-1]

    if exc is not None and exc_types is not None:
        exc_name = str(getattr(exc, "type_name", "") or getattr(exc, "name", ""))

        def _matches(t: object) -> bool:
            """Return whether *t* matches the raised exception's type name."""
            t_name = t.__name__ if isinstance(t, type) else str(t)
            return (
                t_name in {"BaseException", "Exception"}
                or t_name == exc_name
                or (bool(exc_name) and (t_name in exc_name or exc_name in t_name))
            )

        match_found = False
        exc_types_obj: object = exc_types
        items = realize_exception_items(exc_types_obj)
        match_found = any(_matches(t) for t in items) if items else _matches(exc_types)

        exc_types_name = exc_types_obj.__name__ if isinstance(exc_types_obj, type) else ""
        handler_items = items or [exc_types]
        if has_definite_invalid_exception_handler(handler_items):
            return _invalid_exception_handler_type_error(instr, state, ctx)
        concrete_match = concrete_exception_match(exc, handler_items)
        if concrete_match is not None:
            state = state.push(SymbolicValue.from_const(concrete_match))
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)
        if match_found or exc_types_name in {"BaseException", "Exception"}:
            state = state.push(SymbolicValue.from_const(True))
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

    result, constraint = SymbolicValue.symbolic(f"exc_match_{state.pc}")
    state = state.push(result)
    state = state.add_constraint(constraint)
    state = state.add_constraint(result.is_bool)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _invalid_exception_handler_type_error(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Route CPython's invalid exception-handler TypeError."""
    exc = type_error(_INVALID_EXCEPTION_HANDLER_MESSAGE, state=state, instr=instr)
    handler_state = ExceptionFlow.jump_to_handler(state, ctx, instr.offset, exc)
    if handler_state is not None:
        return OpcodeResult.continue_with(handler_state)
    issue = Issue(
        kind=IssueKind.TYPE_ERROR,
        message=f"Possible TypeError: {_INVALID_EXCEPTION_HANDLER_MESSAGE}",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)
