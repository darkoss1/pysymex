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

"""Stack, heap, constraint, and unpack helpers for collection opcode handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.types import VMStateError
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.types.stack_coercion import StackValuePolicy
from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    import dis
    from collections.abc import Sequence

    import z3

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.fallback.types import FallbackEvent
    from pysymex._internal.typing.protocols import StackValue


class CollectionStackOps:
    """Domain owner for collection opcode stack, heap, and unpack operations."""

    @staticmethod
    def require_depth(
        state: VMState,
        instr: dis.Instruction,
        required_depth: int,
        purpose: str,
    ) -> None:
        """Raise :class:`~pysymex._internal.core.state.types.VMStateError` when the stack is too shallow."""
        if len(state.stack) < required_depth:
            msg = (
                f"{instr.opname} at pc {state.pc}: stack depth {len(state.stack)} "
                f"cannot satisfy {required_depth} item(s) for {purpose}"
            )
            raise VMStateError(
                msg,
            )

    @staticmethod
    def add_lowered_constraints(state: VMState, constraints: list[z3.BoolRef]) -> VMState:
        """Append lowered Z3 constraints to *state* and return the updated state."""
        for constraint in constraints:
            state = state.add_constraint(constraint)
        return state

    @staticmethod
    def apply_heap_updates(state: VMState, updates: list[tuple[int, StackValue]]) -> VMState:
        """Apply a sequence of heap updates while maintaining VMState hash invariants."""
        for address, value in updates:
            state = state.store_heap(address, value)
        return state

    @staticmethod
    def branch_or_terminate_exception(
        instr: dis.Instruction,
        state: VMState,
        ctx: OpcodeDispatcher,
        exception_condition: z3.BoolRef,
        *,
        fallback_events: list[FallbackEvent] | None = None,
    ) -> OpcodeResult:
        """Fork to an exception handler or terminate when no handler exists."""
        from pysymex._internal.execution.feasibility.unknowns import (
            degraded_passes_from_events,
            terminal_result_with_events,
        )

        events = fallback_events or []
        handler_pc = ctx.find_exception_handler(instr.offset)
        if handler_pc is None:
            return terminal_result_with_events(events)
        error_state = state.fork().add_constraint(exception_condition)
        return OpcodeResult.continue_with(
            error_state.set_pc(handler_pc),
            degraded_passes=degraded_passes_from_events(events),
            fallback_events=events,
        )

    @staticmethod
    def unpack_at(container: StackValue, index: int) -> StackValue:
        """Read one UNPACK_SEQUENCE element, using havoc when the source is unknown."""
        if isinstance(container, SymbolicTuple):
            return StackValuePolicy.coerce(container[index])

        if isinstance(container, SymbolicList):
            concrete_items = container.concrete_items
            if concrete_items is not None and 0 <= index < len(concrete_items):
                return StackValuePolicy.coerce(concrete_items[index])
            return container[index]

        if isinstance(container, (list, tuple, str, bytes, bytearray, range)):
            return StackValuePolicy.coerce(cast("Sequence[object]", container)[index])

        val, _constraint = SymbolicValue.symbolic(f"unpack_item_{index}")
        return val

    @staticmethod
    def unpack_arity_error(
        instr: dis.Instruction,
        state: VMState,
        ctx: OpcodeDispatcher,
        *,
        expected: int,
        actual: int,
    ) -> OpcodeResult:
        """Route arity mismatch to a handler or emit a feasible ``ValueError`` issue."""
        handler_pc = ctx.find_exception_handler(instr.offset)
        if handler_pc is not None:
            return OpcodeResult.continue_with(state.set_pc(handler_pc))

        relation = "not enough" if actual < expected else "too many"
        if actual < expected:
            message = f"{relation} values to unpack (expected {expected}, got {actual})"
        else:
            message = f"{relation} values to unpack (expected {expected})"
        issue = Issue(
            kind=IssueKind.VALUE_ERROR,
            message=f"Possible ValueError: {message}",
            constraints=list(state.path_constraints),
            pc=state.pc,
        )
        return OpcodeResult.error(issue)
