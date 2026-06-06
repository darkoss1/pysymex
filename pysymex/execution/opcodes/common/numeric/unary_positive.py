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

"""Unary ``+`` opcode helpers with definite TypeError routing.

Distinguishes numeric affinities from invalid container types, records
``unary_positive_type_uncertain`` when symbolic affinity is ambiguous, and
routes modeled ``TypeError`` through exception handlers when present.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.numeric.fallbacks import unary_positive_uncertain_event
from pysymex.execution.opcodes.common.numeric.helpers import jump_to_modeled_exception_handler
from pysymex.execution.opcodes.common.numeric.labels import UNARY_POSITIVE_TYPE_UNCERTAIN

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher

# Affinities that CPython accepts for unary ``+`` without raising TypeError.
_NUMERIC_UNARY_AFFINITIES = frozenset({"int", "bool", "float"})
# Non-numeric affinity tags that definitely raise TypeError for unary ``+``.
_INVALID_UNARY_AFFINITY_TYPES = {
    "str": "str",
    "list": "list",
    "dict": "dict",
    "NoneType": "NoneType",
}


def handle_unary_positive(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher | None = None,
) -> OpcodeResult:
    """Execute Python-faithful unary positive semantics."""
    value = state.pop()
    return continue_unary_positive_value(instr, state, ctx, value)


def continue_unary_positive_value(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher | None,
    value: object,
) -> OpcodeResult:
    """Continue after applying CPython unary ``+`` semantics to a popped value."""
    if isinstance(value, (int, float, bool)):
        state = state.push(+value)
        return OpcodeResult.continue_with(state.advance_pc())

    invalid_type = definite_invalid_unary_positive_type_name(value)
    if invalid_type is not None:
        return unary_positive_type_error(instr, state, ctx, invalid_type)

    if isinstance(value, SymbolicValue):
        state = state.push(value)
        if value.affinity_type not in _NUMERIC_UNARY_AFFINITIES:
            fallback_event = unary_positive_uncertain_event(
                state=state,
                reason="symbolic unary + affinity is not provably numeric",
            )
            return OpcodeResult.continue_with(
                state.advance_pc(),
                degraded_passes=[UNARY_POSITIVE_TYPE_UNCERTAIN],
                fallback_events=[fallback_event],
            )
        return OpcodeResult.continue_with(state.advance_pc())

    symbolic = SymbolicValue.from_const(value)
    fallback_event = unary_positive_uncertain_event(
        state=state,
        reason="non-modeled unary + operand was converted to a symbolic value",
    )
    state = state.push(symbolic)
    return OpcodeResult.continue_with(
        state.advance_pc(),
        degraded_passes=[UNARY_POSITIVE_TYPE_UNCERTAIN],
        fallback_events=[fallback_event],
    )


def definite_invalid_unary_positive_type_name(value: object) -> str | None:
    """Return a CPython type name when unary ``+`` definitely raises TypeError."""
    if isinstance(value, SymbolicString):
        return "str"
    if isinstance(value, SymbolicNone):
        return "NoneType"
    if isinstance(value, SymbolicValue):
        if value.affinity_type in _NUMERIC_UNARY_AFFINITIES:
            return None
        return _INVALID_UNARY_AFFINITY_TYPES.get(value.affinity_type)
    if isinstance(value, (str, bytes, bytearray, list, dict, tuple, set)):
        return type(cast(object, value)).__name__
    if value is None:
        return "NoneType"
    if hasattr(type(value), "__pos__"):
        return None
    return type(value).__name__


def unary_positive_type_error(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher | None,
    type_name: str,
) -> OpcodeResult:
    """Route or report CPython's unary-positive TypeError."""
    handled_state = jump_to_modeled_exception_handler(state, ctx, instr, "TypeError")
    if handled_state is not None:
        return OpcodeResult.continue_with(handled_state)
    issue = Issue(
        kind=IssueKind.TYPE_ERROR,
        message=f"Possible TypeError: bad operand type for unary +: '{type_name}'",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)
