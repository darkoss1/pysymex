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

"""Shared native and retained slice mutation helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.effects.events import WriteEvent, WriteKind
from pysymex._internal.core.effects.locations import item_write_location
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.slices import UNSUPPORTED_SLICE_ABSTRACTION
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.collections.fallbacks import (
    CollectionFallbackEvents,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def record_slice_write(state: VMState, container: StackValue, instr: dis.Instruction) -> VMState:
    """Record a successful exact list slice write."""
    location = item_write_location(state, container)
    return state.record_write_event(
        WriteEvent(WriteKind.ITEM, location.name, state.pc, location.precise, instr.opname),
    )


def replace_direct_container_aliases(
    state: VMState,
    old_container: object,
    new_container: StackValue,
) -> VMState:
    """Refresh aliases and source carriers after exact list slice mutation."""
    from pysymex._internal.execution.opcodes.common.functions.classes.instances.aliases import (
        propagate_container_mutation_reference,
    )

    return propagate_container_mutation_reference(state, old_container, new_container)


def unsupported_slice_result(state: VMState, *, reason: str) -> OpcodeResult:
    """Terminate with unsupported slice abstraction degradation."""
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_SLICE_ABSTRACTION],
        fallback_events=[CollectionFallbackEvents.unsupported_slice(state=state, reason=reason)],
        terminal=True,
    )


_UNRESOLVED_SLICE_BOUND = object()


def concrete_binary_slice(start: object, stop: object) -> slice | None:
    """Return a concrete two-bound slice when both CPython bounds are known."""
    concrete_start = _concrete_binary_slice_bound(start)
    concrete_stop = _concrete_binary_slice_bound(stop)
    if _UNRESOLVED_SLICE_BOUND in (concrete_start, concrete_stop):
        return None
    return slice(concrete_start, concrete_stop)


def _concrete_binary_slice_bound(value: object) -> int | None | object:
    """Resolve a BINARY_SLICE start/stop operand to int, None, or unresolved."""
    if value is None or isinstance(value, SymbolicNoneType):
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, SymbolicValue):
        if z3.is_true(simplify_expr(value.is_none)):
            return None
        concrete = value.value
        if isinstance(concrete, bool):
            return int(concrete)
        if isinstance(concrete, int):
            return concrete
        expr = simplify_expr(value.z3_int)
        if z3.is_int_value(expr):
            return expr.as_long()
    return _UNRESOLVED_SLICE_BOUND
