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

"""BINARY_SLICE read semantics for native slice opcodes."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.slices import (
    UNSUPPORTED_SLICE_ABSTRACTION,
)
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.collections.fallbacks import (
    CollectionFallbackEvents,
)
from pysymex._internal.execution.opcodes.common.collections.protocols.index import (
    route_modeled_slice_index,
)
from pysymex._internal.execution.opcodes.common.collections.slice.shared import (
    concrete_binary_slice,
)
from pysymex._internal.execution.opcodes.common.collections.stack_ops import CollectionStackOps
from pysymex._internal.core.types.containers.sequence_precision import (
    slice_concrete_backed_sequence,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def handle_common_binary_slice(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``BINARY_SLICE``: pop slice bounds then container, push sliced value.

    Tries modeled ``__getitem__``/slice protocols, then concrete string/list lowering
    or havoc with ``UNSUPPORTED_SLICE_ABSTRACTION`` when precision is lost.
    """
    _ = ctx
    CollectionStackOps.require_depth(state, instr, 3, "BINARY_SLICE container, start, and stop")
    stop = state.pop()
    start = state.pop()
    container = state.pop()

    protocol_result = route_modeled_slice_index(state, ctx, [container], start, stop)
    if protocol_result is not None:
        return protocol_result

    concrete_slice = concrete_binary_slice(start, stop)
    real_container = (
        container
        if isinstance(container, SymbolicList)
        else SymbolicObject.resolve_runtime_container(container, state)
    )
    if concrete_slice is not None and isinstance(real_container, SymbolicList):
        retained = slice_concrete_backed_sequence(
            real_container,
            concrete_slice,
            state.path_constraints.to_list(),
        )
        if retained is not None:
            state = state.push(retained)
            return OpcodeResult.continue_with(state.advance_pc())
    if concrete_slice is not None and isinstance(real_container, SymbolicBytes):
        retained_bytes = _slice_symbolic_bytes(real_container, concrete_slice, state.pc)
        if retained_bytes is not None:
            state = state.push(retained_bytes)
            return OpcodeResult.continue_with(state.advance_pc())
    if concrete_slice is not None and isinstance(real_container, SymbolicString):
        retained_string = _slice_symbolic_string(real_container, concrete_slice)
        if retained_string is not None:
            state = state.push(retained_string)
            return OpcodeResult.continue_with(state.advance_pc())

    if not isinstance(start, SymbolicValue):
        start = SymbolicValue.from_const(start)
    if not isinstance(stop, SymbolicValue):
        stop = SymbolicValue.from_const(stop)

    if isinstance(container, SymbolicNoneType):
        result, constraint = SymbolicValue.symbolic(f"slice_{state.pc}")
        state = state.add_constraint(constraint)
        state = state.push(result)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    if isinstance(container, SymbolicString):
        length_val = stop.z3_int - start.z3_int
        real_start = z3.If(start.z3_int < 0, start.z3_int + container.z3_len, start.z3_int)
        result = container.substring(
            _to_int_val(f"start_{state.pc}", real_start),
            _to_int_val(f"len_{state.pc}", length_val),
        )
        state = state.push(result)
    elif isinstance(container, SymbolicList):
        result_len = z3.Int(f"slice_len_{state.pc}")
        result, constraint = SymbolicList.symbolic(f"slice_{state.pc}")
        result.z3_len = result_len
        state = state.add_constraint(constraint)
        state = state.add_constraint(result_len >= 0)
        state = state.push(result)
    else:
        result, constraint = SymbolicValue.symbolic(f"slice_{state.pc}")
        state = state.add_constraint(constraint)
        state = state.push(result)
    fallback_event = CollectionFallbackEvents.unsupported_slice(
        state=state,
        reason="BINARY_SLICE precision was reduced to a symbolic slice result",
    )
    state = state.advance_pc()
    return OpcodeResult.continue_with(
        state,
        degraded_passes=[UNSUPPORTED_SLICE_ABSTRACTION],
        fallback_events=[fallback_event],
    )


def _to_int_val(name: str, expr: z3.ArithRef) -> SymbolicValue:
    """Build an integer-typed symbolic value from an existing Z3 arithmetic term."""
    return SymbolicValue(
        _name=name,
        z3_int=expr,
        is_int=Z3_TRUE,
        is_bool=Z3_FALSE,
        z3_bool=Z3_FALSE,
    )


def _slice_symbolic_bytes(value: SymbolicBytes, key: slice, _pc: int) -> SymbolicBytes | None:
    """Return an exact symbolic bytes slice for unit-step BINARY_SLICE bounds."""
    return value.slice_value(key)


def _slice_symbolic_string(value: SymbolicString, key: slice) -> SymbolicString | None:
    """Return an exact symbolic string slice for unit-step BINARY_SLICE bounds."""
    return value.slice_value(key)
