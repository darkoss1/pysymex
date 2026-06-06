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

"""BINARY_SLICE and STORE_SLICE handlers with modeled protocol fallbacks.

Delegates ``__index__`` and container slice protocols before applying string,
list, or havoc abstractions. Emits ``UNSUPPORTED_SLICE_ABSTRACTION`` when
precision is reduced to fresh symbolic values.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.effects.events import WriteEvent, WriteKind
from pysymex.core.effects.locations import item_write_location
from pysymex.core.constants import Z3_FALSE, Z3_TRUE
from pysymex.core.types.containers.bytes import SymbolicBytes
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.collections.helpers import (
    apply_heap_updates,
    require_stack_depth,
    resolve_runtime_container,
)
from pysymex.execution.opcodes.common.collections.fallbacks import unsupported_slice_event
from pysymex.execution.opcodes.common.collections.protocols import (
    dispatch_modeled_slice_index_protocol,
)
from pysymex.execution.opcodes.common.collections.slice_replacement import (
    apply_slice_replacement_iterator_exhaustion,
    exact_slice_replacement_items,
    preserve_slice_target_type,
)
from pysymex.execution.opcodes.common.lowering import CollectionLowerer
from pysymex.core.types.containers.slices import (
    UNSUPPORTED_SLICE_ABSTRACTION,
)
from pysymex.models.containers.sequence_precision import slice_concrete_backed_sequence

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def handle_common_binary_slice(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``BINARY_SLICE``: pop slice bounds then container, push sliced value.

    Tries modeled ``__getitem__``/slice protocols, then concrete string/list lowering
    or havoc with ``UNSUPPORTED_SLICE_ABSTRACTION`` when precision is lost.
    """
    _ = ctx
    require_stack_depth(state, instr, 3, "BINARY_SLICE container, start, and stop")
    stop = state.pop()
    start = state.pop()
    container = state.pop()

    protocol_result = dispatch_modeled_slice_index_protocol(state, ctx, [container], start, stop)
    if protocol_result is not None:
        return protocol_result

    concrete_slice = _concrete_binary_slice(start, stop)
    real_container = (
        container
        if isinstance(container, SymbolicList)
        else resolve_runtime_container(container, state)
    )
    if concrete_slice is not None and isinstance(real_container, SymbolicList):
        retained = slice_concrete_backed_sequence(real_container, concrete_slice)
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

    if isinstance(container, SymbolicNone):
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
    fallback_event = unsupported_slice_event(
        state=state,
        reason="BINARY_SLICE precision was reduced to a symbolic slice result",
    )
    state = state.advance_pc()
    return OpcodeResult.continue_with(
        state,
        degraded_passes=[UNSUPPORTED_SLICE_ABSTRACTION],
        fallback_events=[fallback_event],
    )


def handle_common_store_slice(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``STORE_SLICE``: assign into a container slice when modeling allows.

    CPython stack effect: pops value, slice, then container. Updates modeled lists or
    reports unsupported abstraction when bounds or container kinds are unknown.
    """
    require_stack_depth(state, instr, 4, "STORE_SLICE container, start, stop, and value")
    stop = state.pop()
    start = state.pop()
    container = state.pop()
    value = state.pop()
    preserved_operands: list[StackValue] = [value, container]
    protocol_result = dispatch_modeled_slice_index_protocol(
        state, ctx, preserved_operands, start, stop
    )
    if protocol_result is not None:
        return protocol_result
    exact_result = _try_store_exact_slice(instr, state, value, container, start, stop)
    if exact_result is not None:
        return exact_result
    return _unsupported_store_slice_result(
        state,
        reason="STORE_SLICE target, bounds, or replacement could not be mutated precisely",
    )


def _try_store_exact_slice(
    instr: dis.Instruction,
    state: VMState,
    value: StackValue,
    container: StackValue,
    start: StackValue,
    stop: StackValue,
) -> OpcodeResult | None:
    """Perform exact list slice assignment when bounds and replacement are concrete."""
    concrete_slice = _concrete_binary_slice(start, stop)
    if concrete_slice is None:
        return None
    real_container, container_addr = _resolve_slice_target(container, state)
    replacement = exact_slice_replacement_items(value, state, real_container)
    if replacement is None:
        return None
    updated_items = _store_slice_items(real_container, concrete_slice, replacement)
    if updated_items is None:
        return None

    state = _record_slice_write(state, container, instr)
    state = apply_slice_replacement_iterator_exhaustion(state, value)
    return _commit_exact_list_mutation(state, real_container, container_addr, updated_items)


def _resolve_slice_target(container: StackValue, state: VMState) -> tuple[object, int]:
    """Resolve a slice target and its heap address when it is heap backed."""
    if isinstance(container, SymbolicObject):
        return state.load_heap(container.address, container), container.address
    return resolve_runtime_container(container, state), -1


def _store_slice_items(
    container: object,
    key: slice,
    replacement: list[StackValue],
) -> list[object] | None:
    """Return concrete post-assignment list items for supported exact targets."""
    if isinstance(container, list):
        concrete_container = cast("list[object]", container)
        concrete_container[key] = list(replacement)
        return concrete_container
    if isinstance(container, SymbolicList) and container.concrete_items is not None:
        items = list(container.concrete_items)
        items[key] = list(replacement)
        return items
    return None


def _commit_exact_list_mutation(
    state: VMState,
    original_container: object,
    container_addr: int,
    items: list[object],
) -> OpcodeResult:
    """Persist exact list mutation and retarget aliases/source carriers."""
    if isinstance(original_container, list):
        return OpcodeResult.continue_with(state.advance_pc())

    built = CollectionLowerer(state.pc).build_list(cast("list[StackValue]", items))
    storage = preserve_slice_target_type(original_container, built.storage)
    state = apply_heap_updates(state, built.heap_updates)
    if container_addr != -1:
        state = state.store_heap(container_addr, storage)
    state = _replace_direct_container_aliases(state, original_container, storage)
    return OpcodeResult.continue_with(state.advance_pc())


def _record_slice_write(state: VMState, container: StackValue, instr: dis.Instruction) -> VMState:
    """Record a successful exact list slice write."""
    location = item_write_location(state, container)
    return state.record_write_event(
        WriteEvent(WriteKind.ITEM, location.name, state.pc, location.precise, instr.opname)
    )


def _replace_direct_container_aliases(
    state: VMState,
    old_container: object,
    new_container: StackValue,
) -> VMState:
    """Refresh aliases and source carriers after exact list slice mutation."""
    from pysymex.execution.opcodes.common.functions.classes import (
        propagate_container_mutation_reference,
    )

    return propagate_container_mutation_reference(state, old_container, new_container)


def _unsupported_store_slice_result(state: VMState, *, reason: str) -> OpcodeResult:
    """Terminate with unsupported native store-slice abstraction degradation."""
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_SLICE_ABSTRACTION],
        fallback_events=[unsupported_slice_event(state=state, reason=reason)],
        terminal=True,
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


_UNRESOLVED_SLICE_BOUND = object()


def _slice_symbolic_bytes(value: SymbolicBytes, key: slice, pc: int) -> SymbolicBytes | None:
    """Return an exact symbolic bytes slice for concrete nonnegative BINARY_SLICE bounds."""
    if key.step is not None:
        return None
    if value.concrete_value is not None:
        return SymbolicBytes.concrete(value.concrete_value[key])

    start = 0 if key.start is None else key.start
    stop = key.stop
    if start < 0 or (stop is not None and stop < 0):
        return None
    offset = z3.IntVal(start)
    if stop is None:
        sequence_length = z3.Length(value.z3_bytes)
        extract_length = z3.If(
            sequence_length > offset,
            sequence_length - offset,
            z3.IntVal(0),
        )
    else:
        extract_length = z3.IntVal(max(stop - start, 0))
    result = z3.SubSeq(value.z3_bytes, offset, extract_length)
    return SymbolicBytes(result, f"{value.name}_slice_{pc}")


def _slice_symbolic_string(value: SymbolicString, key: slice) -> SymbolicString | None:
    """Return an exact symbolic string slice for concrete nonnegative BINARY_SLICE bounds."""
    if key.step is not None:
        return None
    start = 0 if key.start is None else key.start
    stop = key.stop
    if start < 0 or (stop is not None and stop < 0):
        return None
    end: int | z3.ArithRef = value.z3_len if stop is None else stop
    return value.substring(start, end)


def _concrete_binary_slice(start: object, stop: object) -> slice | None:
    """Return a concrete two-bound slice when both CPython bounds are known."""
    concrete_start = _concrete_binary_slice_bound(start)
    concrete_stop = _concrete_binary_slice_bound(stop)
    if _UNRESOLVED_SLICE_BOUND in (concrete_start, concrete_stop):
        return None
    return slice(concrete_start, concrete_stop)


def _concrete_binary_slice_bound(value: object) -> int | None | object:
    """Resolve a BINARY_SLICE start/stop operand to int, None, or unresolved."""
    if value is None or isinstance(value, SymbolicNone):
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, SymbolicValue):
        if z3.is_true(z3.simplify(value.is_none)):
            return None
        concrete = value.value
        if isinstance(concrete, bool):
            return int(concrete)
        if isinstance(concrete, int):
            return concrete
        expr = z3.simplify(value.z3_int)
        if z3.is_int_value(expr):
            return expr.as_long()
    return _UNRESOLVED_SLICE_BOUND
