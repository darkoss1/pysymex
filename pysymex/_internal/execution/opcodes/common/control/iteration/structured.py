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

"""Structured symbolic ``FOR_ITER`` handling for modeled lazy builtins.

This keeps iterator-producing builtins such as ``enumerate()``, ``zip()``, and
``map()`` precise even when their inputs are symbolic containers.  The generic
fallback has to invent an unconstrained item value; these paths instead retain
CPython's tuple/item shape and type constraints.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.types.capabilities import length_expr as core_length_expr
from pysymex._internal.core.types.containers.iterator_sources import (
    EnumerateIteratorSource,
    MapIteratorSource,
    ZipIteratorSource,
)
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.feasibility.branching import branch_feasible
from pysymex._internal.execution.opcodes.common.control.iteration.exit import (
    push_for_iter_exit_sentinel,
)
from pysymex._internal.execution.opcodes.common.control.iteration.state import (
    state_with_iterator_update,
)
from pysymex._internal.models.builtins.iteration.predicates.inputs import callable_payload

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def iter_structured_iterator(
    state: VMState,
    iterator: SymbolicIterator,
    iterable: object,
    *,
    target_index: int,
    push_exit_sentinel: bool = True,
    pop_exit_iterator: bool = False,
) -> OpcodeResult | None:
    """Return precise branches for structured lazy iterator sources."""
    idx = iterator.index
    idx_expr = ConstraintValues.int(idx)
    if isinstance(iterable, EnumerateIteratorSource):
        item = _item_at(iterable.iterable, idx, state)
        length = _length_expr(iterable.iterable, state)
        if item is None or length is None:
            return None
        index_value = SymbolicValue.from_const(iterable.start + idx)
        return _branches(
            state,
            iterator,
            SymbolicTuple.from_elements(index_value, item),
            continue_condition=idx_expr < length,
            exit_condition=idx_expr >= length,
            target_index=target_index,
            push_exit_sentinel=push_exit_sentinel,
            pop_exit_iterator=pop_exit_iterator,
        )

    if isinstance(iterable, ZipIteratorSource):
        items: list[object] = []
        lengths: list[z3.ArithRef] = []
        for source in iterable.iterables:
            item = _item_at(source, idx, state)
            length = _length_expr(source, state)
            if item is None or length is None:
                return None
            items.append(item)
            lengths.append(length)
        if not lengths:
            return _branches(
                state,
                iterator,
                None,
                continue_condition=Z3_FALSE,
                exit_condition=Z3_TRUE,
                target_index=target_index,
                push_exit_sentinel=push_exit_sentinel,
                pop_exit_iterator=pop_exit_iterator,
            )
        continue_condition = z3.And(*(idx_expr < length for length in lengths))
        exit_condition = z3.Or(*(idx_expr >= length for length in lengths))
        return _branches(
            state,
            iterator,
            SymbolicTuple.from_elements(*items),
            continue_condition=continue_condition,
            exit_condition=exit_condition,
            target_index=target_index,
            push_exit_sentinel=push_exit_sentinel,
            pop_exit_iterator=pop_exit_iterator,
        )

    if isinstance(iterable, MapIteratorSource):
        item = _item_at(iterable.iterable, idx, state)
        length = _length_expr(iterable.iterable, state)
        if item is None or length is None:
            return None
        mapped = _mapped_item(iterable.function, item, f"map_{state.pc}_{idx}")
        if mapped is None:
            return None
        return _branches(
            state,
            iterator,
            mapped,
            continue_condition=idx_expr < length,
            exit_condition=idx_expr >= length,
            target_index=target_index,
            push_exit_sentinel=push_exit_sentinel,
            pop_exit_iterator=pop_exit_iterator,
        )

    return None


def _branches(
    state: VMState,
    iterator: SymbolicIterator,
    item: object | None,
    *,
    continue_condition: z3.BoolRef,
    exit_condition: z3.BoolRef,
    target_index: int,
    push_exit_sentinel: bool,
    pop_exit_iterator: bool,
) -> OpcodeResult:
    branches: list[VMState] = []
    known_prefix_len = StateConstraints.known_sat_prefix_len(state)
    if item is not None and branch_feasible(
        state.path_constraints,
        simplify_expr(continue_condition),
        known_sat_prefix_len=known_prefix_len,
    ):
        continue_state = state.fork()
        updated_iterator = iterator.advance()
        continue_state = state_with_iterator_update(continue_state, iterator, updated_iterator)
        continue_state.pop()
        continue_state = continue_state.push(updated_iterator)
        continue_state = continue_state.push(cast("StackValue", item))
        continue_state = continue_state.add_constraint(continue_condition)
        branches.append(continue_state.advance_pc())

    if branch_feasible(
        state.path_constraints,
        simplify_expr(exit_condition),
        known_sat_prefix_len=known_prefix_len,
    ):
        exit_state = state.fork()
        exit_state = state_with_iterator_update(exit_state, iterator, iterator.exhaust())
        exit_state = exit_state.add_constraint(exit_condition)
        exit_state = push_for_iter_exit_sentinel(
            exit_state,
            push_sentinel=push_exit_sentinel,
            pop_iterator=pop_exit_iterator,
        )
        branches.append(exit_state.set_pc(target_index))

    if not branches:
        return OpcodeResult.terminate()
    return OpcodeResult.branch(branches)


def _length_expr(value: object, state: VMState) -> z3.ArithRef | None:
    value = SymbolicObject.resolve(value, state)
    if isinstance(value, SymbolicIterator):
        inner_length = _length_expr(value.iterable, state)
        if inner_length is None:
            return None
        remaining = inner_length - ConstraintValues.int(value.index)
        return z3.If(remaining > 0, remaining, Z3_ZERO)
    if isinstance(value, MapIteratorSource):
        return _length_expr(value.iterable, state)
    if isinstance(value, EnumerateIteratorSource):
        return _length_expr(value.iterable, state)
    if isinstance(value, ZipIteratorSource):
        lengths = [_length_expr(iterable, state) for iterable in value.iterables]
        if not lengths or any(length is None for length in lengths):
            return None
        first_length = lengths[0]
        assert first_length is not None
        minimum = first_length
        for length in lengths[1:]:
            assert length is not None
            minimum = z3.If(length < minimum, length, minimum)
        return minimum
    return core_length_expr(value)


def _item_at(value: object, index: int, state: VMState) -> object | None:
    value = SymbolicObject.resolve(value, state)
    if isinstance(value, SymbolicIterator):
        base_index = value.index + index
        if value.reverse:
            source_length = _length_expr(value.iterable, state)
            if source_length is None:
                return None
            return _item_at_expr(
                value.iterable,
                source_length - ConstraintValues.int(base_index + 1),
                state,
            )
        return _item_at(value.iterable, base_index, state)
    if isinstance(value, EnumerateIteratorSource):
        item = _item_at(value.iterable, index, state)
        if item is None:
            return None
        return SymbolicTuple.from_elements(SymbolicValue.from_const(value.start + index), item)
    if isinstance(value, ZipIteratorSource):
        items = [_item_at(iterable, index, state) for iterable in value.iterables]
        if any(item is None for item in items):
            return None
        return SymbolicTuple.from_elements(*items)
    if isinstance(value, MapIteratorSource):
        item = _item_at(value.iterable, index, state)
        if item is None:
            return None
        return _mapped_item(value.function, item, f"map_item_{index}")
    return _item_at_expr(value, ConstraintValues.int(index), state)


def _item_at_expr(value: object, index_expr: z3.ArithRef, state: VMState) -> object | None:
    value = SymbolicObject.resolve(value, state)
    if isinstance(value, SymbolicList):
        index_value = SymbolicValue.from_z3(index_expr, f"{value.name}_idx")
        return value[index_value]
    if isinstance(value, SymbolicString) and z3.is_int_value(simplify_expr(index_expr)):
        index = simplify_expr(index_expr).as_long()
        return value.substring(index, index + 1)
    if isinstance(value, (list, tuple, str, bytes, bytearray, range)):
        simplified = simplify_expr(index_expr)
        if not z3.is_int_value(simplified):
            return None
        index = simplified.as_long()
        sequence = cast("Sequence[object]", value)
        if not (0 <= index < len(sequence)):
            return None
        return sequence[index]
    return None


def _mapped_item(function: object, item: object, name: str) -> object | None:
    callable_obj = callable_payload(function)
    if callable_obj is abs:
        if isinstance(item, (int, float, bool)):
            return abs(item)
        if isinstance(item, SymbolicValue):
            result = _symbolic_int_value(name)
            result.z3_int = z3.If(item.z3_int >= 0, item.z3_int, -item.z3_int)
            return result
        return None
    if callable_obj is int:
        if isinstance(item, bool):
            return int(item)
        if isinstance(item, int):
            return item
        if isinstance(item, SymbolicValue):
            return _symbolic_int_like(item, name)
        return None
    if callable_obj is bool:
        if isinstance(item, bool):
            return item
        if isinstance(item, int):
            return bool(item)
        if isinstance(item, SymbolicValue):
            return SymbolicValue(
                _name=name,
                z3_int=z3.If(item.z3_int != 0, ConstraintValues.int(1), Z3_ZERO),
                is_int=Z3_FALSE,
                z3_bool=item.z3_int != 0,
                is_bool=Z3_TRUE,
                is_path=Z3_FALSE,
                affinity_type="bool",
            )
        return None
    return None


def _symbolic_int_like(item: SymbolicValue, name: str) -> SymbolicValue:
    result = _symbolic_int_value(name)
    result.z3_int = item.z3_int
    return result


def _symbolic_int_value(name: str) -> SymbolicValue:
    return SymbolicValue(
        _name=name,
        z3_int=z3.Int(f"{name}_int"),
        is_int=Z3_TRUE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_float=Z3_FALSE,
        is_str=Z3_FALSE,
        is_obj=Z3_FALSE,
        is_list=Z3_FALSE,
        is_dict=Z3_FALSE,
        is_path=Z3_FALSE,
        is_none=Z3_FALSE,
        affinity_type="int",
    )
