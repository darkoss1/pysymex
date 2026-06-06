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

"""Exact finite iterator materialization shared by builtin models."""

from __future__ import annotations

import dis
from collections.abc import Hashable, Iterable
from typing import TYPE_CHECKING, TypeAlias, cast

import z3

from pysymex.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.base import SymbolicType
from pysymex.core.types.containers.bytes import SymbolicBytes
from pysymex.core.types.containers.dict_views import SymbolicDictView
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.helpers import storage_int_expr
from pysymex.core.types.containers.iterator_sources import (
    EnumerateIteratorSource,
    FilterIteratorSource,
    MapIteratorSource,
    ZipIteratorSource,
)
from pysymex.core.types.containers.sequences import SymbolicIterator, SymbolicSet, SymbolicTuple
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.core.helpers import resolve_heap_object

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.typing import StackValue


ExactFilterValue: TypeAlias = (
    int | float | bool | str | bytes | bytearray | list[object] | tuple[object, ...]
)
_INVALID_SLICE_BOUND = object()
_ARG_TRUTH_BRANCH = object()


def concrete_iterator_items(
    iterator: SymbolicIterator,
    state: VMState,
) -> list[StackValue] | None:
    """Return all exact source items for a finite iterator, independent of index."""
    if iterator.exhausted:
        return []
    iterable = literal_iterable_payload(
        resolve_heap_object(cast("StackValue", iterator.iterable), state)
    )
    items = concrete_iterable_items(iterable, state)
    if items is not None and iterator.reverse:
        return _reversed_iterator_items(iterator, items)
    return items


def concrete_iterable_items(value: object, state: VMState) -> list[StackValue] | None:
    """Return exact CPython iteration items for a finite non-consuming iterable."""
    iterable = literal_iterable_payload(resolve_heap_object(cast("StackValue", value), state))
    if isinstance(iterable, SymbolicIterator):
        return remaining_concrete_iterator_items(iterable, state)
    return _concrete_source_items(iterable, state)


def literal_iterable_payload(value: object) -> object:
    """Unwrap retained literal iterable payloads carried by generic symbolic values."""
    if isinstance(value, SymbolicValue):
        payload = getattr(value, "_modeled_object", None)
        if isinstance(payload, (str, bytes, bytearray)):
            return payload
        if isinstance(payload, list):
            return cast("list[object]", payload)
        if isinstance(payload, tuple):
            return cast("tuple[object, ...]", payload)
        if isinstance(payload, dict):
            return cast("dict[object, object]", payload)
        if isinstance(payload, set):
            return cast("set[object]", payload)
        if isinstance(payload, frozenset):
            return cast("frozenset[object]", payload)
    return value


def contains_definitely_unhashable_item(
    items: Iterable[object],
    state: VMState | None = None,
) -> bool:
    """Return whether exact items include a CPython-unhashable member."""
    return any(is_definitely_unhashable_item(item, state) for item in items)


def exact_dict_items_from_iterable(
    items: list[StackValue],
    state: VMState,
) -> dict[object, object] | None:
    """Return exact dict update pairs from materialized iterable items."""
    result: dict[object, object] = {}
    for item in items:
        pair = concrete_iterable_items(item, state)
        if pair is None or len(pair) != 2:
            return None
        key, value = pair
        if is_definitely_unhashable_item(key, state):
            return None
        result[key] = value
    return result


def is_definitely_unhashable_item(item: object, state: VMState | None = None) -> bool:
    """Return whether an exact item is known to fail CPython hash-based containers."""
    if state is not None:
        item = resolve_heap_object(cast("StackValue", item), state)
    payload = literal_iterable_payload(item)
    if payload is not item:
        return is_definitely_unhashable_item(payload, state)
    if isinstance(payload, (SymbolicList, SymbolicDict, SymbolicSet)):
        return True
    if isinstance(payload, (list, dict, set, bytearray)):
        return True
    if isinstance(payload, (tuple, frozenset)):
        return any(
            is_definitely_unhashable_item(member, state)
            for member in cast("Iterable[object]", payload)
        )
    if not isinstance(payload, Hashable):
        return True
    try:
        hash(payload)
    except TypeError:
        return True
    return False


def supports_exact_single_iterable_map(function: object) -> bool:
    """Return whether PySyMex can exactly model this single-iterable map callable."""
    callable_obj = _callable_payload(function)
    return callable_obj is bool or callable_obj is int


def materialize_exact_single_iterable_map(
    function: object,
    items: list[object],
) -> list[object] | None:
    """Return exact mapped items for supported map callables, or ``None``."""
    callable_obj = _callable_payload(function)
    if callable_obj is bool:
        return _exact_bool_map(items)
    if callable_obj is int:
        return _exact_int_map(items)
    return None


def is_truth_filter_predicate(predicate: object) -> bool:
    """Return whether ``filter`` can be modeled with item truthiness only."""
    return predicate is None or isinstance(predicate, SymbolicNone) or predicate is bool


def supports_exact_filter_predicate(predicate: object) -> bool:
    """Return whether ``filter`` can exactly evaluate this predicate for concrete items."""
    return is_truth_filter_predicate(predicate) or _simple_filter_predicate(predicate) is not None


def symbolic_truth_filter_list_from_iterator(
    iterator: SymbolicIterator,
    state: VMState,
    name: str,
) -> tuple[SymbolicList, SymbolicIterator] | None:
    """Return a precise one-item list(filter(None, source)) result when possible."""
    source = iterator.iterable
    if not isinstance(source, FilterIteratorSource) or iterator.index != 0:
        return None
    if not supports_exact_filter_predicate(source.predicate):
        return None
    items = concrete_iterable_items(source.iterable, state)
    if items is None or len(items) != 1:
        return None
    item = items[0]
    truth_item = resolve_heap_object(item, state)
    truth = _filter_item_truth(source.predicate, truth_item)
    if truth is None:
        return None

    simplified_truth = z3.simplify(truth)
    if z3.is_true(simplified_truth):
        return SymbolicList.from_const([item]), iterator.advance()
    if z3.is_false(simplified_truth):
        return SymbolicList.from_const([]), iterator.advance()

    z3_array = z3.Store(
        z3.Array(f"{name}_arr", z3.IntSort(), z3.IntSort()),
        0,
        _item_storage_expr(item, name),
    )
    z3_len = z3.If(truth, get_int_val(1), Z3_ZERO)
    return (
        SymbolicList(
            name,
            z3_array=cast("z3.ArrayRef", z3_array),
            z3_len=z3_len,
            element_type="any",
        ),
        iterator.advance(),
    )


def _concrete_source_items(iterable: object, state: VMState) -> list[StackValue] | None:
    if isinstance(iterable, EnumerateIteratorSource):
        return _concrete_enumerate_items(iterable, state)
    if isinstance(iterable, ZipIteratorSource):
        return _concrete_zip_items(iterable, state)
    if isinstance(iterable, MapIteratorSource):
        return _concrete_map_items(iterable, state)
    if isinstance(iterable, FilterIteratorSource):
        return _concrete_filter_items(iterable, state)
    if isinstance(iterable, SymbolicList):
        concrete_items = iterable.concrete_items
        if concrete_items is None:
            return None
        return _stack_values_from_iterable(concrete_items)
    if isinstance(iterable, SymbolicDict):
        concrete_items = iterable.concrete_items
        if concrete_items is None:
            return None
        return _stack_values_from_iterable(tuple(concrete_items.keys()))
    if isinstance(iterable, SymbolicDictView):
        concrete_items = iterable.concrete_items
        if concrete_items is None:
            return None
        return _stack_values_from_iterable(concrete_items)
    if isinstance(iterable, SymbolicSet):
        concrete_items = iterable.concrete_items
        if concrete_items is None:
            return None
        return _stack_values_from_iterable(concrete_items)
    if isinstance(iterable, SymbolicBytes):
        concrete_value = iterable.concrete_value
        if concrete_value is None:
            return None
        return _stack_values_from_iterable(concrete_value)
    if isinstance(iterable, SymbolicString):
        if not z3.is_string_value(iterable.z3_str):
            return None
        try:
            concrete_value = iterable.z3_str.as_string()
        except z3.Z3Exception:
            return None
        return _stack_values_from_iterable(concrete_value)
    if isinstance(iterable, dict):
        return _stack_values_from_iterable(tuple(cast("dict[object, object]", iterable).keys()))
    if isinstance(iterable, (set, frozenset)):
        return _stack_values_from_iterable(cast("Iterable[object]", iterable))
    if isinstance(iterable, (str, bytes, bytearray, list, tuple)):
        return _stack_values_from_iterable(cast("Iterable[object]", iterable))
    return None


def _concrete_enumerate_items(
    source: EnumerateIteratorSource,
    state: VMState,
) -> list[StackValue] | None:
    items = concrete_iterable_items(source.iterable, state)
    if items is None:
        return None
    pairs = ((source.start + index, item) for index, item in enumerate(items))
    return _stack_values_from_iterable(pairs)


def _concrete_zip_items(
    source: ZipIteratorSource,
    state: VMState,
) -> list[StackValue] | None:
    materialized_inputs: list[list[StackValue]] = []
    for iterable in source.iterables:
        items = concrete_iterable_items(iterable, state)
        if items is None:
            return None
        materialized_inputs.append(items)
    pairs = (tuple(items) for items in zip(*materialized_inputs))
    return _stack_values_from_iterable(pairs)


def _concrete_map_items(
    source: MapIteratorSource,
    state: VMState,
) -> list[StackValue] | None:
    items = concrete_iterable_items(source.iterable, state)
    if items is None:
        return None
    mapped_items = materialize_exact_single_iterable_map(source.function, list(items))
    if mapped_items is None:
        return None
    return _stack_values_from_iterable(mapped_items)


def _concrete_filter_items(
    source: FilterIteratorSource,
    state: VMState,
) -> list[StackValue] | None:
    if not supports_exact_filter_predicate(source.predicate):
        return None
    items = concrete_iterable_items(source.iterable, state)
    if items is None:
        return None
    filtered_items: list[StackValue] = []
    for item in items:
        truth_item = resolve_heap_object(item, state)
        truth = _filter_item_truth(source.predicate, truth_item)
        if truth is None:
            return None
        simplified_truth = z3.simplify(truth)
        if z3.is_true(simplified_truth):
            filtered_items.append(item)
        elif not z3.is_false(simplified_truth):
            return None
    return filtered_items


def _reversed_iterator_items(
    iterator: SymbolicIterator,
    items: list[StackValue],
) -> list[StackValue]:
    if iterator.source_size is None:
        return list(reversed(items))
    source_index = iterator.source_size - 1 - iterator.index
    if source_index < 0 or source_index >= len(items):
        return []
    return [items[index] for index in range(source_index, -1, -1)]


def remaining_concrete_iterator_items(
    iterator: SymbolicIterator,
    state: VMState,
) -> list[StackValue] | None:
    """Return exact items that remain from the iterator's current index."""
    if iterator.exhausted:
        return []
    concrete_items = concrete_iterator_items(iterator, state)
    if concrete_items is None:
        return None
    if iterator.index < 0:
        return None
    return concrete_items[iterator.index :]


def iterator_size_change_runtime_error(
    iterator: SymbolicIterator,
    state: VMState,
) -> bool:
    """Return whether CPython would reject advancing this mutated iterator."""
    if iterator.exhausted:
        return False
    if not iterator.size_change_raises or iterator.source_size is None:
        return False
    concrete_items = concrete_iterator_items(iterator, state)
    return concrete_items is not None and len(concrete_items) != iterator.source_size


def exhausted_iterator(
    iterator: SymbolicIterator,
    state: VMState,
) -> SymbolicIterator | None:
    """Return an iterator advanced to the end of its exact finite source."""
    if iterator.exhausted:
        return iterator
    concrete_items = concrete_iterator_items(iterator, state)
    if concrete_items is None:
        return None
    target_index = max(iterator.index, len(concrete_items))
    updated = iterator
    while updated.index < target_index:
        updated = updated.advance()
    return updated.exhaust()


def iterator_consumption_mutations(
    value: object,
    state: VMState,
) -> list[tuple[SymbolicIterator, SymbolicIterator]]:
    """Return iterator updates caused by fully consuming an exact finite iterator."""
    resolved = resolve_heap_object(cast("StackValue", value), state)
    if not isinstance(resolved, SymbolicIterator) or resolved.is_generator:
        return []
    updated_iterator = exhausted_iterator(resolved, state)
    if updated_iterator is None:
        return []
    mutations: list[tuple[SymbolicIterator, SymbolicIterator]] = []
    _append_iterator_mutation(mutations, resolved, updated_iterator)
    mutations.extend(_zip_source_iterator_mutations(resolved, state))
    return mutations


def iterator_mutation_side_effect(
    original_iterator: SymbolicIterator,
    updated_iterator: SymbolicIterator,
) -> dict[str, object]:
    """Return the modeled side effect for an alias-visible iterator update."""
    if (
        updated_iterator.index == original_iterator.index
        and updated_iterator.exhausted == original_iterator.exhausted
    ):
        return {}
    return {
        "iterator_mutation": {
            "original_iterator": original_iterator,
            "updated_iterator": updated_iterator,
        }
    }


def iterator_exhaustion_side_effect(
    value: object,
    state: VMState,
) -> dict[str, object] | None:
    """Return a mutation side effect for models that consume a finite iterator fully."""
    mutations = iterator_consumption_mutations(value, state)
    if not mutations:
        return None
    side_effects = iterator_mutation_side_effect(*mutations[0])
    if len(mutations) > 1:
        side_effects["iterator_source_mutations"] = [
            {
                "original_iterator": original,
                "updated_iterator": updated,
            }
            for original, updated in mutations[1:]
        ]
    return side_effects or None


def _zip_source_iterator_mutations(
    iterator: SymbolicIterator,
    state: VMState,
) -> list[tuple[SymbolicIterator, SymbolicIterator]]:
    source = iterator.iterable
    if not isinstance(source, ZipIteratorSource) or iterator.index != 0:
        return []

    input_lengths: list[int] = []
    for iterable in source.iterables:
        items = concrete_iterable_items(iterable, state)
        if items is None:
            return []
        input_lengths.append(len(items))
    if not input_lengths:
        return []

    pair_count = min(input_lengths)
    first_stop_index = input_lengths.index(pair_count)
    mutations: list[tuple[SymbolicIterator, SymbolicIterator]] = []
    for index, iterable in enumerate(source.iterables):
        resolved = resolve_heap_object(cast("StackValue", iterable), state)
        if not isinstance(resolved, SymbolicIterator) or resolved.is_generator:
            continue
        advance_count = pair_count
        if index < first_stop_index and input_lengths[index] > pair_count:
            advance_count += 1
        updated = _advance_iterator(resolved, advance_count)
        if index == first_stop_index:
            updated = updated.exhaust()
        _append_iterator_mutation(mutations, resolved, updated)
    return mutations


def _advance_iterator(iterator: SymbolicIterator, count: int) -> SymbolicIterator:
    updated = iterator
    for _ in range(count):
        updated = updated.advance()
    return updated


def _append_iterator_mutation(
    mutations: list[tuple[SymbolicIterator, SymbolicIterator]],
    original: SymbolicIterator,
    updated: SymbolicIterator,
) -> None:
    if updated.index == original.index and updated.exhausted == original.exhausted:
        return
    mutations.append((original, updated))


def _stack_values_from_iterable(items: Iterable[object]) -> list[StackValue]:
    return [cast("StackValue", item) for item in items]


def _item_storage_expr(value: object, name: str) -> z3.ArithRef:
    if isinstance(value, SymbolicValue):
        return storage_int_expr(value.z3_int, f"{name}_elem")
    if isinstance(value, bool):
        return get_int_val(int(value))
    if isinstance(value, int):
        return get_int_val(value)
    return Z3_ZERO


def _callable_payload(function: object) -> object:
    if isinstance(function, SymbolicValue):
        payload = getattr(function, "_modeled_object", None)
        if payload is not None:
            return payload
        value = function.value
        if isinstance(value, type):
            return value
    return function


def _exact_int_map(items: list[object]) -> list[object] | None:
    mapped: list[object] = []
    for item in items:
        exact_item = _exact_int_map_input(item)
        if exact_item is None:
            return None
        try:
            mapped.append(int(exact_item))
        except (TypeError, ValueError):
            return None
    return mapped


def _exact_bool_map(items: list[object]) -> list[object] | None:
    mapped: list[object] = []
    for item in items:
        truth = _truth_predicate(item)
        if truth is None:
            return None
        simplified = z3.simplify(truth)
        if z3.is_true(simplified):
            mapped.append(True)
        elif z3.is_false(simplified):
            mapped.append(False)
        else:
            return None
    return mapped


def _filter_item_truth(predicate: object, item: object) -> z3.BoolRef | None:
    if is_truth_filter_predicate(predicate):
        return _truth_predicate(item)
    result = _evaluate_simple_filter_predicate(predicate, item)
    if result is None:
        return None
    return Z3_TRUE if result else Z3_FALSE


def _simple_filter_predicate(predicate: object) -> tuple[str, str, object, object | None] | None:
    callable_obj = _callable_payload(predicate)
    code = getattr(callable_obj, "__code__", None)
    if code is None or getattr(code, "co_argcount", 0) != 1:
        return None
    instructions = [
        instruction
        for instruction in dis.get_instructions(code)
        if instruction.opname not in {"CACHE", "EXTENDED_ARG", "NOP", "PRECALL", "RESUME"}
    ]
    if len(instructions) == 4 and _is_load_arg(instructions[0]):
        load_const, op, ret = instructions[1:]
        if (
            load_const.opname == "LOAD_CONST"
            and op.opname == "COMPARE_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            return ("compare", cast("str", op.argval), load_const.argval, None)
        if (
            load_const.opname == "LOAD_CONST"
            and op.opname == "CONTAINS_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            op_name = "not in" if op.arg == 1 else "in"
            return ("contains", op_name, load_const.argval, None)
    if _is_not_filter_predicate(instructions):
        return ("not_truth", "", None, None)
    chained_compare = _literal_chained_compare_operand(instructions)
    if chained_compare is not None:
        lower_bound, lower_op, upper_op, upper_bound = chained_compare
        return ("chained_compare", lower_op, lower_bound, (upper_op, upper_bound))
    and_compare_mod = _literal_and_compare_mod_compare_operand(instructions)
    if and_compare_mod is not None:
        first_op, first_bound, mod_value, second_op, second_expected = and_compare_mod
        return (
            "and_compare_mod_compare",
            first_op,
            first_bound,
            (mod_value, second_op, second_expected),
        )
    or_compare = _literal_or_compare_operand(instructions)
    if or_compare is not None:
        first_op, first_bound, second_op, second_bound = or_compare
        return ("or_compare", first_op, first_bound, (second_op, second_bound))
    or_compare_mod = _literal_or_compare_mod_compare_operand(instructions)
    if or_compare_mod is not None:
        first_op, first_bound, mod_value, second_op, second_expected = or_compare_mod
        return (
            "or_compare_mod_compare",
            first_op,
            first_bound,
            (mod_value, second_op, second_expected),
        )
    conditional_compare = _literal_conditional_compare_truth_operand(instructions)
    if conditional_compare is not None:
        op_name, bound, true_truth, false_truth = conditional_compare
        return ("conditional_compare_truth", op_name, bound, (true_truth, false_truth))
    if len(instructions) >= 4 and _is_load_arg(instructions[0]):
        op, ret = instructions[-2:]
        slice_operand = _literal_slice_operand(instructions[1:-3])
        if (
            slice_operand is not None
            and instructions[-3].opname == "LOAD_CONST"
            and op.opname == "COMPARE_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            return ("slice_compare", cast("str", op.argval), slice_operand, instructions[-3].argval)
        dict_keys_operand = _literal_dict_keys_operand(instructions[1:-2])
        if (
            dict_keys_operand is not None
            and op.opname == "CONTAINS_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            op_name = "not in" if op.arg == 1 else "in"
            return ("contains", op_name, dict_keys_operand, None)
        range_operand = _literal_range_operand(instructions[1:-2])
        if (
            range_operand is not None
            and op.opname == "CONTAINS_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            op_name = "not in" if op.arg == 1 else "in"
            return ("contains", op_name, range_operand, None)
        list_operand = _literal_list_operand(instructions[1:-2])
        if list_operand is not None and op.opname == "COMPARE_OP" and ret.opname == "RETURN_VALUE":
            return ("compare", cast("str", op.argval), list_operand, None)
        if list_operand is not None and op.opname == "CONTAINS_OP" and ret.opname == "RETURN_VALUE":
            op_name = "not in" if op.arg == 1 else "in"
            return ("contains", op_name, list_operand, None)
    if len(instructions) == 6 and _is_load_arg(instructions[0]):
        load_mod, binary, load_expected, compare, ret = instructions[1:]
        if (
            load_mod.opname == "LOAD_CONST"
            and binary.opname == "BINARY_OP"
            and binary.argrepr == "%"
            and load_expected.opname == "LOAD_CONST"
            and compare.opname == "COMPARE_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            return (
                "mod_compare",
                cast("str", compare.argval),
                load_mod.argval,
                load_expected.argval,
            )
    if len(instructions) == 5 and _is_load_arg(instructions[0]):
        unary, load_expected, compare, ret = instructions[1:]
        unary_name = _unary_filter_operator(unary)
        if (
            unary_name is not None
            and load_expected.opname == "LOAD_CONST"
            and compare.opname == "COMPARE_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            return ("unary_compare", cast("str", compare.argval), unary_name, load_expected.argval)
    if len(instructions) == 5 and _is_load_arg(instructions[0]):
        load_method, load_prefix, call, ret = instructions[1:]
        if (
            load_method.opname == "LOAD_ATTR"
            and load_method.argval in {"startswith", "endswith"}
            and load_prefix.opname == "LOAD_CONST"
            and call.opname == "CALL"
            and call.arg == 1
            and ret.opname == "RETURN_VALUE"
        ):
            return (cast("str", load_method.argval), "", load_prefix.argval, None)
    if len(instructions) == 6 and _is_load_global(instructions[0], abs):
        load_arg, call, load_expected, compare, ret = instructions[1:]
        if (
            _is_load_arg(load_arg)
            and call.opname == "CALL"
            and call.arg == 1
            and load_expected.opname == "LOAD_CONST"
            and compare.opname == "COMPARE_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            return ("abs_compare", cast("str", compare.argval), load_expected.argval, None)
    if len(instructions) == 6 and _is_load_global(instructions[0], len):
        load_arg, call, load_expected, compare, ret = instructions[1:]
        if (
            _is_load_arg(load_arg)
            and call.opname == "CALL"
            and call.arg == 1
            and load_expected.opname == "LOAD_CONST"
            and compare.opname == "COMPARE_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            return ("len_compare", cast("str", compare.argval), load_expected.argval, None)
    if len(instructions) == 6 and _is_load_global(instructions[0], str):
        load_arg, call, load_container, contains, ret = instructions[1:]
        if (
            _is_load_arg(load_arg)
            and call.opname == "CALL"
            and load_container.opname == "LOAD_CONST"
            and contains.opname == "CONTAINS_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            op_name = "not in" if contains.arg == 1 else "in"
            return ("str_contains", op_name, load_container.argval, None)
    return None


def _is_load_arg(instruction: dis.Instruction) -> bool:
    return instruction.opname == "LOAD_FAST" and instruction.arg == 0


def _is_load_global(instruction: dis.Instruction, value: object) -> bool:
    return instruction.opname == "LOAD_GLOBAL" and instruction.argval == getattr(
        value,
        "__name__",
        value,
    )


def _unary_filter_operator(instruction: dis.Instruction) -> str | None:
    if instruction.opname == "UNARY_NEGATIVE":
        return "negative"
    if instruction.opname == "UNARY_POSITIVE":
        return "positive"
    if instruction.opname == "UNARY_INVERT":
        return "invert"
    if (
        instruction.opname == "CALL_INTRINSIC_1"
        and instruction.argrepr == "INTRINSIC_UNARY_POSITIVE"
    ):
        return "positive"
    return None


def _is_not_filter_predicate(instructions: list[dis.Instruction]) -> bool:
    if len(instructions) == 3:
        load_arg, unary_not, ret = instructions
        return (
            _is_load_arg(load_arg)
            and unary_not.opname == "UNARY_NOT"
            and ret.opname == "RETURN_VALUE"
        )
    if len(instructions) == 4:
        load_arg, to_bool, unary_not, ret = instructions
        return (
            _is_load_arg(load_arg)
            and to_bool.opname == "TO_BOOL"
            and unary_not.opname == "UNARY_NOT"
            and ret.opname == "RETURN_VALUE"
        )
    return False


def _literal_list_operand(instructions: list[dis.Instruction]) -> list[object] | None:
    if not instructions:
        return None
    build_list = instructions[-1]
    if build_list.opname != "BUILD_LIST":
        return None
    item_count = build_list.arg
    if item_count is None:
        return None
    item_instructions = instructions[:-1]
    if len(item_instructions) != item_count:
        return None
    if any(instruction.opname != "LOAD_CONST" for instruction in item_instructions):
        return None
    return [instruction.argval for instruction in item_instructions]


def _literal_dict_keys_operand(instructions: list[dis.Instruction]) -> tuple[object, ...] | None:
    if not instructions:
        return None
    build_map = instructions[-1]
    if build_map.opname != "BUILD_CONST_KEY_MAP":
        return None
    item_count = build_map.arg
    if item_count is None or len(instructions) != item_count + 2:
        return None
    value_instructions = instructions[:-2]
    keys_instruction = instructions[-2]
    if any(instruction.opname != "LOAD_CONST" for instruction in value_instructions):
        return None
    keys_value: object = keys_instruction.argval
    if keys_instruction.opname != "LOAD_CONST" or not isinstance(keys_value, tuple):
        return None
    keys = cast("tuple[object, ...]", keys_value)
    return keys if len(keys) == item_count else None


def _literal_range_operand(instructions: list[dis.Instruction]) -> range | None:
    if len(instructions) < 3:
        return None
    load_range = instructions[0]
    call = instructions[-1]
    if not _is_load_global(load_range, range) or call.opname != "CALL":
        return None
    arg_count = call.arg
    if arg_count is None or arg_count not in {1, 2, 3}:
        return None
    arg_instructions = instructions[1:-1]
    if len(arg_instructions) != arg_count:
        return None
    args: list[int] = []
    for instruction in arg_instructions:
        if instruction.opname != "LOAD_CONST" or not isinstance(instruction.argval, int):
            return None
        args.append(instruction.argval)
    try:
        if len(args) == 1:
            return range(args[0])
        if len(args) == 2:
            return range(args[0], args[1])
        return range(args[0], args[1], args[2])
    except ValueError:
        return None


def _literal_chained_compare_operand(
    instructions: list[dis.Instruction],
) -> tuple[object, str, str, object] | None:
    if len(instructions) != 15:
        return None
    (
        load_lower,
        load_arg,
        swap_before_first_compare,
        copy_before_first_compare,
        first_compare,
        copy_first_result,
        to_bool,
        jump_if_false,
        pop_middle,
        load_upper,
        second_compare,
        success_return,
        swap_cleanup,
        pop_cleanup,
        failure_return,
    ) = instructions
    if (
        load_lower.opname != "LOAD_CONST"
        or not _is_load_arg(load_arg)
        or swap_before_first_compare.opname != "SWAP"
        or copy_before_first_compare.opname != "COPY"
        or first_compare.opname != "COMPARE_OP"
        or copy_first_result.opname != "COPY"
        or to_bool.opname != "TO_BOOL"
        or jump_if_false.opname != "POP_JUMP_IF_FALSE"
        or pop_middle.opname != "POP_TOP"
        or load_upper.opname != "LOAD_CONST"
        or second_compare.opname != "COMPARE_OP"
        or success_return.opname != "RETURN_VALUE"
        or swap_cleanup.opname != "SWAP"
        or pop_cleanup.opname != "POP_TOP"
        or failure_return.opname != "RETURN_VALUE"
    ):
        return None
    return (
        load_lower.argval,
        cast("str", first_compare.argval),
        cast("str", second_compare.argval),
        load_upper.argval,
    )


def _literal_and_compare_mod_compare_operand(
    instructions: list[dis.Instruction],
) -> tuple[str, object, int, str, object] | None:
    if len(instructions) != 13:
        return None
    (
        first_load_arg,
        first_load_bound,
        first_compare,
        copy_first_result,
        to_bool,
        jump_if_false,
        pop_first_result,
        second_load_arg,
        load_mod,
        binary_mod,
        load_expected,
        second_compare,
        ret,
    ) = instructions
    if (
        not _is_load_arg(first_load_arg)
        or first_load_bound.opname != "LOAD_CONST"
        or first_compare.opname != "COMPARE_OP"
        or copy_first_result.opname != "COPY"
        or to_bool.opname != "TO_BOOL"
        or jump_if_false.opname != "POP_JUMP_IF_FALSE"
        or pop_first_result.opname != "POP_TOP"
        or not _is_load_arg(second_load_arg)
        or load_mod.opname != "LOAD_CONST"
        or binary_mod.opname != "BINARY_OP"
        or binary_mod.argrepr != "%"
        or load_expected.opname != "LOAD_CONST"
        or second_compare.opname != "COMPARE_OP"
        or ret.opname != "RETURN_VALUE"
    ):
        return None
    mod_value = load_mod.argval
    if not isinstance(mod_value, int) or isinstance(mod_value, bool) or mod_value == 0:
        return None
    return (
        cast("str", first_compare.argval),
        first_load_bound.argval,
        mod_value,
        cast("str", second_compare.argval),
        load_expected.argval,
    )


def _literal_or_compare_operand(
    instructions: list[dis.Instruction],
) -> tuple[str, object, str, object] | None:
    if len(instructions) != 11:
        return None
    (
        first_load_arg,
        first_load_bound,
        first_compare,
        copy_first_result,
        to_bool,
        jump_if_true,
        pop_first_result,
        second_load_arg,
        second_load_bound,
        second_compare,
        ret,
    ) = instructions
    if (
        not _is_load_arg(first_load_arg)
        or first_load_bound.opname != "LOAD_CONST"
        or first_compare.opname != "COMPARE_OP"
        or copy_first_result.opname != "COPY"
        or to_bool.opname != "TO_BOOL"
        or jump_if_true.opname != "POP_JUMP_IF_TRUE"
        or pop_first_result.opname != "POP_TOP"
        or not _is_load_arg(second_load_arg)
        or second_load_bound.opname != "LOAD_CONST"
        or second_compare.opname != "COMPARE_OP"
        or ret.opname != "RETURN_VALUE"
    ):
        return None
    return (
        cast("str", first_compare.argval),
        first_load_bound.argval,
        cast("str", second_compare.argval),
        second_load_bound.argval,
    )


def _literal_or_compare_mod_compare_operand(
    instructions: list[dis.Instruction],
) -> tuple[str, object, int, str, object] | None:
    if len(instructions) != 13:
        return None
    (
        first_load_arg,
        first_load_bound,
        first_compare,
        copy_first_result,
        to_bool,
        jump_if_true,
        pop_first_result,
        second_load_arg,
        load_mod,
        binary_mod,
        load_expected,
        second_compare,
        ret,
    ) = instructions
    if (
        not _is_load_arg(first_load_arg)
        or first_load_bound.opname != "LOAD_CONST"
        or first_compare.opname != "COMPARE_OP"
        or copy_first_result.opname != "COPY"
        or to_bool.opname != "TO_BOOL"
        or jump_if_true.opname != "POP_JUMP_IF_TRUE"
        or pop_first_result.opname != "POP_TOP"
        or not _is_load_arg(second_load_arg)
        or load_mod.opname != "LOAD_CONST"
        or binary_mod.opname != "BINARY_OP"
        or binary_mod.argrepr != "%"
        or load_expected.opname != "LOAD_CONST"
        or second_compare.opname != "COMPARE_OP"
        or ret.opname != "RETURN_VALUE"
    ):
        return None
    mod_value = load_mod.argval
    if not isinstance(mod_value, int) or isinstance(mod_value, bool) or mod_value == 0:
        return None
    return (
        cast("str", first_compare.argval),
        first_load_bound.argval,
        mod_value,
        cast("str", second_compare.argval),
        load_expected.argval,
    )


def _literal_conditional_compare_truth_operand(
    instructions: list[dis.Instruction],
) -> tuple[str, object, object, object] | None:
    if len(instructions) != 8:
        return None
    (
        load_arg,
        load_bound,
        compare,
        jump_if_false,
        load_true_value,
        true_return,
        load_false_value,
        false_return,
    ) = instructions
    if (
        not _is_load_arg(load_arg)
        or load_bound.opname != "LOAD_CONST"
        or compare.opname != "COMPARE_OP"
        or jump_if_false.opname != "POP_JUMP_IF_FALSE"
        or true_return.opname != "RETURN_VALUE"
        or false_return.opname != "RETURN_VALUE"
    ):
        return None
    true_truth = _literal_conditional_truth_branch(load_true_value)
    false_truth = _literal_conditional_truth_branch(load_false_value)
    if true_truth is None or false_truth is None:
        return None
    return (cast("str", compare.argval), load_bound.argval, true_truth, false_truth)


def _literal_conditional_truth_branch(instruction: dis.Instruction) -> object | None:
    if _is_load_arg(instruction):
        return _ARG_TRUTH_BRANCH
    if instruction.opname != "LOAD_CONST":
        return None
    return _exact_constant_truth_value(instruction.argval)


def _literal_slice_operand(
    instructions: list[dis.Instruction],
) -> slice[int | None, int | None, int | None] | None:
    if len(instructions) == 3 and instructions[2].opname == "BINARY_SLICE":
        start = _literal_slice_bound(instructions[0])
        stop = _literal_slice_bound(instructions[1])
        if start is _INVALID_SLICE_BOUND or stop is _INVALID_SLICE_BOUND:
            return None
        return cast("slice[int | None, int | None, int | None]", slice(start, stop))

    if len(instructions) == 4 and instructions[2].opname == "BUILD_SLICE":
        if instructions[3].opname != "BINARY_SUBSCR":
            return None
        arg_count = instructions[2].arg
        if arg_count != 2:
            return None
        start = _literal_slice_bound(instructions[0])
        stop = _literal_slice_bound(instructions[1])
        if start is _INVALID_SLICE_BOUND or stop is _INVALID_SLICE_BOUND:
            return None
        return cast("slice[int | None, int | None, int | None]", slice(start, stop))

    if len(instructions) == 5 and instructions[3].opname == "BUILD_SLICE":
        if instructions[4].opname != "BINARY_SUBSCR":
            return None
        arg_count = instructions[3].arg
        if arg_count != 3:
            return None
        start = _literal_slice_bound(instructions[0])
        stop = _literal_slice_bound(instructions[1])
        step = _literal_slice_bound(instructions[2])
        if (
            start is _INVALID_SLICE_BOUND
            or stop is _INVALID_SLICE_BOUND
            or step is _INVALID_SLICE_BOUND
            or step == 0
        ):
            return None
        return cast("slice[int | None, int | None, int | None]", slice(start, stop, step))

    return None


def _literal_slice_bound(instruction: dis.Instruction) -> int | None | object:
    if instruction.opname != "LOAD_CONST":
        return _INVALID_SLICE_BOUND
    value = instruction.argval
    if value is None or isinstance(value, int):
        return value
    return _INVALID_SLICE_BOUND


def _evaluate_simple_filter_predicate(predicate: object, item: object) -> bool | None:
    spec = _simple_filter_predicate(predicate)
    if spec is None:
        return None
    kind, op_name, operand, expected = spec
    try:
        if kind == "str_contains":
            str_value = _exact_filter_predicate_str_input(item)
            if str_value is None:
                return None
            contains = _contains_exact_python_value(str_value, operand)
            if contains is None:
                return None
            return not contains if op_name == "not in" else contains

        item_value = _exact_filter_predicate_input(item)
        if item_value is None:
            return None
        if kind == "not_truth":
            return not _exact_filter_predicate_truth_value(item_value)
        if kind == "contains":
            contains = _contains_exact_python_value(item_value, operand)
            if contains is None:
                return None
            return not contains if op_name == "not in" else contains
        if kind in {"startswith", "endswith"}:
            return _affix_exact_python_value(item_value, operand, kind)
        if kind == "compare":
            return _compare_exact_python_value(item_value, op_name, operand)
        if kind == "slice_compare":
            if not isinstance(operand, slice):
                return None
            sliced_value = _exact_filter_predicate_slice(
                item_value,
                cast("slice[int | None, int | None, int | None]", operand),
            )
            if sliced_value is None:
                return None
            return _compare_exact_python_value(sliced_value, op_name, expected)
        if kind == "unary_compare":
            if not isinstance(operand, str):
                return None
            unary_value = _exact_filter_predicate_unary_value(item_value, operand)
            if unary_value is None:
                return None
            return _compare_exact_python_value(unary_value, op_name, expected)
        if kind == "abs_compare":
            if not isinstance(item_value, (int, float, bool)):
                return None
            return _compare_exact_python_value(abs(item_value), op_name, operand)
        if kind == "len_compare":
            length = _exact_filter_predicate_len_value(item_value)
            if length is None:
                return None
            return _compare_exact_python_value(length, op_name, operand)
        if kind == "chained_compare":
            if not isinstance(expected, tuple):
                return None
            chain_expected = cast("tuple[object, ...]", expected)
            if len(chain_expected) != 2:
                return None
            upper_op, upper_bound = chain_expected
            if not isinstance(upper_op, str):
                return None
            lower_value = _exact_filter_predicate_input(operand)
            if lower_value is None:
                return None
            lower_result = _compare_exact_python_value(lower_value, op_name, item_value)
            if lower_result is None:
                return None
            if not lower_result:
                return False
            return _compare_exact_python_value(item_value, upper_op, upper_bound)
        if kind == "and_compare_mod_compare":
            if not isinstance(expected, tuple):
                return None
            and_expected = cast("tuple[object, ...]", expected)
            if len(and_expected) != 3:
                return None
            mod_value, second_op, second_expected = and_expected
            if not isinstance(mod_value, int) or not isinstance(second_op, str):
                return None
            if not isinstance(item_value, (int, float, bool)):
                return None
            first_result = _compare_exact_python_value(item_value, op_name, operand)
            if first_result is None:
                return None
            if not first_result:
                return False
            return _compare_exact_python_value(item_value % mod_value, second_op, second_expected)
        if kind == "or_compare":
            if not isinstance(expected, tuple):
                return None
            or_expected = cast("tuple[object, ...]", expected)
            if len(or_expected) != 2:
                return None
            second_op, second_bound = or_expected
            if not isinstance(second_op, str):
                return None
            first_result = _compare_exact_python_value(item_value, op_name, operand)
            if first_result is None:
                return None
            if first_result:
                return True
            return _compare_exact_python_value(item_value, second_op, second_bound)
        if kind == "or_compare_mod_compare":
            if not isinstance(expected, tuple):
                return None
            or_expected = cast("tuple[object, ...]", expected)
            if len(or_expected) != 3:
                return None
            mod_value, second_op, second_expected = or_expected
            if not isinstance(mod_value, int) or not isinstance(second_op, str):
                return None
            first_result = _compare_exact_python_value(item_value, op_name, operand)
            if first_result is None:
                return None
            if first_result:
                return True
            if not isinstance(item_value, (int, float, bool)):
                return None
            return _compare_exact_python_value(item_value % mod_value, second_op, second_expected)
        if kind == "conditional_compare_truth":
            if not isinstance(expected, tuple):
                return None
            conditional_expected = cast("tuple[object, ...]", expected)
            if len(conditional_expected) != 2:
                return None
            true_truth, false_truth = conditional_expected
            condition = _compare_exact_python_value(item_value, op_name, operand)
            if condition is None:
                return None
            return _evaluate_conditional_truth_branch(
                true_truth if condition else false_truth,
                item_value,
            )
        if kind == "mod_compare":
            if not isinstance(item_value, (int, float, bool)):
                return None
            if not isinstance(operand, (int, bool)) or isinstance(operand, bool):
                return None
            if operand == 0:
                return None
            return _compare_exact_python_value(item_value % operand, op_name, expected)
    except (ArithmeticError, TypeError, ValueError):
        return None
    return None


def _contains_exact_python_value(left: ExactFilterValue, right: object) -> bool | None:
    if isinstance(right, dict):
        right = tuple(cast("dict[object, object]", right).keys())
    if isinstance(right, str):
        return left in right if isinstance(left, str) else None
    if isinstance(right, bytes):
        return _contains_exact_bytes_value(left, right)
    if isinstance(right, bytearray):
        return _contains_exact_bytearray_value(left, right)
    if isinstance(right, (list, tuple)):
        return left in right
    if isinstance(right, (set, frozenset)):
        try:
            hash(left)
        except TypeError:
            return None
        try:
            return left in right
        except (TypeError, ValueError):
            return None
    if isinstance(right, range):
        try:
            return left in right
        except TypeError:
            return None
    return None


def _contains_exact_bytes_value(left: ExactFilterValue, right: bytes) -> bool | None:
    try:
        if isinstance(left, (int, bool)):
            return left in right
        if isinstance(left, bytes):
            return left in right
        if isinstance(left, bytearray):
            return bytes(left) in right
    except (TypeError, ValueError):
        return None
    return None


def _contains_exact_bytearray_value(left: ExactFilterValue, right: bytearray) -> bool | None:
    try:
        if isinstance(left, (int, bool)):
            return left in right
        if isinstance(left, bytes):
            return left in right
        if isinstance(left, bytearray):
            return bytes(left) in right
    except (TypeError, ValueError):
        return None
    return None


def _affix_exact_python_value(
    value: ExactFilterValue,
    affix: object,
    method_name: str,
) -> bool | None:
    try:
        if isinstance(value, str) and _is_str_prefix(affix):
            str_affix = cast("str | tuple[str, ...]", affix)
            return (
                value.startswith(str_affix)
                if method_name == "startswith"
                else value.endswith(str_affix)
            )
        if isinstance(value, bytes) and _is_bytes_prefix(affix):
            bytes_affix = cast("bytes | tuple[bytes, ...]", affix)
            return (
                value.startswith(bytes_affix)
                if method_name == "startswith"
                else value.endswith(bytes_affix)
            )
        if isinstance(value, bytearray) and _is_bytearray_prefix(affix):
            bytearray_affix = cast("bytes | bytearray | tuple[bytes | bytearray, ...]", affix)
            return (
                value.startswith(bytearray_affix)
                if method_name == "startswith"
                else value.endswith(bytearray_affix)
            )
    except TypeError:
        return None
    return None


def _is_str_prefix(prefix: object) -> bool:
    if isinstance(prefix, str):
        return True
    if isinstance(prefix, tuple):
        return all(isinstance(item, str) for item in cast("tuple[object, ...]", prefix))
    return False


def _is_bytes_prefix(prefix: object) -> bool:
    if isinstance(prefix, bytes):
        return True
    if isinstance(prefix, tuple):
        return all(isinstance(item, bytes) for item in cast("tuple[object, ...]", prefix))
    return False


def _is_bytearray_prefix(prefix: object) -> bool:
    if isinstance(prefix, (bytes, bytearray)):
        return True
    if isinstance(prefix, tuple):
        return all(
            isinstance(item, (bytes, bytearray)) for item in cast("tuple[object, ...]", prefix)
        )
    return False


def _exact_filter_predicate_slice(
    value: ExactFilterValue,
    slice_operand: slice[int | None, int | None, int | None],
) -> ExactFilterValue | None:
    if isinstance(value, str):
        return value[slice_operand]
    if isinstance(value, bytes):
        return value[slice_operand]
    if isinstance(value, bytearray):
        return value[slice_operand]
    if isinstance(value, list):
        return value[slice_operand]
    if isinstance(value, tuple):
        return value[slice_operand]
    return None


def _exact_filter_predicate_unary_value(
    value: ExactFilterValue,
    operator_name: str,
) -> ExactFilterValue | None:
    if operator_name == "negative" and isinstance(value, (int, float, bool)):
        return -value
    if operator_name == "positive" and isinstance(value, (int, float, bool)):
        return +value
    if operator_name == "invert" and isinstance(value, (int, bool)):
        if isinstance(value, bool):
            return ~int(value)
        return ~value
    return None


def _exact_filter_predicate_truth_value(value: ExactFilterValue) -> bool:
    return bool(value)


def _exact_filter_predicate_len_value(value: ExactFilterValue) -> int | None:
    if isinstance(value, (str, bytes, bytearray, list, tuple)):
        return len(value)
    return None


def _evaluate_conditional_truth_branch(
    branch_truth: object,
    item_value: ExactFilterValue,
) -> bool | None:
    if branch_truth is _ARG_TRUTH_BRANCH:
        return _exact_filter_predicate_truth_value(item_value)
    if isinstance(branch_truth, bool):
        return branch_truth
    return None


def _exact_constant_truth_value(value: object) -> bool | None:
    if value is None or isinstance(value, SymbolicNone):
        return False
    if isinstance(value, (bool, int, float, str, bytes, bytearray)):
        return bool(value)
    if isinstance(value, tuple):
        return bool(cast("tuple[object, ...]", value))
    if isinstance(value, frozenset):
        return bool(cast("frozenset[object]", value))
    return None


def _exact_filter_predicate_str_input(item: object) -> str | None:
    if item is None or isinstance(item, SymbolicNone):
        return "None"
    if isinstance(item, (str, bytes, bytearray, int, float, bool)):
        return str(item)
    if isinstance(item, SymbolicString):
        if not z3.is_string_value(item.z3_str):
            return None
        try:
            return item.z3_str.as_string()
        except z3.Z3Exception:
            return None
    if isinstance(item, SymbolicValue):
        if item.value is None and z3.is_true(z3.simplify(item.is_none)):
            return "None"
        if isinstance(item.value, (str, bytes, bytearray, int, float, bool)):
            return str(item.value)
        if z3.is_true(item.is_str) and z3.is_string_value(item.z3_str):
            try:
                return item.z3_str.as_string()
            except z3.Z3Exception:
                return None
        simplified_int = z3.simplify(item.z3_int)
        if z3.is_int_value(simplified_int):
            return str(simplified_int.as_long())
    return None


def _exact_filter_predicate_input(item: object) -> ExactFilterValue | None:
    if isinstance(item, (int, float, bool, str, bytes, bytearray)):
        return item
    if isinstance(item, SymbolicBytes):
        return item.concrete_value
    list_value = _exact_list_value(item)
    if list_value is not None:
        return list_value
    tuple_value = _exact_tuple_value(item)
    if tuple_value is not None:
        return tuple_value
    if isinstance(item, SymbolicList):
        bytearray_value = _exact_symbolic_bytearray_value(item)
        if bytearray_value is not None:
            return bytearray_value
    if isinstance(item, SymbolicString):
        if not z3.is_string_value(item.z3_str):
            return None
        try:
            return item.z3_str.as_string()
        except z3.Z3Exception:
            return None
    if isinstance(item, SymbolicValue):
        modeled_list = _exact_list_value(getattr(item, "_modeled_object", None))
        if modeled_list is not None:
            return modeled_list
        modeled_tuple = _exact_tuple_value(getattr(item, "_modeled_object", None))
        if modeled_tuple is not None:
            return modeled_tuple
        if isinstance(item.value, (int, float, bool, str, bytes, bytearray)):
            return item.value
        if z3.is_true(item.is_str) and z3.is_string_value(item.z3_str):
            try:
                return item.z3_str.as_string()
            except z3.Z3Exception:
                return None
        simplified_int = z3.simplify(item.z3_int)
        if z3.is_int_value(simplified_int):
            return simplified_int.as_long()
    return None


def _exact_list_value(item: object) -> list[object] | None:
    raw_items: list[object]
    if isinstance(item, SymbolicList):
        if getattr(item, "_type", None) == "bytearray" or item.concrete_items is None:
            return None
        raw_items = item.concrete_items
    elif isinstance(item, list):
        raw_items = cast("list[object]", item)
    else:
        return None

    exact_items: list[object] = []
    for raw_item in raw_items:
        exact_item = _exact_filter_predicate_input(raw_item)
        if exact_item is None:
            return None
        exact_items.append(exact_item)
    return exact_items


def _exact_tuple_value(item: object) -> tuple[object, ...] | None:
    raw_items: tuple[object, ...]
    if isinstance(item, SymbolicTuple):
        raw_items = item.elements
    elif isinstance(item, tuple):
        raw_items = cast("tuple[object, ...]", item)
    else:
        return None

    exact_items: list[object] = []
    for raw_item in raw_items:
        exact_item = _exact_filter_predicate_input(raw_item)
        if exact_item is None:
            return None
        exact_items.append(exact_item)
    return tuple(exact_items)


def _exact_symbolic_bytearray_value(item: SymbolicList) -> bytearray | None:
    if getattr(item, "_type", None) != "bytearray" or item.concrete_items is None:
        return None
    values: list[int] = []
    for concrete_item in item.concrete_items:
        byte_value = _exact_bytearray_item(concrete_item)
        if byte_value is None:
            return None
        values.append(byte_value)
    return bytearray(values)


def _exact_bytearray_item(item: object) -> int | None:
    if isinstance(item, SymbolicValue):
        item = item.value
    if isinstance(item, bool):
        return int(item)
    if isinstance(item, int) and 0 <= item <= 255:
        return item
    return None


def _compare_exact_python_value(
    left: ExactFilterValue,
    op_name: str,
    right: object,
) -> bool | None:
    right_value = _exact_filter_predicate_input(right)
    if right_value is None:
        return None
    try:
        if op_name == "==":
            return left == right_value
        if op_name == "!=":
            return left != right_value
        return _order_compare_exact_python_values(left, op_name, right_value)
    except TypeError:
        return None


def _order_compare_exact_python_values(
    left: ExactFilterValue,
    op_name: str,
    right: ExactFilterValue,
) -> bool | None:
    if isinstance(left, (int, float, bool)) and isinstance(right, (int, float, bool)):
        return _order_compare_numeric(left, op_name, right)
    if isinstance(left, str) and isinstance(right, str):
        return _order_compare_str(left, op_name, right)
    if isinstance(left, bytes) and isinstance(right, bytes):
        return _order_compare_bytes(left, op_name, right)
    if isinstance(left, bytearray) and isinstance(right, bytearray):
        return _order_compare_bytearray(left, op_name, right)
    return None


def _order_compare_numeric(
    left: int | float | bool,
    op_name: str,
    right: int | float | bool,
) -> bool | None:
    if op_name == "<":
        return left < right
    if op_name == "<=":
        return left <= right
    if op_name == ">":
        return left > right
    if op_name == ">=":
        return left >= right
    return None


def _order_compare_str(left: str, op_name: str, right: str) -> bool | None:
    if op_name == "<":
        return left < right
    if op_name == "<=":
        return left <= right
    if op_name == ">":
        return left > right
    if op_name == ">=":
        return left >= right
    return None


def _order_compare_bytes(left: bytes, op_name: str, right: bytes) -> bool | None:
    if op_name == "<":
        return left < right
    if op_name == "<=":
        return left <= right
    if op_name == ">":
        return left > right
    if op_name == ">=":
        return left >= right
    return None


def _order_compare_bytearray(
    left: bytearray,
    op_name: str,
    right: bytearray,
) -> bool | None:
    if op_name == "<":
        return left < right
    if op_name == "<=":
        return left <= right
    if op_name == ">":
        return left > right
    if op_name == ">=":
        return left >= right
    return None


def _exact_int_map_input(item: object) -> str | bytes | bytearray | int | bool | float | None:
    if isinstance(item, (str, bytes, bytearray, int, bool, float)):
        return item
    if isinstance(item, SymbolicString):
        if not z3.is_string_value(item.z3_str):
            return None
        try:
            return item.z3_str.as_string()
        except z3.Z3Exception:
            return None
    if isinstance(item, SymbolicValue):
        if isinstance(item.value, (str, bytes, bytearray, int, bool, float)):
            return item.value
        if z3.is_true(item.is_str) and z3.is_string_value(item.z3_str):
            try:
                return item.z3_str.as_string()
            except z3.Z3Exception:
                return None
    return None


def _truth_predicate(value: object) -> z3.BoolRef | None:
    if isinstance(value, SymbolicValue):
        return value.could_be_truthy()
    if isinstance(value, SymbolicType):
        return value.could_be_truthy()
    if isinstance(value, (bool, int, float, str, bytes, bytearray)):
        return Z3_TRUE if value else Z3_FALSE
    if isinstance(value, list):
        return Z3_TRUE if cast("list[object]", value) else Z3_FALSE
    if isinstance(value, tuple):
        return Z3_TRUE if cast("tuple[object, ...]", value) else Z3_FALSE
    if isinstance(value, dict):
        return Z3_TRUE if cast("dict[object, object]", value) else Z3_FALSE
    if isinstance(value, (set, frozenset)):
        return Z3_TRUE if cast("set[object] | frozenset[object]", value) else Z3_FALSE
    return None
