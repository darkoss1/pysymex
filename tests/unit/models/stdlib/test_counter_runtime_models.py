"""Heap-backed runtime contracts for collections.Counter."""

from __future__ import annotations

from typing import cast

import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.models.stdlib.collections.counter import (
    CounterConstructorModel,
    CounterMutationModel,
    CounterQueryModel,
)
from pysymex._internal.models.stdlib.literals import concrete_value
from pysymex._internal.models.stdlib.registry import get_stdlib_model


def _state() -> VMState:
    return VMState(pc=29)


def _counter_storage(handle: object, state: VMState) -> SymbolicDict:
    assert isinstance(handle, SymbolicObject)
    storage = state.load_heap(handle.address)
    assert isinstance(storage, SymbolicDict)
    return storage


def test_counter_constructor_retains_counts_and_zero_default_lookup() -> None:
    state = _state()
    model = get_stdlib_model("collections.Counter")
    assert isinstance(model, CounterConstructorModel)

    result = model.apply([["a", "b", "a"]], {}, state)
    storage = _counter_storage(result.value, state)

    assert concrete_value(storage) == {"a": 2, "b": 1}
    missing, presence = storage["missing"]
    assert z3.is_true(presence)
    assert z3.simplify(missing.z3_int).as_long() == 0
    assert getattr(storage, "_type", None) == "Counter"


def test_counter_queries_preserve_exact_results() -> None:
    state = _state()
    constructor = get_stdlib_model("collections.Counter")
    most_common = get_stdlib_model("Counter.most_common")
    elements = get_stdlib_model("Counter.elements")
    total = get_stdlib_model("Counter.total")
    assert isinstance(constructor, CounterConstructorModel)
    assert isinstance(most_common, CounterQueryModel)
    assert isinstance(elements, CounterQueryModel)
    assert isinstance(total, CounterQueryModel)
    handle = constructor.apply([{"a": 3, "b": 1}], {}, state).value

    common_result = most_common.apply([handle, 1], {}, state)
    elements_result = elements.apply([handle], {}, state)
    total_result = total.apply([handle], {}, state)

    assert isinstance(common_result.value, SymbolicList)
    assert concrete_value(common_result.value) == [("a", 3)]
    assert isinstance(elements_result.value, SymbolicIterator)
    assert concrete_value(elements_result.value.iterable) == ["a", "a", "a", "b"]
    assert concrete_value(total_result.value) == 4


def test_counter_mutations_emit_exact_tagged_dictionary_replacements() -> None:
    state = _state()
    constructor = get_stdlib_model("collections.Counter")
    update = get_stdlib_model("Counter.update")
    subtract = get_stdlib_model("Counter.subtract")
    assert isinstance(constructor, CounterConstructorModel)
    assert isinstance(update, CounterMutationModel)
    assert isinstance(subtract, CounterMutationModel)
    handle = constructor.apply([["a", "b"]], {}, state).value

    update_result = update.apply([handle, ["a", "c"]], {}, state)
    update_payload = update_result.side_effects["dict_mutation"]
    assert isinstance(update_payload, dict)
    updated = cast("dict[str, object]", update_payload)["updated_dict"]
    assert isinstance(updated, SymbolicDict)
    assert concrete_value(updated) == {"a": 2, "b": 1, "c": 1}
    assert getattr(updated, "_type", None) == "Counter"

    state.store_heap(cast_handle_address(handle), updated)
    subtract_result = subtract.apply([handle, ["a", "b"]], {}, state)
    subtract_payload = subtract_result.side_effects["dict_mutation"]
    assert isinstance(subtract_payload, dict)
    subtracted = cast("dict[str, object]", subtract_payload)["updated_dict"]
    assert isinstance(subtracted, SymbolicDict)
    assert concrete_value(subtracted) == {"a": 1, "b": 0, "c": 1}


def cast_handle_address(handle: object) -> int:
    assert isinstance(handle, SymbolicObject)
    return handle.address
