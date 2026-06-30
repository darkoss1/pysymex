"""Execution-facing coverage for the public itertools family."""

from __future__ import annotations

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.models.stdlib.itertools.runtime import (
    FiniteItertoolsModel,
    OpaqueItertoolsModel,
)
from pysymex._internal.models.stdlib.literals import concrete_value
from pysymex._internal.models.stdlib.registry import get_stdlib_model


def _state() -> VMState:
    return VMState(pc=17)


def _truthy(value: object) -> bool:
    return bool(value)


def _iterator_values(value: object) -> object:
    assert isinstance(value, SymbolicIterator)
    return concrete_value(value.iterable)


def test_public_itertools_family_is_reachable_through_call_registry() -> None:
    names = {
        "accumulate",
        "batched",
        "chain",
        "chain.from_iterable",
        "combinations",
        "combinations_with_replacement",
        "compress",
        "count",
        "cycle",
        "dropwhile",
        "filterfalse",
        "groupby",
        "islice",
        "pairwise",
        "permutations",
        "product",
        "repeat",
        "starmap",
        "takewhile",
        "tee",
        "zip_longest",
    }

    assert all(get_stdlib_model(f"itertools.{name}") is not None for name in names)


def test_combinatoric_and_slice_models_preserve_exact_items() -> None:
    combinations = get_stdlib_model("itertools.combinations")
    islice = get_stdlib_model("itertools.islice")
    assert isinstance(combinations, FiniteItertoolsModel)
    assert isinstance(islice, FiniteItertoolsModel)

    combined = combinations.apply([[1, 2, 3], 2], {}, _state())
    sliced = islice.apply([[10, 20, 30], 1, 3], {}, _state())

    assert _iterator_values(combined.value) == [(1, 2), (1, 3), (2, 3)]
    assert _iterator_values(sliced.value) == [20, 30]
    assert not combined.degradations
    assert not sliced.degradations


def test_groupby_and_filterfalse_without_callbacks_are_exact() -> None:
    groupby = get_stdlib_model("itertools.groupby")
    filterfalse = get_stdlib_model("itertools.filterfalse")
    assert isinstance(groupby, FiniteItertoolsModel)
    assert isinstance(filterfalse, FiniteItertoolsModel)

    grouped = groupby.apply([[1, 1, 2]], {}, _state())
    filtered = filterfalse.apply([None, [0, 1, "", "x"]], {}, _state())

    assert _iterator_values(grouped.value) == [(1, [1, 1]), (2, [2])]
    assert _iterator_values(filtered.value) == [0, ""]


def test_tee_returns_independent_exact_iterator_carriers() -> None:
    tee = get_stdlib_model("itertools.tee")
    assert isinstance(tee, FiniteItertoolsModel)

    result = tee.apply([[1, 2], 3], {}, _state())

    assert isinstance(result.value, SymbolicTuple)
    assert len(result.value.elements) == 3
    assert [_iterator_values(iterator) for iterator in result.value] == [[1, 2]] * 3


def test_finite_models_surface_cpython_argument_errors() -> None:
    combinations = get_stdlib_model("itertools.combinations")
    assert isinstance(combinations, FiniteItertoolsModel)

    result = combinations.apply([[1, 2], -1], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "ValueError"


def test_callback_and_infinite_models_are_explicitly_inconclusive() -> None:
    takewhile = get_stdlib_model("itertools.takewhile")
    count = get_stdlib_model("itertools.count")
    assert isinstance(takewhile, OpaqueItertoolsModel)
    assert isinstance(count, OpaqueItertoolsModel)

    callback_result = takewhile.apply([_truthy, [1, 2]], {}, _state())
    infinite_result = count.apply([], {}, _state())

    assert isinstance(callback_result.value, SymbolicIterator)
    assert callback_result.degradations[0].kind == "unsupported"
    assert isinstance(infinite_result.value, SymbolicIterator)
    assert infinite_result.degradations[0].kind == "unknown"
