from __future__ import annotations

import z3

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.models.stdlib.itertools.combinatorics import (
    combinations_with_replacement_model,
    model_combinations,
    model_permutations,
    model_product,
    model_zip_longest,
)
from pysymex._internal.models.stdlib.itertools.infinite import (
    model_count,
    model_cycle,
    model_repeat,
)
from pysymex._internal.models.stdlib.itertools.sequences import (
    ChainModel,
    model_accumulate,
    model_chain,
    model_chain_from_iterable,
    model_dropwhile,
    model_groupby,
    model_islice,
    model_takewhile,
)


def _sym_list(name: str, length: int) -> SymbolicList:
    sym = SymbolicList.empty(name)
    sym.z3_len = z3.IntVal(length)
    return sym


def _predicate(value: object) -> bool:
    return True


def test_model_chain() -> None:
    result = model_chain(_sym_list("a", 2), _sym_list("b", 3))
    assert isinstance(result, SymbolicList)


def test_model_chain_preserves_concrete_items() -> None:
    result = model_chain(
        SymbolicList.from_const([1]),
        SymbolicList.from_const([2, 3]),
    )

    assert result.concrete_items == [1, 2, 3]


def test_chain_model_registered_for_call_dispatch() -> None:
    from pysymex._internal.models.stdlib.registry import get_stdlib_model

    model = get_stdlib_model("itertools.chain")

    assert isinstance(model, ChainModel)


def test_model_chain_from_iterable() -> None:
    result = model_chain_from_iterable(_sym_list("a", 2))
    assert isinstance(result, SymbolicList)


def test_model_islice() -> None:
    result = model_islice(_sym_list("a", 5), 2)
    assert isinstance(result, SymbolicList)


def test_model_groupby() -> None:
    result = model_groupby(_sym_list("a", 5))
    assert isinstance(result, SymbolicList)


def test_model_product() -> None:
    result = model_product(_sym_list("a", 2), _sym_list("b", 3), repeat=1)
    assert isinstance(result, SymbolicList)


def test_model_permutations() -> None:
    result = model_permutations(_sym_list("a", 4), 2)
    assert isinstance(result, SymbolicList)


def test_model_combinations() -> None:
    result = model_combinations(_sym_list("a", 4), 2)
    assert isinstance(result, SymbolicList)


def test_model_combinations_with_replacement() -> None:
    result = combinations_with_replacement_model(_sym_list("a", 3), 2)
    assert isinstance(result, SymbolicList)


def test_model_count() -> None:
    model_count(1, 2)


def test_model_cycle() -> None:
    result = model_cycle(_sym_list("a", 3))
    assert isinstance(result, SymbolicList)


def test_model_repeat() -> None:
    result = model_repeat("x", 3)
    assert isinstance(result, SymbolicList)


def test_model_accumulate() -> None:
    result = model_accumulate(_sym_list("a", 3), initial=0)
    assert isinstance(result, SymbolicList)


def test_model_takewhile() -> None:
    result = model_takewhile(_predicate, _sym_list("a", 3))
    assert isinstance(result, SymbolicList)


def test_model_dropwhile() -> None:
    result = model_dropwhile(_predicate, _sym_list("a", 3))
    assert isinstance(result, SymbolicList)


def test_model_zip_longest() -> None:
    result = model_zip_longest(_sym_list("a", 2), _sym_list("b", 5))
    assert isinstance(result, SymbolicList)
