from __future__ import annotations


import z3

from pysymex.core.types.containers.lists import SymbolicList

from pysymex.models.stdlib import itertools as itertools_models


def _sym_list(name: str, length: int) -> SymbolicList:
    sym = SymbolicList.empty(name)
    sym.z3_len = z3.IntVal(length)
    return sym


def _predicate(value: object) -> bool:
    return True


def test_model_chain() -> None:
    result = itertools_models.model_chain(_sym_list("a", 2), _sym_list("b", 3))
    assert isinstance(result, SymbolicList)


def test_model_chain_preserves_concrete_items() -> None:
    result = itertools_models.model_chain(
        SymbolicList.from_const([1]),
        SymbolicList.from_const([2, 3]),
    )

    assert result.concrete_items == [1, 2, 3]


def test_chain_model_registered_for_call_dispatch() -> None:
    from pysymex.models.stdlib import get_stdlib_model

    model = get_stdlib_model("itertools.chain")

    assert isinstance(model, itertools_models.ChainModel)


def test_model_chain_from_iterable() -> None:
    result = itertools_models.model_chain_from_iterable(_sym_list("a", 2))
    assert isinstance(result, SymbolicList)


def test_model_islice() -> None:
    result = itertools_models.model_islice(_sym_list("a", 5), 2)
    assert isinstance(result, SymbolicList)


def test_model_groupby() -> None:
    result = itertools_models.model_groupby(_sym_list("a", 5))
    assert isinstance(result, SymbolicList)


def test_model_product() -> None:
    result = itertools_models.model_product(_sym_list("a", 2), _sym_list("b", 3), repeat=1)
    assert isinstance(result, SymbolicList)


def test_model_permutations() -> None:
    result = itertools_models.model_permutations(_sym_list("a", 4), 2)
    assert isinstance(result, SymbolicList)


def test_model_combinations() -> None:
    result = itertools_models.model_combinations(_sym_list("a", 4), 2)
    assert isinstance(result, SymbolicList)


def test_model_combinations_with_replacement() -> None:
    result = itertools_models.model_combinations_with_replacement(_sym_list("a", 3), 2)
    assert isinstance(result, SymbolicList)


def test_model_count() -> None:
    itertools_models.model_count(1, 2)


def test_model_cycle() -> None:
    result = itertools_models.model_cycle(_sym_list("a", 3))
    assert isinstance(result, SymbolicList)


def test_model_repeat() -> None:
    result = itertools_models.model_repeat("x", 3)
    assert isinstance(result, SymbolicList)


def test_model_accumulate() -> None:
    result = itertools_models.model_accumulate(_sym_list("a", 3), initial=0)
    assert isinstance(result, SymbolicList)


def test_model_takewhile() -> None:
    result = itertools_models.model_takewhile(_predicate, _sym_list("a", 3))
    assert isinstance(result, SymbolicList)


def test_model_dropwhile() -> None:
    result = itertools_models.model_dropwhile(_predicate, _sym_list("a", 3))
    assert isinstance(result, SymbolicList)


def test_model_zip_longest() -> None:
    result = itertools_models.model_zip_longest(_sym_list("a", 2), _sym_list("b", 5))
    assert isinstance(result, SymbolicList)


def test_get_itertools_model() -> None:
    assert callable(itertools_models.get_itertools_model("chain"))
    assert itertools_models.get_itertools_model("missing") is None


def test_register_itertools_models() -> None:
    registered = itertools_models.register_itertools_models()
    assert "itertools.chain" in registered
    assert "itertools.zip_longest" in registered
