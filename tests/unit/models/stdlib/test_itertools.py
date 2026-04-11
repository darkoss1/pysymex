from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
import z3

from pysymex.core.types.containers import SymbolicList


def _load_itertools_models() -> ModuleType:
    module_path = Path(__file__).resolve().parents[4] / "pysymex" / "models" / "stdlib" / "itertools.py"
    spec = importlib.util.spec_from_file_location("pysymex_models_stdlib_itertools", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load stdlib itertools models module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


itertools_models = _load_itertools_models()


def _sym_list(name: str, length: int) -> SymbolicList:
    sym = SymbolicList.empty(name)
    sym.z3_len = z3.IntVal(length)
    return sym


def _predicate(_value: object) -> bool:
    return True


def test_model_chain() -> None:
    result = itertools_models.model_chain(_sym_list("a", 2), _sym_list("b", 3))
    assert isinstance(result, SymbolicList)


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
    with pytest.raises(NameError):
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
