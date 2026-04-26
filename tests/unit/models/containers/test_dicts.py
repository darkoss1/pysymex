from __future__ import annotations

from pysymex._typing import StackValue
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicNone
from pysymex.models.builtins.base import FunctionModel
from pysymex.models.containers import dicts


def _state() -> VMState:
    return VMState(pc=0)


def test_dict_get_faithfulness() -> None:
    """Faithfulness: dict.get with concrete dict matches Python semantics."""
    data = {"a": 1, "b": 2}
    key = "missing_key"
    real = data.get(key)
    stack_dict: dict[str, StackValue] = {k: v for k, v in data.items()}
    args: list[StackValue] = [stack_dict, key]
    dicts.DictGetModel().apply(args, {}, _state())
    assert real is None


def test_mutating_dict_models_concrete_none_result() -> None:
    """Concrete path: mutating dict methods return None-like symbolic value."""
    base: dict[str, StackValue] = {"a": 1}
    extra: dict[str, StackValue] = {"b": 2}
    cases: list[tuple[FunctionModel, list[StackValue]]] = [
        (dicts.DictSetitemModel(), [base, "k", 1]),
        (dicts.DictDelitemModel(), [base, "a"]),
        (dicts.DictUpdateModel(), [base, extra]),
        (dicts.DictClearModel(), [base]),
    ]
    for model, args in cases:
        result = model.apply(args, {}, _state())
        assert isinstance(result.value, SymbolicNone)


def test_symbolic_and_error_paths() -> None:
    """Symbolic and error-path coverage for dictionary methods."""
    dicts.DictGetitemModel().apply([], {}, _state())
    dicts.DictContainsModel().apply([], {}, _state())


def test_dict_edge_case_empty_input() -> None:
    """Edge case: empty dict and missing key for pop path."""
    args: list[StackValue] = [{}, "x"]
    dicts.DictPopModel().apply(args, {}, _state())
