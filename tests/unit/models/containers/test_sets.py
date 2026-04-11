from __future__ import annotations

import pytest

from pysymex._typing import StackValue
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicNone, SymbolicValue
from pysymex.models.builtins.base import FunctionModel
from pysymex.models.containers import sets


def _state() -> VMState:
    return VMState(pc=0)


def test_set_add_faithfulness() -> None:
    """Faithfulness: set.add returns None in Python and model returns None-like symbolic value."""
    cases: list[tuple[list[int], int]] = [([], 1), ([1, 2], 3), ([4], 4), ([7, 8, 9], -1)]
    for data, item in cases:
        real = set(data)
        py_result = real.add(item)
        symbolic_set = SymbolicValue.from_const(len(data))
        args: list[StackValue] = [symbolic_set, item]
        model_result = sets.SetAddModel().apply(args, {}, _state())
        assert py_result is None
        assert isinstance(model_result.value, SymbolicNone)


def test_mutating_set_models_concrete_none_result() -> None:
    """Concrete path for mutating set methods."""
    base = SymbolicValue.from_const(2)
    cases: list[tuple[FunctionModel, list[StackValue]]] = [
        (sets.SetAddModel(), [base, 3]),
        (sets.SetDiscardModel(), [base, 3]),
        (sets.SetClearModel(), [base]),
    ]
    for model, args in cases:
        result = model.apply(args, {}, _state())
        assert isinstance(result.value, SymbolicNone)


def test_set_symbolic_and_error_paths() -> None:
    """Symbolic and error path behavior for pop/contains-like operations."""
    with pytest.raises(NameError):
        sets.SetPopModel().apply([], {}, _state())

    with pytest.raises(NameError):
        sets.SetContainsModel().apply([], {}, _state())


def test_set_edge_case_empty_input() -> None:
    """Edge case: empty set constructor args path."""
    with pytest.raises(NameError):
        sets.SetModel().apply([], {}, _state())
