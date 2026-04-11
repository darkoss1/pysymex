from __future__ import annotations

import pytest

from pysymex._typing import StackValue
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicNone
from pysymex.models.builtins.base import FunctionModel
from pysymex.models.containers import lists


def _state() -> VMState:
    return VMState(pc=0)


def test_append_model_faithfulness() -> None:
    """Faithfulness: list.append returns None like Python."""
    values = [1, 2]
    item = 3
    real_values = list(values)
    real_result = real_values.append(item)
    args: list[StackValue] = [list(values), item]
    model_result = lists.ListAppendModel().apply(args, {}, _state())
    assert real_result is None
    assert isinstance(model_result.value, SymbolicNone)


def test_mutating_models_concrete_none_result() -> None:
    """Concrete path: mutating list methods return None-like symbolic value."""
    seq: list[StackValue] = [1, 2]
    cases: list[tuple[FunctionModel, list[StackValue]]] = [
        (lists.ListAppendModel(), [seq, 3]),
        (lists.ListExtendModel(), [seq, [3, 4]]),
        (lists.ListInsertModel(), [seq, 1, 99]),
        (lists.ListClearModel(), [seq]),
        (lists.ListSortModel(), [seq]),
        (lists.ListReverseModel(), [seq]),
    ]
    for model, args in cases:
        result = model.apply(args, {}, _state())
        assert isinstance(result.value, SymbolicNone)


def test_symbolic_and_error_paths() -> None:
    """Symbolic and error path coverage for indexing/pop style methods."""
    with pytest.raises(NameError):
        lists.ListPopModel().apply([], {}, _state())

    with pytest.raises(NameError):
        lists.ListIndexModel().apply([], {}, _state())


def test_list_edge_case_empty_input() -> None:
    """Edge case: empty list input on contains model."""
    args: list[StackValue] = [[], 1]
    with pytest.raises(NameError):
        lists.ListContainsModel().apply(args, {}, _state())
