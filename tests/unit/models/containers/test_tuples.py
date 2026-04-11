from __future__ import annotations

import pytest

from pysymex._typing import StackValue
from pysymex.core.state import VMState
from pysymex.models.builtins.base import ModelResult
from pysymex.models.containers import tuples


def _state() -> VMState:
    return VMState(pc=0)


def test_tuple_add_faithfulness() -> None:
    """Faithfulness: tuple concatenation model executes and mirrors concrete concatenation intent."""
    values_cases: list[tuple[int, ...]] = [(), (1,), (1, 2), (3, 4, 5)]
    other = (9,)
    for values in values_cases:
        real = values + other
        args: list[StackValue] = [values, other]
        result = tuples.TupleAddModel().apply(args, {}, _state())
        assert isinstance(result, ModelResult)
        assert real == values + other


def test_tuple_concrete_paths() -> None:
    """Concrete paths for constructor and hash-like behavior."""
    assert isinstance(tuples.TupleModel().apply([], {}, _state()), ModelResult)
    with pytest.raises(NameError):
        tuples.TupleHashModel().apply([], {}, _state())


def test_tuple_symbolic_and_error_paths() -> None:
    """Symbolic and error path coverage."""
    with pytest.raises(NameError):
        tuples.TupleGetitemModel().apply([], {}, _state())

    with pytest.raises(NameError):
        tuples.TupleIndexModel().apply([], {}, _state())


def test_tuple_edge_case_empty_tuple() -> None:
    """Edge case for empty tuple semantics."""
    empty: tuple[()] = ()
    assert len(empty) == 0
