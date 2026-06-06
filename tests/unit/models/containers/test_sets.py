from __future__ import annotations

import pytest

from pysymex.typing import StackValue
from pysymex.core.state.record import VMState
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import FunctionModel, is_raised_exception_effect
from pysymex.models.containers.sets.constructor import SetModel
from pysymex.models.containers.sets.mutations.membership import (
    SetAddModel,
    SetDiscardModel,
    SetRemoveModel,
)
from pysymex.models.containers.sets.mutations.pop_clear import (
    SetClearModel,
    SetPopModel,
)
from pysymex.models.containers.sets.queries import SetContainsModel
from pysymex.models.containers.sets.operations import (
    SetCopyModel,
    SetDifferenceModel,
    SetIntersectionModel,
    SetSymmetricDifferenceModel,
    SetUnionModel,
)
from pysymex.models.containers.sets.queries import (
    SetIsdisjointModel,
    SetIssubsetModel,
    SetIssupersetModel,
)
from pysymex.models.containers.sets.updates import (
    SetDifferenceUpdateModel,
    SetIntersectionUpdateModel,
    SetSymmetricDifferenceUpdateModel,
    SetUpdateModel,
)


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
        model_result = SetAddModel().apply(args, {}, _state())
        assert py_result is None
        assert isinstance(model_result.value, SymbolicNone)


def test_mutating_set_models_concrete_none_result() -> None:
    """Concrete path for mutating set methods."""
    base = SymbolicValue.from_const(2)
    cases: list[tuple[FunctionModel, list[StackValue]]] = [
        (SetAddModel(), [base, 3]),
        (SetDiscardModel(), [base, 3]),
        (SetClearModel(), [base]),
    ]
    for model, args in cases:
        result = model.apply(args, {}, _state())
        assert isinstance(result.value, SymbolicNone)


def test_set_symbolic_and_error_paths() -> None:
    """Symbolic and error path behavior for pop/contains-like operations."""
    SetPopModel().apply([], {}, _state())
    SetContainsModel().apply([], {}, _state())


def test_set_edge_case_empty_input() -> None:
    """Edge case: empty set constructor args path."""
    SetModel().apply([], {}, _state())


def test_set_constructor_rejects_definite_non_iterable() -> None:
    result = SetModel().apply([1], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


INVALID_POSITIONAL_CASES: list[tuple[FunctionModel, list[StackValue]]] = [
    (SetAddModel(), []),
    (SetAddModel(), [1, 2]),
    (SetDiscardModel(), []),
    (SetDiscardModel(), [1, 2]),
    (SetRemoveModel(), []),
    (SetRemoveModel(), [1, 2]),
    (SetPopModel(), [1]),
    (SetClearModel(), [1]),
    (SetCopyModel(), [1]),
    (SetSymmetricDifferenceModel(), []),
    (SetSymmetricDifferenceModel(), [SymbolicValue.from_const(1), SymbolicValue.from_const(2)]),
    (SetIssubsetModel(), []),
    (SetIssupersetModel(), []),
    (SetIsdisjointModel(), []),
    (SetSymmetricDifferenceUpdateModel(), []),
]


@pytest.mark.parametrize(("model", "method_args"), INVALID_POSITIONAL_CASES)
def test_set_public_methods_reject_invalid_positional_arity(
    model: FunctionModel, method_args: list[StackValue]
) -> None:
    """Exact-arity public set methods reject CPython-invalid positional forms."""
    result = model.apply([SymbolicValue.from_const(1), *method_args], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


PUBLIC_SET_METHODS: list[tuple[FunctionModel, list[StackValue]]] = [
    (SetAddModel(), [1]),
    (SetDiscardModel(), [1]),
    (SetRemoveModel(), [1]),
    (SetPopModel(), []),
    (SetClearModel(), []),
    (SetCopyModel(), []),
    (SetUnionModel(), []),
    (SetIntersectionModel(), []),
    (SetDifferenceModel(), []),
    (SetSymmetricDifferenceModel(), [SymbolicValue.from_const(1)]),
    (SetIssubsetModel(), [SymbolicValue.from_const(1)]),
    (SetIssupersetModel(), [SymbolicValue.from_const(1)]),
    (SetIsdisjointModel(), [SymbolicValue.from_const(1)]),
    (SetUpdateModel(), []),
    (SetIntersectionUpdateModel(), []),
    (SetDifferenceUpdateModel(), []),
    (SetSymmetricDifferenceUpdateModel(), [SymbolicValue.from_const(1)]),
]


@pytest.mark.parametrize(("model", "method_args"), PUBLIC_SET_METHODS)
def test_set_public_methods_reject_keywords(
    model: FunctionModel, method_args: list[StackValue]
) -> None:
    """Public set methods reject keyword arguments in CPython."""
    result = model.apply([SymbolicValue.from_const(1), *method_args], {"unexpected": 1}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize(
    "model",
    [
        SetUnionModel(),
        SetIntersectionModel(),
        SetDifferenceModel(),
        SetUpdateModel(),
        SetIntersectionUpdateModel(),
        SetDifferenceUpdateModel(),
    ],
)
def test_variadic_set_methods_accept_no_additional_iterables(model: FunctionModel) -> None:
    """Variadic set operations accept a receiver-only call in CPython."""
    result = model.apply([SymbolicValue.from_const(1)], {}, _state())

    assert "raised_exception" not in result.side_effects
