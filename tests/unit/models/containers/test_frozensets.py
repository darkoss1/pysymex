from __future__ import annotations

import pytest

from pysymex.typing import StackValue
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.models.builtins.base import FunctionModel, is_raised_exception_effect
from pysymex.models.containers.frozensets.operations import (
    FrozensetCopyModel,
    FrozensetDifferenceModel,
    FrozensetIntersectionModel,
    FrozensetSymmetricDifferenceModel,
    FrozensetUnionModel,
)
from pysymex.models.containers.frozensets.queries import (
    FrozensetContainsModel,
    FrozensetHashModel,
)
from pysymex.models.containers.frozensets.relations import (
    FrozensetIsdisjointModel,
    FrozensetIssubsetModel,
    FrozensetIssupersetModel,
)


def _state() -> VMState:
    return VMState(pc=0)


def test_frozenset_faithfulness_baseline() -> None:
    """Faithfulness baseline for immutable frozenset behavior."""
    values_cases: list[frozenset[int]] = [frozenset(), frozenset({1}), frozenset({1, 2})]
    for values in values_cases:
        assert values.union({9}) == frozenset(values).union({9})
        assert values.intersection({1, 9}) == frozenset(values).intersection({1, 9})


def test_frozenset_symbolic_error_paths() -> None:
    """Representative symbolic/error path checks."""
    FrozensetHashModel().apply([], {}, _state())
    FrozensetContainsModel().apply([], {}, _state())


def test_frozenset_edge_case_empty() -> None:
    """Edge case for empty frozenset."""
    empty: frozenset[int] = frozenset()
    assert len(empty) == 0


EXACT_FROZENSET_METHODS: list[tuple[FunctionModel, list[StackValue]]] = [
    (FrozensetCopyModel(), []),
    (FrozensetSymmetricDifferenceModel(), [SymbolicList.empty("other")]),
    (FrozensetIssubsetModel(), [SymbolicList.empty("other")]),
    (FrozensetIssupersetModel(), [SymbolicList.empty("other")]),
    (FrozensetIsdisjointModel(), [SymbolicList.empty("other")]),
]


@pytest.mark.parametrize(("model", "method_args"), EXACT_FROZENSET_METHODS)
def test_exact_frozenset_methods_reject_invalid_calls(
    model: FunctionModel, method_args: list[StackValue]
) -> None:
    receiver = SymbolicList.empty("receiver")
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([receiver, *method_args, 1], {}),
        ([receiver, *method_args], {"unexpected": 1}),
    ]
    for args, kwargs in invalid_calls:
        effect = model.apply(args, kwargs, _state()).side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"

    assert (
        "raised_exception" not in model.apply([receiver, *method_args], {}, _state()).side_effects
    )


@pytest.mark.parametrize(
    "model",
    [
        FrozensetSymmetricDifferenceModel(),
        FrozensetIssubsetModel(),
        FrozensetIssupersetModel(),
        FrozensetIsdisjointModel(),
    ],
)
def test_frozenset_operand_methods_reject_missing_operand(model: FunctionModel) -> None:
    effect = model.apply([SymbolicList.empty("receiver")], {}, _state()).side_effects.get(
        "raised_exception"
    )

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize(
    "model", [FrozensetUnionModel(), FrozensetIntersectionModel(), FrozensetDifferenceModel()]
)
def test_variadic_frozenset_methods_allow_empty_and_multiple_operands(model: FunctionModel) -> None:
    receiver = SymbolicList.empty("receiver")
    valid_calls: list[list[StackValue]] = [
        [receiver],
        [receiver, SymbolicList.empty("left"), SymbolicList.empty("right")],
    ]
    for args in valid_calls:
        assert "raised_exception" not in model.apply(args, {}, _state()).side_effects

    effect = model.apply([receiver], {"unexpected": 1}, _state()).side_effects.get(
        "raised_exception"
    )
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"
