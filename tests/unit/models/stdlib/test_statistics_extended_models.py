"""Broad semantic coverage for common statistics functions."""

from __future__ import annotations

import statistics

import pytest
import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.models.stdlib.literals import concrete_value
from pysymex._internal.models.stdlib.registry import get_stdlib_model
from pysymex._internal.models.stdlib.statistics.extended import (
    EXTENDED_STATISTICS_FUNCTIONS,
    StatisticsModel,
)

_ERROR_CASES: list[tuple[str, list[object]]] = [
    ("mean", [[]]),
    ("variance", [[1]]),
]


def _state() -> VMState:
    return VMState(pc=23)


def test_common_statistics_function_family_is_registered() -> None:
    expected = {"mean", "median", *EXTENDED_STATISTICS_FUNCTIONS}

    assert len(EXTENDED_STATISTICS_FUNCTIONS) == 16
    assert all(get_stdlib_model(f"statistics.{name}") is not None for name in expected)


@pytest.mark.parametrize(
    ("operation", "args", "kwargs"),
    [
        ("correlation", [[1, 2, 3], [2, 4, 8]], {}),
        ("fmean", [[1, 2, 6]], {}),
        ("linear_regression", [[1, 2, 3], [2, 4, 6]], {}),
        ("multimode", [[1, 2, 2, 3, 3]], {}),
        ("pvariance", [[2, 4, 6]], {}),
        ("quantiles", [[1, 2, 3, 4, 5]], {"n": 4}),
    ],
)
def test_extended_statistics_models_match_cpython(
    operation: str, args: list[object], kwargs: dict[str, object]
) -> None:
    model = get_stdlib_model(f"statistics.{operation}")
    assert isinstance(model, StatisticsModel)

    result = model.apply(args, kwargs, _state())  # type: ignore[arg-type]
    expected = getattr(statistics, operation)(*args, **kwargs)
    expected_value = tuple(expected) if operation == "linear_regression" else expected

    assert concrete_value(result.value) == expected_value
    assert not result.degradations


@pytest.mark.parametrize(("operation", "args"), _ERROR_CASES)
def test_statistics_models_surface_insufficient_sample_errors(
    operation: str, args: list[object]
) -> None:
    model = get_stdlib_model(f"statistics.{operation}")
    assert model is not None

    result = model.apply(args, {}, _state())  # type: ignore[arg-type]
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "StatisticsError"


def test_symbolic_statistics_results_keep_shape_and_unknown_status() -> None:
    values, value_constraint = SymbolicList.symbolic("observations")
    variance = get_stdlib_model("statistics.variance")
    quantiles = get_stdlib_model("statistics.quantiles")
    assert isinstance(variance, StatisticsModel)
    assert isinstance(quantiles, StatisticsModel)

    scalar = variance.apply([values], {}, _state())
    sequence = quantiles.apply([values], {}, _state())

    assert value_constraint is not None
    assert isinstance(scalar.value, SymbolicValue)
    assert z3.is_true(scalar.value.is_float)
    assert scalar.degradations[0].kind == "unknown"
    assert isinstance(sequence.value, SymbolicList)
    assert sequence.degradations[0].kind == "unknown"
