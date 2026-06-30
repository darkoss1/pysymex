"""Coverage and semantic contracts for the extended math model family."""

from __future__ import annotations

import math

import pytest
import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.models.stdlib.literals import concrete_value
from pysymex._internal.models.stdlib.math.extended import EXTENDED_MATH_FUNCTIONS, ExtendedMathModel
from pysymex._internal.models.stdlib.registry import get_stdlib_model


def _state() -> VMState:
    return VMState(pc=19)


def test_all_public_math_callables_resolve_to_models() -> None:
    missing = [
        name
        for name in dir(math)
        if not name.startswith("_")
        and callable(getattr(math, name))
        and get_stdlib_model(f"math.{name}") is None
    ]

    assert missing == []
    assert len(EXTENDED_MATH_FUNCTIONS) == 38


@pytest.mark.parametrize(
    ("operation", "args"),
    [
        ("acos", [0.5]),
        ("atan2", [1.0, 1.0]),
        ("comb", [6, 2]),
        ("dist", [[0.0, 0.0], [3.0, 4.0]]),
        ("frexp", [8.0]),
        ("hypot", [3.0, 4.0]),
        ("prod", [[2, 3, 4]]),
        ("sumprod", [[1, 2], [3, 4]]),
    ],
)
def test_extended_math_models_match_cpython_for_concrete_calls(
    operation: str, args: list[object]
) -> None:
    if not hasattr(math, operation):
        pytest.skip(f"math.{operation} is not available on this Python version")

    model = get_stdlib_model(f"math.{operation}")
    assert isinstance(model, ExtendedMathModel)

    result = model.apply(args, {}, _state())  # type: ignore[arg-type]
    expected = getattr(math, operation)(*args)

    assert concrete_value(result.value) == expected
    assert not result.degradations


@pytest.mark.parametrize(
    ("operation", "args", "exception_type"),
    [
        ("comb", [-1, 2], "ValueError"),
        ("remainder", [1.0, 0.0], "ValueError"),
        ("isqrt", [-1], "ValueError"),
    ],
)
def test_extended_math_models_surface_exact_domain_errors(
    operation: str, args: list[object], exception_type: str
) -> None:
    model = get_stdlib_model(f"math.{operation}")
    assert isinstance(model, ExtendedMathModel)

    result = model.apply(args, {}, _state())  # type: ignore[arg-type]
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == exception_type


def test_symbolic_math_results_keep_result_type_and_explicit_unknown_state() -> None:
    symbolic, symbolic_constraint = SymbolicValue.symbolic_int("math_input")
    acos_model = get_stdlib_model("math.acos")
    comb_model = get_stdlib_model("math.comb")
    assert isinstance(acos_model, ExtendedMathModel)
    assert isinstance(comb_model, ExtendedMathModel)

    float_result = acos_model.apply([symbolic], {}, _state())
    int_result = comb_model.apply([symbolic, 2], {}, _state())

    assert symbolic_constraint is not None
    assert isinstance(float_result.value, SymbolicValue)
    assert z3.is_true(float_result.value.is_float)
    assert float_result.degradations[0].kind == "unknown"
    assert isinstance(int_result.value, SymbolicValue)
    assert z3.is_true(int_result.value.is_int)
    assert int_result.degradations[0].kind == "unknown"
