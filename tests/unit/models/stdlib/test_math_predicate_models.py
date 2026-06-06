"""Tests for predicate stdlib math models."""

from __future__ import annotations

from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import is_raised_exception_effect
from pysymex.models.stdlib.math import (
    MathIsCloseModel,
    MathIsfiniteModel,
    MathIsinfModel,
    MathIsnanModel,
)
from tests.unit.models.stdlib.math_model_helpers import make_state


class TestMathIsfiniteModel:
    def test_concrete_finite(self) -> None:
        result = MathIsfiniteModel().apply([42], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value is True

    def test_concrete_inf(self) -> None:
        result = MathIsfiniteModel().apply([float("inf")], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value is False

    def test_symbolic_input(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = MathIsfiniteModel().apply([x], {}, make_state())
        assert len(result.constraints) >= 2


class TestMathIsCloseModel:
    def test_concrete_close_values(self) -> None:
        result = MathIsCloseModel().apply([1.0, 1.0], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value is True

    def test_concrete_not_close_values(self) -> None:
        result = MathIsCloseModel().apply([1.0, 100.0], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value is False

    def test_symbolic_args_add_constraints(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = MathIsCloseModel().apply([x, 1.0], {}, make_state())
        assert len(result.constraints) >= 2

    def test_no_args(self) -> None:
        result = MathIsCloseModel().apply([], {}, make_state())
        assert isinstance(result.value, SymbolicValue)

    def test_get_fp_with_int(self) -> None:
        result = MathIsCloseModel().apply([1, 2], {}, make_state())
        assert isinstance(result.value, SymbolicValue)


class TestMathIsinfModel:
    def test_no_args(self) -> None:
        result = MathIsinfModel().apply([], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        raised = result.side_effects.get("raised_exception")
        assert is_raised_exception_effect(raised)
        assert raised["exception_type"] == "TypeError"

    def test_concrete_inf(self) -> None:
        result = MathIsinfModel().apply([float("inf")], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value is True

    def test_concrete_finite(self) -> None:
        result = MathIsinfModel().apply([42], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value is False

    def test_symbolic_returns_false(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = MathIsinfModel().apply([x], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value is None
        assert "potential_exception" in result.side_effects
        assert len(result.constraints) >= 2

    def test_non_numeric_non_symbolic(self) -> None:
        result = MathIsinfModel().apply(["string"], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        raised = result.side_effects.get("raised_exception")
        assert is_raised_exception_effect(raised)
        assert raised["exception_type"] == "TypeError"


class TestMathIsnanModel:
    def test_no_args(self) -> None:
        result = MathIsnanModel().apply([], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        raised = result.side_effects.get("raised_exception")
        assert is_raised_exception_effect(raised)
        assert raised["exception_type"] == "TypeError"

    def test_concrete_nan(self) -> None:
        result = MathIsnanModel().apply([float("nan")], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value is True

    def test_symbolic_returns_false(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = MathIsnanModel().apply([x], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value is None
        assert "potential_exception" in result.side_effects
        assert len(result.constraints) >= 2
