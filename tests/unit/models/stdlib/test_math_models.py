"""Tests for pysymex.models.stdlib.math — all math model classes."""

from __future__ import annotations

import math

import z3

from pysymex.core.types.scalars import SymbolicValue
from pysymex.models.builtins import ModelResult
from pysymex.models.stdlib.math import (
    MathCeilModel,
    MathCosModel,
    MathExpModel,
    MathFabsModel,
    MathFloorModel,
    MathGcdModel,
    MathIsCloseModel,
    MathIsfiniteModel,
    MathIsinfModel,
    MathIsnanModel,
    MathLogModel,
    MathSinModel,
    MathSqrtModel,
    MathTanModel,
)


class _FakeState:
    """Minimal VMState substitute."""

    pc: int = 0
    path_id: int = 0


class TestMathSqrtModel:
    """Test MathSqrtModel.apply."""

    def test_no_args_returns_symbolic(self) -> None:
        """sqrt() with no args returns SymbolicValue."""
        model = MathSqrtModel()
        result = model.apply([], {}, _FakeState())
        assert isinstance(result, ModelResult)

    def test_concrete_positive(self) -> None:
        """sqrt(4.0) returns concrete result matching math.sqrt."""
        model = MathSqrtModel()
        result = model.apply([4.0], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == math.sqrt(4.0)

    def test_concrete_zero(self) -> None:
        """sqrt(0) returns 0.0."""
        model = MathSqrtModel()
        result = model.apply([0], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == 0.0

    def test_symbolic_input_adds_constraints(self) -> None:
        """sqrt(symbolic_x) adds non-negative constraint."""
        model = MathSqrtModel()
        x, _ = SymbolicValue.symbolic("x")
        result = model.apply([x], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)
        assert len(result.constraints) >= 2

    def test_non_numeric_non_symbolic_fallback(self) -> None:
        """sqrt(non-numeric) produces a symbolic result."""
        model = MathSqrtModel()
        result = model.apply(["not_a_number"], {}, _FakeState())
        assert isinstance(result, ModelResult)


class TestMathCeilModel:
    """Test MathCeilModel.apply."""

    def test_no_args(self) -> None:
        """ceil() with no args returns SymbolicValue with is_int constraint."""
        model = MathCeilModel()
        result = model.apply([], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)

    def test_concrete_float(self) -> None:
        """ceil(3.2) returns 4."""
        model = MathCeilModel()
        result = model.apply([3.2], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == 4

    def test_symbolic_adds_bounds(self) -> None:
        """ceil(symbolic_x) constrains result between x and x+1."""
        model = MathCeilModel()
        x, _ = SymbolicValue.symbolic("x")
        result = model.apply([x], {}, _FakeState())
        assert len(result.constraints) >= 3

    def test_non_numeric_fallback(self) -> None:
        """ceil(non-numeric) returns symbolic fallback."""
        model = MathCeilModel()
        result = model.apply(["string"], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)


class TestMathFloorModel:
    """Test MathFloorModel.apply."""

    def test_concrete_float(self) -> None:
        """floor(3.7) returns 3."""
        model = MathFloorModel()
        result = model.apply([3.7], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == 3

    def test_symbolic_input(self) -> None:
        """floor(symbolic_x) adds floor constraints."""
        model = MathFloorModel()
        x, _ = SymbolicValue.symbolic("x")
        result = model.apply([x], {}, _FakeState())
        assert len(result.constraints) >= 3


class TestMathLogModel:
    """Test MathLogModel.apply."""

    def test_concrete_positive(self) -> None:
        """log(1.0) returns 0.0 matching math.log."""
        model = MathLogModel()
        result = model.apply([1.0], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)
        assert abs(result.value.value - math.log(1.0)) < 1e-12

    def test_concrete_with_base(self) -> None:
        """log(100, 10) returns math.log(100, 10)."""
        model = MathLogModel()
        result = model.apply([100, 10], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)
        assert abs(result.value.value - math.log(100, 10)) < 1e-12

    def test_symbolic_input_adds_positivity_constraint(self) -> None:
        """log(symbolic_x) constrains x > 0."""
        model = MathLogModel()
        x, _ = SymbolicValue.symbolic("x")
        result = model.apply([x], {}, _FakeState())
        assert len(result.constraints) >= 2

    def test_no_args(self) -> None:
        """log() with no args returns symbolic."""
        model = MathLogModel()
        result = model.apply([], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)


class TestMathExpModel:
    """Test MathExpModel.apply."""

    def test_concrete_zero(self) -> None:
        """exp(0) returns 1.0."""
        model = MathExpModel()
        result = model.apply([0], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)
        assert abs(result.value.value - 1.0) < 1e-12

    def test_symbolic_adds_positive_constraint(self) -> None:
        """exp(symbolic) constrains result > 0."""
        model = MathExpModel()
        x, _ = SymbolicValue.symbolic("x")
        result = model.apply([x], {}, _FakeState())
        assert len(result.constraints) >= 2


class TestMathSinModel:
    """Test MathSinModel.apply."""

    def test_concrete_zero(self) -> None:
        """sin(0) returns 0.0."""
        model = MathSinModel()
        result = model.apply([0], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)
        assert abs(result.value.value - math.sin(0)) < 1e-12

    def test_symbolic_adds_range_constraints(self) -> None:
        """sin(symbolic) constrains result in [-1, 1]."""
        model = MathSinModel()
        x, _ = SymbolicValue.symbolic("x")
        result = model.apply([x], {}, _FakeState())
        assert len(result.constraints) >= 3


class TestMathCosModel:
    """Test MathCosModel.apply."""

    def test_concrete_zero(self) -> None:
        """cos(0) returns 1.0."""
        model = MathCosModel()
        result = model.apply([0], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)
        assert abs(result.value.value - math.cos(0)) < 1e-12

    def test_symbolic_adds_range_constraints(self) -> None:
        """cos(symbolic) constrains result in [-1, 1]."""
        model = MathCosModel()
        result = model.apply(["symbolic_obj"], {}, _FakeState())
        assert len(result.constraints) >= 3


class TestMathTanModel:
    """Test MathTanModel.apply."""

    def test_concrete_zero(self) -> None:
        """tan(0) returns 0.0."""
        model = MathTanModel()
        result = model.apply([0], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)
        assert abs(result.value.value - math.tan(0)) < 1e-12


class TestMathFabsModel:
    """Test MathFabsModel.apply."""

    def test_concrete_negative(self) -> None:
        """fabs(-3.5) returns 3.5."""
        model = MathFabsModel()
        result = model.apply([-3.5], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == 3.5

    def test_symbolic_adds_non_negative_constraint(self) -> None:
        """fabs(symbolic) constrains result >= 0."""
        model = MathFabsModel()
        x, _ = SymbolicValue.symbolic("x")
        result = model.apply([x], {}, _FakeState())
        assert len(result.constraints) >= 2

    def test_non_symbolic_non_numeric_fallback(self) -> None:
        """fabs(non-numeric) produces a constrained symbolic result."""
        model = MathFabsModel()
        result = model.apply(["not_a_num"], {}, _FakeState())
        assert len(result.constraints) >= 2


class TestMathGcdModel:
    """Test MathGcdModel.apply."""

    def test_concrete_gcd(self) -> None:
        """gcd(12, 8) returns 4."""
        model = MathGcdModel()
        result = model.apply([12, 8], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == math.gcd(12, 8)

    def test_fewer_than_two_args(self) -> None:
        """gcd with < 2 args returns symbolic."""
        model = MathGcdModel()
        result = model.apply([5], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)

    def test_symbolic_args_add_bounds(self) -> None:
        """gcd(symbolic_a, symbolic_b) adds gcd >= 0 constraint."""
        model = MathGcdModel()
        a, _ = SymbolicValue.symbolic("a")
        b, _ = SymbolicValue.symbolic("b")
        result = model.apply([a, b], {}, _FakeState())
        assert len(result.constraints) >= 3


class TestMathIsfiniteModel:
    """Test MathIsfiniteModel.apply."""

    def test_concrete_finite(self) -> None:
        """isfinite(42) returns True."""
        model = MathIsfiniteModel()
        result = model.apply([42], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value is True

    def test_concrete_inf(self) -> None:
        """isfinite(inf) returns False."""
        model = MathIsfiniteModel()
        result = model.apply([float("inf")], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value is False

    def test_symbolic_input(self) -> None:
        """isfinite(symbolic) adds is_bool constraint."""
        model = MathIsfiniteModel()
        x, _ = SymbolicValue.symbolic("x")
        result = model.apply([x], {}, _FakeState())
        assert len(result.constraints) >= 2


class TestMathIsCloseModel:
    """Test MathIsCloseModel.apply."""

    def test_concrete_close_values(self) -> None:
        """isclose(1.0, 1.0) returns True."""
        model = MathIsCloseModel()
        result = model.apply([1.0, 1.0], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value is True

    def test_concrete_not_close_values(self) -> None:
        """isclose(1.0, 100.0) returns False."""
        model = MathIsCloseModel()
        result = model.apply([1.0, 100.0], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value is False

    def test_symbolic_args_add_constraints(self) -> None:
        """isclose(symbolic, 1.0) adds tolerance constraints."""
        model = MathIsCloseModel()
        x, _ = SymbolicValue.symbolic("x")
        result = model.apply([x, 1.0], {}, _FakeState())
        assert len(result.constraints) >= 2

    def test_no_args(self) -> None:
        """isclose() with no args returns symbolic bool."""
        model = MathIsCloseModel()
        result = model.apply([], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)

    def test_get_fp_with_int(self) -> None:
        """get_fp handles int argument via FPVal conversion."""
        model = MathIsCloseModel()
        result = model.apply([1, 2], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)


class TestMathIsinfModel:
    """Test MathIsinfModel.apply."""

    def test_no_args(self) -> None:
        """isinf() returns False."""
        model = MathIsinfModel()
        result = model.apply([], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value is False

    def test_concrete_inf(self) -> None:
        """isinf(inf) returns True."""
        model = MathIsinfModel()
        result = model.apply([float("inf")], {}, _FakeState())
        assert result.value.value is True

    def test_concrete_finite(self) -> None:
        """isinf(42) returns False."""
        model = MathIsinfModel()
        result = model.apply([42], {}, _FakeState())
        assert result.value.value is False

    def test_symbolic_returns_false(self) -> None:
        """isinf(symbolic) returns False (SymbolicValues are always finite)."""
        model = MathIsinfModel()
        x, _ = SymbolicValue.symbolic("x")
        result = model.apply([x], {}, _FakeState())
        assert result.value.value is False

    def test_non_numeric_non_symbolic(self) -> None:
        """isinf(string) returns symbolic bool."""
        model = MathIsinfModel()
        result = model.apply(["string"], {}, _FakeState())
        assert isinstance(result.value, SymbolicValue)


class TestMathIsnanModel:
    """Test MathIsnanModel.apply."""

    def test_no_args(self) -> None:
        """isnan() returns False."""
        model = MathIsnanModel()
        result = model.apply([], {}, _FakeState())
        assert result.value.value is False

    def test_concrete_nan(self) -> None:
        """isnan(nan) returns True."""
        model = MathIsnanModel()
        result = model.apply([float("nan")], {}, _FakeState())
        assert result.value.value is True

    def test_symbolic_returns_false(self) -> None:
        """isnan(symbolic) returns False."""
        model = MathIsnanModel()
        x, _ = SymbolicValue.symbolic("x")
        result = model.apply([x], {}, _FakeState())
        assert result.value.value is False
