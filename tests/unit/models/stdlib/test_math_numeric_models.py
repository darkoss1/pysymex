"""Tests for numeric stdlib math models."""

from __future__ import annotations

import math

import z3

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.results import ModelResult, SideEffects
from pysymex._internal.models.stdlib.math.exponential import MathExpModel, MathLogModel
from pysymex._internal.models.stdlib.math.numeric import (
    MathCosModel,
    MathFabsModel,
    MathGcdModel,
    MathSinModel,
    MathTanModel,
)
from pysymex._internal.models.stdlib.math.roots import MathCeilModel, MathFloorModel, MathSqrtModel
from tests.unit.models.stdlib.math_model_helpers import make_state


class TestMathSqrtModel:
    def test_no_args_returns_symbolic(self) -> None:
        result = MathSqrtModel().apply([], {}, make_state())
        assert isinstance(result, ModelResult)

    def test_concrete_positive(self) -> None:
        result = MathSqrtModel().apply([4.0], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == math.sqrt(4.0)

    def test_concrete_zero(self) -> None:
        result = MathSqrtModel().apply([0], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == 0.0

    def test_concrete_negative_emits_value_error_side_effect(self) -> None:
        result = MathSqrtModel().apply([-1], {}, make_state())

        raised = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(raised)
        assert raised["exception_type"] == "ValueError"
        assert raised["message"] == "math domain error"

    def test_symbolic_input_adds_constraints(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = MathSqrtModel().apply([x], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        assert len(result.constraints) >= 2

    def test_symbolic_input_emits_potential_value_error_side_effect(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = MathSqrtModel().apply([x], {}, make_state())

        potential = result.side_effects.get("potential_exception")
        assert SideEffects.is_potential_exception(potential)
        assert potential["type"] == "ValueError"
        assert potential["message"] == "math domain error"

    def test_non_numeric_non_symbolic_fallback(self) -> None:
        result = MathSqrtModel().apply(["not_a_number"], {}, make_state())
        assert isinstance(result, ModelResult)


class TestMathCeilModel:
    def test_no_args(self) -> None:
        result = MathCeilModel().apply([], {}, make_state())
        assert isinstance(result.value, SymbolicValue)

    def test_concrete_float(self) -> None:
        result = MathCeilModel().apply([3.2], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == 4

    def test_symbolic_adds_bounds(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = MathCeilModel().apply([x], {}, make_state())
        assert len(result.constraints) >= 3

    def test_non_numeric_fallback(self) -> None:
        result = MathCeilModel().apply(["string"], {}, make_state())
        assert isinstance(result.value, SymbolicValue)


class TestMathFloorModel:
    def test_concrete_float(self) -> None:
        result = MathFloorModel().apply([3.7], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == 3

    def test_symbolic_input(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = MathFloorModel().apply([x], {}, make_state())
        assert len(result.constraints) >= 3


class TestMathLogModel:
    def test_concrete_positive(self) -> None:
        result = MathLogModel().apply([1.0], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        concrete_val = result.value.value
        assert isinstance(concrete_val, (int, float))
        assert abs(concrete_val - math.log(1.0)) < 1e-12

    def test_concrete_with_base(self) -> None:
        result = MathLogModel().apply([100, 10], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        concrete_val = result.value.value
        assert isinstance(concrete_val, (int, float))
        assert abs(concrete_val - math.log(100, 10)) < 1e-12

    def test_concrete_nonpositive_emits_value_error_side_effect(self) -> None:
        result = MathLogModel().apply([0], {}, make_state())

        raised = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(raised)
        assert raised["exception_type"] == "ValueError"
        assert raised["message"] == "math domain error"

    def test_concrete_invalid_base_emits_value_error_side_effect(self) -> None:
        result = MathLogModel().apply([8, -2], {}, make_state())

        raised = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(raised)
        assert raised["exception_type"] == "ValueError"
        assert raised["message"] == "math domain error"

    def test_concrete_base_one_emits_division_by_zero_side_effect(self) -> None:
        result = MathLogModel().apply([8, 1], {}, make_state())

        raised = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(raised)
        assert raised["exception_type"] == "ZeroDivisionError"
        assert raised["message"] == "float division by zero"

    def test_symbolic_input_adds_positivity_constraint(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = MathLogModel().apply([x], {}, make_state())
        assert len(result.constraints) >= 2

    def test_symbolic_input_emits_potential_value_error_side_effect(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = MathLogModel().apply([x], {}, make_state())

        potential = result.side_effects.get("potential_exception")
        assert SideEffects.is_potential_exception(potential)
        assert potential["type"] == "ValueError"
        assert potential["message"] == "math domain error"

    def test_symbolic_base_emits_potential_value_and_zero_division_side_effects(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        base, _ = SymbolicValue.symbolic("base")
        result = MathLogModel().apply([x, base], {}, make_state())

        potential = result.side_effects.get("potential_exceptions")
        assert SideEffects.is_potential_exception_sequence(potential)
        assert {effect["type"] for effect in potential} == {"ValueError", "ZeroDivisionError"}

    def test_no_args(self) -> None:
        result = MathLogModel().apply([], {}, make_state())
        assert isinstance(result.value, SymbolicValue)


class TestMathExpModel:
    def test_concrete_zero(self) -> None:
        result = MathExpModel().apply([0], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        concrete_val = result.value.value
        assert isinstance(concrete_val, (int, float))
        assert abs(concrete_val - 1.0) < 1e-12

    def test_concrete_large_input_emits_overflow_side_effect(self) -> None:
        result = MathExpModel().apply([710], {}, make_state())

        raised = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(raised)
        assert raised["exception_type"] == "OverflowError"
        assert raised["message"] == "math range error"

    def test_symbolic_adds_positive_constraint(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = MathExpModel().apply([x], {}, make_state())
        assert len(result.constraints) >= 2

    def test_symbolic_input_emits_potential_overflow_side_effect(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = MathExpModel().apply([x], {}, make_state())

        potential = result.side_effects.get("potential_exception")
        assert SideEffects.is_potential_exception(potential)
        assert potential["type"] == "OverflowError"
        assert potential["message"] == "math range error"


class TestMathTrigModels:
    def test_sin_concrete_zero(self) -> None:
        result = MathSinModel().apply([0], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        concrete_val = result.value.value
        assert isinstance(concrete_val, (int, float))
        assert abs(concrete_val - math.sin(0)) < 1e-12

    def test_sin_symbolic_adds_range_constraints(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = MathSinModel().apply([x], {}, make_state())
        assert len(result.constraints) >= 3

    def test_cos_concrete_zero(self) -> None:
        result = MathCosModel().apply([0], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        concrete_val = result.value.value
        assert isinstance(concrete_val, (int, float))
        assert abs(concrete_val - math.cos(0)) < 1e-12

    def test_cos_symbolic_adds_range_constraints(self) -> None:
        result = MathCosModel().apply(["symbolic_obj"], {}, make_state())
        assert len(result.constraints) >= 3

    def test_tan_concrete_zero(self) -> None:
        result = MathTanModel().apply([0], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        concrete_val = result.value.value
        assert isinstance(concrete_val, (int, float))
        assert abs(concrete_val - math.tan(0)) < 1e-12


class TestMathFabsModel:
    def test_concrete_negative(self) -> None:
        result = MathFabsModel().apply([-3.5], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == 3.5

    def test_symbolic_adds_non_negative_constraint(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = MathFabsModel().apply([x], {}, make_state())
        assert len(result.constraints) >= 2

    def test_non_symbolic_non_numeric_fallback(self) -> None:
        result = MathFabsModel().apply(["not_a_num"], {}, make_state())
        assert len(result.constraints) >= 2


class TestMathGcdModel:
    def test_concrete_gcd(self) -> None:
        result = MathGcdModel().apply([12, 8], {}, make_state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == math.gcd(12, 8)

    def test_fewer_than_two_args(self) -> None:
        result = MathGcdModel().apply([5], {}, make_state())
        assert isinstance(result.value, SymbolicValue)

    def test_symbolic_args_add_bounds(self) -> None:
        a, _ = SymbolicValue.symbolic("a")
        b, _ = SymbolicValue.symbolic("b")
        result = MathGcdModel().apply([a, b], {}, make_state())
        assert len(result.constraints) >= 3

    def test_zero_symbolic_gcd_requires_both_operands_zero(self) -> None:
        a, _ = SymbolicValue.symbolic("a")
        b, _ = SymbolicValue.symbolic("b")
        result = MathGcdModel().apply([a, b], {}, make_state())
        assert isinstance(result.value, SymbolicValue)

        solver = z3.Solver()
        solver.add(*result.constraints)
        solver.add(result.value.z3_int == 0, z3.Or(a.z3_int != 0, b.z3_int != 0))

        assert solver.check() == z3.unsat

    def test_zero_symbolic_gcd_allows_two_zero_operands(self) -> None:
        a, _ = SymbolicValue.symbolic("a")
        b, _ = SymbolicValue.symbolic("b")
        result = MathGcdModel().apply([a, b], {}, make_state())
        assert isinstance(result.value, SymbolicValue)

        solver = z3.Solver()
        solver.add(*result.constraints)
        solver.add(result.value.z3_int == 0, a.z3_int == 0, b.z3_int == 0)

        assert solver.check() == z3.sat
