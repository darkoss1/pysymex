from __future__ import annotations

import math

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.results import ModelResult, SideEffects
from pysymex._internal.models.stdlib.math.exponential import MathExpModel, MathLogModel
from pysymex._internal.models.stdlib.math.numeric import (
    MathCopysignModel,
    MathCosModel,
    MathDegreesModel,
    MathFabsModel,
    MathGcdModel,
    MathRadiansModel,
    MathSinModel,
    MathTanModel,
)
from pysymex._internal.models.stdlib.math.predicates import (
    MathIsCloseModel,
    MathIsfiniteModel,
    MathIsinfModel,
    MathIsnanModel,
)
from pysymex._internal.models.stdlib.math.roots import (
    MathCeilModel,
    MathFactorialModel,
    MathFloorModel,
    MathSqrtModel,
    MathTruncModel,
)


def _state() -> VMState:
    return VMState(pc=0)


def _assert_raised_type_error(result: ModelResult) -> None:
    raised = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(raised)
    assert raised["exception_type"] == "TypeError"


class TestMathSqrtModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathSqrtModel."""

    def test_faithfulness(self) -> None:
        """Concrete sqrt matches Python sqrt."""
        result = MathSqrtModel().apply([9.0], {}, _state())
        assert result.value == math.sqrt(9.0)

    def test_error_path(self) -> None:
        """Invalid concrete input follows CPython TypeError semantics."""
        result = MathSqrtModel().apply(["bad"], {}, _state())
        _assert_raised_type_error(result)

    def test_wrong_arity_raises_type_error(self) -> None:
        result = MathSqrtModel().apply([], {}, _state())
        _assert_raised_type_error(result)


class TestMathCeilModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathCeilModel."""

    def test_faithfulness(self) -> None:
        result = MathCeilModel().apply([2.2], {}, _state())
        assert result.value == math.ceil(2.2)

    def test_error_path(self) -> None:
        result = MathCeilModel().apply(["bad"], {}, _state())
        _assert_raised_type_error(result)

    def test_wrong_arity_raises_type_error(self) -> None:
        result = MathCeilModel().apply([], {}, _state())
        _assert_raised_type_error(result)


class TestMathFloorModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathFloorModel."""

    def test_faithfulness(self) -> None:
        result = MathFloorModel().apply([2.8], {}, _state())
        assert result.value == math.floor(2.8)

    def test_error_path(self) -> None:
        result = MathFloorModel().apply(["bad"], {}, _state())
        _assert_raised_type_error(result)

    def test_wrong_arity_raises_type_error(self) -> None:
        result = MathFloorModel().apply([], {}, _state())
        _assert_raised_type_error(result)


class TestMathLogModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathLogModel."""

    def test_faithfulness(self) -> None:
        result = MathLogModel().apply([8.0, 2.0], {}, _state())
        assert result.value == math.log(8.0, 2.0)

    def test_error_path(self) -> None:
        MathLogModel().apply(["bad"], {}, _state())


class TestMathExpModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathExpModel."""

    def test_faithfulness(self) -> None:
        result = MathExpModel().apply([1.0], {}, _state())
        assert result.value == math.exp(1.0)

    def test_error_path(self) -> None:
        MathExpModel().apply([], {}, _state())


class TestMathSinModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathSinModel."""

    def test_faithfulness(self) -> None:
        result = MathSinModel().apply([0.5], {}, _state())
        assert result.value == math.sin(0.5)

    def test_error_path(self) -> None:
        MathSinModel().apply([SymbolicValue.from_const("x")], {}, _state())


class TestMathCosModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathCosModel."""

    def test_faithfulness(self) -> None:
        result = MathCosModel().apply([0.5], {}, _state())
        assert result.value == math.cos(0.5)

    def test_error_path(self) -> None:
        MathCosModel().apply([SymbolicValue.from_const("x")], {}, _state())


class TestMathTanModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathTanModel."""

    def test_faithfulness(self) -> None:
        result = MathTanModel().apply([0.5], {}, _state())
        assert result.value == math.tan(0.5)

    def test_error_path(self) -> None:
        MathTanModel().apply([], {}, _state())


class TestMathFabsModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathFabsModel."""

    def test_faithfulness(self) -> None:
        result = MathFabsModel().apply([-4.25], {}, _state())
        assert result.value == math.fabs(-4.25)

    def test_error_path(self) -> None:
        MathFabsModel().apply([], {}, _state())


class TestMathGcdModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathGcdModel."""

    def test_faithfulness(self) -> None:
        result = MathGcdModel().apply([12, 18], {}, _state())
        assert result.value == math.gcd(12, 18)

    def test_error_path(self) -> None:
        MathGcdModel().apply([12], {}, _state())


class TestMathIsfiniteModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathIsfiniteModel."""

    def test_faithfulness(self) -> None:
        result = MathIsfiniteModel().apply([2.0], {}, _state())
        assert result.value == math.isfinite(2.0)

    def test_error_path(self) -> None:
        MathIsfiniteModel().apply([], {}, _state())


class TestMathIsCloseModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathIsCloseModel."""

    def test_faithfulness(self) -> None:
        MathIsCloseModel().apply([1.0, 1.0], {}, _state())

    def test_error_path(self) -> None:
        MathIsCloseModel().apply([], {}, _state())


class TestMathIsinfModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathIsinfModel."""

    def test_faithfulness(self) -> None:
        result = MathIsinfModel().apply([float("inf")], {}, _state())
        assert result.value == math.isinf(float("inf"))

    def test_error_path(self) -> None:
        result = MathIsinfModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        raised = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(raised)
        assert raised["exception_type"] == "TypeError"


class TestMathIsnanModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathIsnanModel."""

    def test_faithfulness(self) -> None:
        result = MathIsnanModel().apply([float("nan")], {}, _state())
        assert result.value == math.isnan(float("nan"))

    def test_error_path(self) -> None:
        result = MathIsnanModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        raised = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(raised)
        assert raised["exception_type"] == "TypeError"


class TestMathRadiansModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathRadiansModel."""

    def test_faithfulness(self) -> None:
        result = MathRadiansModel().apply([180.0], {}, _state())
        assert result.value == math.radians(180.0)

    def test_symbolic(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = MathRadiansModel().apply([x], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        assert len(result.constraints) > 0

    def test_error_path(self) -> None:
        result = MathRadiansModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicValue)


class TestMathDegreesModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathDegreesModel."""

    def test_faithfulness(self) -> None:
        result = MathDegreesModel().apply([math.pi], {}, _state())
        assert result.value == math.degrees(math.pi)

    def test_symbolic(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = MathDegreesModel().apply([x], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        assert len(result.constraints) > 0

    def test_error_path(self) -> None:
        result = MathDegreesModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicValue)


class TestMathCopysignModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathCopysignModel."""

    def test_faithfulness(self) -> None:
        result = MathCopysignModel().apply([1.5, -2.0], {}, _state())
        assert result.value == math.copysign(1.5, -2.0)

    def test_symbolic(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        y, _ = SymbolicValue.symbolic("y")
        result = MathCopysignModel().apply([x, y], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        assert len(result.constraints) > 0

    def test_error_path(self) -> None:
        result = MathCopysignModel().apply([1.5], {}, _state())
        assert isinstance(result.value, SymbolicValue)


class TestMathFactorialModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathFactorialModel."""

    def test_faithfulness(self) -> None:
        result = MathFactorialModel().apply([5], {}, _state())
        assert result.value == math.factorial(5)
        result2 = MathFactorialModel().apply([5.0], {}, _state())
        assert result2.value == math.factorial(5)

    def test_concrete_errors(self) -> None:
        res1 = MathFactorialModel().apply([-1], {}, _state())
        raised1 = res1.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(raised1)
        assert raised1["exception_type"] == "ValueError"

        res2 = MathFactorialModel().apply([5.5], {}, _state())
        raised2 = res2.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(raised2)
        assert raised2["exception_type"] == "TypeError"

    def test_symbolic(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = MathFactorialModel().apply([x], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        assert len(result.constraints) > 0
        potential = result.side_effects.get("potential_exception")
        assert SideEffects.is_potential_exception(potential)

    def test_error_path(self) -> None:
        result = MathFactorialModel().apply(["bad"], {}, _state())
        _assert_raised_type_error(result)

    def test_wrong_arity_raises_type_error(self) -> None:
        result = MathFactorialModel().apply([], {}, _state())
        _assert_raised_type_error(result)


class TestMathTruncModel:
    """Test suite for pysymex._internal.models.stdlib.math.MathTruncModel."""

    def test_faithfulness(self) -> None:
        result = MathTruncModel().apply([2.9], {}, _state())
        assert result.value == math.trunc(2.9)
        result2 = MathTruncModel().apply([-2.9], {}, _state())
        assert result2.value == math.trunc(-2.9)

    def test_symbolic(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = MathTruncModel().apply([x], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        assert len(result.constraints) > 0
        assert "potential_exception" in result.side_effects

    def test_error_path(self) -> None:
        result = MathTruncModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        raised = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(raised)
