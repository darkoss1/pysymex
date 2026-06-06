from __future__ import annotations

import math

from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import is_raised_exception_effect
from pysymex.models.builtins.results import is_potential_exception_effect

from pysymex.models.stdlib import math as math_models


def _state() -> VMState:
    return VMState(pc=0)


class TestMathSqrtModel:
    """Test suite for pysymex.models.stdlib.math.MathSqrtModel."""

    def test_faithfulness(self) -> None:
        """Concrete sqrt matches Python sqrt."""
        result = math_models.MathSqrtModel().apply([9.0], {}, _state())
        assert result.value == math.sqrt(9.0)

    def test_error_path(self) -> None:
        """Invalid input follows symbolic fallback path."""
        math_models.MathSqrtModel().apply(["bad"], {}, _state())


class TestMathCeilModel:
    """Test suite for pysymex.models.stdlib.math.MathCeilModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathCeilModel().apply([2.2], {}, _state())
        assert result.value == math.ceil(2.2)

    def test_error_path(self) -> None:
        math_models.MathCeilModel().apply([], {}, _state())


class TestMathFloorModel:
    """Test suite for pysymex.models.stdlib.math.MathFloorModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathFloorModel().apply([2.8], {}, _state())
        assert result.value == math.floor(2.8)

    def test_error_path(self) -> None:
        math_models.MathFloorModel().apply([], {}, _state())


class TestMathLogModel:
    """Test suite for pysymex.models.stdlib.math.MathLogModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathLogModel().apply([8.0, 2.0], {}, _state())
        assert result.value == math.log(8.0, 2.0)

    def test_error_path(self) -> None:
        math_models.MathLogModel().apply(["bad"], {}, _state())


class TestMathExpModel:
    """Test suite for pysymex.models.stdlib.math.MathExpModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathExpModel().apply([1.0], {}, _state())
        assert result.value == math.exp(1.0)

    def test_error_path(self) -> None:
        math_models.MathExpModel().apply([], {}, _state())


class TestMathSinModel:
    """Test suite for pysymex.models.stdlib.math.MathSinModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathSinModel().apply([0.5], {}, _state())
        assert result.value == math.sin(0.5)

    def test_error_path(self) -> None:
        math_models.MathSinModel().apply([SymbolicValue.from_const("x")], {}, _state())


class TestMathCosModel:
    """Test suite for pysymex.models.stdlib.math.MathCosModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathCosModel().apply([0.5], {}, _state())
        assert result.value == math.cos(0.5)

    def test_error_path(self) -> None:
        math_models.MathCosModel().apply([SymbolicValue.from_const("x")], {}, _state())


class TestMathTanModel:
    """Test suite for pysymex.models.stdlib.math.MathTanModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathTanModel().apply([0.5], {}, _state())
        assert result.value == math.tan(0.5)

    def test_error_path(self) -> None:
        math_models.MathTanModel().apply([], {}, _state())


class TestMathFabsModel:
    """Test suite for pysymex.models.stdlib.math.MathFabsModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathFabsModel().apply([-4.25], {}, _state())
        assert result.value == math.fabs(-4.25)

    def test_error_path(self) -> None:
        math_models.MathFabsModel().apply([], {}, _state())


class TestMathGcdModel:
    """Test suite for pysymex.models.stdlib.math.MathGcdModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathGcdModel().apply([12, 18], {}, _state())
        assert result.value == math.gcd(12, 18)

    def test_error_path(self) -> None:
        math_models.MathGcdModel().apply([12], {}, _state())


class TestMathIsfiniteModel:
    """Test suite for pysymex.models.stdlib.math.MathIsfiniteModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathIsfiniteModel().apply([2.0], {}, _state())
        assert result.value == math.isfinite(2.0)

    def test_error_path(self) -> None:
        math_models.MathIsfiniteModel().apply([], {}, _state())


class TestMathIsCloseModel:
    """Test suite for pysymex.models.stdlib.math.MathIsCloseModel."""

    def test_faithfulness(self) -> None:
        math_models.MathIsCloseModel().apply([1.0, 1.0], {}, _state())

    def test_error_path(self) -> None:
        math_models.MathIsCloseModel().apply([], {}, _state())


class TestMathIsinfModel:
    """Test suite for pysymex.models.stdlib.math.MathIsinfModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathIsinfModel().apply([float("inf")], {}, _state())
        assert result.value == math.isinf(float("inf"))

    def test_error_path(self) -> None:
        result = math_models.MathIsinfModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        raised = result.side_effects.get("raised_exception")
        assert is_raised_exception_effect(raised)
        assert raised["exception_type"] == "TypeError"


class TestMathIsnanModel:
    """Test suite for pysymex.models.stdlib.math.MathIsnanModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathIsnanModel().apply([float("nan")], {}, _state())
        assert result.value == math.isnan(float("nan"))

    def test_error_path(self) -> None:
        result = math_models.MathIsnanModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        raised = result.side_effects.get("raised_exception")
        assert is_raised_exception_effect(raised)
        assert raised["exception_type"] == "TypeError"


class TestMathRadiansModel:
    """Test suite for pysymex.models.stdlib.math.MathRadiansModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathRadiansModel().apply([180.0], {}, _state())
        assert result.value == math.radians(180.0)

    def test_symbolic(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = math_models.MathRadiansModel().apply([x], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        assert len(result.constraints) > 0

    def test_error_path(self) -> None:
        result = math_models.MathRadiansModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicValue)


class TestMathDegreesModel:
    """Test suite for pysymex.models.stdlib.math.MathDegreesModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathDegreesModel().apply([math.pi], {}, _state())
        assert result.value == math.degrees(math.pi)

    def test_symbolic(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = math_models.MathDegreesModel().apply([x], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        assert len(result.constraints) > 0

    def test_error_path(self) -> None:
        result = math_models.MathDegreesModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicValue)


class TestMathCopysignModel:
    """Test suite for pysymex.models.stdlib.math.MathCopysignModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathCopysignModel().apply([1.5, -2.0], {}, _state())
        assert result.value == math.copysign(1.5, -2.0)

    def test_symbolic(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        y, _ = SymbolicValue.symbolic("y")
        result = math_models.MathCopysignModel().apply([x, y], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        assert len(result.constraints) > 0

    def test_error_path(self) -> None:
        result = math_models.MathCopysignModel().apply([1.5], {}, _state())
        assert isinstance(result.value, SymbolicValue)


class TestMathFactorialModel:
    """Test suite for pysymex.models.stdlib.math.MathFactorialModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathFactorialModel().apply([5], {}, _state())
        assert result.value == math.factorial(5)
        result2 = math_models.MathFactorialModel().apply([5.0], {}, _state())
        assert result2.value == math.factorial(5)

    def test_concrete_errors(self) -> None:
        res1 = math_models.MathFactorialModel().apply([-1], {}, _state())
        raised1 = res1.side_effects.get("raised_exception")
        assert is_raised_exception_effect(raised1)
        assert raised1["exception_type"] == "ValueError"

        res2 = math_models.MathFactorialModel().apply([5.5], {}, _state())
        raised2 = res2.side_effects.get("raised_exception")
        assert is_raised_exception_effect(raised2)
        assert raised2["exception_type"] == "ValueError"

    def test_symbolic(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = math_models.MathFactorialModel().apply([x], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        assert len(result.constraints) > 0
        potential = result.side_effects.get("potential_exception")
        assert is_potential_exception_effect(potential)

    def test_error_path(self) -> None:
        result = math_models.MathFactorialModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicValue)


class TestMathTruncModel:
    """Test suite for pysymex.models.stdlib.math.MathTruncModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathTruncModel().apply([2.9], {}, _state())
        assert result.value == math.trunc(2.9)
        result2 = math_models.MathTruncModel().apply([-2.9], {}, _state())
        assert result2.value == math.trunc(-2.9)

    def test_symbolic(self) -> None:
        x, _ = SymbolicValue.symbolic("x")
        result = math_models.MathTruncModel().apply([x], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        assert len(result.constraints) > 0
        assert "potential_exception" in result.side_effects

    def test_error_path(self) -> None:
        result = math_models.MathTruncModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        raised = result.side_effects.get("raised_exception")
        assert is_raised_exception_effect(raised)
