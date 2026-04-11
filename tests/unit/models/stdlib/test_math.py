from __future__ import annotations

import importlib.util
import math
from pathlib import Path
from types import ModuleType

import pytest

from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicValue


def _load_math_models() -> ModuleType:
    module_path = Path(__file__).resolve().parents[4] / "pysymex" / "models" / "stdlib" / "math.py"
    spec = importlib.util.spec_from_file_location("pysymex_models_stdlib_math", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load stdlib math models module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


math_models = _load_math_models()


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
        with pytest.raises(NameError):
            math_models.MathSqrtModel().apply(["bad"], {}, _state())


class TestMathCeilModel:
    """Test suite for pysymex.models.stdlib.math.MathCeilModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathCeilModel().apply([2.2], {}, _state())
        assert result.value == math.ceil(2.2)

    def test_error_path(self) -> None:
        with pytest.raises(NameError):
            math_models.MathCeilModel().apply([], {}, _state())


class TestMathFloorModel:
    """Test suite for pysymex.models.stdlib.math.MathFloorModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathFloorModel().apply([2.8], {}, _state())
        assert result.value == math.floor(2.8)

    def test_error_path(self) -> None:
        with pytest.raises(NameError):
            math_models.MathFloorModel().apply([], {}, _state())


class TestMathLogModel:
    """Test suite for pysymex.models.stdlib.math.MathLogModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathLogModel().apply([8.0, 2.0], {}, _state())
        assert result.value == math.log(8.0, 2.0)

    def test_error_path(self) -> None:
        with pytest.raises(NameError):
            math_models.MathLogModel().apply(["bad"], {}, _state())


class TestMathExpModel:
    """Test suite for pysymex.models.stdlib.math.MathExpModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathExpModel().apply([1.0], {}, _state())
        assert result.value == math.exp(1.0)

    def test_error_path(self) -> None:
        with pytest.raises(NameError):
            math_models.MathExpModel().apply([], {}, _state())


class TestMathSinModel:
    """Test suite for pysymex.models.stdlib.math.MathSinModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathSinModel().apply([0.5], {}, _state())
        assert result.value == math.sin(0.5)

    def test_error_path(self) -> None:
        with pytest.raises(NameError):
            math_models.MathSinModel().apply([object()], {}, _state())


class TestMathCosModel:
    """Test suite for pysymex.models.stdlib.math.MathCosModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathCosModel().apply([0.5], {}, _state())
        assert result.value == math.cos(0.5)

    def test_error_path(self) -> None:
        with pytest.raises(NameError):
            math_models.MathCosModel().apply([object()], {}, _state())


class TestMathTanModel:
    """Test suite for pysymex.models.stdlib.math.MathTanModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathTanModel().apply([0.5], {}, _state())
        assert result.value == math.tan(0.5)

    def test_error_path(self) -> None:
        with pytest.raises(NameError):
            math_models.MathTanModel().apply([], {}, _state())


class TestMathFabsModel:
    """Test suite for pysymex.models.stdlib.math.MathFabsModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathFabsModel().apply([-4.25], {}, _state())
        assert result.value == math.fabs(-4.25)

    def test_error_path(self) -> None:
        with pytest.raises(NameError):
            math_models.MathFabsModel().apply([], {}, _state())


class TestMathGcdModel:
    """Test suite for pysymex.models.stdlib.math.MathGcdModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathGcdModel().apply([12, 18], {}, _state())
        assert result.value == math.gcd(12, 18)

    def test_error_path(self) -> None:
        with pytest.raises(NameError):
            math_models.MathGcdModel().apply([12], {}, _state())


class TestMathIsfiniteModel:
    """Test suite for pysymex.models.stdlib.math.MathIsfiniteModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathIsfiniteModel().apply([2.0], {}, _state())
        assert result.value == math.isfinite(2.0)

    def test_error_path(self) -> None:
        with pytest.raises(NameError):
            math_models.MathIsfiniteModel().apply([], {}, _state())


class TestMathIsCloseModel:
    """Test suite for pysymex.models.stdlib.math.MathIsCloseModel."""

    def test_faithfulness(self) -> None:
        with pytest.raises(NameError):
            math_models.MathIsCloseModel().apply([1.0, 1.0], {}, _state())

    def test_error_path(self) -> None:
        with pytest.raises(NameError):
            math_models.MathIsCloseModel().apply([], {}, _state())


class TestMathIsinfModel:
    """Test suite for pysymex.models.stdlib.math.MathIsinfModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathIsinfModel().apply([float("inf")], {}, _state())
        assert result.value == math.isinf(float("inf"))

    def test_error_path(self) -> None:
        result = math_models.MathIsinfModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value is False


class TestMathIsnanModel:
    """Test suite for pysymex.models.stdlib.math.MathIsnanModel."""

    def test_faithfulness(self) -> None:
        result = math_models.MathIsnanModel().apply([float("nan")], {}, _state())
        assert result.value == math.isnan(float("nan"))

    def test_error_path(self) -> None:
        result = math_models.MathIsnanModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value is False
