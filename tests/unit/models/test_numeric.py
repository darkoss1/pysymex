from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicValue, SymbolicString
from pysymex.core.types.scalars import SymbolicList


def _load_numeric_models() -> ModuleType:
    module_path = Path(__file__).resolve().parents[3] / "pysymex" / "models" / "numeric.py"
    spec = importlib.util.spec_from_file_location("pysymex_models_numeric", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load numeric models module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


numeric = _load_numeric_models()


def _state() -> VMState:
    return VMState(pc=0)


class TestIntBitLengthModel:
    """Test suite for pysymex.models.numeric.IntBitLengthModel."""

    def test_faithfulness(self) -> None:
        result = numeric.IntBitLengthModel().apply([], {}, _state())
        assert result.value == 0

    def test_error_path(self) -> None:
        result = numeric.IntBitLengthModel().apply([1], {}, _state())
        assert result.value == 1


class TestIntBitCountModel:
    """Test suite for pysymex.models.numeric.IntBitCountModel."""

    def test_faithfulness(self) -> None:
        result = numeric.IntBitCountModel().apply([], {}, _state())
        assert result.value == 0

    def test_error_path(self) -> None:
        result = numeric.IntBitCountModel().apply([1], {}, _state())
        assert result.value == 1


class TestIntToBytesModel:
    """Test suite for pysymex.models.numeric.IntToBytesModel."""

    def test_faithfulness(self) -> None:
        result = numeric.IntToBytesModel().apply([1, 2], {}, _state())
        assert isinstance(result.value, SymbolicList)

    def test_error_path(self) -> None:
        result = numeric.IntToBytesModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicList)


class TestIntFromBytesModel:
    """Test suite for pysymex.models.numeric.IntFromBytesModel."""

    def test_faithfulness(self) -> None:
        result = numeric.IntFromBytesModel().apply([b"a", "big"], {}, _state())
        assert result.value == 0

    def test_error_path(self) -> None:
        result = numeric.IntFromBytesModel().apply([], {}, _state())
        assert result.value == 0


class TestIntAsIntegerRatioModel:
    """Test suite for pysymex.models.numeric.IntAsIntegerRatioModel."""

    def test_faithfulness(self) -> None:
        result = numeric.IntAsIntegerRatioModel().apply([1], {}, _state())
        assert isinstance(result.value, SymbolicList)

    def test_error_path(self) -> None:
        result = numeric.IntAsIntegerRatioModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicList)


class TestIntConjugateModel:
    """Test suite for pysymex.models.numeric.IntConjugateModel."""

    def test_faithfulness(self) -> None:
        result = numeric.IntConjugateModel().apply([7], {}, _state())
        assert result.value == 7

    def test_error_path(self) -> None:
        result = numeric.IntConjugateModel().apply([], {}, _state())
        assert result.value == 0


class TestFloatIsIntegerModel:
    """Test suite for pysymex.models.numeric.FloatIsIntegerModel."""

    def test_faithfulness(self) -> None:
        result = numeric.FloatIsIntegerModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicValue)

    def test_error_path(self) -> None:
        result = numeric.FloatIsIntegerModel().apply([1.0], {}, _state())
        assert isinstance(result.value, SymbolicValue)


class TestFloatAsIntegerRatioModel:
    """Test suite for pysymex.models.numeric.FloatAsIntegerRatioModel."""

    def test_faithfulness(self) -> None:
        result = numeric.FloatAsIntegerRatioModel().apply([1.0], {}, _state())
        assert isinstance(result.value, SymbolicList)

    def test_error_path(self) -> None:
        result = numeric.FloatAsIntegerRatioModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicList)


class TestFloatHexModel:
    """Test suite for pysymex.models.numeric.FloatHexModel."""

    def test_faithfulness(self) -> None:
        result = numeric.FloatHexModel().apply([1.0], {}, _state())
        assert isinstance(result.value, SymbolicString)

    def test_error_path(self) -> None:
        result = numeric.FloatHexModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicString)


class TestFloatFromhexModel:
    """Test suite for pysymex.models.numeric.FloatFromhexModel."""

    def test_faithfulness(self) -> None:
        result = numeric.FloatFromhexModel().apply(["0x1.0p+0"], {}, _state())
        assert isinstance(result.value, SymbolicValue)

    def test_error_path(self) -> None:
        result = numeric.FloatFromhexModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicValue)


class TestFloatConjugateModel:
    """Test suite for pysymex.models.numeric.FloatConjugateModel."""

    def test_faithfulness(self) -> None:
        result = numeric.FloatConjugateModel().apply([3.5], {}, _state())
        assert result.value == 3.5

    def test_error_path(self) -> None:
        result = numeric.FloatConjugateModel().apply([], {}, _state())
        assert result.value == 0.0


class TestIntNumeratorModel:
    """Test suite for pysymex.models.numeric.IntNumeratorModel."""

    def test_faithfulness(self) -> None:
        result = numeric.IntNumeratorModel().apply([9], {}, _state())
        assert result.value == 9

    def test_error_path(self) -> None:
        result = numeric.IntNumeratorModel().apply([], {}, _state())
        assert result.value == 1


class TestIntDenominatorModel:
    """Test suite for pysymex.models.numeric.IntDenominatorModel."""

    def test_faithfulness(self) -> None:
        result = numeric.IntDenominatorModel().apply([9], {}, _state())
        assert result.value == 1

    def test_error_path(self) -> None:
        result = numeric.IntDenominatorModel().apply([], {}, _state())
        assert result.value == 1


class TestIntRealModel:
    """Test suite for pysymex.models.numeric.IntRealModel."""

    def test_faithfulness(self) -> None:
        result = numeric.IntRealModel().apply([9], {}, _state())
        assert result.value == 9

    def test_error_path(self) -> None:
        result = numeric.IntRealModel().apply([], {}, _state())
        assert result.value == 0


class TestIntImagModel:
    """Test suite for pysymex.models.numeric.IntImagModel."""

    def test_faithfulness(self) -> None:
        result = numeric.IntImagModel().apply([9], {}, _state())
        assert result.value == 0

    def test_error_path(self) -> None:
        result = numeric.IntImagModel().apply([], {}, _state())
        assert result.value == 0


class TestFloatRealModel:
    """Test suite for pysymex.models.numeric.FloatRealModel."""

    def test_faithfulness(self) -> None:
        result = numeric.FloatRealModel().apply([2.25], {}, _state())
        assert result.value == 2.25

    def test_error_path(self) -> None:
        result = numeric.FloatRealModel().apply([], {}, _state())
        assert result.value == 0.0


class TestFloatImagModel:
    """Test suite for pysymex.models.numeric.FloatImagModel."""

    def test_faithfulness(self) -> None:
        result = numeric.FloatImagModel().apply([2.25], {}, _state())
        assert result.value == 0.0

    def test_error_path(self) -> None:
        result = numeric.FloatImagModel().apply([], {}, _state())
        assert result.value == 0.0
