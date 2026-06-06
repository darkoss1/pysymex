from __future__ import annotations

import pysymex.models.numeric as numeric

from pysymex.core.state.record import VMState
from pysymex.core.types.containers.sequences import SymbolicTuple
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import is_raised_exception_effect


def _state() -> VMState:
    return VMState(pc=0)


def _assert_type_error(result: object) -> None:
    effect = getattr(result, "side_effects", {}).get("raised_exception")
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


class TestIntBitLengthModel:
    """Test suite for pysymex.models.numeric.IntBitLengthModel."""

    def test_faithfulness(self) -> None:
        result = numeric.IntBitLengthModel().apply([], {}, _state())
        _assert_type_error(result)

    def test_error_path(self) -> None:
        result = numeric.IntBitLengthModel().apply([1], {}, _state())
        assert result.value == 1

    def test_faithfulness_large_positive_int(self) -> None:
        result = numeric.IntBitLengthModel().apply([1 << 200], {}, _state())
        assert result.value == (1 << 200).bit_length()

    def test_faithfulness_large_negative_int(self) -> None:
        result = numeric.IntBitLengthModel().apply([-(1 << 170)], {}, _state())
        assert result.value == (-(1 << 170)).bit_length()


class TestIntBitCountModel:
    """Test suite for pysymex.models.numeric.IntBitCountModel."""

    def test_faithfulness(self) -> None:
        result = numeric.IntBitCountModel().apply([], {}, _state())
        _assert_type_error(result)

    def test_error_path(self) -> None:
        result = numeric.IntBitCountModel().apply([1], {}, _state())
        assert result.value == 1

    def test_faithfulness_large_positive_int(self) -> None:
        value = (1 << 140) + (1 << 73) + (1 << 5) + 1
        result = numeric.IntBitCountModel().apply([value], {}, _state())
        assert result.value == value.bit_count()

    def test_faithfulness_large_negative_int(self) -> None:
        value = -((1 << 155) + (1 << 7) + 1)
        result = numeric.IntBitCountModel().apply([value], {}, _state())
        assert result.value == value.bit_count()


class TestIntToBytesModel:
    """Test suite for pysymex.models.numeric.IntToBytesModel."""

    def test_faithfulness(self) -> None:
        result = numeric.IntToBytesModel().apply([1, 2], {}, _state())
        assert isinstance(result.value, SymbolicList)

    def test_error_path(self) -> None:
        result = numeric.IntToBytesModel().apply([], {}, _state())
        _assert_type_error(result)


class TestIntFromBytesModel:
    """Test suite for pysymex.models.numeric.IntFromBytesModel."""

    def test_faithfulness(self) -> None:
        result = numeric.IntFromBytesModel().apply([b"a", "big"], {}, _state())
        assert result.value == 0

    def test_error_path(self) -> None:
        result = numeric.IntFromBytesModel().apply([], {}, _state())
        _assert_type_error(result)


class TestIntAsIntegerRatioModel:
    """Test suite for pysymex.models.numeric.IntAsIntegerRatioModel."""

    def test_faithfulness(self) -> None:
        result = numeric.IntAsIntegerRatioModel().apply([1], {}, _state())
        assert isinstance(result.value, SymbolicTuple)

    def test_error_path(self) -> None:
        result = numeric.IntAsIntegerRatioModel().apply([], {}, _state())
        _assert_type_error(result)


class TestIntConjugateModel:
    """Test suite for pysymex.models.numeric.IntConjugateModel."""

    def test_faithfulness(self) -> None:
        result = numeric.IntConjugateModel().apply([7], {}, _state())
        assert result.value == 7

    def test_error_path(self) -> None:
        result = numeric.IntConjugateModel().apply([], {}, _state())
        _assert_type_error(result)


class TestFloatIsIntegerModel:
    """Test suite for pysymex.models.numeric.FloatIsIntegerModel."""

    def test_faithfulness(self) -> None:
        result = numeric.FloatIsIntegerModel().apply([], {}, _state())
        _assert_type_error(result)

    def test_error_path(self) -> None:
        result = numeric.FloatIsIntegerModel().apply([1.0], {}, _state())
        assert isinstance(result.value, SymbolicValue)


class TestFloatAsIntegerRatioModel:
    """Test suite for pysymex.models.numeric.FloatAsIntegerRatioModel."""

    def test_faithfulness(self) -> None:
        result = numeric.FloatAsIntegerRatioModel().apply([1.0], {}, _state())
        assert isinstance(result.value, SymbolicTuple)

    def test_error_path(self) -> None:
        result = numeric.FloatAsIntegerRatioModel().apply([], {}, _state())
        _assert_type_error(result)


class TestFloatHexModel:
    """Test suite for pysymex.models.numeric.FloatHexModel."""

    def test_faithfulness(self) -> None:
        result = numeric.FloatHexModel().apply([1.0], {}, _state())
        assert isinstance(result.value, SymbolicString)

    def test_error_path(self) -> None:
        result = numeric.FloatHexModel().apply([], {}, _state())
        _assert_type_error(result)


class TestFloatFromhexModel:
    """Test suite for pysymex.models.numeric.FloatFromhexModel."""

    def test_faithfulness(self) -> None:
        result = numeric.FloatFromhexModel().apply(["0x1.0p+0"], {}, _state())
        assert isinstance(result.value, SymbolicValue)

    def test_error_path(self) -> None:
        result = numeric.FloatFromhexModel().apply([], {}, _state())
        _assert_type_error(result)


class TestFloatConjugateModel:
    """Test suite for pysymex.models.numeric.FloatConjugateModel."""

    def test_faithfulness(self) -> None:
        result = numeric.FloatConjugateModel().apply([3.5], {}, _state())
        assert result.value == 3.5

    def test_error_path(self) -> None:
        result = numeric.FloatConjugateModel().apply([], {}, _state())
        _assert_type_error(result)


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
