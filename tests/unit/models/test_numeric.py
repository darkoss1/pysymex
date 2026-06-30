from __future__ import annotations

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.types.numeric.float import (
    FloatConjugateModel,
    FloatFromhexModel,
    FloatHexModel,
    FloatIsIntegerModel,
    FloatRatioModel,
)
from pysymex._internal.models.builtins.types.numeric.int import (
    IntAsIntegerRatioModel,
    IntBitCountModel,
    IntBitLengthModel,
    IntConjugateModel,
    IntFromBytesModel,
    IntToBytesModel,
)
from pysymex._internal.models.builtins.types.numeric.properties import (
    FloatImagModel,
    FloatRealModel,
    IntDenominatorModel,
    IntImagModel,
    IntNumeratorModel,
    IntRealModel,
)
from pysymex._internal.models.contracts.results import SideEffects


def _state() -> VMState:
    return VMState(pc=0)


def _assert_type_error(result: object) -> None:
    effect = getattr(result, "side_effects", {}).get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


class TestIntBitLengthModel:
    """Test suite for pysymex._internal.models.builtins.types.IntBitLengthModel."""

    def test_faithfulness(self) -> None:
        result = IntBitLengthModel().apply([], {}, _state())
        _assert_type_error(result)

    def test_error_path(self) -> None:
        result = IntBitLengthModel().apply([1], {}, _state())
        assert result.value == 1

    def test_faithfulness_large_positive_int(self) -> None:
        result = IntBitLengthModel().apply([1 << 200], {}, _state())
        assert result.value == (1 << 200).bit_length()

    def test_faithfulness_large_negative_int(self) -> None:
        result = IntBitLengthModel().apply([-(1 << 170)], {}, _state())
        assert result.value == (-(1 << 170)).bit_length()


class TestIntBitCountModel:
    """Test suite for pysymex._internal.models.builtins.types.IntBitCountModel."""

    def test_faithfulness(self) -> None:
        result = IntBitCountModel().apply([], {}, _state())
        _assert_type_error(result)

    def test_error_path(self) -> None:
        result = IntBitCountModel().apply([1], {}, _state())
        assert result.value == 1

    def test_faithfulness_large_positive_int(self) -> None:
        value = (1 << 140) + (1 << 73) + (1 << 5) + 1
        result = IntBitCountModel().apply([value], {}, _state())
        assert result.value == value.bit_count()

    def test_faithfulness_large_negative_int(self) -> None:
        value = -((1 << 155) + (1 << 7) + 1)
        result = IntBitCountModel().apply([value], {}, _state())
        assert result.value == value.bit_count()


class TestIntToBytesModel:
    """Test suite for pysymex._internal.models.builtins.types.IntToBytesModel."""

    def test_faithfulness(self) -> None:
        result = IntToBytesModel().apply([1, 2], {}, _state())
        assert isinstance(result.value, SymbolicList)

    def test_error_path(self) -> None:
        result = IntToBytesModel().apply([], {}, _state())
        _assert_type_error(result)


class TestIntFromBytesModel:
    """Test suite for pysymex._internal.models.builtins.types.IntFromBytesModel."""

    def test_faithfulness(self) -> None:
        result = IntFromBytesModel().apply([b"a", "big"], {}, _state())
        assert result.value == 0

    def test_error_path(self) -> None:
        result = IntFromBytesModel().apply([], {}, _state())
        _assert_type_error(result)


class TestIntAsIntegerRatioModel:
    """Test suite for pysymex._internal.models.builtins.types.IntAsIntegerRatioModel."""

    def test_faithfulness(self) -> None:
        result = IntAsIntegerRatioModel().apply([1], {}, _state())
        assert isinstance(result.value, SymbolicTuple)

    def test_error_path(self) -> None:
        result = IntAsIntegerRatioModel().apply([], {}, _state())
        _assert_type_error(result)


class TestIntConjugateModel:
    """Test suite for pysymex._internal.models.builtins.types.IntConjugateModel."""

    def test_faithfulness(self) -> None:
        result = IntConjugateModel().apply([7], {}, _state())
        assert result.value == 7

    def test_error_path(self) -> None:
        result = IntConjugateModel().apply([], {}, _state())
        _assert_type_error(result)


class TestFloatIsIntegerModel:
    """Test suite for pysymex._internal.models.builtins.types.FloatIsIntegerModel."""

    def test_faithfulness(self) -> None:
        result = FloatIsIntegerModel().apply([], {}, _state())
        _assert_type_error(result)

    def test_error_path(self) -> None:
        result = FloatIsIntegerModel().apply([1.0], {}, _state())
        assert isinstance(result.value, SymbolicValue)


class TestFloatAsIntegerRatioModel:
    """Test suite for pysymex._internal.models.builtins.types.FloatAsIntegerRatioModel."""

    def test_faithfulness(self) -> None:
        result = FloatRatioModel().apply([1.0], {}, _state())
        assert isinstance(result.value, SymbolicTuple)

    def test_error_path(self) -> None:
        result = FloatRatioModel().apply([], {}, _state())
        _assert_type_error(result)


class TestFloatHexModel:
    """Test suite for pysymex._internal.models.builtins.types.FloatHexModel."""

    def test_faithfulness(self) -> None:
        result = FloatHexModel().apply([1.0], {}, _state())
        assert isinstance(result.value, SymbolicString)

    def test_error_path(self) -> None:
        result = FloatHexModel().apply([], {}, _state())
        _assert_type_error(result)


class TestFloatFromhexModel:
    """Test suite for pysymex._internal.models.builtins.types.FloatFromhexModel."""

    def test_faithfulness(self) -> None:
        result = FloatFromhexModel().apply(["0x1.0p+0"], {}, _state())
        assert isinstance(result.value, SymbolicValue)

    def test_error_path(self) -> None:
        result = FloatFromhexModel().apply([], {}, _state())
        _assert_type_error(result)


class TestFloatConjugateModel:
    """Test suite for pysymex._internal.models.builtins.types.FloatConjugateModel."""

    def test_faithfulness(self) -> None:
        result = FloatConjugateModel().apply([3.5], {}, _state())
        assert result.value == 3.5

    def test_error_path(self) -> None:
        result = FloatConjugateModel().apply([], {}, _state())
        _assert_type_error(result)


class TestIntNumeratorModel:
    """Test suite for pysymex._internal.models.builtins.types.IntNumeratorModel."""

    def test_faithfulness(self) -> None:
        result = IntNumeratorModel().apply([9], {}, _state())
        assert result.value == 9

    def test_error_path(self) -> None:
        result = IntNumeratorModel().apply([], {}, _state())
        assert result.value == 1


class TestIntDenominatorModel:
    """Test suite for pysymex._internal.models.builtins.types.IntDenominatorModel."""

    def test_faithfulness(self) -> None:
        result = IntDenominatorModel().apply([9], {}, _state())
        assert result.value == 1

    def test_error_path(self) -> None:
        result = IntDenominatorModel().apply([], {}, _state())
        assert result.value == 1


class TestIntRealModel:
    """Test suite for pysymex._internal.models.builtins.types.IntRealModel."""

    def test_faithfulness(self) -> None:
        result = IntRealModel().apply([9], {}, _state())
        assert result.value == 9

    def test_error_path(self) -> None:
        result = IntRealModel().apply([], {}, _state())
        assert result.value == 0


class TestIntImagModel:
    """Test suite for pysymex._internal.models.builtins.types.IntImagModel."""

    def test_faithfulness(self) -> None:
        result = IntImagModel().apply([9], {}, _state())
        assert result.value == 0

    def test_error_path(self) -> None:
        result = IntImagModel().apply([], {}, _state())
        assert result.value == 0


class TestFloatRealModel:
    """Test suite for pysymex._internal.models.builtins.types.FloatRealModel."""

    def test_faithfulness(self) -> None:
        result = FloatRealModel().apply([2.25], {}, _state())
        assert result.value == 2.25

    def test_error_path(self) -> None:
        result = FloatRealModel().apply([], {}, _state())
        assert result.value == 0.0


class TestFloatImagModel:
    """Test suite for pysymex._internal.models.builtins.types.FloatImagModel."""

    def test_faithfulness(self) -> None:
        result = FloatImagModel().apply([2.25], {}, _state())
        assert result.value == 0.0

    def test_error_path(self) -> None:
        result = FloatImagModel().apply([], {}, _state())
        assert result.value == 0.0
