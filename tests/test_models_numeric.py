"""Tests for numeric method models (numeric_models.py)."""
from __future__ import annotations
import pytest
from tests.helpers import make_state, make_symbolic_int
from pysymex.core.types import SymbolicValue
from pysymex.models.builtins_base import ModelResult
from pysymex.models.numeric_models import (
    IntBitLengthModel, IntBitCountModel, IntToBytesModel, IntFromBytesModel,
    IntAsIntegerRatioModel, IntConjugateModel, FloatIsIntegerModel,
    FloatAsIntegerRatioModel, FloatHexModel, FloatFromhexModel,
    FloatConjugateModel, IntNumeratorModel, IntDenominatorModel,
    IntRealModel, IntImagModel, FloatRealModel, FloatImagModel,
)

def _state(pc=0):
    return make_state(pc=pc)

def _sv(name="n"):
    return make_symbolic_int(name)

class TestIntBitLengthModel:
    def test_returns_result(self):
        r = IntBitLengthModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)
    def test_no_args(self):
        r = IntBitLengthModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

class TestIntBitCountModel:
    def test_returns_result(self):
        r = IntBitCountModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestIntToBytesModel:
    def test_returns_result(self):
        r = IntToBytesModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestIntFromBytesModel:
    def test_returns_result(self):
        r = IntFromBytesModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestIntAsIntegerRatioModel:
    def test_returns_result(self):
        r = IntAsIntegerRatioModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestIntConjugateModel:
    def test_returns_result(self):
        r = IntConjugateModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestFloatIsIntegerModel:
    def test_returns_result(self):
        r = FloatIsIntegerModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestFloatAsIntegerRatioModel:
    def test_returns_result(self):
        r = FloatAsIntegerRatioModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestFloatHexModel:
    def test_returns_result(self):
        r = FloatHexModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestFloatFromhexModel:
    def test_returns_result(self):
        r = FloatFromhexModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestFloatConjugateModel:
    def test_returns_result(self):
        r = FloatConjugateModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestIntNumeratorModel:
    def test_returns_result(self):
        r = IntNumeratorModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestIntDenominatorModel:
    def test_returns_result(self):
        r = IntDenominatorModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestIntRealModel:
    def test_returns_result(self):
        r = IntRealModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestIntImagModel:
    def test_returns_result(self):
        r = IntImagModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestFloatRealModel:
    def test_returns_result(self):
        r = FloatRealModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestFloatImagModel:
    def test_returns_result(self):
        r = FloatImagModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)
