"""Tests for tuple method models (tuples.py)."""
from __future__ import annotations
import pytest
from tests.helpers import make_state, make_symbolic_int
from pysymex.core.types import SymbolicList, SymbolicValue
from pysymex.models.builtins_base import ModelResult
from pysymex.models.tuples import (
    TupleModel, TupleGetitemModel, TupleContainsModel, TupleLenModel,
    TupleCountModel, TupleIndexModel, TupleAddModel, TupleMulModel,
    TupleSliceModel, TupleEqModel, TupleHashModel,
)

def _state(pc=0):
    return make_state(pc=pc)

def _sv(name="t"):
    return make_symbolic_int(name)

class TestTupleModel:
    def test_returns_result(self):
        r = TupleModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

class TestTupleGetitemModel:
    def test_returns_result(self):
        r = TupleGetitemModel().apply([_sv(), 0], {}, _state())
        assert isinstance(r, ModelResult)
    def test_no_args(self):
        r = TupleGetitemModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

class TestTupleContainsModel:
    def test_returns_result(self):
        r = TupleContainsModel().apply([_sv(), 42], {}, _state())
        assert isinstance(r, ModelResult)

class TestTupleLenModel:
    def test_returns_result(self):
        r = TupleLenModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestTupleCountModel:
    def test_returns_result(self):
        r = TupleCountModel().apply([_sv(), 42], {}, _state())
        assert isinstance(r, ModelResult)

class TestTupleIndexModel:
    def test_returns_result(self):
        r = TupleIndexModel().apply([_sv(), 42], {}, _state())
        assert isinstance(r, ModelResult)

class TestTupleAddModel:
    def test_returns_result(self):
        r = TupleAddModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestTupleMulModel:
    def test_returns_result(self):
        r = TupleMulModel().apply([_sv(), 3], {}, _state())
        assert isinstance(r, ModelResult)

class TestTupleSliceModel:
    def test_returns_result(self):
        r = TupleSliceModel().apply([_sv(), 0, 2], {}, _state())
        assert isinstance(r, ModelResult)

class TestTupleEqModel:
    def test_returns_result(self):
        r = TupleEqModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestTupleHashModel:
    def test_returns_result(self):
        r = TupleHashModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)
