"""Tests for frozenset method models (frozenset_models.py)."""
from __future__ import annotations
import pytest
from tests.helpers import make_state, make_symbolic_int
from pysymex.core.types import SymbolicValue
from pysymex.models.builtins_base import ModelResult
from pysymex.models.frozenset_models import (
    FrozensetContainsModel, FrozensetLenModel, FrozensetUnionModel,
    FrozensetIntersectionModel, FrozensetDifferenceModel,
    FrozensetSymmetricDifferenceModel, FrozensetIssubsetModel,
    FrozensetIssupersetModel, FrozensetIsdisjointModel,
    FrozensetCopyModel, FrozensetHashModel,
)

def _state(pc=0):
    return make_state(pc=pc)

def _sv(name="fs"):
    return make_symbolic_int(name)

class TestFrozensetContainsModel:
    def test_returns_result(self):
        r = FrozensetContainsModel().apply([_sv(), 42], {}, _state())
        assert isinstance(r, ModelResult)
    def test_no_args(self):
        r = FrozensetContainsModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

class TestFrozensetLenModel:
    def test_returns_result(self):
        r = FrozensetLenModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestFrozensetUnionModel:
    def test_returns_result(self):
        r = FrozensetUnionModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestFrozensetIntersectionModel:
    def test_returns_result(self):
        r = FrozensetIntersectionModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestFrozensetDifferenceModel:
    def test_returns_result(self):
        r = FrozensetDifferenceModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestFrozensetSymmetricDifferenceModel:
    def test_returns_result(self):
        r = FrozensetSymmetricDifferenceModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestFrozensetIssubsetModel:
    def test_returns_result(self):
        r = FrozensetIssubsetModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestFrozensetIssupersetModel:
    def test_returns_result(self):
        r = FrozensetIssupersetModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestFrozensetIsdisjointModel:
    def test_returns_result(self):
        r = FrozensetIsdisjointModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestFrozensetCopyModel:
    def test_returns_result(self):
        r = FrozensetCopyModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestFrozensetHashModel:
    def test_returns_result(self):
        r = FrozensetHashModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)
