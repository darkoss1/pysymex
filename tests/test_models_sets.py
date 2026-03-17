"""Tests for set method models (sets.py)."""
from __future__ import annotations
import pytest
from tests.helpers import make_state, make_symbolic_int
from pysymex.core.types import SymbolicList, SymbolicNone, SymbolicValue
from pysymex.models.builtins_base import ModelResult
from pysymex.models.sets import (
    SetModel as SetsConstructorModel, SetAddModel, SetRemoveModel,
    SetDiscardModel, SetPopModel, SetClearModel, SetCopyModel,
    SetUnionModel, SetIntersectionModel, SetContainsModel, SetLenModel,
    SetDifferenceModel, SetSymmetricDifferenceModel, SetIssubsetModel,
    SetIssupersetModel, SetIsdisjointModel, SetUpdateModel,
    SetIntersectionUpdateModel, SetDifferenceUpdateModel,
    SetSymmetricDifferenceUpdateModel,
)

def _state(pc=0):
    return make_state(pc=pc)

def _sv(name="s"):
    return make_symbolic_int(name)

class TestSetsConstructorModel:
    def test_returns_result(self):
        r = SetsConstructorModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetAddModel:
    def test_returns_result(self):
        r = SetAddModel().apply([_sv(), 42], {}, _state())
        assert isinstance(r, ModelResult)
    def test_no_args(self):
        r = SetAddModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetRemoveModel:
    def test_returns_result(self):
        r = SetRemoveModel().apply([_sv(), 42], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetDiscardModel:
    def test_returns_result(self):
        r = SetDiscardModel().apply([_sv(), 42], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetPopModel:
    def test_returns_result(self):
        r = SetPopModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)
    def test_no_args(self):
        r = SetPopModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetClearModel:
    def test_returns_result(self):
        r = SetClearModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetCopyModel:
    def test_returns_result(self):
        r = SetCopyModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetUnionModel:
    def test_returns_result(self):
        r = SetUnionModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetIntersectionModel:
    def test_returns_result(self):
        r = SetIntersectionModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetContainsModel:
    def test_returns_result(self):
        r = SetContainsModel().apply([_sv(), 42], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetLenModel:
    def test_returns_result(self):
        r = SetLenModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetDifferenceModel:
    def test_returns_result(self):
        r = SetDifferenceModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetSymmetricDifferenceModel:
    def test_returns_result(self):
        r = SetSymmetricDifferenceModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetIssubsetModel:
    def test_returns_result(self):
        r = SetIssubsetModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetIssupersetModel:
    def test_returns_result(self):
        r = SetIssupersetModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetIsdisjointModel:
    def test_returns_result(self):
        r = SetIsdisjointModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetUpdateModel:
    def test_returns_result(self):
        r = SetUpdateModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetIntersectionUpdateModel:
    def test_returns_result(self):
        r = SetIntersectionUpdateModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetDifferenceUpdateModel:
    def test_returns_result(self):
        r = SetDifferenceUpdateModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestSetSymmetricDifferenceUpdateModel:
    def test_returns_result(self):
        r = SetSymmetricDifferenceUpdateModel().apply([_sv(), _sv("b")], {}, _state())
        assert isinstance(r, ModelResult)
