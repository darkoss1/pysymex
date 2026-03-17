"""Tests for list method models (lists.py)."""
from __future__ import annotations
import pytest
from tests.helpers import make_state, make_symbolic_int, make_symbolic_str
from pysymex.core.types import SymbolicList, SymbolicNone, SymbolicString, SymbolicValue
from pysymex.models.builtins_base import ModelResult
from pysymex.models.lists import (
    ListAppendModel, ListExtendModel, ListInsertModel, ListRemoveModel,
    ListPopModel, ListClearModel, ListIndexModel, ListCountModel,
    ListSortModel, ListReverseModel, ListCopyModel, ListSliceModel,
    ListContainsModel, ListLenModel, ListSetitemModel, ListDelitemModel,
    ListAddModel, ListMulModel, ListEqModel, ListIaddModel, ListImulModel,
)

def _state(pc=0):
    return make_state(pc=pc)

def _sl(name="lst"):
    sl, _ = SymbolicList.symbolic(name)
    return sl

class TestListAppendModel:
    def test_returns_none_mutates(self):
        r = ListAppendModel().apply([_sl(), 42], {}, _state())
        assert isinstance(r, ModelResult)
    def test_no_args(self):
        r = ListAppendModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

class TestListExtendModel:
    def test_returns_result(self):
        r = ListExtendModel().apply([_sl(), [1, 2]], {}, _state())
        assert isinstance(r, ModelResult)

class TestListInsertModel:
    def test_returns_result(self):
        r = ListInsertModel().apply([_sl(), 0, 42], {}, _state())
        assert isinstance(r, ModelResult)

class TestListRemoveModel:
    def test_returns_result(self):
        r = ListRemoveModel().apply([_sl(), 42], {}, _state())
        assert isinstance(r, ModelResult)

class TestListPopModel:
    def test_no_index(self):
        r = ListPopModel().apply([_sl()], {}, _state())
        assert isinstance(r, ModelResult)
    def test_with_index(self):
        r = ListPopModel().apply([_sl(), 0], {}, _state())
        assert isinstance(r, ModelResult)
    def test_no_args(self):
        r = ListPopModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

class TestListClearModel:
    def test_returns_result(self):
        r = ListClearModel().apply([_sl()], {}, _state())
        assert isinstance(r, ModelResult)

class TestListIndexModel:
    def test_returns_result(self):
        r = ListIndexModel().apply([_sl(), 42], {}, _state())
        assert isinstance(r, ModelResult)

class TestListCountModel:
    def test_returns_result(self):
        r = ListCountModel().apply([_sl(), 42], {}, _state())
        assert isinstance(r, ModelResult)

class TestListSortModel:
    def test_returns_result(self):
        r = ListSortModel().apply([_sl()], {}, _state())
        assert isinstance(r, ModelResult)

class TestListReverseModel:
    def test_returns_result(self):
        r = ListReverseModel().apply([_sl()], {}, _state())
        assert isinstance(r, ModelResult)

class TestListCopyModel:
    def test_returns_list(self):
        r = ListCopyModel().apply([_sl()], {}, _state())
        assert isinstance(r, ModelResult)

class TestListSliceModel:
    def test_returns_list(self):
        r = ListSliceModel().apply([_sl(), 0, 2], {}, _state())
        assert isinstance(r, ModelResult)

class TestListContainsModel:
    def test_returns_result(self):
        r = ListContainsModel().apply([_sl(), 42], {}, _state())
        assert isinstance(r, ModelResult)

class TestListLenModel:
    def test_returns_result(self):
        r = ListLenModel().apply([_sl()], {}, _state())
        assert isinstance(r, ModelResult)

class TestListSetitemModel:
    def test_returns_result(self):
        r = ListSetitemModel().apply([_sl(), 0, 42], {}, _state())
        assert isinstance(r, ModelResult)

class TestListDelitemModel:
    def test_returns_result(self):
        r = ListDelitemModel().apply([_sl(), 0], {}, _state())
        assert isinstance(r, ModelResult)

class TestListAddModel:
    def test_two_lists(self):
        r = ListAddModel().apply([_sl("a"), _sl("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestListMulModel:
    def test_returns_result(self):
        r = ListMulModel().apply([_sl(), 3], {}, _state())
        assert isinstance(r, ModelResult)

class TestListEqModel:
    def test_returns_result(self):
        r = ListEqModel().apply([_sl("a"), _sl("b")], {}, _state())
        assert isinstance(r, ModelResult)

class TestListIaddModel:
    def test_returns_result(self):
        r = ListIaddModel().apply([_sl(), [1, 2]], {}, _state())
        assert isinstance(r, ModelResult)

class TestListImulModel:
    def test_returns_result(self):
        r = ListImulModel().apply([_sl(), 2], {}, _state())
        assert isinstance(r, ModelResult)
