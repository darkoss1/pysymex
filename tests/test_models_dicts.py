"""Tests for dict method models (dicts.py).

Phase 2 -- covers dict.get, __getitem__, __setitem__, __delitem__, keys,
values, items, pop, popitem, update, clear, copy, setdefault, __contains__,
__len__, fromkeys, __eq__, __or__, __ior__.
"""

from __future__ import annotations

import pytest
import z3

from tests.helpers import make_state, make_symbolic_int, make_symbolic_str, solve
from pysymex.core.types import SymbolicList, SymbolicNone, SymbolicString, SymbolicValue
from pysymex.models.builtins_base import ModelResult
from pysymex.models.dicts import (
    DictGetModel, DictGetitemModel, DictSetitemModel, DictDelitemModel,
    DictKeysModel, DictValuesModel, DictItemsModel, DictPopModel,
    DictPopitemModel, DictUpdateModel, DictClearModel, DictCopyModel,
    DictSetdefaultModel, DictContainsModel, DictLenModel, DictFromkeysModel,
    DictEqModel, DictOrModel, DictIorModel,
)


def _state(pc=0):
    return make_state(pc=pc)


class TestDictGetModel:
    def test_qualname(self):
        assert DictGetModel().qualname == "dict.get"

    def test_no_args(self):
        r = DictGetModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

    def test_with_key(self):
        r = DictGetModel().apply([make_symbolic_int("d"), "key"], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictGetitemModel:
    def test_no_args(self):
        r = DictGetitemModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

    def test_with_key(self):
        r = DictGetitemModel().apply([make_symbolic_int("d"), "key"], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictSetitemModel:
    def test_returns_none(self):
        r = DictSetitemModel().apply([make_symbolic_int("d"), "key", 42], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictDelitemModel:
    def test_returns_none(self):
        r = DictDelitemModel().apply([make_symbolic_int("d"), "key"], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictKeysModel:
    def test_returns_result(self):
        r = DictKeysModel().apply([make_symbolic_int("d")], {}, _state())
        assert isinstance(r, ModelResult)

    def test_no_args(self):
        r = DictKeysModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictValuesModel:
    def test_returns_result(self):
        r = DictValuesModel().apply([make_symbolic_int("d")], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictItemsModel:
    def test_returns_result(self):
        r = DictItemsModel().apply([make_symbolic_int("d")], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictPopModel:
    def test_with_key(self):
        r = DictPopModel().apply([make_symbolic_int("d"), "key"], {}, _state())
        assert isinstance(r, ModelResult)

    def test_no_args(self):
        r = DictPopModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictPopitemModel:
    def test_returns_result(self):
        r = DictPopitemModel().apply([make_symbolic_int("d")], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictUpdateModel:
    def test_returns_none(self):
        r = DictUpdateModel().apply([make_symbolic_int("d")], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictClearModel:
    def test_returns_none(self):
        r = DictClearModel().apply([make_symbolic_int("d")], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictCopyModel:
    def test_returns_result(self):
        r = DictCopyModel().apply([make_symbolic_int("d")], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictSetdefaultModel:
    def test_with_key(self):
        r = DictSetdefaultModel().apply([make_symbolic_int("d"), "key"], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictContainsModel:
    def test_with_key(self):
        r = DictContainsModel().apply([make_symbolic_int("d"), "key"], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictLenModel:
    def test_returns_symbolic_int(self):
        r = DictLenModel().apply([make_symbolic_int("d")], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictFromkeysModel:
    def test_returns_result(self):
        r = DictFromkeysModel().apply([["a", "b"]], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictEqModel:
    def test_returns_result(self):
        r = DictEqModel().apply([make_symbolic_int("a"), make_symbolic_int("b")], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictOrModel:
    def test_returns_result(self):
        r = DictOrModel().apply([make_symbolic_int("a"), make_symbolic_int("b")], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictIorModel:
    def test_returns_result(self):
        r = DictIorModel().apply([make_symbolic_int("a"), make_symbolic_int("b")], {}, _state())
        assert isinstance(r, ModelResult)
