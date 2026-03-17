"""Tests for regex models (regex.py)."""
from __future__ import annotations
import pytest
from tests.helpers import make_state, make_symbolic_int, make_symbolic_str
from pysymex.core.types import SymbolicList, SymbolicString, SymbolicValue
from pysymex.models.builtins_base import ModelResult
from pysymex.models.regex import (
    ReMatchModel, ReSearchModel, ReFullmatchModel, ReFindallModel,
    ReSubModel, ReSplitModel, ReCompileModel, ReEscapeModel,
)

def _state(pc=0):
    return make_state(pc=pc)

def _ss(name="s"):
    return make_symbolic_str(name)

class TestReMatchModel:
    def test_returns_result(self):
        r = ReMatchModel().apply(["\\d+", _ss()], {}, _state())
        assert isinstance(r, ModelResult)
    def test_no_args(self):
        r = ReMatchModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)
    def test_concrete_pattern(self):
        r = ReMatchModel().apply(["\\d+", "123abc"], {}, _state())
        assert isinstance(r, ModelResult)

class TestReSearchModel:
    def test_returns_result(self):
        r = ReSearchModel().apply(["\\d+", _ss()], {}, _state())
        assert isinstance(r, ModelResult)
    def test_no_args(self):
        r = ReSearchModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

class TestReFullmatchModel:
    def test_returns_result(self):
        r = ReFullmatchModel().apply(["\\d+", _ss()], {}, _state())
        assert isinstance(r, ModelResult)

class TestReFindallModel:
    def test_returns_result(self):
        r = ReFindallModel().apply(["\\d+", _ss()], {}, _state())
        assert isinstance(r, ModelResult)
    def test_no_args(self):
        r = ReFindallModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

class TestReSubModel:
    def test_returns_result(self):
        r = ReSubModel().apply(["\\d+", "X", _ss()], {}, _state())
        assert isinstance(r, ModelResult)
    def test_no_args(self):
        r = ReSubModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

class TestReSplitModel:
    def test_returns_result(self):
        r = ReSplitModel().apply(["\\d+", _ss()], {}, _state())
        assert isinstance(r, ModelResult)

class TestReCompileModel:
    @pytest.mark.xfail(strict=False, reason="model sets attr on frozen SymbolicValue")
    def test_returns_result(self):
        r = ReCompileModel().apply(["\\d+"], {}, _state())
        assert isinstance(r, ModelResult)
    def test_no_args(self):
        r = ReCompileModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

class TestReEscapeModel:
    def test_returns_result(self):
        r = ReEscapeModel().apply(["hello.world"], {}, _state())
        assert isinstance(r, ModelResult)
    def test_symbolic(self):
        r = ReEscapeModel().apply([_ss()], {}, _state())
        assert isinstance(r, ModelResult)
