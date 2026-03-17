"""Tests for core builtin function models (builtins_core.py).

Phase 2 -- covers len, range, abs, min, max, int, str, bool, print,
type, isinstance, sorted, sum, enumerate, zip, map, filter, float,
list, tuple, NoneType.
"""

from __future__ import annotations

import pytest
import z3

from tests.helpers import make_state, make_symbolic_int, make_symbolic_str, solve, prove
from pysymex.core.types import (
    SymbolicList,
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
)
from pysymex.models.builtins_base import ModelResult
from pysymex.models.builtins_core import (
    LenModel,
    RangeModel,
    AbsModel,
    MinModel,
    MaxModel,
    IntModel,
    StrModel,
    BoolModel,
    PrintModel,
    TypeModel,
    IsinstanceModel,
    SortedModel,
    SumModel,
    EnumerateModel,
    ZipModel,
    MapModel,
    FilterModel,
    FloatModel,
    ListModel,
    TupleModel,
    NoneModel,
)


def _state(pc=0):
    return make_state(pc=pc)


# -------------------------------------------------------------------
# LenModel
# -------------------------------------------------------------------
class TestLenModel:
    def test_qualname(self):
        assert LenModel().qualname == "builtins.len"

    def test_no_args(self):
        r = LenModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)
        assert isinstance(r.value, SymbolicValue)

    def test_symbolic_list(self):
        sl, _ = SymbolicList.symbolic("lst")
        r = LenModel().apply([sl], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 4

    def test_symbolic_string(self):
        ss = make_symbolic_str("s")
        r = LenModel().apply([ss], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 4

    def test_symbolic_value_fallback(self):
        sv = make_symbolic_int("x")
        r = LenModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 3


# -------------------------------------------------------------------
# RangeModel
# -------------------------------------------------------------------
class TestRangeModel:
    def test_qualname(self):
        assert RangeModel().qualname == "builtins.range"

    def test_no_args(self):
        r = RangeModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_one_symbolic_arg(self):
        sv = make_symbolic_int("n")
        r = RangeModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicList)
        assert len(r.constraints) >= 2

    def test_two_args(self):
        a = make_symbolic_int("a")
        b = make_symbolic_int("b")
        r = RangeModel().apply([a, b], {}, _state())
        assert isinstance(r.value, SymbolicList)
        assert len(r.constraints) >= 3

    def test_three_args(self):
        a = make_symbolic_int("a")
        b = make_symbolic_int("b")
        c = make_symbolic_int("c")
        r = RangeModel().apply([a, b, c], {}, _state())
        assert isinstance(r.value, SymbolicList)
        assert len(r.constraints) >= 3


# -------------------------------------------------------------------
# AbsModel
# -------------------------------------------------------------------
class TestAbsModel:
    def test_qualname(self):
        assert AbsModel().qualname == "builtins.abs"

    def test_no_args(self):
        r = AbsModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_symbolic_int(self):
        sv = make_symbolic_int("x")
        r = AbsModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 3

    def test_concrete_negative(self):
        r = AbsModel().apply([-5], {}, _state())
        assert r.value == 5

    def test_concrete_positive(self):
        r = AbsModel().apply([3], {}, _state())
        assert r.value == 3


# -------------------------------------------------------------------
# MinModel
# -------------------------------------------------------------------
class TestMinModel:
    def test_qualname(self):
        assert MinModel().qualname == "builtins.min"

    def test_no_args(self):
        r = MinModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete_list(self):
        r = MinModel().apply([[3, 1, 2]], {}, _state())
        assert r.value == 1

    def test_two_symbolic_args(self):
        a = make_symbolic_int("a")
        b = make_symbolic_int("b")
        r = MinModel().apply([a, b], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 3

    def test_concrete_args(self):
        r = MinModel().apply([5, 3], {}, _state())
        assert r.value == 3


# -------------------------------------------------------------------
# MaxModel
# -------------------------------------------------------------------
class TestMaxModel:
    def test_qualname(self):
        assert MaxModel().qualname == "builtins.max"

    def test_no_args(self):
        r = MaxModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete_list(self):
        r = MaxModel().apply([[1, 5, 3]], {}, _state())
        assert r.value == 5

    def test_two_symbolic_args(self):
        a = make_symbolic_int("a")
        b = make_symbolic_int("b")
        r = MaxModel().apply([a, b], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 3


# -------------------------------------------------------------------
# IntModel
# -------------------------------------------------------------------
class TestIntModel:
    def test_qualname(self):
        assert IntModel().qualname == "builtins.int"

    def test_no_args(self):
        r = IntModel().apply([], {}, _state())
        assert r.value == 0

    def test_symbolic_value(self):
        sv = make_symbolic_int("x")
        r = IntModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 3

    def test_symbolic_string(self):
        ss = make_symbolic_str("s")
        r = IntModel().apply([ss], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 3

    def test_concrete(self):
        r = IntModel().apply([3.7], {}, _state())
        assert r.value == 3


# -------------------------------------------------------------------
# StrModel
# -------------------------------------------------------------------
class TestStrModel:
    def test_qualname(self):
        assert StrModel().qualname == "builtins.str"

    def test_no_args(self):
        r = StrModel().apply([], {}, _state())
        assert r.value == ""

    def test_symbolic_value(self):
        sv = make_symbolic_int("x")
        r = StrModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicString)
        assert len(r.constraints) >= 2

    def test_concrete(self):
        r = StrModel().apply([42], {}, _state())
        assert r.value == "42"


# -------------------------------------------------------------------
# BoolModel
# -------------------------------------------------------------------
class TestBoolModel:
    def test_qualname(self):
        assert BoolModel().qualname == "builtins.bool"

    def test_no_args(self):
        r = BoolModel().apply([], {}, _state())
        assert r.value is False

    def test_symbolic_value(self):
        sv = make_symbolic_int("x")
        r = BoolModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 3

    def test_concrete_truthy(self):
        r = BoolModel().apply([1], {}, _state())
        assert r.value is True

    def test_concrete_falsy(self):
        r = BoolModel().apply([0], {}, _state())
        assert r.value is False


# -------------------------------------------------------------------
# PrintModel
# -------------------------------------------------------------------
class TestPrintModel:
    def test_qualname(self):
        assert PrintModel().qualname == "builtins.print"

    def test_returns_none(self):
        r = PrintModel().apply(["hello"], {}, _state())
        assert isinstance(r.value, SymbolicNone)

    def test_no_args(self):
        r = PrintModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicNone)


# -------------------------------------------------------------------
# TypeModel
# -------------------------------------------------------------------
class TestTypeModel:
    def test_qualname(self):
        assert TypeModel().qualname == "builtins.type"

    def test_no_args(self):
        r = TypeModel().apply([], {}, _state())
        assert r.value is type

    def test_with_arg(self):
        r = TypeModel().apply([42], {}, _state())
        assert isinstance(r.value, SymbolicValue)


# -------------------------------------------------------------------
# IsinstanceModel
# -------------------------------------------------------------------
class TestIsinstanceModel:
    def test_qualname(self):
        assert IsinstanceModel().qualname == "builtins.isinstance"

    def test_no_args(self):
        r = IsinstanceModel().apply([], {}, _state())
        assert r.value is False

    def test_symbolic_is_int(self):
        sv = make_symbolic_int("x")
        r = IsinstanceModel().apply([sv, int], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 3

    def test_symbolic_string_is_str(self):
        ss = make_symbolic_str("s")
        r = IsinstanceModel().apply([ss, str], {}, _state())
        assert r.value is True

    def test_symbolic_list_is_list(self):
        sl, _ = SymbolicList.symbolic("l")
        r = IsinstanceModel().apply([sl, list], {}, _state())
        assert r.value is True


# -------------------------------------------------------------------
# SortedModel
# -------------------------------------------------------------------
class TestSortedModel:
    def test_qualname(self):
        assert SortedModel().qualname == "builtins.sorted"

    def test_no_args(self):
        r = SortedModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_symbolic_list(self):
        sl, _ = SymbolicList.symbolic("lst")
        r = SortedModel().apply([sl], {}, _state())
        assert isinstance(r.value, SymbolicList)
        assert len(r.constraints) >= 2


# -------------------------------------------------------------------
# SumModel
# -------------------------------------------------------------------
class TestSumModel:
    def test_qualname(self):
        assert SumModel().qualname == "builtins.sum"

    def test_no_args(self):
        r = SumModel().apply([], {}, _state())
        assert r.value == 0

    def test_concrete_list(self):
        r = SumModel().apply([[1, 2, 3]], {}, _state())
        assert r.value == 6

    def test_concrete_with_start(self):
        r = SumModel().apply([[1, 2], 10], {}, _state())
        assert r.value == 13

    def test_symbolic_fallback(self):
        sv = make_symbolic_int("x")
        r = SumModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicValue)


# -------------------------------------------------------------------
# EnumerateModel
# -------------------------------------------------------------------
class TestEnumerateModel:
    def test_qualname(self):
        assert EnumerateModel().qualname == "builtins.enumerate"

    def test_returns_symbolic_list(self):
        r = EnumerateModel().apply([[1, 2]], {}, _state())
        assert isinstance(r.value, SymbolicList)


# -------------------------------------------------------------------
# ZipModel
# -------------------------------------------------------------------
class TestZipModel:
    def test_qualname(self):
        assert ZipModel().qualname == "builtins.zip"

    def test_returns_symbolic_list(self):
        r = ZipModel().apply([[1], [2]], {}, _state())
        assert isinstance(r.value, SymbolicList)


# -------------------------------------------------------------------
# MapModel
# -------------------------------------------------------------------
class TestMapModel:
    def test_qualname(self):
        assert MapModel().qualname == "builtins.map"

    def test_returns_symbolic_list(self):
        r = MapModel().apply([None, [1, 2]], {}, _state())
        assert isinstance(r.value, SymbolicList)


# -------------------------------------------------------------------
# FilterModel
# -------------------------------------------------------------------
class TestFilterModel:
    def test_qualname(self):
        assert FilterModel().qualname == "builtins.filter"

    def test_returns_symbolic_list(self):
        r = FilterModel().apply([None, [1, 2]], {}, _state())
        assert isinstance(r.value, SymbolicList)


# -------------------------------------------------------------------
# FloatModel
# -------------------------------------------------------------------
class TestFloatModel:
    def test_qualname(self):
        assert FloatModel().qualname == "builtins.float"

    def test_no_args(self):
        r = FloatModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

    def test_concrete_int(self):
        r = FloatModel().apply([5], {}, _state())
        assert isinstance(r, ModelResult)

    def test_concrete_float(self):
        r = FloatModel().apply([3.14], {}, _state())
        assert isinstance(r, ModelResult)


# -------------------------------------------------------------------
# ListModel
# -------------------------------------------------------------------
class TestListModel:
    def test_qualname(self):
        assert ListModel().qualname == "builtins.list"

    def test_no_args(self):
        r = ListModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_symbolic_list_passthrough(self):
        sl, _ = SymbolicList.symbolic("lst")
        r = ListModel().apply([sl], {}, _state())
        assert r.value is sl

    def test_concrete_list(self):
        r = ListModel().apply([[1, 2, 3]], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_concrete_tuple(self):
        r = ListModel().apply([(1, 2)], {}, _state())
        assert isinstance(r.value, SymbolicList)


# -------------------------------------------------------------------
# TupleModel
# -------------------------------------------------------------------
class TestTupleModel:
    def test_qualname(self):
        assert TupleModel().qualname == "builtins.tuple"

    def test_no_args(self):
        r = TupleModel().apply([], {}, _state())
        assert r.value == ()

    def test_tuple_passthrough(self):
        r = TupleModel().apply([(1, 2)], {}, _state())
        assert r.value == (1, 2)

    def test_concrete_list(self):
        r = TupleModel().apply([[1, 2]], {}, _state())
        assert r.value == (1, 2)

    def test_symbolic_list(self):
        sl, _ = SymbolicList.symbolic("lst")
        r = TupleModel().apply([sl], {}, _state())
        assert isinstance(r.value, SymbolicList)


# -------------------------------------------------------------------
# NoneModel
# -------------------------------------------------------------------
class TestNoneModel:
    def test_qualname(self):
        assert NoneModel().qualname == "builtins.NoneType"

    def test_returns_symbolic_none(self):
        r = NoneModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicNone)
