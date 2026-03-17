"""Tests for string method models (strings.py).

Phase 2 -- covers str.lower, upper, capitalize, title, swapcase, strip,
lstrip, rstrip, split, join, replace, startswith, endswith, find, index,
count, format, isdigit, isalpha, isalnum, isspace, islower, isupper,
center, ljust, rjust, zfill, removeprefix, removesuffix, __contains__,
rsplit, rfind, rindex, partition, rpartition, splitlines, encode,
casefold, expandtabs, maketrans, translate, istitle, isprintable,
isidentifier, isdecimal, isnumeric, format_map, isascii.
"""

from __future__ import annotations

import pytest
import z3

from tests.helpers import make_state, make_symbolic_int, make_symbolic_str, solve
from pysymex.core.types import SymbolicList, SymbolicNone, SymbolicString, SymbolicValue
from pysymex.models.builtins_base import ModelResult
from pysymex.models.strings import (
    StrLowerModel, StrUpperModel, StrCapitalizeModel, StrTitleModel,
    StrSwapcaseModel, StrStripModel, StrLstripModel, StrRstripModel,
    StrSplitModel, StrJoinModel, StrReplaceModel, StrStartswithModel,
    StrEndswithModel, StrFindModel, StrIndexModel, StrCountModel,
    StrFormatModel, StrIsdigitModel, StrIsalphaModel, StrIsalnumModel,
    StrIsspaceModel, StrIslowerModel, StrIsupperModel, StrCenterModel,
    StrLjustModel, StrRjustModel, StrZfillModel, StrRemovePrefixModel,
    StrRemoveSuffixModel, StrContainsModel, StrRsplitModel, StrRfindModel,
    StrRindexModel, StrPartitionModel, StrRpartitionModel,
    StrSplitlinesModel, StrEncodeModel, StrCasefoldModel,
    StrExpandtabsModel, StrMaketransModel, StrTranslateModel,
    StrIstitleModel, StrIsprintableModel, StrIsidentifierModel,
    StrIsdecimalModel, StrIsnumericModel, StrFormatMapModel, StrIsasciiModel,
)


def _state(pc=0):
    return make_state(pc=pc)


def _sym_str(name="s"):
    return make_symbolic_str(name)


# -- Case transforms --

class TestStrLowerModel:
    def test_qualname(self):
        assert StrLowerModel().qualname == "str.lower"

    def test_symbolic(self):
        r = StrLowerModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicString)

    def test_no_args(self):
        r = StrLowerModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestStrUpperModel:
    def test_symbolic(self):
        r = StrUpperModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicString)

    def test_no_args(self):
        r = StrUpperModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestStrCapitalizeModel:
    def test_symbolic(self):
        r = StrCapitalizeModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicString)


class TestStrTitleModel:
    def test_symbolic(self):
        r = StrTitleModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicString)


class TestStrSwapcaseModel:
    def test_symbolic(self):
        r = StrSwapcaseModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicString)


# -- Strip --

class TestStrStripModel:
    def test_symbolic(self):
        r = StrStripModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicString)

    def test_no_args(self):
        r = StrStripModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestStrLstripModel:
    def test_symbolic(self):
        r = StrLstripModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicString)


class TestStrRstripModel:
    def test_symbolic(self):
        r = StrRstripModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicString)


# -- Split / Join / Replace --

class TestStrSplitModel:
    def test_symbolic(self):
        r = StrSplitModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_no_args(self):
        r = StrSplitModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestStrJoinModel:
    def test_symbolic(self):
        r = StrJoinModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicString)

    def test_no_args(self):
        r = StrJoinModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestStrReplaceModel:
    def test_symbolic(self):
        r = StrReplaceModel().apply([_sym_str(), _sym_str("old"), _sym_str("new")], {}, _state())
        assert isinstance(r.value, SymbolicString)

    def test_no_args(self):
        r = StrReplaceModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


# -- Predicates --

class TestStrStartswithModel:
    def test_symbolic(self):
        r = StrStartswithModel().apply([_sym_str(), _sym_str("pfx")], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_no_args(self):
        r = StrStartswithModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestStrEndswithModel:
    def test_symbolic(self):
        r = StrEndswithModel().apply([_sym_str(), _sym_str("sfx")], {}, _state())
        assert isinstance(r.value, SymbolicValue)


# -- Find / Index / Count --

class TestStrFindModel:
    def test_symbolic(self):
        r = StrFindModel().apply([_sym_str(), _sym_str("sub")], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_no_args(self):
        r = StrFindModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestStrIndexModel:
    def test_symbolic(self):
        r = StrIndexModel().apply([_sym_str(), _sym_str("sub")], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestStrCountModel:
    def test_symbolic(self):
        r = StrCountModel().apply([_sym_str(), _sym_str("sub")], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestStrFormatModel:
    def test_symbolic(self):
        r = StrFormatModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicString)


# -- is* predicates --

class TestStrIsdigitModel:
    def test_symbolic(self):
        r = StrIsdigitModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_no_args(self):
        r = StrIsdigitModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestStrIsalphaModel:
    def test_symbolic(self):
        r = StrIsalphaModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestStrIsalnumModel:
    def test_symbolic(self):
        r = StrIsalnumModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestStrIsspaceModel:
    def test_symbolic(self):
        r = StrIsspaceModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestStrIslowerModel:
    def test_symbolic(self):
        r = StrIslowerModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestStrIsupperModel:
    def test_symbolic(self):
        r = StrIsupperModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicValue)


# -- Padding --

class TestStrCenterModel:
    def test_symbolic(self):
        r = StrCenterModel().apply([_sym_str(), make_symbolic_int("w")], {}, _state())
        assert isinstance(r.value, SymbolicString)

    def test_no_args(self):
        r = StrCenterModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestStrLjustModel:
    def test_symbolic(self):
        r = StrLjustModel().apply([_sym_str(), make_symbolic_int("w")], {}, _state())
        assert isinstance(r.value, SymbolicString)


class TestStrRjustModel:
    def test_symbolic(self):
        r = StrRjustModel().apply([_sym_str(), make_symbolic_int("w")], {}, _state())
        assert isinstance(r.value, SymbolicString)


class TestStrZfillModel:
    def test_symbolic(self):
        r = StrZfillModel().apply([_sym_str(), make_symbolic_int("w")], {}, _state())
        assert isinstance(r.value, SymbolicString)


# -- Remove prefix/suffix --

class TestStrRemovePrefixModel:
    def test_symbolic(self):
        r = StrRemovePrefixModel().apply([_sym_str(), _sym_str("pfx")], {}, _state())
        assert isinstance(r.value, SymbolicString)


class TestStrRemoveSuffixModel:
    def test_symbolic(self):
        r = StrRemoveSuffixModel().apply([_sym_str(), _sym_str("sfx")], {}, _state())
        assert isinstance(r.value, SymbolicString)


class TestStrContainsModel:
    def test_symbolic(self):
        r = StrContainsModel().apply([_sym_str(), _sym_str("sub")], {}, _state())
        assert isinstance(r.value, SymbolicValue)


# -- More split/find variants --

class TestStrRsplitModel:
    def test_symbolic(self):
        r = StrRsplitModel().apply([_sym_str()], {}, _state())
        assert isinstance(r, ModelResult)


class TestStrRfindModel:
    def test_symbolic(self):
        r = StrRfindModel().apply([_sym_str(), _sym_str("sub")], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestStrRindexModel:
    def test_symbolic(self):
        r = StrRindexModel().apply([_sym_str(), _sym_str("sub")], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestStrPartitionModel:
    def test_symbolic(self):
        r = StrPartitionModel().apply([_sym_str(), _sym_str("sep")], {}, _state())
        assert isinstance(r, ModelResult)


class TestStrRpartitionModel:
    def test_symbolic(self):
        r = StrRpartitionModel().apply([_sym_str(), _sym_str("sep")], {}, _state())
        assert isinstance(r, ModelResult)


class TestStrSplitlinesModel:
    def test_symbolic(self):
        r = StrSplitlinesModel().apply([_sym_str()], {}, _state())
        assert isinstance(r, ModelResult)


class TestStrEncodeModel:
    def test_symbolic(self):
        r = StrEncodeModel().apply([_sym_str()], {}, _state())
        assert isinstance(r, ModelResult)


class TestStrCasefoldModel:
    def test_symbolic(self):
        r = StrCasefoldModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicString)


class TestStrExpandtabsModel:
    def test_symbolic(self):
        r = StrExpandtabsModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicString)


class TestStrMaketransModel:
    def test_symbolic(self):
        r = StrMaketransModel().apply([_sym_str()], {}, _state())
        assert isinstance(r, ModelResult)


class TestStrTranslateModel:
    def test_symbolic(self):
        r = StrTranslateModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicString)


class TestStrIstitleModel:
    def test_symbolic(self):
        r = StrIstitleModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestStrIsprintableModel:
    def test_symbolic(self):
        r = StrIsprintableModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestStrIsidentifierModel:
    def test_symbolic(self):
        r = StrIsidentifierModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestStrIsdecimalModel:
    def test_symbolic(self):
        r = StrIsdecimalModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestStrIsnumericModel:
    def test_symbolic(self):
        r = StrIsnumericModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestStrFormatMapModel:
    def test_symbolic(self):
        r = StrFormatMapModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicString)

    def test_no_args(self):
        r = StrFormatMapModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestStrIsasciiModel:
    def test_symbolic(self):
        r = StrIsasciiModel().apply([_sym_str()], {}, _state())
        assert isinstance(r.value, SymbolicValue)
