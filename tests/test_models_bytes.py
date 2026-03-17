"""Tests for bytes/bytearray method models (bytes_models.py)."""
from __future__ import annotations
import pytest
from tests.helpers import make_state, make_symbolic_int, make_symbolic_str
from pysymex.core.types import SymbolicList, SymbolicNone, SymbolicString, SymbolicValue
from pysymex.models.builtins_base import ModelResult
from pysymex.models.bytes_models import (
    BytesDecodeModel, BytesCountModel, BytesFindModel, BytesRfindModel,
    BytesIndexModel, BytesRindexModel, BytesJoinModel, BytesSplitModel,
    BytesRsplitModel, BytesReplaceModel, BytesStripModel, BytesLstripModel,
    BytesRstripModel, BytesStartswithModel, BytesEndswithModel,
    BytesUpperModel, BytesLowerModel, BytesTitleModel, BytesCapitalizeModel,
    BytesSwapcaseModel, BytesContainsModel, BytesLenModel, BytesHexModel,
    BytesPartitionModel, BytesRpartitionModel, BytesSplitlinesModel,
    BytesCenterModel, BytesLjustModel, BytesRjustModel, BytesZfillModel,
    BytesTranslateModel, BytesMaketransModel, BytesExpandtabsModel,
    BytesIsdigitModel, BytesIsalphaModel, BytesIsalnumModel,
    BytesIsspaceModel, BytesIslowerModel, BytesIsupperModel,
    BytesIstitleModel, BytesRemovePrefixModel, BytesRemoveSuffixModel,
    BytearrayAppendModel, BytearrayExtendModel, BytearrayInsertModel,
    BytearrayPopModel, BytearrayRemoveModel, BytearrayClearModel,
    BytearrayReverseModel, BytearrayCopyModel,
    BytesIsasciiModel, BytearrayIsasciiModel,
)

def _state(pc=0):
    return make_state(pc=pc)

def _sv(name="b"):
    return make_symbolic_int(name)

# -- Bytes string-like methods --
class TestBytesDecodeModel:
    def test_returns_result(self):
        r = BytesDecodeModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)
    def test_no_args(self):
        r = BytesDecodeModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesCountModel:
    def test_returns_result(self):
        r = BytesCountModel().apply([_sv(), _sv("sub")], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesFindModel:
    def test_returns_result(self):
        r = BytesFindModel().apply([_sv(), _sv("sub")], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesRfindModel:
    def test_returns_result(self):
        r = BytesRfindModel().apply([_sv(), _sv("sub")], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesIndexModel:
    def test_returns_result(self):
        r = BytesIndexModel().apply([_sv(), _sv("sub")], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesRindexModel:
    def test_returns_result(self):
        r = BytesRindexModel().apply([_sv(), _sv("sub")], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesJoinModel:
    def test_returns_result(self):
        r = BytesJoinModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesSplitModel:
    def test_returns_result(self):
        r = BytesSplitModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesRsplitModel:
    def test_returns_result(self):
        r = BytesRsplitModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesReplaceModel:
    def test_returns_result(self):
        r = BytesReplaceModel().apply([_sv(), _sv("old"), _sv("new")], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesStripModel:
    def test_returns_result(self):
        r = BytesStripModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesLstripModel:
    def test_returns_result(self):
        r = BytesLstripModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesRstripModel:
    def test_returns_result(self):
        r = BytesRstripModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesStartswithModel:
    def test_returns_result(self):
        r = BytesStartswithModel().apply([_sv(), _sv("pfx")], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesEndswithModel:
    def test_returns_result(self):
        r = BytesEndswithModel().apply([_sv(), _sv("sfx")], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesUpperModel:
    def test_returns_result(self):
        r = BytesUpperModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesLowerModel:
    def test_returns_result(self):
        r = BytesLowerModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesTitleModel:
    def test_returns_result(self):
        r = BytesTitleModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesCapitalizeModel:
    def test_returns_result(self):
        r = BytesCapitalizeModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesSwapcaseModel:
    def test_returns_result(self):
        r = BytesSwapcaseModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesContainsModel:
    def test_returns_result(self):
        r = BytesContainsModel().apply([_sv(), _sv("sub")], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesLenModel:
    def test_returns_result(self):
        r = BytesLenModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesHexModel:
    def test_returns_result(self):
        r = BytesHexModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesPartitionModel:
    def test_returns_result(self):
        r = BytesPartitionModel().apply([_sv(), _sv("sep")], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesRpartitionModel:
    def test_returns_result(self):
        r = BytesRpartitionModel().apply([_sv(), _sv("sep")], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesSplitlinesModel:
    def test_returns_result(self):
        r = BytesSplitlinesModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesCenterModel:
    def test_returns_result(self):
        r = BytesCenterModel().apply([_sv(), make_symbolic_int("w")], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesLjustModel:
    def test_returns_result(self):
        r = BytesLjustModel().apply([_sv(), make_symbolic_int("w")], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesRjustModel:
    def test_returns_result(self):
        r = BytesRjustModel().apply([_sv(), make_symbolic_int("w")], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesZfillModel:
    def test_returns_result(self):
        r = BytesZfillModel().apply([_sv(), make_symbolic_int("w")], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesTranslateModel:
    def test_returns_result(self):
        r = BytesTranslateModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesMaketransModel:
    def test_returns_result(self):
        r = BytesMaketransModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesExpandtabsModel:
    def test_returns_result(self):
        r = BytesExpandtabsModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesIsdigitModel:
    def test_returns_result(self):
        r = BytesIsdigitModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesIsalphaModel:
    def test_returns_result(self):
        r = BytesIsalphaModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesIsalnumModel:
    def test_returns_result(self):
        r = BytesIsalnumModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesIsspaceModel:
    def test_returns_result(self):
        r = BytesIsspaceModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesIslowerModel:
    def test_returns_result(self):
        r = BytesIslowerModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesIsupperModel:
    def test_returns_result(self):
        r = BytesIsupperModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesIstitleModel:
    def test_returns_result(self):
        r = BytesIstitleModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesRemovePrefixModel:
    def test_returns_result(self):
        r = BytesRemovePrefixModel().apply([_sv(), _sv("pfx")], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesRemoveSuffixModel:
    def test_returns_result(self):
        r = BytesRemoveSuffixModel().apply([_sv(), _sv("sfx")], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytesIsasciiModel:
    def test_returns_result(self):
        r = BytesIsasciiModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

# -- Bytearray mutation methods --
class TestBytearrayAppendModel:
    def test_returns_result(self):
        r = BytearrayAppendModel().apply([_sv(), 42], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytearrayExtendModel:
    def test_returns_result(self):
        r = BytearrayExtendModel().apply([_sv(), [1, 2]], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytearrayInsertModel:
    def test_returns_result(self):
        r = BytearrayInsertModel().apply([_sv(), 0, 42], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytearrayPopModel:
    def test_returns_result(self):
        r = BytearrayPopModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytearrayRemoveModel:
    def test_returns_result(self):
        r = BytearrayRemoveModel().apply([_sv(), 42], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytearrayClearModel:
    def test_returns_result(self):
        r = BytearrayClearModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytearrayReverseModel:
    def test_returns_result(self):
        r = BytearrayReverseModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytearrayCopyModel:
    def test_returns_result(self):
        r = BytearrayCopyModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)

class TestBytearrayIsasciiModel:
    def test_returns_result(self):
        r = BytearrayIsasciiModel().apply([_sv()], {}, _state())
        assert isinstance(r, ModelResult)
