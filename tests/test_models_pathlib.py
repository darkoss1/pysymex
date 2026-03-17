"""Tests for pathlib method models (pathlib_models.py)."""
from __future__ import annotations
import pytest
from tests.helpers import make_state, make_symbolic_str
from pysymex.core.types import SymbolicList, SymbolicNone, SymbolicString, SymbolicValue
from pysymex.models.builtins_base import ModelResult
from pysymex.models.pathlib_models import (
    PathModel, PurePathModel, PathExistsModel, PathIsFileModel,
    PathIsDirModel, PathIsAbsoluteModel, PathNameModel, PathStemModel,
    PathSuffixModel, PathParentModel, PathJoinpathModel, PathTruedivModel,
    PathReadTextModel, PathReadBytesModel, PathWriteTextModel,
    PathWriteBytesModel, PathResolveModel, PathMkdirModel, PathUnlinkModel,
    PathGlobModel, PathRglobModel,
)

def _state(pc=0):
    return make_state(pc=pc)

def _ss(name="p"):
    return make_symbolic_str(name)

class TestPathModel:
    def test_returns_result(self):
        r = PathModel().apply(["some/path"], {}, _state())
        assert isinstance(r, ModelResult)
    def test_no_args(self):
        r = PathModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

class TestPurePathModel:
    def test_returns_result(self):
        r = PurePathModel().apply(["some/path"], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathExistsModel:
    def test_returns_result(self):
        r = PathExistsModel().apply([_ss()], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathIsFileModel:
    def test_returns_result(self):
        r = PathIsFileModel().apply([_ss()], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathIsDirModel:
    def test_returns_result(self):
        r = PathIsDirModel().apply([_ss()], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathIsAbsoluteModel:
    def test_returns_result(self):
        r = PathIsAbsoluteModel().apply([_ss()], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathNameModel:
    def test_returns_result(self):
        r = PathNameModel().apply([_ss()], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathStemModel:
    def test_returns_result(self):
        r = PathStemModel().apply([_ss()], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathSuffixModel:
    def test_returns_result(self):
        r = PathSuffixModel().apply([_ss()], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathParentModel:
    def test_returns_result(self):
        r = PathParentModel().apply([_ss()], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathJoinpathModel:
    def test_returns_result(self):
        r = PathJoinpathModel().apply([_ss(), "sub"], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathTruedivModel:
    def test_returns_result(self):
        r = PathTruedivModel().apply([_ss(), "sub"], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathReadTextModel:
    def test_returns_result(self):
        r = PathReadTextModel().apply([_ss()], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathReadBytesModel:
    def test_returns_result(self):
        r = PathReadBytesModel().apply([_ss()], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathWriteTextModel:
    def test_returns_result(self):
        r = PathWriteTextModel().apply([_ss(), _ss("data")], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathWriteBytesModel:
    def test_returns_result(self):
        r = PathWriteBytesModel().apply([_ss(), _ss("data")], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathResolveModel:
    def test_returns_result(self):
        r = PathResolveModel().apply([_ss()], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathMkdirModel:
    def test_returns_result(self):
        r = PathMkdirModel().apply([_ss()], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathUnlinkModel:
    def test_returns_result(self):
        r = PathUnlinkModel().apply([_ss()], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathGlobModel:
    def test_returns_result(self):
        r = PathGlobModel().apply([_ss(), "*.py"], {}, _state())
        assert isinstance(r, ModelResult)

class TestPathRglobModel:
    def test_returns_result(self):
        r = PathRglobModel().apply([_ss(), "*.py"], {}, _state())
        assert isinstance(r, ModelResult)
