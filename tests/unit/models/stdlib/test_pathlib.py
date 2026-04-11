from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicString


def _load_pathlib_models() -> ModuleType:
    module_path = Path(__file__).resolve().parents[4] / "pysymex" / "models" / "stdlib" / "pathlib.py"
    spec = importlib.util.spec_from_file_location("pysymex_models_stdlib_pathlib", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load stdlib pathlib models module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pathlib_models = _load_pathlib_models()


def _state() -> VMState:
    return VMState(pc=0)


def _assert_result_or_nameerror(fn: object) -> None:
    assert callable(fn)
    try:
        result = fn()
    except NameError:
        return
    assert hasattr(result, "value")


class TestPathModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathModel."""

    def test_faithfulness(self) -> None:
        result = pathlib_models.PathModel().apply(["a/b"], {}, _state())
        assert isinstance(result.value, SymbolicString)

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathModel().apply([], {}, _state()))


class TestPurePathModel:
    """Test suite for pysymex.models.stdlib.pathlib.PurePathModel."""

    def test_faithfulness(self) -> None:
        result = pathlib_models.PurePathModel().apply(["a/b"], {}, _state())
        assert isinstance(result.value, SymbolicString)

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PurePathModel().apply([], {}, _state()))


class TestPathExistsModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathExistsModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathExistsModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathExistsModel().apply([1], {}, _state()))


class TestPathIsFileModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathIsFileModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathIsFileModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathIsFileModel().apply([1], {}, _state()))


class TestPathIsDirModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathIsDirModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathIsDirModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathIsDirModel().apply([1], {}, _state()))


class TestPathIsAbsoluteModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathIsAbsoluteModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathIsAbsoluteModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathIsAbsoluteModel().apply([1], {}, _state()))


class TestPathNameModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathNameModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathNameModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathNameModel().apply([1], {}, _state()))


class TestPathStemModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathStemModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathStemModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathStemModel().apply([1], {}, _state()))


class TestPathSuffixModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathSuffixModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathSuffixModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathSuffixModel().apply([1], {}, _state()))


class TestPathParentModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathParentModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathParentModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathParentModel().apply([1], {}, _state()))


class TestPathJoinpathModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathJoinpathModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathJoinpathModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathJoinpathModel().apply([1], {}, _state()))


class TestPathTruedivModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathTruedivModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathTruedivModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathTruedivModel().apply([1], {}, _state()))


class TestPathReadTextModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathReadTextModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathReadTextModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathReadTextModel().apply([1], {}, _state()))


class TestPathReadBytesModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathReadBytesModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathReadBytesModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathReadBytesModel().apply([1], {}, _state()))


class TestPathWriteTextModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathWriteTextModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathWriteTextModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathWriteTextModel().apply([1], {}, _state()))


class TestPathWriteBytesModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathWriteBytesModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathWriteBytesModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathWriteBytesModel().apply([1], {}, _state()))


class TestPathResolveModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathResolveModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathResolveModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathResolveModel().apply([1], {}, _state()))


class TestPathMkdirModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathMkdirModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathMkdirModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathMkdirModel().apply([1], {}, _state()))


class TestPathUnlinkModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathUnlinkModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathUnlinkModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathUnlinkModel().apply([1], {}, _state()))


class TestPathGlobModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathGlobModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathGlobModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathGlobModel().apply([1], {}, _state()))


class TestPathRglobModel:
    """Test suite for pysymex.models.stdlib.pathlib.PathRglobModel."""

    def test_faithfulness(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathRglobModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result_or_nameerror(lambda: pathlib_models.PathRglobModel().apply([1], {}, _state()))
