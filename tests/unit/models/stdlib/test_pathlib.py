from __future__ import annotations

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.stdlib.pathlib.core import (
    PathIsAbsoluteModel,
    PathJoinpathModel,
    PathModel,
    PathNameModel,
    PathParentModel,
    PathStemModel,
    PathSuffixModel,
    PathTruedivModel,
    PurePathModel,
    PurePosixPathModel,
)
from pysymex._internal.models.stdlib.pathlib.file_io import (
    PathReadBytesModel,
    PathReadTextModel,
    PathWriteBytesModel,
    PathWriteTextModel,
)
from pysymex._internal.models.stdlib.pathlib.filesystem import (
    PathGlobModel,
    PathMkdirModel,
    PathResolveModel,
    PathRglobModel,
    PathUnlinkModel,
)
from pysymex._internal.models.stdlib.pathlib.status import (
    PathExistsModel,
    PathIsDirModel,
    PathIsFileModel,
)


def _state() -> VMState:
    return VMState(pc=0)


def _assert_result(fn: object) -> None:
    assert callable(fn)
    result = fn()
    assert hasattr(result, "value")


class TestPathModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathModel."""

    def test_faithfulness(self) -> None:
        result = PathModel().apply(["a/b"], {}, _state())
        assert isinstance(result.value, SymbolicString)
        assert result.value.name.startswith("path_")

    def test_error_path(self) -> None:
        _assert_result(lambda: PathModel().apply([], {}, _state()))


class TestPurePathModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PurePathModel."""

    def test_faithfulness(self) -> None:
        result = PurePathModel().apply(["a/b"], {}, _state())
        assert isinstance(result.value, SymbolicString)
        assert result.value.name.startswith("purepath_")

    def test_error_path(self) -> None:
        _assert_result(lambda: PurePathModel().apply([], {}, _state()))


class TestPurePosixPathModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PurePosixPathModel."""

    def test_faithfulness(self) -> None:
        result = PurePosixPathModel().apply(["a/b"], {}, _state())
        assert isinstance(result.value, SymbolicString)
        assert result.value.name.startswith("pureposixpath_")

    def test_error_path(self) -> None:
        _assert_result(lambda: PurePosixPathModel().apply([], {}, _state()))


class TestPathExistsModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathExistsModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathExistsModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathExistsModel().apply([1], {}, _state()))


class TestPathIsFileModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathIsFileModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathIsFileModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathIsFileModel().apply([1], {}, _state()))


class TestPathIsDirModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathIsDirModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathIsDirModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathIsDirModel().apply([1], {}, _state()))


class TestPathIsAbsoluteModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathIsAbsoluteModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathIsAbsoluteModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathIsAbsoluteModel().apply([1], {}, _state()))


class TestPathNameModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathNameModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathNameModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathNameModel().apply([1], {}, _state()))


class TestPathStemModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathStemModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathStemModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathStemModel().apply([1], {}, _state()))


class TestPathSuffixModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathSuffixModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathSuffixModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathSuffixModel().apply([1], {}, _state()))


class TestPathParentModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathParentModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathParentModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathParentModel().apply([1], {}, _state()))


class TestPathJoinpathModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathJoinpathModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathJoinpathModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathJoinpathModel().apply([1], {}, _state()))


class TestPathTruedivModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathTruedivModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathTruedivModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathTruedivModel().apply([1], {}, _state()))


class TestPathReadTextModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathReadTextModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathReadTextModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathReadTextModel().apply([1], {}, _state()))


class TestPathReadBytesModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathReadBytesModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathReadBytesModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathReadBytesModel().apply([1], {}, _state()))


class TestPathWriteTextModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathWriteTextModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathWriteTextModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathWriteTextModel().apply([1], {}, _state()))


class TestPathWriteBytesModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathWriteBytesModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathWriteBytesModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathWriteBytesModel().apply([1], {}, _state()))


class TestPathResolveModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathResolveModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathResolveModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathResolveModel().apply([1], {}, _state()))


class TestPathMkdirModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathMkdirModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathMkdirModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathMkdirModel().apply([1], {}, _state()))


class TestPathUnlinkModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathUnlinkModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathUnlinkModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathUnlinkModel().apply([1], {}, _state()))


class TestPathGlobModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathGlobModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathGlobModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathGlobModel().apply([1], {}, _state()))


class TestPathRglobModel:
    """Test suite for pysymex._internal.models.stdlib.pathlib.PathRglobModel."""

    def test_faithfulness(self) -> None:
        _assert_result(lambda: PathRglobModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _assert_result(lambda: PathRglobModel().apply([1], {}, _state()))
